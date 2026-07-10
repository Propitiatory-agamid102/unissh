import { ApiError, errorFromResponse } from "./errors";
import type {
  AccountLookupResp,
  AccountsResp,
  AdminOverview,
  AuditResp,
  AuditVerify,
  AuthChallenge,
  BootstrapResp,
  ConfigPutReq,
  ConfigPutResp,
  ConfigResp,
  DevicesResp,
  EnrollGrantsResp,
  EnrollIssueResp,
  GrantsResp,
  HealthInfo,
  InstanceInfo,
  InviteIssueResp,
  InvitesResp,
  KeysetsResp,
  MetricsRaw,
  MetricsSummary,
  MigrationsResp,
  ObjectsResp,
  OpsOverview,
  OpsSeqBumpResp,
  OpsTenantsResp,
  RelayResp,
  SeqBumpResp,
  SessionsResp,
  VaultRow,
  VaultsResp,
  VerifyResp,
  VersionInfo,
} from "./types";

/** Auth/context resolved per-request from the stores (non-reactive read). */
export interface AuthContext {
  instanceUrl: string;
  opsToken: string | null;
  /** Admin Bearer access token (base64) from the keyset session. */
  bearer: string | null;
  /** Active tenant id (already base64) for the UniSSH-Tenant header. */
  tenantId: string | null;
}

interface CallOpts {
  method?: "GET" | "POST" | "PUT";
  body?: unknown;
  /** Send UniSSH-Tenant header. */
  tenant?: boolean;
  /** Override the tenant id for this call (bootstrap a new tenant). */
  tenantId?: string;
  /** Send Authorization: Bearer header. */
  bearer?: boolean;
  /** Send X-UniSSH-Ops-Token header. */
  ops?: boolean;
  /** Attach an Idempotency-Key (mutations). */
  idem?: boolean;
  query?: Record<string, string | number | undefined | null>;
}

function uuid(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return "idem-" + Math.abs(Date.now() ^ (Math.random() * 1e9)).toString(36);
}

function qs(query?: CallOpts["query"]): string {
  if (!query) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export function createClient(
  getAuth: () => AuthContext,
  refresh?: () => Promise<boolean>,
  /** Called when an auth tier is rejected by the server and can't be recovered:
   *  "keyset" = admin Bearer 401 that refresh couldn't rotate; "ops" = the ops
   *  token was rejected. Lets the app lock/return-to-login instead of leaving a
   *  green badge that lies while every screen 401s. */
  onAuthLost?: (scope: "keyset" | "ops") => void,
) {
  // Dedupe concurrent refreshes: when the access token lapses, many in-flight admin
  // calls 401 at the same instant. A single shared refresh avoids firing N parallel
  // /v1/session/refresh calls, which would trip the server's refresh-token REUSE
  // detection and revoke the whole session.
  let inflightRefresh: Promise<boolean> | null = null;
  function refreshOnce(): Promise<boolean> {
    if (!refresh) return Promise.resolve(false);
    if (!inflightRefresh) {
      inflightRefresh = refresh().finally(() => {
        inflightRefresh = null;
      });
    }
    return inflightRefresh;
  }

  async function call<T>(path: string, opts: CallOpts = {}, retried = false): Promise<T> {
    const auth = getAuth();
    const base = auth.instanceUrl.replace(/\/+$/, "");
    const url = base + path + qs(opts.query);
    const headers: Record<string, string> = { Accept: "application/json" };

    if (opts.tenant) {
      const tid = opts.tenantId ?? auth.tenantId;
      if (!tid) throw new ApiError("malformed", "no active tenant", 0);
      headers["UniSSH-Tenant"] = tid;
    }
    if (opts.bearer) {
      if (!auth.bearer) throw new ApiError("unauthenticated", "keyset locked", 401);
      headers["Authorization"] = `Bearer ${auth.bearer}`;
    }
    if (opts.ops) {
      if (!auth.opsToken) throw new ApiError("forbidden", "ops token not set", 403);
      headers["X-UniSSH-Ops-Token"] = auth.opsToken;
    }
    if (opts.idem) headers["Idempotency-Key"] = uuid();

    const init: RequestInit = { method: opts.method ?? "GET", headers };
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }

    let res: Response;
    try {
      res = await fetch(url, init);
    } catch (e) {
      throw new ApiError("network", e instanceof Error ? e.message : "network error", 0);
    }
    if (!res.ok) {
      // Access token lapsed → rotate it with the refresh token and retry once, so the
      // operator keeps working instead of being bounced to the keyset-unlock screen.
      if (res.status === 401 && opts.bearer && !retried) {
        const ok = await refreshOnce();
        if (ok) return call<T>(path, opts, true);
        // Refresh failed (session revoked, device removed, tenant changed): the
        // keyset session is dead. Signal it so the UI auto-locks and says so.
        onAuthLost?.("keyset");
      } else if (opts.ops && (res.status === 401 || res.status === 403)) {
        // The ops token itself was rejected (rotated in config, ops disabled) —
        // the whole panel is unauthenticated; bounce to login.
        onAuthLost?.("ops");
      }
      throw await errorFromResponse(res);
    }
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    if (!text) return undefined as T;
    return JSON.parse(text) as T;
  }

  return {
    call,

    // ── service (no auth) ──
    version: () => call<VersionInfo>("/v1/version"),
    readyz: async (): Promise<boolean> => {
      const auth = getAuth();
      try {
        const r = await fetch(auth.instanceUrl.replace(/\/+$/, "") + "/readyz");
        return r.ok;
      } catch {
        return false;
      }
    },

    // ── ops (X-UniSSH-Ops-Token) ──
    ops: {
      tenants: () => call<OpsTenantsResp>("/v1/ops/tenants", { ops: true }),
      overview: () => call<OpsOverview>("/v1/ops/overview", { ops: true }),
      instance: () => call<InstanceInfo>("/v1/ops/instance", { ops: true }),
      tenantStatus: (tenant_id: string, suspended: boolean) =>
        call<void>("/v1/ops/tenant/status", {
          method: "POST",
          ops: true,
          idem: true,
          body: { tenant_id, suspended },
        }),
      tenantProfile: (tenant_id: string, display_name: string) =>
        call<void>("/v1/ops/tenant/profile", {
          method: "POST",
          ops: true,
          idem: true,
          body: { tenant_id, display_name },
        }),
      account: (handle: string) =>
        call<AccountLookupResp>("/v1/ops/account", { ops: true, query: { handle } }),
      seqBump: (req: { tenant_id?: string; by?: number; to?: number }) =>
        call<OpsSeqBumpResp>("/v1/ops/seq-bump", {
          method: "POST",
          ops: true,
          idem: true,
          body: req,
        }),
      enrollGrants: () => call<EnrollGrantsResp>("/v1/ops/enroll", { ops: true }),
      enrollCreate: (label: string, tier?: string, ttl_seconds?: number) =>
        call<EnrollIssueResp>("/v1/ops/enroll/create", {
          method: "POST",
          ops: true,
          idem: true,
          body: { label, tier, ttl_seconds },
        }),
      enrollRevoke: (grant_id: string) =>
        call<void>("/v1/ops/enroll/revoke", {
          method: "POST",
          ops: true,
          idem: true,
          body: { grant_id },
        }),
    },

    // ── admin (UniSSH-Tenant + Bearer) ──
    admin: {
      overview: () =>
        call<AdminOverview>("/v1/admin/overview", { tenant: true, bearer: true }),
      instance: () =>
        call<InstanceInfo>("/v1/admin/instance", { tenant: true, bearer: true }),
      tenantStatus: (suspended: boolean) =>
        call<void>("/v1/admin/tenant/status", {
          method: "POST",
          tenant: true,
          bearer: true,
          idem: true,
          body: { suspended },
        }),
      accountStatus: (account_id: string, disabled: boolean) =>
        call<void>("/v1/admin/account/status", {
          method: "POST",
          tenant: true,
          bearer: true,
          idem: true,
          body: { account_id, disabled },
        }),
      devices: (account_id?: string) =>
        call<DevicesResp>("/v1/admin/devices", {
          tenant: true,
          bearer: true,
          query: { account_id },
        }),
      sessions: (account_id?: string) =>
        call<SessionsResp>("/v1/admin/sessions", {
          tenant: true,
          bearer: true,
          query: { account_id },
        }),
      sessionRevoke: (session_id: string) =>
        call<void>("/v1/admin/session/revoke", {
          method: "POST",
          tenant: true,
          bearer: true,
          idem: true,
          body: { session_id },
        }),
      invites: () =>
        call<InvitesResp>("/v1/admin/invites", { tenant: true, bearer: true }),
      inviteRevoke: (invite_id: string) =>
        call<void>("/v1/admin/invite/revoke", {
          method: "POST",
          tenant: true,
          bearer: true,
          idem: true,
          body: { invite_id },
        }),
      vaults: () => call<VaultsResp>("/v1/admin/vaults", { tenant: true, bearer: true }),
      vault: (vault_id: string) =>
        call<VaultRow>("/v1/admin/vault", {
          tenant: true,
          bearer: true,
          query: { vault_id },
        }),
      objects: (q: {
        tag?: number;
        vault_id?: string;
        cursor?: number;
        limit?: number;
      }) =>
        call<ObjectsResp>("/v1/admin/objects", {
          tenant: true,
          bearer: true,
          query: q,
        }),
      relay: () => call<RelayResp>("/v1/admin/relay", { tenant: true, bearer: true }),
      keysets: (account_id?: string) =>
        call<KeysetsResp>("/v1/admin/keysets", {
          tenant: true,
          bearer: true,
          query: { account_id },
        }),
      config: () => call<ConfigResp>("/v1/admin/config", { tenant: true, bearer: true }),
      configPut: (body: ConfigPutReq) =>
        call<ConfigPutResp>("/v1/admin/config", {
          method: "PUT",
          tenant: true,
          bearer: true,
          idem: true,
          body,
        }),
      metrics: () => call<MetricsRaw>("/v1/admin/metrics", { tenant: true, bearer: true }),
      metricsSummary: () =>
        call<MetricsSummary>("/v1/admin/metrics/summary", { tenant: true, bearer: true }),
      health: () => call<HealthInfo>("/v1/admin/health", { tenant: true, bearer: true }),
      seqBump: (req: { by?: number; to?: number }) =>
        call<SeqBumpResp>("/v1/admin/seq-bump", {
          method: "POST",
          tenant: true,
          bearer: true,
          idem: true,
          body: req,
        }),
      migrations: () =>
        call<MigrationsResp>("/v1/admin/migrations", { tenant: true, bearer: true }),
      auditVerify: () =>
        call<AuditVerify>("/v1/admin/audit/verify", { tenant: true, bearer: true }),
    },

    // ── identity (tenant + bearer, crypto flows) ──
    identity: {
      accounts: () =>
        call<AccountsResp>("/v1/accounts", { tenant: true, bearer: true }),
      adminSet: (account_id: string, is_admin: boolean) =>
        call<void>("/v1/admin/set", {
          method: "POST",
          tenant: true,
          bearer: true,
          idem: true,
          body: { account_id, is_admin },
        }),
      deviceRevoke: (device_id: string) =>
        call<void>("/v1/session/device-revoke", {
          method: "POST",
          tenant: true,
          bearer: true,
          idem: true,
          body: { device_id },
        }),
      issueInvite: (role: string, scope: string | undefined, ttl_seconds: number | undefined) =>
        call<InviteIssueResp>("/v1/invite", {
          method: "POST",
          tenant: true,
          bearer: true,
          idem: true,
          body: { role, scope, ttl_seconds },
        }),
      audit: (since_seq?: number, limit?: number) =>
        call<AuditResp>("/v1/audit", {
          tenant: true,
          bearer: true,
          query: { since_seq, limit },
        }),
      grants: (vault_id: string, key_epoch?: number) =>
        call<GrantsResp>("/v1/grants", {
          tenant: true,
          bearer: true,
          query: { vault_id, key_epoch },
        }),
      grantsPublish: (body: {
        manifest: string;
        grants: unknown[];
        new_epoch: number;
        revoke_epoch?: number;
      }) =>
        call<{ new_epoch: number; server_seq: number[] }>("/v1/grants/publish", {
          method: "POST",
          tenant: true,
          bearer: true,
          idem: true,
          body,
        }),
      // ── auth (keyset unlock: challenge → sign → verify) ──
      challenge: (account_id: string, device_id: string, key_id: string) =>
        call<AuthChallenge>("/v1/auth/challenge", {
          method: "POST",
          tenant: true,
          body: { account_id, device_id, key_id },
        }),
      verify: (challenge: AuthChallenge, signature: string) =>
        call<VerifyResp>("/v1/auth/verify", {
          method: "POST",
          tenant: true,
          body: { challenge, signature },
        }),
      bootstrap: (
        tenantId: string,
        body: {
          registration_payload: string;
          registration_signature: string;
          tier?: string;
          display_name?: string;
          handle?: string;
          tenant_bootstrap_token?: string;
        },
      ) =>
        call<BootstrapResp>("/v1/bootstrap", {
          method: "POST",
          tenant: true,
          tenantId,
          body,
        }),
    },
  };
}

export type ApiClient = ReturnType<typeof createClient>;
