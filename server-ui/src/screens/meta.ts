import type { Route } from "../store/ui";

/** Routes that carry the ZERO-KNOWLEDGE header tag (mockup META.zk). */
export const ZK_TAG: ReadonlySet<Route> = new Set<Route>([
  "accounts",
  "vaults",
  "grants",
  "relay",
  "objects",
  "audit",
]);
