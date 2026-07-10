// Minimal Prometheus text-exposition parser for the client-side Metrics screen
// (the server exposes raw `/v1/admin/metrics`, no pre-aggregated summary).

export interface PromSample {
  name: string;
  labels: Record<string, string>;
  value: number;
}

export function parsePrometheus(text: string): PromSample[] {
  const out: PromSample[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    // name{labels} value   |   name value
    const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([-+0-9.eE]+|NaN|\+Inf|-Inf)/.exec(line);
    if (!m) continue;
    const name = m[1];
    const labels: Record<string, string> = {};
    if (m[2]) {
      const inner = m[2].slice(1, -1);
      for (const pair of inner.split(",")) {
        const eq = pair.indexOf("=");
        if (eq < 0) continue;
        const k = pair.slice(0, eq).trim();
        const v = pair.slice(eq + 1).trim().replace(/^"|"$/g, "");
        if (k) labels[k] = v;
      }
    }
    const value = Number(m[3]);
    if (Number.isNaN(value)) continue;
    out.push({ name, labels, value });
  }
  return out;
}

/** Sum all samples per metric name (labels collapsed) → name → total. */
export function sumByName(samples: PromSample[]): Map<string, number> {
  const map = new Map<string, number>();
  for (const s of samples) map.set(s.name, (map.get(s.name) ?? 0) + s.value);
  return map;
}
