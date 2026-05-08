import { getCrowdSecConfig } from "./config";
import type { CrowdSecMetrics } from "./types";

function metricValue(body: string, name: string): number | undefined {
  const line = body.split("\n").find((candidate) => candidate.startsWith(name));
  if (!line) return undefined;
  const raw = line.trim().split(/\s+/).at(-1);
  const value = raw ? Number(raw) : Number.NaN;
  return Number.isFinite(value) ? value : undefined;
}

export async function getMetrics(): Promise<CrowdSecMetrics> {
  const config = getCrowdSecConfig();
  const started = Date.now();
  try {
    const response = await fetch(config.prometheusUrl, { cache: "no-store", signal: AbortSignal.timeout(3_000) });
    if (!response.ok) throw new Error(`Prometheus returned ${response.status}`);
    const body = await response.text();
    return {
      activeDecisions: metricValue(body, "cs_lapi_decisions") ?? 0,
      alerts24h: metricValue(body, "cs_alerts") ?? 0,
      blockedIps24h: metricValue(body, "cs_bouncers_dropped") ?? 0,
      machinesOnline: metricValue(body, "cs_lapi_machines") ?? 0,
      bouncersActive: metricValue(body, "cs_lapi_bouncers") ?? 0,
      lapiLatencyMs: Date.now() - started
    };
  } catch {
    return { activeDecisions: 0, alerts24h: 0, blockedIps24h: 0, machinesOnline: 0, bouncersActive: 0 };
  }
}
