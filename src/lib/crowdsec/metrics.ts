import { getCrowdSecConfig } from "./config";
import type { CrowdSecMetrics } from "./types";

let metricsCache: { expiresAt: number; staleUntil: number; data: CrowdSecMetrics; inFlight?: Promise<CrowdSecMetrics> | undefined } | null = null;
const emptyMetrics: CrowdSecMetrics = { activeDecisions: 0, alerts24h: 0, blockedIps24h: 0, machinesOnline: 0, bouncersActive: 0 };

function metricValue(body: string, name: string): number | undefined {
  const line = body.split("\n").find((candidate) => candidate.startsWith(name));
  if (!line) return undefined;
  const raw = line.trim().split(/\s+/).at(-1);
  const value = raw ? Number(raw) : Number.NaN;
  return Number.isFinite(value) ? value : undefined;
}

async function loadMetrics(): Promise<CrowdSecMetrics> {
  const config = getCrowdSecConfig();
  const started = Date.now();
  const response = await fetch(config.prometheusUrl, { cache: "no-store", signal: AbortSignal.timeout(config.prometheusTimeoutMs) });
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
}

export async function getMetrics(): Promise<CrowdSecMetrics> {
  const now = Date.now();
  if (metricsCache && metricsCache.expiresAt > now) return metricsCache.data;
  if (metricsCache?.inFlight) return metricsCache.inFlight;

  const inFlight = loadMetrics()
    .then((data) => {
      metricsCache = { data, expiresAt: Date.now() + 3_000, staleUntil: Date.now() + 30_000 };
      return data;
    })
    .catch(() => {
      if (metricsCache && metricsCache.staleUntil > Date.now()) return metricsCache.data;
      return emptyMetrics;
    });

  metricsCache = metricsCache ? { ...metricsCache, inFlight } : { data: emptyMetrics, expiresAt: 0, staleUntil: 0, inFlight };
  return inFlight;
}
