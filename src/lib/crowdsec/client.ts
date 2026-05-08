import { audit } from "./audit";
import { evaluateAutoDecision } from "./auto-rules";
import { getCrowdSecConfig } from "./config";
import { attacksFromAlerts, attacksFromEvents } from "./attacks";
import { normalizeAlert, normalizeDecision } from "./normalizers";
import { enrichAlertsWithGeo, enrichDecisionsWithGeo } from "./geo";
import { listAttackEvents } from "./events";
import { isAllowedTarget } from "@/lib/security/ip-allowlist";
import { getLocalAllowlistValues, persistAlerts, persistDecisions } from "./store";
import type { ApiEnvelope, AttackArc, CreateDecisionInput, CrowdSecAlert, CrowdSecDecision } from "./types";

interface TokenCache {
  token: string;
  expiresAt: number;
}

let tokenCache: TokenCache | null = null;

function jsonResponse<T>(data: T, source: ApiEnvelope<T>["source"], error?: string): ApiEnvelope<T> {
  return error ? { data, source, error } : { data, source };
}

async function login(): Promise<string> {
  const config = getCrowdSecConfig();
  if (tokenCache && tokenCache.expiresAt > Date.now() + 30_000) return tokenCache.token;
  if (!config.machineId || !config.machinePassword) throw new Error("Missing CrowdSec machine credentials");
  const response = await fetch(`${config.lapiUrl}/v1/watchers/login`, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": process.env.CROWDSEC_LAPI_USER_AGENT ?? "crowdsec/v1.7.7" },
    body: JSON.stringify({ machine_id: config.machineId, password: config.machinePassword }),
    cache: "no-store",
    signal: AbortSignal.timeout(5_000)
  });
  if (!response.ok) throw new Error(`CrowdSec login failed with ${response.status}`);
  const body = (await response.json()) as { token?: string; expire?: string };
  if (!body.token) throw new Error("CrowdSec login response did not include a token");
  tokenCache = { token: body.token, expiresAt: body.expire ? new Date(body.expire).getTime() : Date.now() + 10 * 60_000 };
  return body.token;
}

async function lapiFetch(path: string, init: RequestInit = {}, write = false): Promise<Response> {
  const config = getCrowdSecConfig();
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  headers.set("user-agent", process.env.CROWDSEC_LAPI_USER_AGENT ?? "crowdsec/v1.7.7");
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  if (write || config.machineId) {
    headers.set("authorization", `Bearer ${await login()}`);
  } else if (config.bouncerApiKey) {
    headers.set("x-api-key", config.bouncerApiKey);
  }
  return fetch(`${config.lapiUrl}${path}`, { ...init, headers, cache: "no-store", signal: AbortSignal.timeout(7_000) });
}

export async function getAlerts(): Promise<ApiEnvelope<CrowdSecAlert[]>> {
  try {
    const response = await lapiFetch("/v1/alerts?limit=50");
    if (!response.ok) throw new Error(`CrowdSec alerts returned ${response.status}`);
    const body = (await response.json()) as unknown;
    const rows = Array.isArray(body) ? body : Array.isArray((body as { alerts?: unknown[] }).alerts) ? (body as { alerts: unknown[] }).alerts : [];
    const alerts = await enrichAlertsWithGeo(rows.map(normalizeAlert));
    persistAlerts(alerts, rows);
    return jsonResponse(alerts, "crowdsec");
  } catch (error) {
    return jsonResponse([], "partial", error instanceof Error ? error.message : "Unable to fetch alerts");
  }
}

export async function getDecisions(): Promise<ApiEnvelope<CrowdSecDecision[]>> {
  const config = getCrowdSecConfig();
  try {
    const headers = new Headers({ accept: "application/json", "user-agent": process.env.CROWDSEC_LAPI_USER_AGENT ?? "crowdsec/v1.7.7" });
    if (!config.bouncerApiKey) throw new Error("Missing CrowdSec bouncer API key for decisions read");
    headers.set("x-api-key", config.bouncerApiKey);
    const response = await fetch(`${config.lapiUrl}/v1/decisions`, { headers, cache: "no-store", signal: AbortSignal.timeout(7_000) });
    if (!response.ok) throw new Error(`CrowdSec decisions returned ${response.status}`);
    const body = (await response.json()) as unknown;
    const rows = Array.isArray(body) ? body : [];
    const decisions = await enrichDecisionsWithGeo(rows.map(normalizeDecision));
    persistDecisions(decisions);
    return jsonResponse(decisions, "crowdsec");
  } catch (error) {
    return jsonResponse([], "partial", error instanceof Error ? error.message : "Unable to fetch decisions");
  }
}

export async function createDecision(input: CreateDecisionInput): Promise<CrowdSecDecision> {
  const config = getCrowdSecConfig();
  if (isAllowedTarget(input.value, [...config.allowlist, ...getLocalAllowlistValues()])) {
    await audit({ action: "decision.rejected", actor: input.mode === "automatic" ? "auto-rule" : "panel", target: input.value, result: "blocked", reason: "Target is allowlisted", metadata: { scope: input.scope, type: input.type } });
    throw new Error("Target is allowlisted. Remove it from the allowlist before creating a decision.");
  }
  const autoRule = await evaluateAutoDecision(input);
  if (!autoRule.allowed) throw new Error(autoRule.reason ?? "Automatic decision rejected");

  const payload = {
    duration: input.duration,
    reason: input.reason,
    scope: input.scope,
    type: input.type,
    value: input.value
  };
  const response = await lapiFetch("/v1/decisions", { method: "POST", body: JSON.stringify(payload) }, true);
  if (!response.ok) throw new Error(`CrowdSec decision create failed with ${response.status}`);
  await audit({ action: "decision.create", actor: input.mode === "automatic" ? "auto-rule" : "panel", target: input.value, result: "allowed", reason: input.reason, metadata: { scope: input.scope, type: input.type, duration: input.duration } });
  try {
    return normalizeDecision(await response.json());
  } catch {
    return { id: `${input.scope}:${input.value}`, origin: "panel", scenario: input.reason, scope: input.scope, value: input.value, type: input.type, duration: input.duration };
  }
}

export async function deleteDecision(id: string): Promise<void> {
  const response = await lapiFetch(`/v1/decisions/${encodeURIComponent(id)}`, { method: "DELETE" }, true);
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`CrowdSec decision delete failed with ${response.status}${body ? `: ${body.slice(0, 200)}` : ""}`);
  }
  await audit({ action: "decision.delete", actor: "panel", target: id, result: "allowed", reason: "Operator unblock" });
}

export async function getAttackArcs(): Promise<ApiEnvelope<AttackArc[]>> {
  const alerts = await getAlerts();
  const alertArcs = await attacksFromAlerts(alerts.data);
  const accessArcs = await attacksFromEvents(listAttackEvents(120));
  const seen = new Set<string>();
  const arcs = [...accessArcs, ...alertArcs].filter((arc) => {
    const key = `${arc.sourceIp}:${arc.scenario}:${arc.timestamp}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 120);
  return jsonResponse(arcs, alerts.source, alerts.error);
}
