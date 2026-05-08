import type { CrowdSecAlert, CrowdSecBouncer, CrowdSecDecision, CrowdSecMachine, DecisionScope, DecisionType, Severity } from "./types";

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function text(value: unknown, fallback = ""): string {
  return typeof value === "string" || typeof value === "number" ? String(value) : fallback;
}

function numberValue(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function severity(events: number): Severity {
  if (events >= 30) return "critical";
  if (events >= 10) return "high";
  if (events >= 4) return "medium";
  if (events >= 1) return "low";
  return "info";
}

function normalizeScope(value: unknown): DecisionScope {
  const lower = text(value, "unknown").toLowerCase();
  if (["ip", "range", "username", "session", "country", "as"].includes(lower)) return lower as DecisionScope;
  if (lower === "ipaddr" || lower === "ip_addr") return "ip";
  return "unknown";
}

function normalizeType(value: unknown): DecisionType {
  const lower = text(value, "unknown").toLowerCase();
  if (["ban", "captcha", "throttle", "enforce_mfa"].includes(lower)) return lower as DecisionType;
  return "unknown";
}

export function normalizeDecision(raw: unknown): CrowdSecDecision {
  const item = asRecord(raw);
  return {
    id: text(item.id ?? item.uuid ?? `${item.scope}:${item.value}`, crypto.randomUUID()),
    origin: text(item.origin, "unknown"),
    scenario: text(item.scenario ?? item.reason, "unknown"),
    scope: normalizeScope(item.scope),
    value: text(item.value),
    type: normalizeType(item.type),
    duration: text(item.duration, undefined as unknown as string),
    expiresAt: text(item.until ?? item.expiration, undefined as unknown as string),
    country: text(item.country, undefined as unknown as string),
    asName: text(item.as_name ?? item.as, undefined as unknown as string)
  };
}

export function normalizeAlert(raw: unknown): CrowdSecAlert {
  const item = asRecord(raw);
  const source = asRecord(item.source);
  const events = numberValue(item.events_count ?? item.events ?? item.capacity, 1);
  return {
    id: text(item.id ?? item.uuid, crypto.randomUUID()),
    scenario: text(item.scenario ?? item.message, "unknown"),
    sourceIp: text(source.ip ?? item.source_ip ?? item.value, undefined as unknown as string),
    sourceCountry: text(source.country ?? item.country, undefined as unknown as string),
    sourceAsName: text(source.as_name ?? item.as_name, undefined as unknown as string),
    events,
    severity: severity(events),
    createdAt: text(item.created_at ?? item.createdAt ?? item.start_at, undefined as unknown as string),
    message: text(item.message ?? item.scenario, "CrowdSec alert")
  };
}

export function normalizeMachine(raw: unknown): CrowdSecMachine {
  const item = asRecord(raw);
  const validated = Boolean(item.validated ?? item.is_validated ?? true);
  return {
    name: text(item.machineId ?? item.name ?? item.login, "unknown-machine"),
    ipAddress: text(item.ip_address ?? item.ipAddress ?? item.ip, undefined as unknown as string),
    validated,
    lastHeartbeat: text(item.last_heartbeat ?? item.lastHeartbeat, undefined as unknown as string),
    version: text(item.version, undefined as unknown as string),
    status: validated ? "online" : "unknown"
  };
}

export function normalizeBouncer(raw: unknown): CrowdSecBouncer {
  const item = asRecord(raw);
  const revoked = Boolean(item.revoked ?? false);
  return {
    name: text(item.name ?? item.bouncer_id ?? item.login, "unknown-bouncer"),
    ipAddress: text(item.ip_address ?? item.ipAddress ?? item.ip, undefined as unknown as string),
    type: text(item.type, undefined as unknown as string),
    lastPull: text(item.last_pull ?? item.lastPull, undefined as unknown as string),
    revoked,
    status: revoked ? "revoked" : "active"
  };
}
