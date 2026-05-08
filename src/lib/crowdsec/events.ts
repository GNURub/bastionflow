import { getStoredAlertPayloads } from "./store";
import { listTraefikAccessEvents } from "./traefik-logs";
import type { AttackCampaign, AttackEvent, CrowdSecAlert, Severity } from "./types";

type Dict = Record<string, unknown>;

function asRecord(value: unknown): Dict {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Dict : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) return Number(value);
  return undefined;
}

function firstText(...values: unknown[]): string | undefined {
  for (const value of values) {
    const candidate = text(value);
    if (candidate) return candidate;
  }
  return undefined;
}


function lookup(record: Dict, keys: string[]): unknown {
  for (const key of keys) if (record[key] !== undefined) return record[key];
  return undefined;
}

function compactPath(value?: string): string | undefined {
  if (!value) return undefined;
  try {
    const parsed = value.startsWith("http://") || value.startsWith("https://") ? new URL(value) : null;
    return parsed ? `${parsed.pathname}${parsed.search}` : value;
  } catch {
    return value;
  }
}

function rawLine(raw: Dict, event: Dict): string | undefined {
  const line = asRecord(event.Line ?? event.line);
  return firstText(
    event.raw,
    event.raw_message,
    event.message,
    line.Raw,
    line.raw,
    line.Message,
    line.message,
    raw.message
  );
}

function eventRecords(raw: unknown): Dict[] {
  const alert = asRecord(raw);
  const events = asArray(alert.events ?? alert.Events ?? alert.alert_events);
  if (events.length > 0) return events.map(asRecord).filter((item) => Object.keys(item).length > 0);
  return [alert];
}

function eventContext(raw: unknown, event: Dict): Dict[] {
  const alert = asRecord(raw);
  return [
    event,
    asRecord(event.meta), asRecord(event.Meta),
    asRecord(event.parsed), asRecord(event.Parsed),
    asRecord(event.enriched), asRecord(event.Enriched),
    asRecord(event.whitelisted),
    alert,
    asRecord(alert.source)
  ];
}

function findText(context: Dict[], keys: string[]): string | undefined {
  for (const record of context) {
    const value = lookup(record, keys);
    const candidate = text(value);
    if (candidate) return candidate;
  }
  return undefined;
}

function findNumber(context: Dict[], keys: string[]): number | undefined {
  for (const record of context) {
    const value = lookup(record, keys);
    const candidate = numberValue(value);
    if (candidate !== undefined) return candidate;
  }
  return undefined;
}

function timestampFor(alert: CrowdSecAlert, raw: unknown, event: Dict): string {
  const context = eventContext(raw, event);
  return findText(context, ["timestamp", "time", "evt_time", "created_at", "createdAt", "start_at", "MarshaledTime"]) ?? alert.createdAt ?? new Date().toISOString();
}

function targetHost(context: Dict[]): string | undefined {
  return findText(context, [
    "target_fqdn", "target_host", "targetHost", "http_host", "httpHost", "host", "hostname", "fqdn", "domain", "vhost", "request_host", "requestHost",
    "cs_host"
  ]);
}

function targetService(context: Dict[]): string | undefined {
  return findText(context, ["service", "serviceName", "ServiceName", "traefik_service_name", "traefik_router_name", "router", "RouterName"]);
}

function targetPath(context: Dict[], raw?: string): string | undefined {
  const direct = findText(context, ["http_path", "httpPath", "path", "request_path", "requestPath", "target_uri", "targetUri", "uri", "url", "cs_uri_stem"]);
  const compacted = compactPath(direct);
  if (compacted) return compacted;
  if (!raw) return undefined;
  const match = /\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP\//i.exec(raw);
  return match?.[1];
}

function method(context: Dict[], raw?: string): string | undefined {
  const direct = findText(context, ["http_verb", "httpVerb", "http_method", "httpMethod", "method", "verb", "cs_method"]);
  if (direct) return direct.toUpperCase();
  return /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/i.exec(raw ?? "")?.[1]?.toUpperCase();
}

function eventFrom(alert: CrowdSecAlert, raw: unknown, event: Dict, index: number): AttackEvent {
  const context = eventContext(raw, event);
  const rawLog = rawLine(asRecord(raw), event);
  const host = targetHost(context);
  const service = targetService(context);
  const path = targetPath(context, rawLog);
  const httpMethod = method(context, rawLog);
  const sourceIp = findText(context, ["source_ip", "sourceIp", "ip", "src_ip", "src", "remote_addr", "remoteAddr"]) ?? alert.sourceIp;
  const userAgent = findText(context, ["http_user_agent", "httpUserAgent", "user_agent", "userAgent", "cs_user_agent"]);
  const status = findNumber(context, ["http_status", "httpStatus", "status", "status_code", "statusCode", "sc_status"]);
  const requestId = findText(context, ["request_id", "requestId", "trace_id", "traceId", "x_request_id"]);
  const timestamp = timestampFor(alert, raw, event);
  return {
    id: `${alert.id}:${index}:${timestamp}`,
    alertId: alert.id,
    scenario: alert.scenario,
    severity: alert.severity,
    sourceIp,
    sourceCountry: alert.sourceCountry,
    sourceAsName: alert.sourceAsName,
    method: httpMethod,
    host,
    service,
    path,
    status,
    userAgent,
    requestId,
    timestamp,
    raw: rawLog
  };
}

export function attackEventsFromPayloads(payloads: Array<{ alert: CrowdSecAlert; raw: unknown }>): AttackEvent[] {
  return payloads.flatMap(({ alert, raw }) => eventRecords(raw).map((event, index) => eventFrom(alert, raw, event, index)))
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

export function listAttackEvents(limit = 80): AttackEvent[] {
  const payloads = getStoredAlertPayloads(Math.max(limit, 200));
  const alertEvents = attackEventsFromPayloads(payloads);
  const accessEvents = listTraefikAccessEvents(limit);
  const seen = new Set<string>();
  return [...accessEvents, ...alertEvents]
    .filter((event) => {
      if (seen.has(event.id)) return false;
      seen.add(event.id);
      return true;
    })
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit);
}

export function summarizeCampaigns(events: readonly AttackEvent[]): AttackCampaign[] {
  const campaigns = new Map<string, AttackCampaign>();
  for (const event of events) {
    const key = `${event.scenario}|${event.host ?? "unknown-host"}|${event.sourceIp ?? "unknown-source"}`;
    const current = campaigns.get(key) ?? {
      id: key,
      scenario: event.scenario,
      severity: event.severity,
      sourceIp: event.sourceIp,
      host: event.host,
      events: 0,
      methods: [],
      paths: [],
      firstSeen: event.timestamp,
      lastSeen: event.timestamp
    };
    current.events += 1;
    if (event.method && !current.methods.includes(event.method)) current.methods.push(event.method);
    if (event.path && !current.paths.includes(event.path)) current.paths.push(event.path);
    if (new Date(event.timestamp).getTime() < new Date(current.firstSeen).getTime()) current.firstSeen = event.timestamp;
    if (new Date(event.timestamp).getTime() > new Date(current.lastSeen).getTime()) current.lastSeen = event.timestamp;
    if (severityRank(event.severity) > severityRank(current.severity)) current.severity = event.severity;
    campaigns.set(key, current);
  }
  return [...campaigns.values()].sort((a, b) => b.events - a.events).slice(0, 12);
}

function severityRank(value: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[value];
}
