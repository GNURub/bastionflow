import { readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import type { AttackEvent, Severity } from "./types";

type JsonRecord = Record<string, unknown>;

const defaultPath = "/var/log/traefik/access.log";

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

function firstNumber(...values: unknown[]): number | undefined {
  for (const value of values) {
    const candidate = numberValue(value);
    if (candidate !== undefined) return candidate;
  }
  return undefined;
}

function firstForwardedIp(value?: string): string | undefined {
  return value?.split(",").map((part) => part.trim()).find(Boolean);
}

function stableId(line: string, index: number): string {
  return `traefik:${createHash("sha1").update(line).update(String(index)).digest("hex").slice(0, 20)}`;
}

function safeIso(value?: string): string {
  if (!value) return new Date().toISOString();
  const direct = new Date(value);
  if (!Number.isNaN(direct.getTime())) return direct.toISOString();
  const clf = new Date(value.replace(":", " "));
  return Number.isNaN(clf.getTime()) ? new Date().toISOString() : clf.toISOString();
}

function severityFor(method?: string, path?: string, status?: number): Severity {
  const lower = path?.toLowerCase() ?? "";
  if (status === 429) return "high";
  if (lower.includes("/.env") || lower.includes("/.git") || lower.includes("phpunit") || lower.includes("actuator") || lower.includes("/phpmyadmin")) return "high";
  if (lower.includes("wp-login") || lower.includes("xmlrpc") || lower.includes("admin")) return method === "POST" ? "high" : "medium";
  if (lower.includes("<script") || lower.includes("%3cscript") || lower.includes(" or ") || lower.includes("%27")) return "medium";
  if (status && status >= 500) return "medium";
  if (status && [401, 403, 404].includes(status)) return "low";
  return "info";
}

function scenarioFor(method?: string, path?: string, status?: number): string {
  const lower = path?.toLowerCase() ?? "";
  if (status === 429) return "edge-rate-limit";
  if (lower.includes("/.env") || lower.includes("/.git")) return "http-sensitive-files";
  if (lower.includes("wp-login") || lower.includes("xmlrpc")) return method === "POST" ? "http-wordpress-bruteforce" : "http-wordpress-probing";
  if (lower.includes("/admin")) return method === "POST" ? "http-admin-interface-bruteforce" : "http-admin-interface-probing";
  if (lower.includes("phpmyadmin")) return "http-phpmyadmin-probing";
  if (lower.includes("phpunit") || lower.includes("actuator") || lower.includes("cgi-bin")) return "http-cve-probing";
  if (lower.includes("<script") || lower.includes("%3cscript")) return "http-xss-probing";
  if (lower.includes("%27") || lower.includes(" or ")) return "http-sqli-probing";
  if (method && ["POST", "PUT", "PATCH", "DELETE"].includes(method)) return "http-write-attempt";
  return "traefik-access-log";
}

function jsonEvent(record: JsonRecord, line: string, index: number): AttackEvent {
  const method = firstText(record.RequestMethod, record.requestMethod, record.Method)?.toUpperCase();
  const path = firstText(record.RequestPath, record.requestPath, record.RequestURI, record.RequestLine)?.split(" ")[1] ?? firstText(record.RequestPath, record.requestPath);
  const host = firstText(record.RequestHost, record.RequestAddr, record.requestHost, record.RouterName, record.ServiceName, record.ServiceURL);
  const sourceIp = firstForwardedIp(firstText(record["request_X-Forwarded-For"], record["request_X-Real-IP"], record["request_X-Real-Ip"])) ?? firstText(record.ClientHost, record.clientHost);
  const status = firstNumber(record.DownstreamStatus, record.OriginStatus, record.Status, record.status);
  const userAgent = firstText(record["request_User-Agent"], record.RequestUserAgent, record.UserAgent);
  const timestamp = safeIso(firstText(record.StartUTC, record.StartLocal, record.time, record.Time));
  const router = firstText(record.RouterName);
  const service = firstText(record.ServiceName, record.ServiceURL);
  const scenario = scenarioFor(method, path, status);
  return {
    id: stableId(line, index),
    alertId: "traefik-access-log",
    scenario,
    severity: severityFor(method, path, status),
    sourceIp,
    method,
    host,
    service: service ?? router,
    path,
    status,
    userAgent,
    requestId: firstText(record.TraceId, record.traceId, router, service),
    timestamp,
    raw: line
  };
}

function clfEvent(line: string, index: number): AttackEvent | null {
  const match = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)]\s+"(\S+)\s+([^\s"]+)\s+([^\s"]+)"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"(?:\s+\S+\s+"([^"]*)"\s+"([^"]*)")?/.exec(line);
  if (!match) return null;
  const [, sourceIp, rawTime, methodRaw, path, , statusRaw, , , userAgent, router, serviceUrl] = match;
  const method = methodRaw?.toUpperCase();
  const status = Number(statusRaw);
  const scenario = scenarioFor(method, path, status);
  return {
    id: stableId(line, index),
    alertId: "traefik-access-log",
    scenario,
    severity: severityFor(method, path, status),
    sourceIp,
    method,
    host: router || serviceUrl || undefined,
    service: serviceUrl || router || undefined,
    path,
    status,
    userAgent: userAgent && userAgent !== "-" ? userAgent : undefined,
    requestId: serviceUrl || undefined,
    timestamp: safeIso(rawTime),
    raw: line
  };
}

function parseLine(line: string, index: number): AttackEvent | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("{")) {
    try { return jsonEvent(JSON.parse(trimmed) as JsonRecord, trimmed, index); } catch {}
  }
  return clfEvent(trimmed, index);
}

function tailLines(path: string, maxLines: number): string[] {
  try {
    const stat = statSync(path);
    const maxBytes = Math.min(stat.size, 2_000_000);
    const content = readFileSync(path, { encoding: "utf8" }).slice(-maxBytes);
    return content.split(/\r?\n/).filter(Boolean).slice(-maxLines);
  } catch {
    return [];
  }
}

export function listTraefikAccessEvents(limit = 120): AttackEvent[] {
  const path = process.env.TRAEFIK_ACCESS_LOG_PATH?.trim() || defaultPath;
  return tailLines(path, Math.max(limit * 4, 400))
    .map(parseLine)
    .filter((event): event is AttackEvent => Boolean(event))
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit);
}
