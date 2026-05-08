import { createEdgeRateLimitRule, deleteEdgeRateLimitRule, listEdgeRateLimitRules, recordEdgeRateLimitHit } from "@/lib/crowdsec/store";
import type { CreateEdgeRateLimitRuleInput, EdgeRateLimitDecision, EdgeRateLimitRule } from "@/lib/crowdsec/types";
import { originalUrl } from "@/lib/security/edge-gate";

function firstForwardedIp(value: string | null): string | undefined {
  return value?.split(",").map((part) => part.trim()).find(Boolean);
}

function requestContext(request: Request): { sourceIp: string; host: string; path: string } {
  const sourceIp = firstForwardedIp(request.headers.get("x-forwarded-for"))
    ?? request.headers.get("x-real-ip")?.trim()
    ?? "unknown";
  const host = (request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? "unknown").toLowerCase();
  const forwardedUri = request.headers.get("x-forwarded-uri") ?? "/";
  let path = forwardedUri.split("?", 1)[0] || "/";
  try { path = new URL(originalUrl(request)).pathname; } catch {}
  return { sourceIp, host, path };
}

function ipToLong(ip: string): number | null {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((parts[0]! * 256 + parts[1]!) * 256 + parts[2]!) * 256 + parts[3]!) >>> 0;
}

function cidrContains(cidr: string, ip: string): boolean {
  const [network, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  const networkLong = network ? ipToLong(network) : null;
  const ipLong = ipToLong(ip);
  if (networkLong === null || ipLong === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (networkLong & mask) === (ipLong & mask);
}

function ipMatches(ruleValue: string, sourceIp: string): boolean {
  if (ruleValue === "*") return true;
  if (ruleValue.includes("/")) return cidrContains(ruleValue, sourceIp);
  return ruleValue === sourceIp;
}

function serviceMatches(ruleValue: string, host: string): boolean {
  const value = ruleValue.toLowerCase();
  if (value === "*") return true;
  if (value.startsWith("*.")) return host.endsWith(value.slice(1));
  return host === value;
}

function matchRule(rule: EdgeRateLimitRule, context: { sourceIp: string; host: string; path: string }): string | null {
  if (!rule.enabled) return null;
  if (rule.target === "ip") return ipMatches(rule.value, context.sourceIp) ? context.sourceIp : null;
  if (rule.target === "path") return context.path.startsWith(rule.value) ? `${context.sourceIp}:${context.host}:${rule.value}` : null;
  if (rule.target === "service") return serviceMatches(rule.value, context.host) ? `${context.sourceIp}:${context.host}` : null;
  return null;
}

export function evaluateEdgeRateLimits(request: Request): EdgeRateLimitDecision {
  const context = requestContext(request);
  for (const rule of listEdgeRateLimitRules(false)) {
    const key = matchRule(rule, context);
    if (!key) continue;
    const hit = recordEdgeRateLimitHit(rule, key);
    return { allowed: hit.allowed, rule, key, count: hit.count, remaining: hit.remaining, resetAt: hit.resetAt };
  }
  return { allowed: true };
}

export function getEdgeRateLimitRules(): EdgeRateLimitRule[] {
  return listEdgeRateLimitRules(true);
}

export function addEdgeRateLimitRule(input: CreateEdgeRateLimitRuleInput): EdgeRateLimitRule {
  return createEdgeRateLimitRule({ ...input, value: input.value.trim(), name: input.name.trim() });
}

export function removeEdgeRateLimitRule(id: string): boolean {
  return deleteEdgeRateLimitRule(id);
}
