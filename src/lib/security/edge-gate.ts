import { createHmac, timingSafeEqual } from "node:crypto";
import { getEdgeGateSettings } from "@/lib/security/edge-gate-settings";

export interface EdgeGateConfig {
  enabled: boolean;
  botChallengeEnabled: boolean;
  authEnabled: boolean;
  passwordConfigured: boolean;
  cookieSecret: string;
  maxAgeSeconds: number;
}

export interface EdgeGateState {
  botPassed: boolean;
  authPassed: boolean;
  passed: boolean;
  required: Array<"bot" | "auth">;
}

function optionalEnv(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

export function getEdgeGateConfig(): EdgeGateConfig {
  const settings = getEdgeGateSettings();
  return {
    enabled: settings.enabled,
    botChallengeEnabled: settings.botChallengeEnabled,
    authEnabled: settings.authEnabled,
    passwordConfigured: settings.passwordConfigured,
    cookieSecret: optionalEnv("EDGE_GATE_COOKIE_SECRET") ?? optionalEnv("CROWDSEC_INTERNAL_TOKEN") ?? "local-edge-gate-secret-change-me",
    maxAgeSeconds: settings.maxAgeSeconds
  };
}

function base64url(value: string): string {
  return Buffer.from(value).toString("base64url");
}

function unbase64url(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}

function sign(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function createGateToken(kind: "bot" | "auth", host: string, userAgent: string): string {
  const config = getEdgeGateConfig();
  const payload = JSON.stringify({ kind, host, ua: userAgent.slice(0, 160), exp: Math.floor(Date.now() / 1000) + config.maxAgeSeconds });
  const encoded = base64url(payload);
  return `${encoded}.${sign(encoded, config.cookieSecret)}`;
}

export function verifyGateToken(token: string | undefined, kind: "bot" | "auth", host: string, userAgent: string): boolean {
  if (!token || !token.includes(".")) return false;
  const config = getEdgeGateConfig();
  const [encoded, signature] = token.split(".", 2) as [string, string];
  const expected = sign(encoded, config.cookieSecret);
  if (signature.length !== expected.length || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false;
  try {
    const payload = JSON.parse(unbase64url(encoded)) as { kind?: string; host?: string; ua?: string; exp?: number };
    if (payload.kind !== kind) return false;
    if (payload.host !== host) return false;
    if (payload.ua !== userAgent.slice(0, 160)) return false;
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return false;
    return true;
  } catch {
    return false;
  }
}

export function parseCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  const cookies = header.split(";").map((part) => part.trim());
  const found = cookies.find((part) => part.startsWith(`${name}=`));
  return found ? decodeURIComponent(found.slice(name.length + 1)) : undefined;
}

export function cookieHeader(name: string, value: string, maxAge: number): string {
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax`;
}

export function evaluateGate(request: Request): EdgeGateState {
  const config = getEdgeGateConfig();
  if (!config.enabled) return { botPassed: true, authPassed: true, passed: true, required: [] };
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? "unknown";
  const userAgent = request.headers.get("user-agent") ?? "";
  const cookie = request.headers.get("cookie");
  const required: Array<"bot" | "auth"> = [];
  const botPassed = !config.botChallengeEnabled || verifyGateToken(parseCookie(cookie, "crowdsec_gate_bot"), "bot", host, userAgent);
  const authPassed = !config.authEnabled || verifyGateToken(parseCookie(cookie, "crowdsec_gate_auth"), "auth", host, userAgent);
  if (config.botChallengeEnabled && !botPassed) required.push("bot");
  if (config.authEnabled && !authPassed) required.push("auth");
  return { botPassed, authPassed, passed: botPassed && authPassed, required };
}

export function originalUrl(request: Request): string {
  const proto = request.headers.get("x-forwarded-proto") ?? "http";
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? "localhost";
  const uri = request.headers.get("x-forwarded-uri") ?? "/";
  return `${proto}://${host}${uri}`;
}
