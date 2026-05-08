import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { getPersistedEdgeGateSettings, saveEdgeGateSettings } from "@/lib/crowdsec/store";
import type { EdgeGateSettings, UpdateEdgeGateSettingsInput } from "@/lib/crowdsec/types";

function optionalEnv(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

function legacySha256(password: string): string {
  return createHash("sha256").update(password).digest("hex");
}

function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("base64url");
  const key = scryptSync(password, salt, 64, { N: 16_384, r: 8, p: 1 }).toString("base64url");
  return `scrypt$16384$8$1$${salt}$${key}`;
}

function verifyPasswordHash(password: string, stored: string): boolean {
  if (/^[a-f0-9]{64}$/i.test(stored)) {
    const candidate = legacySha256(password);
    return candidate.length === stored.length && timingSafeEqual(Buffer.from(candidate), Buffer.from(stored));
  }

  const [scheme, nRaw, rRaw, pRaw, salt, key] = stored.split("$");
  if (scheme !== "scrypt" || !salt || !key) return false;
  const n = Number(nRaw);
  const r = Number(rRaw);
  const p = Number(pRaw);
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p) || n <= 0 || r <= 0 || p <= 0) return false;
  const candidate = scryptSync(password, salt, 64, { N: n, r, p }).toString("base64url");
  return candidate.length === key.length && timingSafeEqual(Buffer.from(candidate), Buffer.from(key));
}

export function defaultEdgeGateSettings(): EdgeGateSettings & { passwordHash?: string | undefined } {
  const envPassword = optionalEnv("EDGE_GATE_PASSWORD");
  return {
    enabled: (optionalEnv("EDGE_GATE_ENABLED") ?? "true") === "true",
    botChallengeEnabled: (optionalEnv("EDGE_GATE_BOT_CHALLENGE_ENABLED") ?? "true") === "true",
    authEnabled: (optionalEnv("EDGE_GATE_AUTH_ENABLED") ?? "false") === "true",
    passwordConfigured: Boolean(envPassword),
    passwordHash: envPassword ? hashPassword(envPassword) : undefined,
    maxAgeSeconds: Number(optionalEnv("EDGE_GATE_COOKIE_MAX_AGE_SECONDS") ?? 86_400)
  };
}

export function getEdgeGateSettings(): EdgeGateSettings & { passwordHash?: string | undefined } {
  return getPersistedEdgeGateSettings() ?? defaultEdgeGateSettings();
}

export function updateEdgeGateSettings(input: UpdateEdgeGateSettingsInput): EdgeGateSettings {
  const password = input.password?.trim();
  const passwordHash = password ? hashPassword(password) : undefined;
  return saveEdgeGateSettings(input, passwordHash);
}

export function verifyEdgeGatePassword(password: string): boolean {
  const hash = getEdgeGateSettings().passwordHash;
  if (!hash) return false;
  return verifyPasswordHash(password, hash);
}
