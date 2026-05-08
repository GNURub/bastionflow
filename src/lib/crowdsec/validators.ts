import { z } from "zod";

const durationPattern = /^\d+(s|m|h|d)$/;
const ipv4Pattern = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const cidrPattern = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/;

export const createDecisionSchema = z.object({
  scope: z.enum(["ip", "range", "username", "session", "country", "as"]),
  value: z.string().min(1).max(256),
  type: z.enum(["ban", "captcha", "throttle", "enforce_mfa"]).default("ban"),
  duration: z.string().regex(durationPattern, "Use CrowdSec duration syntax like 30m, 4h, or 1d"),
  reason: z.string().min(3).max(180),
  mode: z.enum(["manual", "automatic"]).default("manual"),
  evidenceCount: z.number().int().min(0).optional()
}).superRefine((value, ctx) => {
  if (value.scope === "ip" && !ipv4Pattern.test(value.value)) ctx.addIssue({ code: "custom", path: ["value"], message: "Expected IPv4 address" });
  if (value.scope === "range" && !cidrPattern.test(value.value)) ctx.addIssue({ code: "custom", path: ["value"], message: "Expected IPv4 CIDR range" });
});

export function parseDurationMs(duration: string): number {
  const match = /^(\d+)(s|m|h|d)$/.exec(duration);
  if (!match) return Number.POSITIVE_INFINITY;
  const value = Number(match[1]);
  const unit = match[2];
  const multiplier = unit === "s" ? 1_000 : unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : 86_400_000;
  return value * multiplier;
}
