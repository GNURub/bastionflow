import { isAllowedTarget } from "@/lib/security/ip-allowlist";
import { audit } from "./audit";
import { getCrowdSecConfig } from "./config";
import { getLocalAllowlistValues } from "./store";
import type { CreateDecisionInput } from "./types";
import { parseDurationMs } from "./validators";

const recentAutoBlocks = new Map<string, number>();

export interface AutoRuleResult {
  allowed: boolean;
  reason?: string;
}

function prune(now: number): void {
  const cutoff = now - 60 * 60_000;
  for (const [key, timestamp] of recentAutoBlocks.entries()) {
    if (timestamp < cutoff) recentAutoBlocks.delete(key);
  }
}

export async function evaluateAutoDecision(input: CreateDecisionInput): Promise<AutoRuleResult> {
  if (input.mode !== "automatic") return { allowed: true };
  const config = getCrowdSecConfig();
  const target = input.value.trim();

  if (isAllowedTarget(target, [...config.allowlist, ...getLocalAllowlistValues()])) {
    await audit({ action: "decision.rejected", actor: "auto-rule", target, result: "blocked", reason: "Target is allowlisted", metadata: { scope: input.scope } });
    return { allowed: false, reason: "Target is allowlisted" };
  }

  if ((input.evidenceCount ?? 0) < config.autoBlockMinAlerts) {
    await audit({ action: "decision.rejected", actor: "auto-rule", target, result: "blocked", reason: "Insufficient alert evidence", metadata: { evidenceCount: input.evidenceCount, minimum: config.autoBlockMinAlerts } });
    return { allowed: false, reason: `Automatic decisions require at least ${config.autoBlockMinAlerts} correlated alerts` };
  }

  if (parseDurationMs(input.duration) > parseDurationMs(config.autoBlockMaxDuration)) {
    await audit({ action: "decision.rejected", actor: "auto-rule", target, result: "blocked", reason: "Duration exceeds maximum", metadata: { duration: input.duration, maximum: config.autoBlockMaxDuration } });
    return { allowed: false, reason: `Automatic decisions cannot exceed ${config.autoBlockMaxDuration}` };
  }

  const now = Date.now();
  prune(now);
  if (recentAutoBlocks.size >= config.autoBlockRateLimitPerHour) {
    await audit({ action: "auto-rule.rate-limited", actor: "auto-rule", target, result: "blocked", reason: "Hourly automatic block limit reached", metadata: { limit: config.autoBlockRateLimitPerHour } });
    return { allowed: false, reason: "Hourly automatic block limit reached" };
  }

  recentAutoBlocks.set(`${input.scope}:${target}:${now}`, now);
  return { allowed: true };
}
