import { appendFile } from "node:fs/promises";

export type AuditAction = "decision.create" | "decision.delete" | "decision.rejected" | "auto-rule.rate-limited";

export interface AuditEvent {
  action: AuditAction;
  actor: "panel" | "auto-rule";
  target: string;
  result: "allowed" | "blocked" | "failed";
  reason: string;
  metadata?: Record<string, unknown>;
}

export async function audit(event: AuditEvent): Promise<void> {
  const line = JSON.stringify({ ...event, timestamp: new Date().toISOString() });
  await appendFile(process.env.CROWDSEC_AUDIT_LOG ?? "/tmp/bastionflow-audit.log", `${line}\n`, "utf8").catch(() => undefined);
}
