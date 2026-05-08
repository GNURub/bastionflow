import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { getEdgeGateSettings } from "@/lib/security/edge-gate-settings";
import { listAttackEvents } from "./events";
import { listNotificationChannels } from "./notifications";
import type { ProtectionControl, ProtectionPosture } from "./types";

async function readText(path: string): Promise<string> {
  try { return await readFile(path, "utf8"); } catch { return ""; }
}

function enabled(id: string, name: string, category: ProtectionControl["category"], detail: string, evidence?: string): ProtectionControl {
  return { id, name, category, status: "enabled", detail, evidence };
}
function attention(id: string, name: string, category: ProtectionControl["category"], detail: string, recommendation: string, evidence?: string): ProtectionControl {
  return { id, name, category, status: "attention", detail, recommendation, evidence };
}
function unknown(id: string, name: string, category: ProtectionControl["category"], detail: string, recommendation: string): ProtectionControl {
  return { id, name, category, status: "unknown", detail, recommendation };
}

export async function getProtectionPosture(): Promise<ProtectionPosture> {
  const dynamic = [
    await readText(process.env.CROWDSEC_TRAEFIK_DYNAMIC_CONFIG ?? "/etc/traefik/dynamic/dynamic.yml"),
    await readText(join(process.cwd(), "compose/traefik/dynamic.yml.tpl"))
  ].join("\n");
  const middlewares = process.env.CROWDSEC_EDGE_MIDDLEWARES ?? "";
  const notifications = listNotificationChannels();
  const attackEvents = listAttackEvents(20);
  const edgeGate = getEdgeGateSettings();
  const controls: ProtectionControl[] = [];

  controls.push(dynamic.includes("crowdsec-bouncer:") && middlewares.includes("crowdsec-bouncer@file")
    ? enabled("crowdsec-bouncer", "CrowdSec bouncer", "waf", "Traefik routes use the CrowdSec bouncer middleware.", "crowdsec-bouncer@file")
    : attention("crowdsec-bouncer", "CrowdSec bouncer", "waf", "The bouncer middleware is not confirmed on edge routes.", "Attach crowdsec-bouncer@file to every public router."));

  controls.push(dynamic.includes("crowdsecAppsecEnabled: true")
    ? enabled("appsec", "AppSec / virtual patching", "waf", "CrowdSec AppSec is enabled for the Traefik bouncer.", "crowdsecAppsecEnabled: true")
    : attention("appsec", "AppSec / virtual patching", "waf", "AppSec is not confirmed.", "Enable CrowdSec AppSec and install appsec-generic-rules/appsec-virtual-patching collections."));

  controls.push(dynamic.includes("rateLimit:") && middlewares.includes("edge-rate-limit@file")
    ? enabled("rate-limit", "HTTP flood rate limiting", "rate-limit", "Traefik rateLimit middleware is configured and attached to edge routes.", "edge-rate-limit@file")
    : attention("rate-limit", "HTTP flood rate limiting", "rate-limit", "No edge rate limiting confirmed.", "Add a Traefik rateLimit middleware before the bouncer for public routers."));

  controls.push(dynamic.includes("edge-gate:") && dynamic.includes("forwardAuth:") && edgeGate.enabled && edgeGate.botChallengeEnabled
    ? enabled("anti-bot-challenge", "Browser anti-bot challenge", "access-control", "Traefik forwardAuth edge gate is configured for browser challenge checks.", "edge-gate@file + UI settings")
    : attention("anti-bot-challenge", "Browser anti-bot challenge", "access-control", "Browser challenge is not confirmed.", "Enable the Edge Gate browser challenge from the dashboard settings and attach edge-gate@file to protected routers."));

  controls.push(dynamic.includes("edge-gate:") && dynamic.includes("forwardAuth:") && edgeGate.enabled && edgeGate.authEnabled && edgeGate.passwordConfigured
    ? enabled("auth-challenge", "Authentication challenge", "access-control", "Password challenge is enabled at the Traefik edge gate.", "UI settings: auth challenge enabled")
    : attention("auth-challenge", "Authentication challenge", "access-control", "Password challenge is not enabled.", "Enable the Edge Gate password challenge from the dashboard settings, set a password, and attach edge-gate@file to protected routers."));

  controls.push(dynamic.includes("security-headers:") && middlewares.includes("security-headers@file")
    ? enabled("security-headers", "Security headers", "access-control", "Basic browser hardening headers are attached.", "security-headers@file")
    : attention("security-headers", "Security headers", "access-control", "Security headers are not confirmed on edge routes.", "Attach security-headers@file to public routers."));

  controls.push(process.env.CROWDSEC_ALLOWLIST?.trim()
    ? enabled("allowlist", "Operator allowlist", "access-control", "Internal/operator networks are configured as allowlist candidates.", process.env.CROWDSEC_ALLOWLIST)
    : unknown("allowlist", "Operator allowlist", "access-control", "No allowlist env was found.", "Configure CROWDSEC_ALLOWLIST for trusted internal/operator networks."));

  controls.push(notifications.some((channel) => channel.enabled)
    ? enabled("notifications", "Out-of-band notifications", "notifications", "At least one notification route is enabled.", `${notifications.filter((channel) => channel.enabled).length} enabled channel(s)`)
    : attention("notifications", "Out-of-band notifications", "notifications", "No enabled notification channel exists.", "Configure Slack, Discord, or a generic webhook and test it."));

  controls.push(attackEvents.length > 0
    ? enabled("http-event-visibility", "HTTP target visibility", "observability", "Raw CrowdSec events include enough HTTP context to inspect targets.", `${attackEvents.length} recent normalized event(s)`)
    : attention("http-event-visibility", "HTTP target visibility", "observability", "No normalized HTTP target events are available yet.", "Ensure Traefik access logs are parsed by CrowdSec and alerts include raw event metadata."));

  const known = controls.filter((control) => control.status !== "unknown");
  const score = known.length === 0 ? 0 : Math.round((known.filter((control) => control.status === "enabled").length / known.length) * 100);
  return { score, controls, generatedAt: new Date().toISOString() };
}
