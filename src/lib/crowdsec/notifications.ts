import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { createNotificationChannel, deleteNotificationChannel, getNotificationChannelSecret, hasNotificationDispatch, listNotificationChannels, markNotificationDispatch, seedNotificationChannelsFromEnv, updateNotificationChannelTest } from "./store";
import type { AttackEvent, CreateNotificationChannelInput, NotificationChannel, NotificationTestResult, Severity } from "./types";

export { createNotificationChannel, deleteNotificationChannel, listNotificationChannels, seedNotificationChannelsFromEnv };

const severityRank: Record<Severity, number> = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };

function envFlag(name: string): boolean {
  return process.env[name]?.trim().toLowerCase() === "true";
}

function dashboardBaseUrl(): string {
  return process.env.CROWDSEC_PANEL_PUBLIC_URL?.trim() || "http://bastionflow.localhost:8080";
}

function isPrivateIpv4(address: string): boolean {
  const parts = address.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b] = parts as [number, number, number, number];
  return a === 10
    || a === 127
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 169 && b === 254)
    || a === 0
    || a >= 224;
}

function isPrivateIpv6(address: string): boolean {
  const normalized = address.toLowerCase();
  return normalized === "::1"
    || normalized === "::"
    || normalized.startsWith("fc")
    || normalized.startsWith("fd")
    || normalized.startsWith("fe80:")
    || normalized.startsWith("::ffff:127.")
    || normalized.startsWith("::ffff:10.")
    || normalized.startsWith("::ffff:192.168.");
}

function isUnsafeAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isPrivateIpv4(address);
  if (family === 6) return isPrivateIpv6(address);
  return false;
}

function isLocalHostname(hostname: string): boolean {
  const value = hostname.toLowerCase();
  return value === "localhost" || value.endsWith(".localhost") || value.endsWith(".local") || value.endsWith(".internal");
}

function parseWebhookUrl(url: string): URL {
  const parsed = new URL(url);
  const allowHttp = envFlag("CROWDSEC_ALLOW_INSECURE_WEBHOOKS");
  if (parsed.protocol !== "https:" && !(allowHttp && parsed.protocol === "http:")) {
    throw new Error("Webhook URL must use https. Set CROWDSEC_ALLOW_INSECURE_WEBHOOKS=true only for trusted lab environments.");
  }
  if (!parsed.hostname) throw new Error("Webhook URL must include a hostname");
  return parsed;
}

function validateUrl(url: string): void {
  parseWebhookUrl(url);
}

async function assertSafeWebhookDestination(url: string): Promise<void> {
  const parsed = parseWebhookUrl(url);
  if (envFlag("CROWDSEC_ALLOW_PRIVATE_WEBHOOKS")) return;
  if (isLocalHostname(parsed.hostname) || isUnsafeAddress(parsed.hostname)) {
    throw new Error("Webhook URL targets a private/local address. Set CROWDSEC_ALLOW_PRIVATE_WEBHOOKS=true only for trusted lab environments.");
  }
  const records = await lookup(parsed.hostname, { all: true, verbatim: true });
  if (records.some((record) => isUnsafeAddress(record.address))) {
    throw new Error("Webhook hostname resolves to a private/local address; refusing to send notification.");
  }
}

export function validateNotificationInput(input: CreateNotificationChannelInput): void {
  if (!input.name.trim()) throw new Error("Channel name is required");
  if (!["slack", "discord", "webhook"].includes(input.type)) throw new Error("Unsupported notification channel type");
  if (!input.url.trim()) throw new Error("Webhook URL is required");
  validateUrl(input.url);
  if (!Object.keys(severityRank).includes(input.minSeverity)) throw new Error("Invalid minimum severity");
}

function messageText(event: AttackEvent): string {
  const target = `${event.host ?? "unknown-host"}${event.path ?? ""}`;
  return `CrowdSec ${event.severity.toUpperCase()} · ${event.scenario}\n${event.method ?? "EVENT"} ${target}\nSource: ${event.sourceIp ?? "unknown"}${event.status ? ` · status ${event.status}` : ""}`;
}

function genericPayload(event: AttackEvent): Record<string, unknown> {
  return {
    type: "crowdsec.attack_event",
    severity: event.severity,
    scenario: event.scenario,
    sourceIp: event.sourceIp,
    sourceCountry: event.sourceCountry,
    sourceAsName: event.sourceAsName,
    method: event.method,
    host: event.host,
    path: event.path,
    status: event.status,
    userAgent: event.userAgent,
    requestId: event.requestId,
    timestamp: event.timestamp,
    links: {
      ip: event.sourceIp ? `${dashboardBaseUrl()}/ip/${encodeURIComponent(event.sourceIp)}` : undefined,
      dashboard: dashboardBaseUrl()
    }
  };
}

function payloadFor(type: NotificationChannel["type"], event: AttackEvent): unknown {
  const text = messageText(event);
  if (type === "slack") {
    return {
      text,
      blocks: [
        { type: "section", text: { type: "mrkdwn", text: `*CrowdSec ${event.severity.toUpperCase()}* · ${event.scenario}` } },
        { type: "section", fields: [
          { type: "mrkdwn", text: `*Source*\n${event.sourceIp ?? "unknown"}` },
          { type: "mrkdwn", text: `*Target*\n${event.host ?? "unknown"}${event.path ?? ""}` },
          { type: "mrkdwn", text: `*Method*\n${event.method ?? "-"}` },
          { type: "mrkdwn", text: `*Status*\n${event.status ?? "-"}` }
        ] }
      ]
    };
  }
  if (type === "discord") {
    return {
      content: text,
      embeds: [{
        title: `CrowdSec ${event.severity.toUpperCase()} · ${event.scenario}`,
        color: event.severity === "critical" || event.severity === "high" ? 0xef4444 : 0xf59e0b,
        fields: [
          { name: "Source", value: event.sourceIp ?? "unknown", inline: true },
          { name: "Target", value: `${event.host ?? "unknown"}${event.path ?? ""}`.slice(0, 1024), inline: true },
          { name: "Method", value: event.method ?? "-", inline: true }
        ],
        timestamp: event.timestamp
      }]
    };
  }
  return genericPayload(event);
}

export async function sendNotification(channelId: string, event: AttackEvent): Promise<NotificationTestResult> {
  const channel = getNotificationChannelSecret(channelId);
  if (!channel) return { id: channelId, ok: false, error: "Notification channel not found" };
  try {
    if (!channel.enabled) throw new Error("Notification channel is disabled");
    await assertSafeWebhookDestination(channel.url);
    const response = await fetch(channel.url, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "bastionflow/0.1" },
      body: JSON.stringify(payloadFor(channel.type, event)),
      signal: AbortSignal.timeout(5_000)
    });
    if (!response.ok) throw new Error(`Webhook returned ${response.status}: ${(await response.text()).slice(0, 200)}`);
    updateNotificationChannelTest(channelId, true);
    return { id: channelId, ok: true, status: response.status };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to send notification";
    updateNotificationChannelTest(channelId, false, message);
    return { id: channelId, ok: false, error: message };
  }
}

export function shouldNotify(channel: NotificationChannel, event: AttackEvent): boolean {
  return channel.enabled && severityRank[event.severity] >= severityRank[channel.minSeverity];
}

export async function notifyAttackEvent(event: AttackEvent): Promise<NotificationTestResult[]> {
  seedNotificationChannelsFromEnv();
  const channels = listNotificationChannels().filter((channel) => shouldNotify(channel, event));
  return Promise.all(channels.map((channel) => sendNotification(channel.id, event)));
}

export function testEvent(): AttackEvent {
  return {
    id: `test-${Date.now()}`,
    alertId: "manual-test",
    scenario: "bastionflow/notification-test",
    severity: "high",
    sourceIp: "203.0.113.250",
    method: "POST",
    host: "bastionflow.localhost",
    path: "/login",
    status: 403,
    userAgent: "notification-test",
    timestamp: new Date().toISOString(),
    raw: "POST /login HTTP/1.1"
  };
}

export async function dispatchAttackEvent(event: AttackEvent): Promise<{ eventId: string; skipped: boolean; results: NotificationTestResult[] }> {
  if (hasNotificationDispatch(event.id)) return { eventId: event.id, skipped: true, results: [] };
  const results = await notifyAttackEvent(event);
  markNotificationDispatch(event.id, results);
  return { eventId: event.id, skipped: false, results };
}
