import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { isAllowedTarget } from "@/lib/security/ip-allowlist";
import { getCrowdSecConfig } from "./config";
import type { CreateEdgeRateLimitRuleInput, CreateNotificationChannelInput, CrowdSecAlert, CrowdSecDecision, EdgeGateSettings, EdgeRateLimitRule, LocalAllowlistEntry, NotificationChannel, NotificationChannelType, NotificationWorkerStatus, Severity, UpdateEdgeGateSettingsInput } from "./types";

interface AlertRow {
  id: string;
  scenario: string;
  source_ip: string | null;
  source_country: string | null;
  source_as_name: string | null;
  events: number;
  severity: Severity;
  created_at: string | null;
  message: string;
  observed_at: string;
  raw_json: string;
}

interface DecisionRow {
  id: string;
  origin: string;
  scenario: string;
  scope: string;
  value: string;
  type: string;
  duration: string | null;
  expires_at: string | null;
  country: string | null;
  as_name: string | null;
  observed_at: string;
}

interface NotificationChannelRow {
  id: string;
  name: string;
  type: NotificationChannelType;
  url: string;
  enabled: number;
  min_severity: Severity;
  created_at: string;
  updated_at: string;
  last_test_at: string | null;
  last_error: string | null;
}

interface EdgeRateLimitRuleRow {
  id: string;
  name: string;
  target: EdgeRateLimitRule["target"];
  value: string;
  window_seconds: number;
  max_requests: number;
  enabled: number;
  created_at: string;
  updated_at: string;
}

interface LocalAllowlistRow {
  id: string;
  value: string;
  reason: string;
  created_at: string;
}

interface IpIntelRow {
  ip: string;
  country: string | null;
  country_name: string | null;
  city: string | null;
  region: string | null;
  continent: string | null;
  continent_code: string | null;
  postal_code: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
  currency: string | null;
  languages: string | null;
  asn: string | null;
  as_name: string | null;
  isp: string | null;
  org: string | null;
  is_proxy: number | null;
  is_hosting: number | null;
  is_mobile: number | null;
  reverse_dns: string | null;
  provider: string | null;
  updated_at: string;
}

export interface IpScenarioSummary {
  scenario: string;
  events: number;
  alerts: number;
  severity: Severity;
}

export interface IpActivityBucket {
  day: string;
  events: number;
}

export interface CachedIpIntel {
  ip: string;
  country?: string | undefined;
  countryName?: string | undefined;
  city?: string | undefined;
  region?: string | undefined;
  continent?: string | undefined;
  continentCode?: string | undefined;
  postalCode?: string | undefined;
  latitude?: number | undefined;
  longitude?: number | undefined;
  timezone?: string | undefined;
  currency?: string | undefined;
  languages?: string | undefined;
  asn?: string | undefined;
  asName?: string | undefined;
  isp?: string | undefined;
  org?: string | undefined;
  isProxy?: boolean | undefined;
  isHosting?: boolean | undefined;
  isMobile?: boolean | undefined;
  reverseDns?: string | undefined;
  provider?: string | undefined;
  updatedAt?: string | undefined;
}

export interface IpNetworkInfo {
  range: string;
  isPublic: boolean;
  isSpecial: boolean;
  specialName?: string | undefined;
  specialDescription?: string | undefined;
}

export interface IpIntelProfile extends CachedIpIntel {
  range: string;
  network: IpNetworkInfo;
  confidence: "Low" | "Medium" | "High";
  backgroundNoise: "Quiet" | "Noisy" | "Very Noisy";
  firstSeen?: string | undefined;
  lastSeen?: string | undefined;
  totalEvents: number;
  totalAlerts: number;
  activeDecisions: number;
  localAllowlisted: boolean;
  operatorAllowlisted: boolean;
  allowlisted: boolean;
  knownFor: string[];
  mitreTechniques: string[];
  riskSignals: string[];
  scenarios: IpScenarioSummary[];
  decisions: CrowdSecDecision[];
  recentAlerts: CrowdSecAlert[];
  activity: IpActivityBucket[];
}

let db: DatabaseSync | null = null;

function dbPath(): string {
  return process.env.CROWDSEC_PANEL_DB_PATH?.trim() || "/tmp/bastionflow/panel.sqlite";
}

function database(): DatabaseSync {
  if (db) return db;
  const path = dbPath();
  mkdirSync(dirname(path), { recursive: true });
  db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      scenario TEXT NOT NULL,
      source_ip TEXT,
      source_country TEXT,
      source_as_name TEXT,
      events INTEGER NOT NULL,
      severity TEXT NOT NULL,
      created_at TEXT,
      message TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      raw_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
    CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
    CREATE TABLE IF NOT EXISTS decisions (
      id TEXT PRIMARY KEY,
      origin TEXT NOT NULL,
      scenario TEXT NOT NULL,
      scope TEXT NOT NULL,
      value TEXT NOT NULL,
      type TEXT NOT NULL,
      duration TEXT,
      expires_at TEXT,
      country TEXT,
      as_name TEXT,
      observed_at TEXT NOT NULL,
      raw_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_decisions_value ON decisions(value);
    CREATE TABLE IF NOT EXISTS ip_intel (
      ip TEXT PRIMARY KEY,
      country TEXT,
      country_name TEXT,
      city TEXT,
      region TEXT,
      continent TEXT,
      continent_code TEXT,
      postal_code TEXT,
      latitude REAL,
      longitude REAL,
      timezone TEXT,
      currency TEXT,
      languages TEXT,
      asn TEXT,
      as_name TEXT,
      isp TEXT,
      org TEXT,
      is_proxy INTEGER,
      is_hosting INTEGER,
      is_mobile INTEGER,
      reverse_dns TEXT,
      provider TEXT,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notification_channels (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('slack','discord','webhook')),
      url TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      min_severity TEXT NOT NULL DEFAULT 'high',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      last_test_at TEXT,
      last_error TEXT
    );
    CREATE TABLE IF NOT EXISTS notification_dispatch_log (
      event_id TEXT PRIMARY KEY,
      dispatched_at TEXT NOT NULL,
      result_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notification_worker_heartbeat (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      worker_id TEXT NOT NULL,
      interval_ms INTEGER NOT NULL,
      last_seen_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS edge_gate_settings (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      enabled INTEGER NOT NULL,
      bot_challenge_enabled INTEGER NOT NULL,
      auth_enabled INTEGER NOT NULL,
      password_hash TEXT,
      max_age_seconds INTEGER NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS edge_rate_limit_rules (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      target TEXT NOT NULL CHECK(target IN ('ip','path','service')),
      value TEXT NOT NULL,
      window_seconds INTEGER NOT NULL,
      max_requests INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS edge_rate_limit_hits (
      rule_id TEXT NOT NULL,
      key TEXT NOT NULL,
      window_start INTEGER NOT NULL,
      count INTEGER NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY(rule_id, key, window_start)
    );
    CREATE INDEX IF NOT EXISTS idx_edge_rate_limit_hits_window ON edge_rate_limit_hits(window_start);
    CREATE TABLE IF NOT EXISTS local_allowlist (
      id TEXT PRIMARY KEY,
      value TEXT NOT NULL UNIQUE,
      reason TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);
  migrateIpIntel(db);
  return db;
}

function migrateIpIntel(db: DatabaseSync): void {
  const columns: Array<[string, string]> = [
    ["country_name", "TEXT"], ["region", "TEXT"], ["continent", "TEXT"], ["continent_code", "TEXT"], ["postal_code", "TEXT"],
    ["latitude", "REAL"], ["longitude", "REAL"], ["timezone", "TEXT"], ["currency", "TEXT"], ["languages", "TEXT"],
    ["asn", "TEXT"], ["isp", "TEXT"], ["org", "TEXT"], ["is_proxy", "INTEGER"], ["is_hosting", "INTEGER"], ["is_mobile", "INTEGER"],
    ["reverse_dns", "TEXT"], ["provider", "TEXT"]
  ];
  for (const [name, type] of columns) {
    try { db.exec(`ALTER TABLE ip_intel ADD COLUMN ${name} ${type}`); } catch {}
  }
}

function severityRank(value: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[value];
}

function rowToAlert(row: AlertRow): CrowdSecAlert {
  return {
    id: row.id,
    scenario: row.scenario,
    sourceIp: row.source_ip ?? undefined,
    sourceCountry: row.source_country ?? undefined,
    sourceAsName: row.source_as_name ?? undefined,
    events: row.events,
    severity: row.severity,
    createdAt: row.created_at ?? undefined,
    message: row.message
  };
}

export function getStoredAlertPayloads(limit = 200): Array<{ alert: CrowdSecAlert; raw: unknown }> {
  const rows = database().prepare("SELECT * FROM alerts ORDER BY COALESCE(created_at, observed_at) DESC LIMIT ?").all(limit) as unknown as AlertRow[];
  return rows.map((row) => {
    let raw: unknown = rowToAlert(row);
    try { raw = JSON.parse(row.raw_json); } catch {}
    return { alert: rowToAlert(row), raw };
  });
}

function rowToDecision(row: DecisionRow): CrowdSecDecision {
  return {
    id: row.id,
    origin: row.origin,
    scenario: row.scenario,
    scope: row.scope as CrowdSecDecision["scope"],
    value: row.value,
    type: row.type as CrowdSecDecision["type"],
    duration: row.duration ?? undefined,
    expiresAt: row.expires_at ?? undefined,
    country: row.country ?? undefined,
    asName: row.as_name ?? undefined
  };
}

function boolValue(value: number | null): boolean | undefined {
  return value === null ? undefined : value === 1;
}

function rowToIntel(row: IpIntelRow): CachedIpIntel {
  return {
    ip: row.ip,
    country: row.country ?? undefined,
    countryName: row.country_name ?? undefined,
    city: row.city ?? undefined,
    region: row.region ?? undefined,
    continent: row.continent ?? undefined,
    continentCode: row.continent_code ?? undefined,
    postalCode: row.postal_code ?? undefined,
    latitude: row.latitude ?? undefined,
    longitude: row.longitude ?? undefined,
    timezone: row.timezone ?? undefined,
    currency: row.currency ?? undefined,
    languages: row.languages ?? undefined,
    asn: row.asn ?? undefined,
    asName: row.as_name ?? undefined,
    isp: row.isp ?? undefined,
    org: row.org ?? undefined,
    isProxy: boolValue(row.is_proxy),
    isHosting: boolValue(row.is_hosting),
    isMobile: boolValue(row.is_mobile),
    reverseDns: row.reverse_dns ?? undefined,
    provider: row.provider ?? undefined,
    updatedAt: row.updated_at
  };
}

export function getCachedIpIntel(ip: string): CachedIpIntel | null {
  const row = database().prepare("SELECT * FROM ip_intel WHERE ip = ?").get(ip) as unknown as IpIntelRow | undefined;
  return row ? rowToIntel(row) : null;
}

export function upsertIpIntel(ip: string, intel: Omit<CachedIpIntel, "ip">): void {
  const hasValue = Object.entries(intel).some(([key, value]) => key !== "updatedAt" && value !== undefined && value !== null && value !== "");
  if (!hasValue) return;
  database().prepare(`
    INSERT INTO ip_intel (ip, country, country_name, city, region, continent, continent_code, postal_code, latitude, longitude, timezone, currency, languages, asn, as_name, isp, org, is_proxy, is_hosting, is_mobile, reverse_dns, provider, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
      country=COALESCE(excluded.country, ip_intel.country),
      country_name=COALESCE(excluded.country_name, ip_intel.country_name),
      city=COALESCE(excluded.city, ip_intel.city),
      region=COALESCE(excluded.region, ip_intel.region),
      continent=COALESCE(excluded.continent, ip_intel.continent),
      continent_code=COALESCE(excluded.continent_code, ip_intel.continent_code),
      postal_code=COALESCE(excluded.postal_code, ip_intel.postal_code),
      latitude=COALESCE(excluded.latitude, ip_intel.latitude),
      longitude=COALESCE(excluded.longitude, ip_intel.longitude),
      timezone=COALESCE(excluded.timezone, ip_intel.timezone),
      currency=COALESCE(excluded.currency, ip_intel.currency),
      languages=COALESCE(excluded.languages, ip_intel.languages),
      asn=COALESCE(excluded.asn, ip_intel.asn),
      as_name=COALESCE(excluded.as_name, ip_intel.as_name),
      isp=COALESCE(excluded.isp, ip_intel.isp),
      org=COALESCE(excluded.org, ip_intel.org),
      is_proxy=COALESCE(excluded.is_proxy, ip_intel.is_proxy),
      is_hosting=COALESCE(excluded.is_hosting, ip_intel.is_hosting),
      is_mobile=COALESCE(excluded.is_mobile, ip_intel.is_mobile),
      reverse_dns=COALESCE(excluded.reverse_dns, ip_intel.reverse_dns),
      provider=COALESCE(excluded.provider, ip_intel.provider),
      updated_at=excluded.updated_at
  `).run(
    ip,
    intel.country ?? null, intel.countryName ?? null, intel.city ?? null, intel.region ?? null, intel.continent ?? null, intel.continentCode ?? null, intel.postalCode ?? null,
    intel.latitude ?? null, intel.longitude ?? null, intel.timezone ?? null, intel.currency ?? null, intel.languages ?? null, intel.asn ?? null, intel.asName ?? null,
    intel.isp ?? null, intel.org ?? null, intel.isProxy === undefined ? null : Number(intel.isProxy), intel.isHosting === undefined ? null : Number(intel.isHosting), intel.isMobile === undefined ? null : Number(intel.isMobile),
    intel.reverseDns ?? null, intel.provider ?? null, new Date().toISOString()
  );
}

function maskWebhookUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const tail = parsed.pathname.split("/").filter(Boolean).at(-1) ?? "";
    const maskedTail = tail.length > 8 ? `${tail.slice(0, 4)}…${tail.slice(-4)}` : "••••";
    parsed.pathname = `${parsed.pathname.split("/").filter(Boolean).slice(0, -1).join("/")}/${maskedTail}`;
    parsed.search = "";
    return parsed.toString();
  } catch {
    return "invalid-url";
  }
}

function rowToNotificationChannel(row: NotificationChannelRow): NotificationChannel {
  return {
    id: row.id,
    name: row.name,
    type: row.type,
    enabled: row.enabled === 1,
    urlMasked: maskWebhookUrl(row.url),
    minSeverity: row.min_severity,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastTestAt: row.last_test_at ?? undefined,
    lastError: row.last_error ?? undefined
  };
}

export function listNotificationChannels(): NotificationChannel[] {
  const rows = database().prepare("SELECT * FROM notification_channels ORDER BY created_at DESC").all() as unknown as NotificationChannelRow[];
  return rows.map(rowToNotificationChannel);
}

export function getNotificationChannelSecret(id: string): (NotificationChannel & { url: string }) | null {
  const row = database().prepare("SELECT * FROM notification_channels WHERE id = ?").get(id) as unknown as NotificationChannelRow | undefined;
  return row ? { ...rowToNotificationChannel(row), url: row.url } : null;
}

export function createNotificationChannel(input: CreateNotificationChannelInput): NotificationChannel {
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  database().prepare(`
    INSERT INTO notification_channels (id, name, type, url, enabled, min_severity, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, input.name, input.type, input.url, Number(input.enabled), input.minSeverity, now, now);
  const channel = listNotificationChannels().find((item) => item.id === id);
  if (!channel) throw new Error("Notification channel was not created");
  return channel;
}

export function deleteNotificationChannel(id: string): boolean {
  const result = database().prepare("DELETE FROM notification_channels WHERE id = ?").run(id);
  return result.changes > 0;
}

export function updateNotificationChannelTest(id: string, ok: boolean, error?: string): void {
  database().prepare("UPDATE notification_channels SET last_test_at = ?, last_error = ?, updated_at = ? WHERE id = ?")
    .run(new Date().toISOString(), ok ? null : error ?? "Unknown notification error", new Date().toISOString(), id);
}

function rowToEdgeRateLimitRule(row: EdgeRateLimitRuleRow): EdgeRateLimitRule {
  return {
    id: row.id,
    name: row.name,
    target: row.target,
    value: row.value,
    windowSeconds: row.window_seconds,
    maxRequests: row.max_requests,
    enabled: row.enabled === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function listEdgeRateLimitRules(includeDisabled = true): EdgeRateLimitRule[] {
  const sql = includeDisabled
    ? "SELECT * FROM edge_rate_limit_rules ORDER BY updated_at DESC"
    : "SELECT * FROM edge_rate_limit_rules WHERE enabled = 1 ORDER BY updated_at DESC";
  return (database().prepare(sql).all() as unknown as EdgeRateLimitRuleRow[]).map(rowToEdgeRateLimitRule);
}

export function createEdgeRateLimitRule(input: CreateEdgeRateLimitRuleInput): EdgeRateLimitRule {
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  database().prepare(`
    INSERT INTO edge_rate_limit_rules (id, name, target, value, window_seconds, max_requests, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, input.name, input.target, input.value, input.windowSeconds, input.maxRequests, Number(input.enabled), now, now);
  const row = database().prepare("SELECT * FROM edge_rate_limit_rules WHERE id = ?").get(id) as unknown as EdgeRateLimitRuleRow | undefined;
  if (!row) throw new Error("Edge rate limit rule was not created");
  return rowToEdgeRateLimitRule(row);
}

export function deleteEdgeRateLimitRule(id: string): boolean {
  database().prepare("DELETE FROM edge_rate_limit_hits WHERE rule_id = ?").run(id);
  const result = database().prepare("DELETE FROM edge_rate_limit_rules WHERE id = ?").run(id);
  return result.changes > 0;
}

export function recordEdgeRateLimitHit(rule: EdgeRateLimitRule, key: string, nowMs = Date.now()): { count: number; remaining: number; resetAt: string; allowed: boolean } {
  const windowStart = Math.floor(Math.floor(nowMs / 1000) / rule.windowSeconds) * rule.windowSeconds;
  const resetAtSeconds = windowStart + rule.windowSeconds;
  const nowIso = new Date(nowMs).toISOString();
  database().prepare("DELETE FROM edge_rate_limit_hits WHERE window_start < ?").run(Math.floor(nowMs / 1000) - 86_400);
  database().prepare(`
    INSERT INTO edge_rate_limit_hits (rule_id, key, window_start, count, updated_at)
    VALUES (?, ?, ?, 1, ?)
    ON CONFLICT(rule_id, key, window_start) DO UPDATE SET
      count = count + 1,
      updated_at = excluded.updated_at
  `).run(rule.id, key, windowStart, nowIso);
  const row = database().prepare("SELECT count FROM edge_rate_limit_hits WHERE rule_id = ? AND key = ? AND window_start = ?")
    .get(rule.id, key, windowStart) as { count: number } | undefined;
  const count = row?.count ?? 1;
  return {
    count,
    remaining: Math.max(0, rule.maxRequests - count),
    resetAt: new Date(resetAtSeconds * 1000).toISOString(),
    allowed: count <= rule.maxRequests
  };
}

interface EdgeGateSettingsRow {
  enabled: number;
  bot_challenge_enabled: number;
  auth_enabled: number;
  password_hash: string | null;
  max_age_seconds: number;
  updated_at: string;
}

export function getPersistedEdgeGateSettings(): (EdgeGateSettings & { passwordHash?: string | undefined }) | null {
  const row = database().prepare("SELECT * FROM edge_gate_settings WHERE id = 1").get() as unknown as EdgeGateSettingsRow | undefined;
  return row ? {
    enabled: row.enabled === 1,
    botChallengeEnabled: row.bot_challenge_enabled === 1,
    authEnabled: row.auth_enabled === 1,
    passwordConfigured: Boolean(row.password_hash),
    passwordHash: row.password_hash ?? undefined,
    maxAgeSeconds: row.max_age_seconds
  } : null;
}

export function saveEdgeGateSettings(input: UpdateEdgeGateSettingsInput, passwordHash?: string | undefined): EdgeGateSettings {
  const current = getPersistedEdgeGateSettings();
  const nextHash = passwordHash ?? current?.passwordHash ?? null;
  database().prepare(`
    INSERT INTO edge_gate_settings (id, enabled, bot_challenge_enabled, auth_enabled, password_hash, max_age_seconds, updated_at)
    VALUES (1, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      enabled=excluded.enabled,
      bot_challenge_enabled=excluded.bot_challenge_enabled,
      auth_enabled=excluded.auth_enabled,
      password_hash=excluded.password_hash,
      max_age_seconds=excluded.max_age_seconds,
      updated_at=excluded.updated_at
  `).run(Number(input.enabled), Number(input.botChallengeEnabled), Number(input.authEnabled), nextHash, input.maxAgeSeconds, new Date().toISOString());
  return {
    enabled: input.enabled,
    botChallengeEnabled: input.botChallengeEnabled,
    authEnabled: input.authEnabled,
    passwordConfigured: Boolean(nextHash),
    maxAgeSeconds: input.maxAgeSeconds
  };
}

function rowToLocalAllowlistEntry(row: LocalAllowlistRow): LocalAllowlistEntry {
  return { id: row.id, value: row.value, reason: row.reason, createdAt: row.created_at };
}

export function listLocalAllowlistEntries(): LocalAllowlistEntry[] {
  return (database().prepare("SELECT * FROM local_allowlist ORDER BY created_at DESC").all() as unknown as LocalAllowlistRow[]).map(rowToLocalAllowlistEntry);
}

export function getLocalAllowlistValues(): string[] {
  return (database().prepare("SELECT value FROM local_allowlist ORDER BY created_at DESC").all() as Array<{ value: string }>).map((row) => row.value);
}

export function createLocalAllowlistEntry(value: string, reason: string): LocalAllowlistEntry {
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  database().prepare(`
    INSERT INTO local_allowlist (id, value, reason, created_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(value) DO UPDATE SET reason=excluded.reason
  `).run(id, value, reason, now);
  const row = database().prepare("SELECT * FROM local_allowlist WHERE value = ?").get(value) as unknown as LocalAllowlistRow | undefined;
  if (!row) throw new Error("Local allowlist entry was not created");
  return rowToLocalAllowlistEntry(row);
}

export function deleteLocalAllowlistEntry(value: string): boolean {
  const result = database().prepare("DELETE FROM local_allowlist WHERE value = ? OR id = ?").run(value, value);
  return result.changes > 0;
}

export function isLocalAllowlisted(value: string): boolean {
  const row = database().prepare("SELECT value FROM local_allowlist WHERE value = ?").get(value) as { value: string } | undefined;
  return Boolean(row);
}

export function updateNotificationWorkerHeartbeat(workerId: string, intervalMs: number): NotificationWorkerStatus {
  const lastSeenAt = new Date().toISOString();
  database().prepare(`
    INSERT INTO notification_worker_heartbeat (id, worker_id, interval_ms, last_seen_at)
    VALUES (1, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET worker_id=excluded.worker_id, interval_ms=excluded.interval_ms, last_seen_at=excluded.last_seen_at
  `).run(workerId, intervalMs, lastSeenAt);
  return getNotificationWorkerStatus();
}

export function getNotificationWorkerStatus(now = Date.now()): NotificationWorkerStatus {
  const row = database().prepare("SELECT worker_id, interval_ms, last_seen_at FROM notification_worker_heartbeat WHERE id = 1")
    .get() as { worker_id: string; interval_ms: number; last_seen_at: string } | undefined;
  const intervalMs = row?.interval_ms;
  const staleAfterSeconds = Math.max(15, Math.ceil(((intervalMs ?? 5000) * 3) / 1000));
  const lastSeen = row?.last_seen_at ? new Date(row.last_seen_at).getTime() : Number.NaN;
  const online = Number.isFinite(lastSeen) && now - lastSeen <= staleAfterSeconds * 1000;
  return {
    online,
    lastSeenAt: row?.last_seen_at,
    staleAfterSeconds,
    intervalMs,
    workerId: row?.worker_id
  };
}

export function hasNotificationDispatch(eventId: string): boolean {
  const row = database().prepare("SELECT event_id FROM notification_dispatch_log WHERE event_id = ?").get(eventId) as { event_id: string } | undefined;
  return Boolean(row);
}

export function markNotificationDispatch(eventId: string, result: unknown): void {
  database().prepare(`
    INSERT INTO notification_dispatch_log (event_id, dispatched_at, result_json)
    VALUES (?, ?, ?)
    ON CONFLICT(event_id) DO UPDATE SET dispatched_at=excluded.dispatched_at, result_json=excluded.result_json
  `).run(eventId, new Date().toISOString(), JSON.stringify(result));
}

export function seedNotificationChannelsFromEnv(): void {
  const existing = listNotificationChannels();
  if (existing.length > 0) return;
  const raw = process.env.CROWDSEC_NOTIFICATION_CHANNELS?.trim();
  if (!raw) return;
  try {
    const channels = JSON.parse(raw) as Array<Partial<CreateNotificationChannelInput>>;
    for (const channel of channels) {
      if (!channel.name || !channel.type || !channel.url) continue;
      createNotificationChannel({ name: channel.name, type: channel.type, url: channel.url, enabled: channel.enabled ?? true, minSeverity: channel.minSeverity ?? "high" });
    }
  } catch {}
}

export function persistAlerts(alerts: readonly CrowdSecAlert[], rawAlerts: readonly unknown[] = []): void {
  if (alerts.length === 0) return;
  const db = database();
  const stmt = db.prepare(`
    INSERT INTO alerts (id, scenario, source_ip, source_country, source_as_name, events, severity, created_at, message, observed_at, raw_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      scenario=excluded.scenario,
      source_ip=excluded.source_ip,
      source_country=excluded.source_country,
      source_as_name=excluded.source_as_name,
      events=excluded.events,
      severity=excluded.severity,
      created_at=excluded.created_at,
      message=excluded.message,
      observed_at=excluded.observed_at,
      raw_json=excluded.raw_json
  `);
  const observedAt = new Date().toISOString();
  db.exec("BEGIN");
  try {
    for (const [index, alert] of alerts.entries()) {
      stmt.run(alert.id, alert.scenario, alert.sourceIp ?? null, alert.sourceCountry ?? null, alert.sourceAsName ?? null, alert.events, alert.severity, alert.createdAt ?? null, alert.message, observedAt, JSON.stringify(rawAlerts[index] ?? alert));
      if (alert.sourceIp && (alert.sourceCountry || alert.sourceAsName)) upsertIpIntel(alert.sourceIp, { country: alert.sourceCountry, asName: alert.sourceAsName, provider: "crowdsec" });
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

export function persistDecisions(decisions: readonly CrowdSecDecision[]): void {
  if (decisions.length === 0) return;
  const db = database();
  const stmt = db.prepare(`
    INSERT INTO decisions (id, origin, scenario, scope, value, type, duration, expires_at, country, as_name, observed_at, raw_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      origin=excluded.origin,
      scenario=excluded.scenario,
      scope=excluded.scope,
      value=excluded.value,
      type=excluded.type,
      duration=excluded.duration,
      expires_at=excluded.expires_at,
      country=excluded.country,
      as_name=excluded.as_name,
      observed_at=excluded.observed_at,
      raw_json=excluded.raw_json
  `);
  const observedAt = new Date().toISOString();
  db.exec("BEGIN");
  try {
    for (const decision of decisions) {
      stmt.run(decision.id, decision.origin, decision.scenario, decision.scope, decision.value, decision.type, decision.duration ?? null, decision.expiresAt ?? null, decision.country ?? null, decision.asName ?? null, observedAt, JSON.stringify(decision));
      if (decision.scope === "ip" && (decision.country || decision.asName)) upsertIpIntel(decision.value, { country: decision.country, asName: decision.asName, provider: "crowdsec" });
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function parseIpv4(ip: string): [number, number, number, number] | null {
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts as [number, number, number, number];
}

function ipRange(ip: string): string {
  const parts = parseIpv4(ip);
  if (!parts) return ip;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

export function classifyIp(ip: string): IpNetworkInfo {
  const parts = parseIpv4(ip);
  const range = ipRange(ip);
  if (!parts) return { range, isPublic: false, isSpecial: true, specialName: "Unsupported address", specialDescription: "Only IPv4 enrichment is currently enabled for this local dashboard." };
  const [a, b, c] = parts;
  const special = (specialName: string, specialDescription: string): IpNetworkInfo => ({ range, isPublic: false, isSpecial: true, specialName, specialDescription });
  if (a === 10) return special("RFC1918 private", "Private address space; not routable on the public Internet.");
  if (a === 172 && b >= 16 && b <= 31) return special("RFC1918 private", "Private address space; not routable on the public Internet.");
  if (a === 192 && b === 168) return special("RFC1918 private", "Private address space; not routable on the public Internet.");
  if (a === 127) return special("Loopback", "Localhost range; never represents an external attacker.");
  if (a === 169 && b === 254) return special("Link-local", "Automatic link-local range; not globally routable.");
  if (a === 100 && b >= 64 && b <= 127) return special("Carrier-grade NAT", "Shared address space used by providers; attribution is limited.");
  if (a === 192 && b === 0 && c === 2) return special("TEST-NET-1", "Documentation-only range from RFC 5737; no real GeoIP/ASN should exist.");
  if (a === 198 && b === 51 && c === 100) return special("TEST-NET-2", "Documentation-only range from RFC 5737; no real GeoIP/ASN should exist.");
  if (a === 203 && b === 0 && c === 113) return special("TEST-NET-3", "Documentation-only range from RFC 5737; no real GeoIP/ASN should exist.");
  if (a >= 224) return special("Multicast/reserved", "Reserved or multicast range; not a normal public host address.");
  if (a === 0) return special("Current network", "Reserved source range; not a normal public host address.");
  return { range, isPublic: true, isSpecial: false };
}

function knownFor(scenario: string): string {
  return scenario.replace(/^crowdsecurity\//, "").replace(/^CAPI:/, "").replaceAll("-", " ");
}

function mitreFor(scenario: string): string[] {
  const lower = scenario.toLowerCase();
  const values = new Set<string>();
  if (lower.includes("scan") || lower.includes("probe") || lower.includes("crawl")) values.add("Active Scanning");
  if (lower.includes("cve") || lower.includes("exploit") || lower.includes("sensitive") || lower.includes("admin")) values.add("Exploit Public-Facing Application");
  if (lower.includes("bf") || lower.includes("brute")) values.add("Brute Force");
  if (lower.includes("dos")) values.add("Network Denial of Service");
  if (values.size === 0) values.add("Reconnaissance");
  return [...values];
}

function riskSignals(profile: CachedIpIntel, decisions: CrowdSecDecision[], totalEvents: number, scenarios: IpScenarioSummary[], network: IpNetworkInfo, localAllowlisted = false): string[] {
  const signals = new Set<string>();
  if (localAllowlisted) signals.add("Local allowlist");
  if (network.isSpecial) signals.add(network.specialName ?? "Special-purpose address");
  if (decisions.length > 0) signals.add("Active remediation decision");
  if (totalEvents >= 30) signals.add("High event volume");
  if (scenarios.length >= 3) signals.add("Multiple attack classifications");
  if (profile.isProxy) signals.add("Proxy/VPN signal");
  if (profile.isHosting) signals.add("Hosting/datacenter signal");
  if (profile.reverseDns) signals.add("Reverse DNS available");
  return [...signals];
}

export function getIpProfile(ip: string): IpIntelProfile {
  const db = database();
  const alertRows = db.prepare("SELECT * FROM alerts WHERE source_ip = ? ORDER BY COALESCE(created_at, observed_at) DESC LIMIT 200").all(ip) as unknown as AlertRow[];
  const decisionRows = db.prepare("SELECT * FROM decisions WHERE value = ? ORDER BY observed_at DESC").all(ip) as unknown as DecisionRow[];
  const alerts = alertRows.map(rowToAlert);
  const decisions = decisionRows.map(rowToDecision);
  const totalEvents = alerts.reduce((sum, alert) => sum + alert.events, 0);
  const dates = alerts.map((alert) => alert.createdAt ?? "").filter(Boolean).sort();
  const scenarioMap = new Map<string, IpScenarioSummary>();
  const mitre = new Set<string>();
  for (const alert of alerts) {
    const current = scenarioMap.get(alert.scenario) ?? { scenario: alert.scenario, events: 0, alerts: 0, severity: alert.severity };
    current.events += alert.events;
    current.alerts += 1;
    if (severityRank(alert.severity) > severityRank(current.severity)) current.severity = alert.severity;
    scenarioMap.set(alert.scenario, current);
    mitreFor(alert.scenario).forEach((item) => mitre.add(item));
  }
  const scenarios = [...scenarioMap.values()].sort((a, b) => b.events - a.events);
  const highestSeverity = scenarios[0]?.severity ?? "info";
  const confidence: IpIntelProfile["confidence"] = decisions.length > 0 || severityRank(highestSeverity) >= 4 || totalEvents >= 10 ? "High" : totalEvents >= 3 ? "Medium" : "Low";
  const backgroundNoise: IpIntelProfile["backgroundNoise"] = totalEvents >= 30 ? "Very Noisy" : totalEvents >= 8 ? "Noisy" : "Quiet";
  const cachedIntel = getCachedIpIntel(ip) ?? { ip };
  const network = classifyIp(ip);
  const country = decisions[0]?.country ?? alerts.find((alert) => alert.sourceCountry)?.sourceCountry ?? cachedIntel.country;
  const asName = decisions[0]?.asName ?? alerts.find((alert) => alert.sourceAsName)?.sourceAsName ?? cachedIntel.asName;
  const buckets = new Map<string, number>();
  for (const alert of alerts) {
    const date = alert.createdAt ? new Date(alert.createdAt) : null;
    if (!date || Number.isNaN(date.getTime())) continue;
    const day = date.toISOString().slice(0, 10);
    buckets.set(day, (buckets.get(day) ?? 0) + alert.events);
  }
  const mergedIntel: CachedIpIntel = { ...cachedIntel, country, asName };
  const localAllowlisted = isLocalAllowlisted(ip);
  const operatorAllowlisted = isAllowedTarget(ip, getCrowdSecConfig().allowlist);
  const allowlisted = localAllowlisted || operatorAllowlisted;
  return {
    ...mergedIntel,
    ip,
    range: network.range,
    network,
    confidence,
    backgroundNoise,
    firstSeen: dates[0],
    lastSeen: dates.at(-1),
    totalEvents,
    totalAlerts: alerts.length,
    activeDecisions: decisions.length,
    localAllowlisted,
    operatorAllowlisted,
    allowlisted,
    knownFor: scenarios.slice(0, 8).map((item) => knownFor(item.scenario)),
    mitreTechniques: [...mitre],
    riskSignals: riskSignals(mergedIntel, decisions, totalEvents, scenarios, network, allowlisted),
    scenarios,
    decisions,
    recentAlerts: alerts.slice(0, 20),
    activity: [...buckets.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([day, events]) => ({ day, events }))
  };
}
