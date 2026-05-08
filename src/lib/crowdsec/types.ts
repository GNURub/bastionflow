export type DecisionScope = "ip" | "range" | "username" | "session" | "country" | "as" | "unknown";
export type DecisionType = "ban" | "captcha" | "throttle" | "enforce_mfa" | "unknown";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Coordinates = readonly [number, number];

export interface CrowdSecAlert {
  id: string;
  scenario: string;
  sourceIp?: string | undefined;
  sourceCountry?: string | undefined;
  sourceAsName?: string | undefined;
  events: number;
  severity: Severity;
  createdAt?: string | undefined;
  message: string;
}

export interface CrowdSecDecision {
  id: string;
  origin: string;
  scenario: string;
  scope: DecisionScope;
  value: string;
  type: DecisionType;
  duration?: string | undefined;
  expiresAt?: string | undefined;
  country?: string | undefined;
  asName?: string | undefined;
}

export interface CrowdSecMachine {
  name: string;
  ipAddress?: string | undefined;
  validated: boolean;
  lastHeartbeat?: string | undefined;
  version?: string | undefined;
  status: "online" | "stale" | "unknown";
}

export interface CrowdSecBouncer {
  name: string;
  ipAddress?: string | undefined;
  type?: string | undefined;
  lastPull?: string | undefined;
  revoked: boolean;
  status: "active" | "stale" | "revoked" | "unknown";
}

export interface CrowdSecMetrics {
  activeDecisions: number;
  alerts24h: number;
  blockedIps24h: number;
  machinesOnline: number;
  bouncersActive: number;
  lapiLatencyMs?: number | undefined;
}

export interface AttackArc {
  id: string;
  sourceIp: string;
  origin: string;
  destination: string;
  from: Coordinates;
  to: Coordinates;
  severity: Severity;
  scenario: string;
  timestamp: string;
}


export interface AttackEvent {
  id: string;
  alertId: string;
  scenario: string;
  severity: Severity;
  sourceIp?: string | undefined;
  sourceCountry?: string | undefined;
  sourceAsName?: string | undefined;
  method?: string | undefined;
  host?: string | undefined;
  service?: string | undefined;
  path?: string | undefined;
  status?: number | undefined;
  userAgent?: string | undefined;
  requestId?: string | undefined;
  timestamp: string;
  raw?: string | undefined;
}

export interface AttackCampaign {
  id: string;
  scenario: string;
  severity: Severity;
  sourceIp?: string | undefined;
  host?: string | undefined;
  events: number;
  methods: string[];
  paths: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface AttackEventSnapshot {
  events: AttackEvent[];
  campaigns: AttackCampaign[];
}

export interface CreateDecisionInput {
  scope: DecisionScope;
  value: string;
  type: Exclude<DecisionType, "unknown">;
  duration: string;
  reason: string;
  mode: "manual" | "automatic";
  evidenceCount?: number | undefined;
}


export type NotificationChannelType = "slack" | "discord" | "webhook";

export interface NotificationChannel {
  id: string;
  name: string;
  type: NotificationChannelType;
  enabled: boolean;
  urlMasked: string;
  minSeverity: Severity;
  createdAt: string;
  updatedAt: string;
  lastTestAt?: string | undefined;
  lastError?: string | undefined;
}

export interface CreateNotificationChannelInput {
  name: string;
  type: NotificationChannelType;
  url: string;
  enabled: boolean;
  minSeverity: Severity;
}
export interface NotificationWorkerStatus {
  online: boolean;
  lastSeenAt?: string | undefined;
  staleAfterSeconds: number;
  intervalMs?: number | undefined;
  workerId?: string | undefined;
}


export interface NotificationTestResult {
  id: string;
  ok: boolean;
  status?: number | undefined;
  error?: string | undefined;
}

export interface LocalAllowlistEntry {
  id: string;
  value: string;
  reason: string;
  createdAt: string;
}

export interface CreateLocalAllowlistEntryInput {
  value: string;
  reason: string;
}


export type EdgeRateLimitTarget = "ip" | "path" | "service";

export interface EdgeRateLimitRule {
  id: string;
  name: string;
  target: EdgeRateLimitTarget;
  value: string;
  windowSeconds: number;
  maxRequests: number;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateEdgeRateLimitRuleInput {
  name: string;
  target: EdgeRateLimitTarget;
  value: string;
  windowSeconds: number;
  maxRequests: number;
  enabled: boolean;
}

export interface EdgeRateLimitDecision {
  allowed: boolean;
  rule?: EdgeRateLimitRule | undefined;
  key?: string | undefined;
  count?: number | undefined;
  remaining?: number | undefined;
  resetAt?: string | undefined;
}


export interface EdgeGateSettings {
  enabled: boolean;
  botChallengeEnabled: boolean;
  authEnabled: boolean;
  passwordConfigured: boolean;
  maxAgeSeconds: number;
}

export interface UpdateEdgeGateSettingsInput {
  enabled: boolean;
  botChallengeEnabled: boolean;
  authEnabled: boolean;
  password?: string | undefined;
  maxAgeSeconds: number;
}

export interface ProtectionControl {
  id: string;
  name: string;
  status: "enabled" | "attention" | "unknown";
  category: "waf" | "rate-limit" | "access-control" | "notifications" | "observability";
  detail: string;
  evidence?: string | undefined;
  recommendation?: string | undefined;
}

export interface ProtectionPosture {
  score: number;
  controls: ProtectionControl[];
  generatedAt: string;
}

export interface ApiEnvelope<T> {
  data: T;
  source: "crowdsec" | "partial";
  error?: string | undefined;
}
