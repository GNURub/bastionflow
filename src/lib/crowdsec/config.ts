export interface CrowdSecConfig {
  lapiUrl: string;
  machineId?: string | undefined;
  machinePassword?: string | undefined;
  bouncerApiKey?: string | undefined;
  prometheusUrl: string;
  targetName: string;
  targetLng?: number | undefined;
  targetLat?: number | undefined;
  cscliBin: string;
  cscliUseSudo: boolean;
  allowlist: string[];
  autoBlockMaxDuration: string;
  autoBlockMinAlerts: number;
  autoBlockRateLimitPerHour: number;
  lapiTimeoutMs: number;
  prometheusTimeoutMs: number;
  cscliTimeoutMs: number;
}

function optionalEnv(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

function numberEnv(name: string, fallback: number): number {
  const value = Number(process.env[name]);
  return Number.isFinite(value) ? value : fallback;
}

function optionalNumberEnv(name: string): number | undefined {
  const value = Number(process.env[name]);
  return Number.isFinite(value) ? value : undefined;
}

export function getCrowdSecConfig(): CrowdSecConfig {
  return {
    lapiUrl: optionalEnv("CROWDSEC_LAPI_URL") ?? "http://localhost:8080",
    machineId: optionalEnv("CROWDSEC_MACHINE_ID"),
    machinePassword: optionalEnv("CROWDSEC_MACHINE_PASSWORD"),
    bouncerApiKey: optionalEnv("CROWDSEC_BOUNCER_API_KEY"),
    prometheusUrl: optionalEnv("CROWDSEC_PROMETHEUS_URL") ?? "http://localhost:6060/metrics",
    targetName: optionalEnv("CROWDSEC_TARGET_NAME") ?? "Protected edge",
    targetLng: optionalNumberEnv("CROWDSEC_TARGET_LNG"),
    targetLat: optionalNumberEnv("CROWDSEC_TARGET_LAT"),
    cscliBin: optionalEnv("CSCLI_BIN") ?? "cscli",
    cscliUseSudo: (optionalEnv("CSCLI_USE_SUDO") ?? "false") === "true",
    allowlist: (optionalEnv("CROWDSEC_ALLOWLIST") ?? "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",").map((item) => item.trim()).filter(Boolean),
    autoBlockMaxDuration: optionalEnv("AUTO_BLOCK_MAX_DURATION") ?? "4h",
    autoBlockMinAlerts: numberEnv("AUTO_BLOCK_MIN_ALERTS", 3),
    autoBlockRateLimitPerHour: numberEnv("AUTO_BLOCK_RATE_LIMIT_PER_HOUR", 20),
    lapiTimeoutMs: numberEnv("CROWDSEC_LAPI_TIMEOUT_MS", 2_500),
    prometheusTimeoutMs: numberEnv("CROWDSEC_PROMETHEUS_TIMEOUT_MS", 1_500),
    cscliTimeoutMs: numberEnv("CSCLI_TIMEOUT_MS", 1_500)
  };
}
