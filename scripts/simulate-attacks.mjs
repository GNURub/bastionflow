#!/usr/bin/env node

const DEFAULT_TARGET = "http://whoami.localhost:8080";
const DEFAULT_DASHBOARD = "http://bastionflow.localhost:8080";

const safeHostnames = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1"]);
const sourceProfiles = {
  documentation: ["203.0.113.10", "203.0.113.11", "203.0.113.12", "198.51.100.23", "198.51.100.24", "192.0.2.44", "192.0.2.45"],
  // Lab-only spoofed X-Forwarded-For sources. No traffic is sent to these IPs; they only make GeoIP/map demos visible.
  "global-demo": ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "80.80.80.80", "185.228.168.9", "64.6.64.6"]
};
const userAgents = [
  "sqlmap/1.8.10#stable (https://sqlmap.org)",
  "Nikto/2.5.0",
  "masscan/1.3",
  "zgrab/0.x",
  "python-requests/2.31.0",
  "Go-http-client/1.1",
  "Mozilla/5.0 (compatible; wp-scan; +https://wpscan.com/)",
  "curl/8.6.0"
];

const attacks = [
  { method: "GET", path: "/.env", label: "secret-file" },
  { method: "GET", path: "/.git/config", label: "git-leak" },
  { method: "GET", path: "/wp-login.php", label: "wordpress-login" },
  { method: "POST", path: "/wp-login.php", body: "log=admin&pwd=admin123&wp-submit=Log+In", contentType: "application/x-www-form-urlencoded", label: "wordpress-bruteforce" },
  { method: "GET", path: "/xmlrpc.php", label: "xmlrpc-probe" },
  { method: "POST", path: "/xmlrpc.php", body: "<methodCall><methodName>system.listMethods</methodName></methodCall>", contentType: "text/xml", label: "xmlrpc-post" },
  { method: "GET", path: "/admin", label: "admin-probe" },
  { method: "GET", path: "/admin/login", label: "admin-login-probe" },
  { method: "POST", path: "/admin/login", body: "username=admin&password=password", contentType: "application/x-www-form-urlencoded", label: "admin-bruteforce" },
  { method: "GET", path: "/phpmyadmin/index.php", label: "phpmyadmin-probe" },
  { method: "GET", path: "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", label: "phpunit-cve" },
  { method: "GET", path: "/actuator/env", label: "spring-actuator" },
  { method: "GET", path: "/server-status", label: "apache-status" },
  { method: "GET", path: "/cgi-bin/luci/;stok=/locale?form=country", label: "router-luci" },
  { method: "GET", path: "/?id=1%27%20OR%20%271%27=%271", label: "sqli-query" },
  { method: "GET", path: "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", label: "xss-query" },
  { method: "POST", path: "/api/login", body: JSON.stringify({ username: "admin' OR '1'='1", password: "password" }), contentType: "application/json", label: "api-sqli-login" },
  { method: "POST", path: "/graphql", body: JSON.stringify({ query: "{__schema{types{name}}}" }), contentType: "application/json", label: "graphql-introspection" }
];

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) continue;
    const raw = token.slice(2);
    if (raw.includes("=")) {
      const [key, ...rest] = raw.split("=");
      args[key] = rest.join("=");
      continue;
    }
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) args[raw] = "true";
    else { args[raw] = next; i += 1; }
  }
  return args;
}

function numberArg(args, key, fallback, min, max) {
  const value = Number(args[key] ?? fallback);
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, value));
}

function boolArg(args, key, fallback = false) {
  const value = args[key];
  if (value === undefined) return fallback;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function isSafeLocalUrl(rawUrl) {
  const url = new URL(rawUrl);
  return safeHostnames.has(url.hostname) || url.hostname.endsWith(".localhost");
}

function pick(items) {
  return items[Math.floor(Math.random() * items.length)];
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildUrl(base, attack, cacheBust) {
  const url = new URL(attack.path, base);
  url.searchParams.set("sim", String(cacheBust));
  return url;
}

async function installRateLimitRule(config) {
  const payload = {
    name: `simulation ${config.rateLimitTarget}:${config.rateLimitValue} ${new Date().toISOString()}`,
    target: config.rateLimitTarget,
    value: config.rateLimitValue,
    windowSeconds: config.rateLimitWindow,
    maxRequests: config.rateLimitMax,
    enabled: true
  };
  const response = await fetch(new URL("/api/edge-rate-limits", config.dashboardUrl), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(payload),
    redirect: "manual",
    signal: AbortSignal.timeout(5000)
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`Unable to install rate-limit rule: ${response.status} ${JSON.stringify(body).slice(0, 300)}`);
  console.log(JSON.stringify({ at: new Date().toISOString(), installedRateLimitRule: body.data }, null, 2));
}

async function requestOnce(config, index, stats) {
  const sourceIp = pick(config.sources);
  const attack = config.forcePath
    ? { method: config.forceMethod, path: config.forcePath, label: "forced-path" }
    : pick(attacks);
  const url = buildUrl(config.targetUrl, attack, `${Date.now()}-${index}`);
  const started = Date.now();
  try {
    const response = await fetch(url, {
      method: attack.method,
      body: attack.body,
      redirect: "manual",
      headers: {
        accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
        "content-type": attack.contentType ?? "text/plain",
        "user-agent": pick(userAgents),
        "x-forwarded-for": sourceIp,
        "x-real-ip": sourceIp,
        "cf-connecting-ip": sourceIp,
        "x-simulation-attack": attack.label,
        "x-simulation-source": "bastionflow/scripts/simulate-attacks"
      },
      signal: AbortSignal.timeout(config.timeoutMs)
    });
    const status = String(response.status);
    stats.sent += 1;
    stats.statuses.set(status, (stats.statuses.get(status) ?? 0) + 1);
    stats.labels.set(attack.label, (stats.labels.get(attack.label) ?? 0) + 1);
    if (response.status === 429) stats.rateLimited += 1;
    if (response.status >= 500) stats.errors += 1;
  } catch (error) {
    stats.sent += 1;
    stats.errors += 1;
    const key = error instanceof Error ? error.name : "request-error";
    stats.statuses.set(key, (stats.statuses.get(key) ?? 0) + 1);
  } finally {
    stats.latencies.push(Date.now() - started);
    if (stats.latencies.length > 1000) stats.latencies.shift();
  }
}

async function worker(config, workerId, stats) {
  let index = workerId;
  const delay = Math.max(1, Math.round((1000 * config.concurrency) / config.rps));
  while (Date.now() < config.deadline) {
    await requestOnce(config, index, stats);
    index += config.concurrency;
    const jitter = Math.round(delay * (0.75 + Math.random() * 0.5));
    await sleep(jitter);
  }
}

function percentile(values, p) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[index];
}

async function pollDashboard(config) {
  if (!config.pollDashboard) return null;
  try {
    const response = await fetch(new URL("/api/attack-events?limit=20", config.dashboardUrl), {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(3000)
    });
    if (!response.ok) return { dashboard: `HTTP ${response.status}` };
    const body = await response.json();
    return {
      attackEvents: body?.data?.events?.length ?? 0,
      campaigns: body?.data?.campaigns?.length ?? 0,
      source: body?.source
    };
  } catch (error) {
    return { dashboard: error instanceof Error ? error.message : String(error) };
  }
}

function printUsage() {
  console.log(`Usage:
  npm run simulate:attacks -- [options]

Options:
  --target <url>                 Target URL. Default: ${DEFAULT_TARGET}
  --dashboard <url>              Dashboard URL for optional polling/rule install. Default: ${DEFAULT_DASHBOARD}
  --duration <seconds>           Simulation duration. Default: 90
  --rps <number>                 Approx requests per second. Default: 12
  --concurrency <number>         Concurrent workers. Default: 6
  --source-profile <name>         documentation | global-demo. Default: documentation
  --sources <ip,ip,cidr>         Override spoofed X-Forwarded-For source IPs
  --install-rate-limit           Create a real Edge Gate rate-limit rule before the run
  --rate-limit-target <type>     ip | path | service. Default: path
  --rate-limit-value <value>     Example: /admin, whoami.localhost, 203.0.113.10. Default: /admin
  --rate-limit-window <seconds>  Default: 10
  --rate-limit-max <requests>    Default: 5
  --force-path <path>            Only hit one path, useful with --install-rate-limit. Example: /admin
  --force-method <method>        Default: GET
  --no-dashboard-poll            Do not poll /api/attack-events during the run
  --allow-non-localhost          Required if target/dashboard are not localhost
  --help                         Show this help

Examples:
  npm run simulate:attacks -- --duration=120 --rps=20
  npm run simulate:attacks -- --source-profile=global-demo --duration=120 --rps=20
  npm run simulate:attacks -- --install-rate-limit --force-path=/admin --rps=30 --duration=45
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (boolArg(args, "help")) { printUsage(); return; }

  const config = {
    targetUrl: args.target ?? DEFAULT_TARGET,
    dashboardUrl: args.dashboard ?? DEFAULT_DASHBOARD,
    duration: numberArg(args, "duration", 90, 1, 3600),
    rps: numberArg(args, "rps", 12, 1, 1000),
    concurrency: numberArg(args, "concurrency", 6, 1, 500),
    timeoutMs: numberArg(args, "timeout-ms", 4000, 250, 30000),
    sourceProfile: args["source-profile"] ?? "documentation",
    sources: [],
    installRateLimit: boolArg(args, "install-rate-limit"),
    rateLimitTarget: args["rate-limit-target"] ?? "path",
    rateLimitValue: args["rate-limit-value"] ?? "/admin",
    rateLimitWindow: numberArg(args, "rate-limit-window", 10, 1, 86400),
    rateLimitMax: numberArg(args, "rate-limit-max", 5, 1, 1000000),
    forcePath: args["force-path"],
    forceMethod: String(args["force-method"] ?? "GET").toUpperCase(),
    pollDashboard: !boolArg(args, "no-dashboard-poll"),
    deadline: 0
  };

  config.sources = String(args.sources ?? (sourceProfiles[config.sourceProfile]?.join(",") ?? sourceProfiles.documentation.join(","))).split(",").map((item) => item.trim()).filter(Boolean);

  const allowNonLocalhost = boolArg(args, "allow-non-localhost");
  if (!allowNonLocalhost && (!isSafeLocalUrl(config.targetUrl) || !isSafeLocalUrl(config.dashboardUrl))) {
    throw new Error("Refusing to run against non-localhost URLs. Use --allow-non-localhost only for an explicit lab target you own.");
  }
  if (!["ip", "path", "service"].includes(config.rateLimitTarget)) throw new Error("--rate-limit-target must be ip, path, or service");
  if (config.sources.length === 0) throw new Error("At least one source IP is required");

  if (config.installRateLimit) await installRateLimitRule(config);

  config.deadline = Date.now() + config.duration * 1000;
  const stats = { sent: 0, errors: 0, rateLimited: 0, statuses: new Map(), labels: new Map(), latencies: [] };
  console.log(JSON.stringify({
    at: new Date().toISOString(),
    simulator: "bastionflow-attack-simulator",
    target: config.targetUrl,
    dashboard: config.dashboardUrl,
    duration: config.duration,
    rps: config.rps,
    concurrency: config.concurrency,
    sourceProfile: config.sourceProfile,
    sources: config.sources,
    note: config.sourceProfile === "global-demo"
      ? "Traffic is real HTTP to Traefik; source IPs are spoofed X-Forwarded-For values for lab GeoIP/map visualization only."
      : "Traffic is real HTTP to Traefik. CrowdSec alerts may appear after parser/scenario delay. Defaults use RFC 5737 documentation IPs."
  }, null, 2));

  const reporter = setInterval(async () => {
    const dashboard = await pollDashboard(config);
    console.log(JSON.stringify({
      at: new Date().toISOString(),
      sent: stats.sent,
      errors: stats.errors,
      rateLimited: stats.rateLimited,
      p95Ms: percentile(stats.latencies, 95),
      statuses: Object.fromEntries(stats.statuses),
      dashboard
    }));
  }, 5000);

  await Promise.all(Array.from({ length: config.concurrency }, (_, index) => worker(config, index, stats)));
  clearInterval(reporter);
  const dashboard = await pollDashboard(config);
  console.log(JSON.stringify({
    at: new Date().toISOString(),
    done: true,
    sent: stats.sent,
    errors: stats.errors,
    rateLimited: stats.rateLimited,
    p95Ms: percentile(stats.latencies, 95),
    statuses: Object.fromEntries(stats.statuses),
    topAttackLabels: Object.fromEntries([...stats.labels.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)),
    dashboard
  }, null, 2));
}

main().catch((error) => {
  console.error(JSON.stringify({ at: new Date().toISOString(), error: error instanceof Error ? error.message : String(error) }, null, 2));
  process.exit(1);
});
