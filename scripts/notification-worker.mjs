const dashboardUrl = process.env.CROWDSEC_PANEL_INTERNAL_URL || "http://bastionflow:3000";
const token = process.env.CROWDSEC_INTERNAL_TOKEN;
const intervalMs = Number(process.env.NOTIFICATION_WORKER_INTERVAL_MS || 5000);
const minSeverity = process.env.NOTIFICATION_WORKER_MIN_SEVERITY || "info";
const ranks = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };
const workerId = process.env.NOTIFICATION_WORKER_ID || "bastionflow-notification-worker";
const seen = new Set();

if (!token) {
  console.error("CROWDSEC_INTERNAL_TOKEN is required for notification worker");
  process.exit(1);
}

function shouldSend(event) {
  return (ranks[event.severity] || 0) >= (ranks[minSeverity] || 1);
}

async function heartbeat() {
  const response = await fetch(`${dashboardUrl}/api/notifications/worker`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-internal-token": token },
    body: JSON.stringify({ workerId, intervalMs })
  });
  if (!response.ok) throw new Error(`worker heartbeat returned ${response.status}: ${(await response.text()).slice(0, 200)}`);
}

async function pollOnce() {
  await heartbeat();
  const response = await fetch(`${dashboardUrl}/api/attack-events?limit=120`, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`attack-events returned ${response.status}`);
  const envelope = await response.json();
  const events = Array.isArray(envelope?.data?.events) ? envelope.data.events.filter(shouldSend) : [];
  const next = events.filter((event) => !seen.has(event.id));
  if (next.length === 0) return;
  for (const event of next) seen.add(event.id);
  const dispatch = await fetch(`${dashboardUrl}/api/notifications/dispatch`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-internal-token": token },
    body: JSON.stringify({ events: next })
  });
  if (!dispatch.ok) throw new Error(`notification dispatch returned ${dispatch.status}: ${(await dispatch.text()).slice(0, 200)}`);
  const body = await dispatch.json();
  console.log(JSON.stringify({ at: new Date().toISOString(), processed: body?.data?.processed ?? next.length, source: envelope.source }));
}

console.log(JSON.stringify({ at: new Date().toISOString(), worker: "bastionflow-notifications", workerId, dashboardUrl, intervalMs, minSeverity }));
setInterval(() => {
  pollOnce().catch((error) => console.error(JSON.stringify({ at: new Date().toISOString(), error: error instanceof Error ? error.message : String(error) })));
}, intervalMs);

pollOnce().catch((error) => console.error(JSON.stringify({ at: new Date().toISOString(), error: error instanceof Error ? error.message : String(error) })));
