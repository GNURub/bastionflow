import { getNotificationWorkerStatus, updateNotificationWorkerHeartbeat } from "@/lib/crowdsec/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function authorized(request: Request): boolean {
  const expected = process.env.CROWDSEC_INTERNAL_TOKEN?.trim();
  if (!expected) return false;
  return request.headers.get("x-internal-token") === expected;
}

export async function GET(): Promise<Response> {
  return Response.json({ data: getNotificationWorkerStatus(), source: "crowdsec" });
}

export async function POST(request: Request): Promise<Response> {
  if (!authorized(request)) return Response.json({ error: "Unauthorized" }, { status: 401 });
  const body = await request.json().catch(() => null) as { workerId?: unknown; intervalMs?: unknown } | null;
  const workerId = typeof body?.workerId === "string" && body.workerId.trim() ? body.workerId.trim() : "notification-worker";
  const intervalMs = typeof body?.intervalMs === "number" && Number.isFinite(body.intervalMs) ? Math.max(1000, Math.round(body.intervalMs)) : 5000;
  return Response.json({ data: updateNotificationWorkerHeartbeat(workerId, intervalMs), source: "crowdsec" });
}
