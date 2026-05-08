import { dispatchAttackEvent } from "@/lib/crowdsec/notifications";
import type { AttackEvent } from "@/lib/crowdsec/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function authorized(request: Request): boolean {
  const expected = process.env.CROWDSEC_INTERNAL_TOKEN?.trim();
  if (!expected) return false;
  return request.headers.get("x-internal-token") === expected;
}

function isAttackEvent(value: unknown): value is AttackEvent {
  return Boolean(value && typeof value === "object" && typeof (value as { id?: unknown }).id === "string" && typeof (value as { scenario?: unknown }).scenario === "string");
}

export async function POST(request: Request): Promise<Response> {
  if (!authorized(request)) return Response.json({ error: "Unauthorized" }, { status: 401 });
  const body = await request.json().catch(() => null) as { events?: unknown[] } | null;
  const events = Array.isArray(body?.events) ? body.events.filter(isAttackEvent).slice(0, 200) : [];
  const results = [];
  for (const event of events) results.push(await dispatchAttackEvent(event));
  return Response.json({ data: { processed: results.length, results }, source: "crowdsec" });
}
