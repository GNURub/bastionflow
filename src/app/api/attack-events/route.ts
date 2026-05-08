import { getAlerts } from "@/lib/crowdsec/client";
import { listAttackEvents, summarizeCampaigns } from "@/lib/crowdsec/events";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const limit = Math.min(250, Math.max(1, Number(new URL(request.url).searchParams.get("limit") ?? 80)));
  const alerts = await getAlerts();
  const events = listAttackEvents(limit);
  return Response.json({ data: { events, campaigns: summarizeCampaigns(events) }, source: alerts.source, error: alerts.error });
}
