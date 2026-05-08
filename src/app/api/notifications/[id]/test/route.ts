import { sendNotification, testEvent } from "@/lib/crowdsec/notifications";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(_request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  if (!id) return Response.json({ error: "Notification channel id is required" }, { status: 400 });
  const result = await sendNotification(id, testEvent());
  return Response.json({ data: result, source: "crowdsec" }, { status: result.ok ? 200 : 502 });
}
