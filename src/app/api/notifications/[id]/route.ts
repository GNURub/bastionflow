import { deleteNotificationChannel } from "@/lib/crowdsec/notifications";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function DELETE(_request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  if (!id) return Response.json({ error: "Notification channel id is required" }, { status: 400 });
  const deleted = deleteNotificationChannel(id);
  return deleted ? Response.json({ data: { id, deleted: true }, source: "crowdsec" }) : Response.json({ error: "Notification channel not found" }, { status: 404 });
}
