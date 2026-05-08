import { deleteDecision } from "@/lib/crowdsec/client";

export const runtime = "nodejs";

export async function DELETE(_request: Request, context: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await context.params;
  if (!id) return Response.json({ error: "Decision id is required" }, { status: 400 });
  try {
    await deleteDecision(id);
    return Response.json({ data: { id, deleted: true }, source: "crowdsec" });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : "Unable to delete decision" }, { status: 502 });
  }
}
