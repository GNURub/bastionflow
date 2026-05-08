import { deleteLocalAllowlistEntry } from "@/lib/crowdsec/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function DELETE(_request: Request, { params }: { params: Promise<{ value: string }> }): Promise<Response> {
  const { value } = await params;
  const deleted = deleteLocalAllowlistEntry(decodeURIComponent(value));
  if (!deleted) return Response.json({ error: "Allowlist entry not found" }, { status: 404 });
  return Response.json({ data: { value, deleted: true }, source: "crowdsec" });
}
