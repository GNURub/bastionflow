import { removeEdgeRateLimitRule } from "@/lib/security/edge-rate-limits";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function DELETE(_request: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await params;
  const deleted = removeEdgeRateLimitRule(id);
  if (!deleted) return Response.json({ error: "Rate limit rule not found" }, { status: 404 });
  return Response.json({ data: { id }, source: "crowdsec" });
}
