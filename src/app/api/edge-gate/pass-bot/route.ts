import { cookieHeader, createGateToken, getEdgeGateConfig } from "@/lib/security/edge-gate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  const config = getEdgeGateConfig();
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? "unknown";
  const userAgent = request.headers.get("user-agent") ?? "";
  const token = createGateToken("bot", host, userAgent);
  return Response.json({ data: { ok: true }, source: "crowdsec" }, { headers: { "set-cookie": cookieHeader("crowdsec_gate_bot", token, config.maxAgeSeconds) } });
}
