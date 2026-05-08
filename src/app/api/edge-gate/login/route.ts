import { cookieHeader, createGateToken, getEdgeGateConfig } from "@/lib/security/edge-gate";
import { verifyEdgeGatePassword } from "@/lib/security/edge-gate-settings";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  const config = getEdgeGateConfig();
  if (!config.authEnabled) return Response.json({ data: { ok: true }, source: "crowdsec" });
  if (!config.passwordConfigured) return Response.json({ error: "Auth challenge enabled but no password is configured" }, { status: 503 });
  const body = await request.json().catch(() => null) as { password?: string } | null;
  if (!verifyEdgeGatePassword(String(body?.password ?? ""))) return Response.json({ error: "Invalid password" }, { status: 401 });
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? "unknown";
  const userAgent = request.headers.get("user-agent") ?? "";
  const authToken = createGateToken("auth", host, userAgent);
  const botToken = createGateToken("bot", host, userAgent);
  const headers = new Headers();
  headers.append("set-cookie", cookieHeader("crowdsec_gate_auth", authToken, config.maxAgeSeconds));
  headers.append("set-cookie", cookieHeader("crowdsec_gate_bot", botToken, config.maxAgeSeconds));
  return Response.json({ data: { ok: true }, source: "crowdsec" }, { headers });
}
