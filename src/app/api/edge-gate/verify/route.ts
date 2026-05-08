import { evaluateGate, originalUrl } from "@/lib/security/edge-gate";
import { evaluateEdgeRateLimits } from "@/lib/security/edge-rate-limits";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const rateLimit = evaluateEdgeRateLimits(request);
  if (!rateLimit.allowed) {
    return Response.json({
      error: "Rate limit exceeded",
      rule: rateLimit.rule ? { id: rateLimit.rule.id, name: rateLimit.rule.name, target: rateLimit.rule.target, value: rateLimit.rule.value } : undefined,
      count: rateLimit.count,
      resetAt: rateLimit.resetAt
    }, {
      status: 429,
      headers: {
        "retry-after": rateLimit.resetAt ? String(Math.max(1, Math.ceil((new Date(rateLimit.resetAt).getTime() - Date.now()) / 1000))) : "60",
        "x-crowdsec-edge-rule": rateLimit.rule?.name ?? "edge-rate-limit"
      }
    });
  }

  const state = evaluateGate(request);
  if (state.passed) return new Response(null, { status: 204 });
  const url = new URL("/edge-gate/challenge", originalUrl(request));
  url.searchParams.set("next", originalUrl(request));
  url.searchParams.set("required", state.required.join(","));
  return Response.redirect(url, 302);
}
