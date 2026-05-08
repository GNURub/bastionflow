import { z } from "zod";
import { addEdgeRateLimitRule, getEdgeRateLimitRules } from "@/lib/security/edge-rate-limits";
import type { CreateEdgeRateLimitRuleInput } from "@/lib/crowdsec/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ipv4Pattern = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const cidrPattern = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/;

const RuleSchema = z.object({
  name: z.string().trim().min(3).max(80),
  target: z.enum(["ip", "path", "service"]),
  value: z.string().trim().min(1).max(260),
  windowSeconds: z.coerce.number().int().min(1).max(86_400),
  maxRequests: z.coerce.number().int().min(1).max(1_000_000),
  enabled: z.boolean().default(true)
}).superRefine((value, ctx) => {
  if (value.target === "ip" && value.value !== "*" && !ipv4Pattern.test(value.value) && !cidrPattern.test(value.value)) {
    ctx.addIssue({ code: "custom", path: ["value"], message: "IP target expects IPv4, CIDR, or *" });
  }
  if (value.target === "path" && !value.value.startsWith("/")) {
    ctx.addIssue({ code: "custom", path: ["value"], message: "Path target must start with /" });
  }
  if (value.target === "service" && /\s/.test(value.value)) {
    ctx.addIssue({ code: "custom", path: ["value"], message: "Service target expects a host like whoami.localhost or *.example.com" });
  }
});

export async function GET(): Promise<Response> {
  return Response.json({ data: getEdgeRateLimitRules(), source: "crowdsec" });
}

export async function POST(request: Request): Promise<Response> {
  const body = await request.json().catch(() => null) as unknown;
  const parsed = RuleSchema.safeParse(body);
  if (!parsed.success) {
    return Response.json({ error: "Invalid rate limit rule", issues: parsed.error.flatten() }, { status: 400 });
  }
  const input: CreateEdgeRateLimitRuleInput = parsed.data;
  return Response.json({ data: addEdgeRateLimitRule(input), source: "crowdsec" }, { status: 201 });
}
