import { createDecision, getDecisions } from "@/lib/crowdsec/client";
import { createDecisionSchema } from "@/lib/crowdsec/validators";

export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  return Response.json(await getDecisions());
}

export async function POST(request: Request): Promise<Response> {
  const parsed = createDecisionSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    return Response.json({ error: "Invalid decision payload", issues: parsed.error.flatten() }, { status: 400 });
  }
  try {
    const decision = await createDecision(parsed.data);
    return Response.json({ data: decision, source: "crowdsec" }, { status: 201 });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : "Unable to create decision" }, { status: 502 });
  }
}
