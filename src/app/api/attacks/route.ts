import { getAttackArcs } from "@/lib/crowdsec/client";

export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  return Response.json(await getAttackArcs());
}
