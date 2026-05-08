import { getMetrics } from "@/lib/crowdsec/metrics";

export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  return Response.json({ data: await getMetrics(), source: "crowdsec" });
}
