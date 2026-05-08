import { getProtectionPosture } from "@/lib/crowdsec/protection-posture";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  return Response.json({ data: await getProtectionPosture(), source: "crowdsec" });
}
