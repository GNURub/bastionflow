import { listBouncers } from "@/lib/crowdsec/cscli";

export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  return Response.json({ data: await listBouncers(), source: "crowdsec" });
}
