import { listMachines } from "@/lib/crowdsec/cscli";

export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  return Response.json({ data: await listMachines(), source: "crowdsec" });
}
