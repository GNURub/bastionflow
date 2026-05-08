import { getAlerts, getDecisions } from "@/lib/crowdsec/client";
import { getCachedIpIntelOrSchedule } from "@/lib/crowdsec/geo";
import { getIpProfile } from "@/lib/crowdsec/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function isSafeIpLookup(value: string): boolean {
  return /^[a-zA-Z0-9:.%-]{1,128}$/.test(value);
}

export async function GET(_request: Request, context: { params: Promise<{ value: string }> }): Promise<Response> {
  const { value } = await context.params;
  const ip = decodeURIComponent(value ?? "").trim();
  if (!ip || !isSafeIpLookup(ip)) return Response.json({ error: "Invalid IP value" }, { status: 400 });

  getCachedIpIntelOrSchedule(ip);
  void getAlerts();
  void getDecisions();

  return Response.json({ data: getIpProfile(ip), source: "crowdsec" });
}
