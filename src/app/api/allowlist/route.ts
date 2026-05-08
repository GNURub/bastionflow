import { z } from "zod";
import { createLocalAllowlistEntry, listLocalAllowlistEntries } from "@/lib/crowdsec/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const AllowlistSchema = z.object({
  value: z.string().trim().min(1).max(256),
  reason: z.string().trim().min(3).max(180).default("operator allowlist")
});

export async function GET(): Promise<Response> {
  return Response.json({ data: listLocalAllowlistEntries(), source: "crowdsec" });
}

export async function POST(request: Request): Promise<Response> {
  const parsed = AllowlistSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return Response.json({ error: "Invalid allowlist payload", issues: parsed.error.flatten() }, { status: 400 });
  return Response.json({ data: createLocalAllowlistEntry(parsed.data.value, parsed.data.reason), source: "crowdsec" }, { status: 201 });
}
