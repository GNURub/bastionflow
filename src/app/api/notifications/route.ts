import { createNotificationChannel, listNotificationChannels, seedNotificationChannelsFromEnv, validateNotificationInput } from "@/lib/crowdsec/notifications";
import type { CreateNotificationChannelInput } from "@/lib/crowdsec/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  seedNotificationChannelsFromEnv();
  return Response.json({ data: listNotificationChannels(), source: "crowdsec" });
}

export async function POST(request: Request): Promise<Response> {
  const body = await request.json().catch(() => null) as Partial<CreateNotificationChannelInput> | null;
  if (!body) return Response.json({ error: "Invalid JSON payload" }, { status: 400 });
  const input: CreateNotificationChannelInput = {
    name: String(body.name ?? "").trim(),
    type: body.type ?? "webhook",
    url: String(body.url ?? "").trim(),
    enabled: body.enabled ?? true,
    minSeverity: body.minSeverity ?? "high"
  };
  try {
    validateNotificationInput(input);
    return Response.json({ data: createNotificationChannel(input), source: "crowdsec" }, { status: 201 });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : "Unable to create notification channel" }, { status: 400 });
  }
}
