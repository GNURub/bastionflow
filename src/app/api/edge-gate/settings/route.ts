import { z } from "zod";
import { getEdgeGateSettings, updateEdgeGateSettings } from "@/lib/security/edge-gate-settings";
import type { EdgeGateSettings, UpdateEdgeGateSettingsInput } from "@/lib/crowdsec/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const SettingsSchema = z.object({
  enabled: z.boolean(),
  botChallengeEnabled: z.boolean(),
  authEnabled: z.boolean(),
  password: z.string().max(256).optional(),
  maxAgeSeconds: z.coerce.number().int().min(300).max(2_592_000)
});

function toPublicSettings(settings: EdgeGateSettings): EdgeGateSettings {
  return {
    enabled: settings.enabled,
    botChallengeEnabled: settings.botChallengeEnabled,
    authEnabled: settings.authEnabled,
    passwordConfigured: settings.passwordConfigured,
    maxAgeSeconds: settings.maxAgeSeconds
  };
}

export async function GET(): Promise<Response> {
  return Response.json({ data: toPublicSettings(getEdgeGateSettings()), source: "crowdsec" });
}

export async function PUT(request: Request): Promise<Response> {
  const body = await request.json().catch(() => null) as unknown;
  const parsed = SettingsSchema.safeParse(body);
  if (!parsed.success) {
    return Response.json({ error: parsed.error.issues.map((issue) => issue.message).join("; ") }, { status: 400 });
  }

  const current = getEdgeGateSettings();
  const password = parsed.data.password?.trim();
  if (parsed.data.authEnabled && !current.passwordConfigured && !password) {
    return Response.json({ error: "Password challenge requires a password before it can be enabled" }, { status: 400 });
  }

  const input: UpdateEdgeGateSettingsInput = {
    enabled: parsed.data.enabled,
    botChallengeEnabled: parsed.data.botChallengeEnabled,
    authEnabled: parsed.data.authEnabled,
    password: password || undefined,
    maxAgeSeconds: parsed.data.maxAgeSeconds
  };
  return Response.json({ data: toPublicSettings(updateEdgeGateSettings(input)), source: "crowdsec" });
}
