"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Bot, Gauge, LockKeyhole, RadioTower, ShieldCheck, ShieldOff, Siren, Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EdgeGateSettingsDialog } from "@/components/dashboard/edge-gate-settings-dialog";
import type { ApiEnvelope, ProtectionControl, ProtectionPosture } from "@/lib/crowdsec/types";
import { relativeTime } from "@/lib/utils";

const categoryIcon: Record<ProtectionControl["category"], typeof ShieldCheck> = {
  waf: ShieldCheck,
  "rate-limit": Gauge,
  "access-control": LockKeyhole,
  notifications: Siren,
  observability: RadioTower
};

async function loadPosture(): Promise<ProtectionPosture> {
  const response = await fetch("/api/protection-posture", { cache: "no-store" });
  if (!response.ok) throw new Error(`protection-posture returned ${response.status}`);
  return ((await response.json()) as ApiEnvelope<ProtectionPosture>).data;
}

export function ProtectionPosturePanel(): React.ReactElement {
  const [posture, setPosture] = useState<ProtectionPosture | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refreshInFlight = useRef(false);

  const refresh = useCallback((): void => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    void loadPosture()
      .then((data) => { setPosture(data); setError(null); })
      .catch((err: unknown) => { setError(err instanceof Error ? err.message : "Unable to load protection posture"); })
      .finally(() => { refreshInFlight.current = false; });
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 15_000);
    return () => { clearInterval(timer); };
  }, [refresh]);

  const grouped = useMemo(() => {
    const controls = posture?.controls ?? [];
    return {
      enabled: controls.filter((control) => control.status === "enabled"),
      attention: controls.filter((control) => control.status === "attention"),
      unknown: controls.filter((control) => control.status === "unknown")
    };
  }, [posture]);

  return (
    <Card className="border-white/10 bg-white/[0.03]">
      <CardHeader className="gap-3 md:flex-row md:items-start md:justify-between">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2"><Zap className="h-4 w-4 text-amber-300" /> Protection posture</CardTitle>
        </div>
        <EdgeGateSettingsDialog onSaved={refresh} />
      </CardHeader>
      <CardContent className="grid gap-4 xl:grid-cols-[260px_1fr]">
        <div className="rounded-xl border border-white/10 bg-black/20 p-4">
          <div className="text-xs uppercase tracking-wide text-muted-foreground">Coverage score</div>
          <div className="mt-3 flex items-end gap-2"><span className="text-5xl font-semibold tracking-tight">{posture?.score ?? 0}</span><span className="pb-2 text-muted-foreground">/100</span></div>
          <div className="mt-4 h-2 overflow-hidden rounded-full bg-white/10"><div className="h-full rounded-full bg-emerald-400" style={{ width: `${posture?.score ?? 0}%` }} /></div>
          <div className="mt-3 text-xs text-muted-foreground">{posture ? `Updated ${relativeTime(posture.generatedAt)}` : error ?? "Loading posture..."}</div>
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {[...grouped.attention, ...grouped.enabled, ...grouped.unknown].map((control) => <ControlCard key={control.id} control={control} />)}
        </div>
      </CardContent>
    </Card>
  );
}

function ControlCard({ control }: { control: ProtectionControl }): React.ReactElement {
  const Icon = categoryIcon[control.category] ?? Bot;
  const badge = control.status === "enabled" ? "success" : control.status === "attention" ? "warning" : "secondary";
  return (
    <div className="rounded-lg border border-white/10 bg-black/20 p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2"><Icon className="h-4 w-4 text-muted-foreground" /><span className="truncate text-sm font-medium">{control.name}</span></div>
        <Badge variant={badge}>{control.status}</Badge>
      </div>
      <p className="mt-2 text-xs text-muted-foreground">{control.detail}</p>
      {control.evidence && <p className="mt-2 truncate font-mono text-[11px] text-muted-foreground">{control.evidence}</p>}
      {control.recommendation && <p className="mt-2 text-xs text-amber-200"><ShieldOff className="mr-1 inline h-3 w-3" />{control.recommendation}</p>}
    </div>
  );
}
