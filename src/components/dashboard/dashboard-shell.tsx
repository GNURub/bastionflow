"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Ban, Bot, Crosshair, DatabaseZap, Gavel, Radar, Server, ShieldAlert, type LucideIcon } from "lucide-react";
import { AttackMap } from "./attack-map";
import { AttackEventsPanel } from "./attack-events-panel";
import { DecisionActions } from "./decision-actions";
import { EdgeRateLimitRulesPanel } from "./edge-rate-limit-rules-panel";
import { IntelligenceCards } from "./intelligence-cards";
import { NotificationChannelsPanel } from "./notification-channels-panel";
import { ProtectionPosturePanel } from "./protection-posture-panel";
import { SourcePill } from "./source-pill";
import { StatCard } from "./stat-card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ApiEnvelope, AttackArc, CrowdSecAlert, CrowdSecBouncer, CrowdSecDecision, CrowdSecMachine, CrowdSecMetrics, Severity } from "@/lib/crowdsec/types";
import { formatNumber, relativeTime } from "@/lib/utils";

interface DashboardState {
  alerts: ApiEnvelope<CrowdSecAlert[]>;
  decisions: ApiEnvelope<CrowdSecDecision[]>;
  machines: ApiEnvelope<CrowdSecMachine[]>;
  bouncers: ApiEnvelope<CrowdSecBouncer[]>;
  metrics: ApiEnvelope<CrowdSecMetrics>;
  attacks: ApiEnvelope<AttackArc[]>;
}

const emptyState: DashboardState = {
  alerts: { data: [], source: "partial" },
  decisions: { data: [], source: "partial" },
  machines: { data: [], source: "partial" },
  bouncers: { data: [], source: "partial" },
  metrics: { data: { activeDecisions: 0, alerts24h: 0, blockedIps24h: 0, machinesOnline: 0, bouncersActive: 0 }, source: "partial" },
  attacks: { data: [], source: "partial" }
};

async function getJson<T>(path: string): Promise<ApiEnvelope<T>> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json() as Promise<ApiEnvelope<T>>;
}

function severityVariant(severity: Severity): "destructive" | "warning" | "secondary" | "outline" {
  if (severity === "critical" || severity === "high") return "destructive";
  if (severity === "medium") return "warning";
  if (severity === "low") return "secondary";
  return "outline";
}

export function DashboardShell(): React.ReactElement {
  const [state, setState] = useState<DashboardState>(emptyState);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const refreshInFlight = useRef(false);

  const refresh = useCallback(async ({ silent = false }: { silent?: boolean } = {}) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    if (!silent) setLoading(true);
    try {
      const [alerts, decisions, machines, bouncers, metrics, attacks] = await Promise.all([
        getJson<CrowdSecAlert[]>("/api/alerts"),
        getJson<CrowdSecDecision[]>("/api/decisions"),
        getJson<CrowdSecMachine[]>("/api/machines"),
        getJson<CrowdSecBouncer[]>("/api/bouncers"),
        getJson<CrowdSecMetrics>("/api/metrics"),
        getJson<AttackArc[]>("/api/attacks").catch(async () => ({ data: [], source: "partial" as const }))
      ]);
      setState({ alerts, decisions, machines, bouncers, metrics, attacks });
      setLastRefresh(new Date());
    } finally {
      refreshInFlight.current = false;
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    void refresh();
    const timer = setInterval(() => {
      if (active) void refresh({ silent: true }).catch(() => undefined);
    }, 5_000);
    return () => { active = false; clearInterval(timer); };
  }, [refresh]);

  const topScenarios = useMemo(() => state.alerts.data.slice(0, 4), [state.alerts.data]);

  async function unblock(id: string): Promise<void> {
    const response = await fetch(`/api/decisions/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (response.ok) void refresh();
  }

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-[1500px] flex-col gap-6 px-4 py-6 lg:px-8">
      <header className="flex flex-col gap-4 border-b border-white/10 pb-6 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-xs text-muted-foreground">
            <Radar className="h-3.5 w-3.5 text-red-400" /> CrowdSec private operations console
          </div>
          <h1 className="text-4xl font-semibold tracking-tight md:text-6xl">Security edge control.</h1>
          <p className="mt-3 max-w-3xl text-sm text-muted-foreground md:text-base">Visualize alerts, decisions, machines, bouncers and metrics. Block, unblock and let automatic rules act ONLY within limits. This is not decorative UI: this is security operations.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <SourcePill source={state.alerts.source} error={state.alerts.error} />
          <Button variant="outline" asChild><Link href="/decisions"><Gavel className="h-4 w-4" /> Decisions</Link></Button>
          <Button variant="outline" onClick={() => void refresh()} disabled={loading}>{loading ? "Refreshing..." : "Refresh"}</Button>
        </div>
      </header>

      <ProtectionPosturePanel />

      <EdgeRateLimitRulesPanel />

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <StatCard title="Active decisions" value={state.metrics.data.activeDecisions || state.decisions.data.length} detail="Current remediations" icon={Ban} />
        <StatCard title="Alerts 24h" value={state.metrics.data.alerts24h || state.alerts.data.length} detail="Recent detections" icon={ShieldAlert} />
        <StatCard title="Active blocked IPs" value={new Set(state.decisions.data.filter((decision) => decision.scope === "ip" && decision.type === "ban").map((decision) => decision.value)).size} detail="Unique active IP ban decisions" icon={Crosshair} />
        <StatCard title="Machines online" value={state.metrics.data.machinesOnline || state.machines.data.filter((m) => m.status === "online").length} detail="CrowdSec agents" icon={Server} />
        <StatCard title="Bouncers active" value={state.metrics.data.bouncersActive || state.bouncers.data.filter((b) => b.status === "active").length} detail="Remediation components" icon={Bot} />
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.6fr_.9fr]">
        <AttackMap initial={state.attacks.data} />
        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader>
            <CardTitle>Top live scenarios</CardTitle>
            <CardDescription>Recent alert sources driving decisions.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {topScenarios.map((alert) => (
              <div key={alert.id} className="rounded-lg border border-white/10 bg-black/20 p-3">
                <div className="mb-2 flex items-center justify-between gap-2"><span className="truncate text-sm font-medium">{alert.scenario}</span><Badge variant={severityVariant(alert.severity)}>{alert.severity}</Badge></div>
                <div className="text-xs text-muted-foreground">{alert.sourceIp ? <Link className="font-mono text-foreground underline-offset-4 hover:text-amber-300 hover:underline" href={`/ip/${encodeURIComponent(alert.sourceIp)}`}>{alert.sourceIp}</Link> : "unknown source"} · {formatNumber(alert.events)} events · {relativeTime(alert.createdAt)}</div>
              </div>
            ))}
          </CardContent>
        </Card>
      </section>

      <AttackEventsPanel />

      <IntelligenceCards alerts={state.alerts.data} decisions={state.decisions.data} />

      <div id="decision-actions">
        <DecisionActions onChanged={() => void refresh()} />
      </div>

      <NotificationChannelsPanel />

      <section className="grid gap-6 xl:grid-cols-2">
        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader><CardTitle>Decisions</CardTitle><CardDescription>Active blocks and unblock operations.</CardDescription></CardHeader>
          <CardContent className="overflow-x-auto">
            <Table><TableHeader><TableRow><TableHead>Target</TableHead><TableHead>Type</TableHead><TableHead>Origin</TableHead><TableHead>Duration</TableHead><TableHead /></TableRow></TableHeader><TableBody>
              {state.decisions.data.map((decision) => <TableRow key={decision.id}><TableCell className="font-mono text-xs">{decision.scope}:{decision.scope === "ip" ? <Link className="underline-offset-4 hover:text-amber-300 hover:underline" href={`/ip/${encodeURIComponent(decision.value)}`}>{decision.value}</Link> : decision.value}</TableCell><TableCell><Badge variant="destructive">{decision.type}</Badge></TableCell><TableCell>{decision.origin}</TableCell><TableCell>{decision.duration ?? "unknown"}</TableCell><TableCell className="text-right"><Button size="sm" variant="outline" onClick={() => void unblock(decision.id)}>Unblock</Button></TableCell></TableRow>)}
            </TableBody></Table>
          </CardContent>
        </Card>

        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader><CardTitle>Alerts</CardTitle><CardDescription>Latest normalized signals from LAPI.</CardDescription></CardHeader>
          <CardContent className="overflow-x-auto">
            <Table><TableHeader><TableRow><TableHead>Scenario</TableHead><TableHead>Source</TableHead><TableHead>Events</TableHead><TableHead>Seen</TableHead></TableRow></TableHeader><TableBody>
              {state.alerts.data.map((alert) => <TableRow key={alert.id}><TableCell className="max-w-[260px] truncate">{alert.scenario}</TableCell><TableCell className="font-mono text-xs">{alert.sourceIp ? <Link className="underline-offset-4 hover:text-amber-300 hover:underline" href={`/ip/${encodeURIComponent(alert.sourceIp)}`}>{alert.sourceIp}</Link> : "-"}</TableCell><TableCell>{alert.events}</TableCell><TableCell>{relativeTime(alert.createdAt)}</TableCell></TableRow>)}
            </TableBody></Table>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-6 xl:grid-cols-2">
        <InventoryCard title="Machines" rows={state.machines.data.map((m) => [m.name, m.ipAddress ?? "-", m.status, relativeTime(m.lastHeartbeat)])} icon={DatabaseZap} />
        <InventoryCard title="Bouncers" rows={state.bouncers.data.map((b) => [b.name, b.type ?? "-", b.status, relativeTime(b.lastPull)])} icon={Bot} />
      </section>

      <footer className="pb-6 text-xs text-muted-foreground">Last refresh: {lastRefresh ? lastRefresh.toLocaleTimeString() : "never"}. Access assumption: private network or authenticated reverse proxy.</footer>
    </main>
  );
}

function InventoryCard({ title, rows, icon: Icon }: { title: string; rows: string[][]; icon: LucideIcon }): React.ReactElement {
  return <Card className="border-white/10 bg-white/[0.03]"><CardHeader><CardTitle className="flex items-center gap-2"><Icon className="h-4 w-4" /> {title}</CardTitle></CardHeader><CardContent className="overflow-x-auto"><Table><TableBody>{rows.map((row) => <TableRow key={row.join(":")}>{row.map((cell) => <TableCell key={cell}>{cell}</TableCell>)}</TableRow>)}</TableBody></Table></CardContent></Card>;
}
