"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowLeft, Bot, ChevronDown, RefreshCcw, Search, ShieldBan, Trash2 } from "lucide-react";
import { AddDecisionDialog } from "@/components/decisions/add-decision-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import type { ApiEnvelope, CrowdSecAlert, CrowdSecDecision } from "@/lib/crowdsec/types";
import { cn, formatNumber, relativeTime } from "@/lib/utils";

interface EnrichedDecision extends CrowdSecDecision {
  countryLabel: string;
  flag: string;
  events: number;
  scenarioLabel: string;
  latestSeen?: string | undefined;
}

const scenarioIcon: Record<string, string> = {
  probing: "🔐",
  sensitive: "💻",
  crawl: "🖥️",
  admin: "🧾",
  appsec: "🛡️",
  cve: "🚨",
  bf: "⚔️",
  brute: "⚔️"
};

async function getJson<T>(path: string): Promise<ApiEnvelope<T>> {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json() as Promise<ApiEnvelope<T>>;
}

function countryFlag(country?: string): string {
  const code = country?.trim().toUpperCase();
  if (!code || code.length !== 2) return "🏴";
  return String.fromCodePoint(0x1f1e6 + code.charCodeAt(0) - 65, 0x1f1e6 + code.charCodeAt(1) - 65);
}

function countryLabel(country?: string): string {
  const code = country?.trim().toUpperCase();
  return code && code.length === 2 ? code : "UN";
}

function normalizeScenario(value: string): string {
  return value.replace(/^crowdsecurity\//, "").replace(/^CAPI:/, "");
}

function iconForScenario(scenario: string): string {
  const lower = scenario.toLowerCase();
  const hit = Object.entries(scenarioIcon).find(([key]) => lower.includes(key));
  return hit?.[1] ?? "🧩";
}

function durationLabel(decision: CrowdSecDecision): string {
  if (decision.expiresAt) {
    const date = new Date(decision.expiresAt);
    if (!Number.isNaN(date.getTime())) return relativeTime(decision.expiresAt).replace("in ", "Up to ");
  }
  const duration = decision.duration?.trim();
  if (!duration) return "Unknown";
  const hours = duration.match(/(\d+)h/);
  const minutes = duration.match(/(\d+)m/);
  if (hours) return `Up to ${hours[1]} ${Number(hours[1]) === 1 ? "hour" : "hours"}`;
  if (minutes) return `Up to ${minutes[1]} ${Number(minutes[1]) === 1 ? "minute" : "minutes"}`;
  return `Up to ${duration}`;
}

function isSoon(decision: CrowdSecDecision): boolean {
  const label = durationLabel(decision).toLowerCase();
  return label.includes("minute") || label.includes("1 hour") || label.includes("2 hours");
}

function enrichDecisions(decisions: readonly CrowdSecDecision[], alerts: readonly CrowdSecAlert[]): EnrichedDecision[] {
  const alertsByIp = new Map<string, CrowdSecAlert[]>();
  for (const alert of alerts) {
    if (!alert.sourceIp) continue;
    alertsByIp.set(alert.sourceIp, [...(alertsByIp.get(alert.sourceIp) ?? []), alert]);
  }

  return decisions.map((decision) => {
    const relatedAlerts = alertsByIp.get(decision.value) ?? [];
    const topAlert = [...relatedAlerts].sort((a, b) => b.events - a.events)[0];
    const country = countryLabel(decision.country ?? topAlert?.sourceCountry);
    return {
      ...decision,
      countryLabel: country,
      flag: countryFlag(country),
      events: relatedAlerts.reduce((sum, alert) => sum + alert.events, 0),
      scenarioLabel: normalizeScenario(decision.scenario !== "unknown" ? decision.scenario : topAlert?.scenario ?? "manual-decision"),
      latestSeen: topAlert?.createdAt
    };
  });
}

export function DecisionsPage(): React.ReactElement {
  const [decisions, setDecisions] = useState<CrowdSecDecision[]>([]);
  const [alerts, setAlerts] = useState<CrowdSecAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [engine, setEngine] = useState("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const refresh = useCallback(async () => {
    setLoading(true);
    setMessage(null);
    try {
      const [nextDecisions, nextAlerts] = await Promise.all([
        getJson<CrowdSecDecision[]>("/api/decisions"),
        getJson<CrowdSecAlert[]>("/api/alerts").catch(async () => ({ data: [], source: "partial" as const }))
      ]);
      setDecisions(nextDecisions.data);
      setAlerts(nextAlerts.data);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to load decisions");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const enriched = useMemo(() => enrichDecisions(decisions, alerts), [alerts, decisions]);
  const engines = useMemo(() => ["all", ...Array.from(new Set(enriched.map((decision) => decision.origin))).sort()], [enriched]);
  const visible = useMemo(() => enriched.filter((decision) => {
    const matchesEngine = engine === "all" || decision.origin === engine;
    const needle = query.trim().toLowerCase();
    const matchesQuery = !needle || decision.value.toLowerCase().includes(needle) || decision.scenarioLabel.toLowerCase().includes(needle);
    return matchesEngine && matchesQuery;
  }), [engine, enriched, query]);

  const allVisibleSelected = visible.length > 0 && visible.every((decision) => selected.has(decision.id));

  function toggleSelected(id: string): void {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function toggleAll(): void {
    setSelected((current) => {
      const next = new Set(current);
      if (allVisibleSelected) visible.forEach((decision) => next.delete(decision.id));
      else visible.forEach((decision) => next.add(decision.id));
      return next;
    });
  }

  function toggleExpanded(id: string): void {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  async function removeDecision(id: string): Promise<void> {
    setMessage(null);
    const response = await fetch(`/api/decisions/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!response.ok) {
      const body = await response.json().catch(() => ({})) as { error?: string };
      setMessage(body.error ?? "Unable to delete the decision");
      return;
    }
    setSelected((current) => {
      const next = new Set(current);
      next.delete(id);
      return next;
    });
    await refresh();
  }

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-[1500px] flex-col gap-6 px-4 py-6 lg:px-8">
      <div className="flex items-center justify-between border-b border-white/10 pb-5">
        <Button variant="ghost" asChild>
          <Link href="/" className="text-muted-foreground"><ArrowLeft className="h-4 w-4" /> Back</Link>
        </Button>
        <Button variant="outline" onClick={() => void refresh()} disabled={loading}><RefreshCcw className={cn("h-4 w-4", loading && "animate-spin")} /> Refresh</Button>
      </div>

      <header className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="flex items-start gap-5">
          <div className="relative mt-1 grid size-12 place-items-center rounded-full bg-amber-500/15 text-2xl shadow-[0_0_40px_rgba(245,158,11,.18)]">
            <span>👋</span>
            <span className="absolute -right-0.5 top-0 grid size-4 place-items-center rounded-full bg-amber-500 text-[10px] text-black">×</span>
          </div>
          <div>
            <h1 className="text-3xl font-semibold tracking-tight md:text-4xl">Decisions</h1>
            <p className="mt-1 text-sm text-muted-foreground">View and manage the remediation decisions that CrowdSec has taken.</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <AddDecisionDialog onCreated={refresh} />
        </div>
      </header>

      <section className="grid gap-3 lg:grid-cols-[320px_1fr_auto]">
        <label className="relative">
          <select className="h-10 w-full appearance-none rounded-md border border-input bg-background px-3 pr-10 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring" value={engine} onChange={(event) => setEngine(event.target.value)}>
            {engines.map((item) => <option key={item} value={item}>{item === "all" ? "Filter by Security Engine" : item}</option>)}
          </select>
          <ChevronDown className="pointer-events-none absolute right-3 top-3 h-4 w-4 text-muted-foreground" />
        </label>
        <label className="relative max-w-[420px]">
          <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
          <Input className="pl-9" placeholder="Search by IP address" value={query} onChange={(event) => setQuery(event.target.value)} />
        </label>
        <div className="flex items-center justify-end text-sm text-muted-foreground">{formatNumber(visible.length)} decisions displayed</div>
      </section>

      <div className="flex items-center justify-between gap-3 text-sm">
        <button className="inline-flex items-center gap-3" type="button" onClick={toggleAll}>
          <span className={cn("grid size-4 place-items-center rounded border border-white/25", allVisibleSelected && "border-amber-400 bg-amber-400 text-black")}>{allVisibleSelected ? "✓" : ""}</span>
          Select all
        </button>
        {message && <span className="text-amber-300">{message}</span>}
      </div>

      <Card className="border-0 bg-transparent shadow-none">
        <CardContent className="space-y-3 p-0">
          {visible.map((decision) => (
            <div key={decision.id} className="overflow-hidden rounded-lg border border-white/10 bg-white/[0.03] transition hover:border-amber-400/35 hover:bg-amber-500/[0.04]">
              <div className="grid min-h-14 grid-cols-[28px_1.25fr_.35fr_1fr_.9fr_1.1fr_52px_34px] items-center gap-3 px-4 text-sm max-xl:grid-cols-[28px_1fr_.45fr_.8fr_42px]">
                <button className={cn("grid size-4 place-items-center rounded border border-white/25", selected.has(decision.id) && "border-amber-400 bg-amber-400 text-black")} type="button" onClick={() => toggleSelected(decision.id)} aria-label={`Select ${decision.value}`}>{selected.has(decision.id) ? "✓" : ""}</button>
                <Link href={`/ip/${encodeURIComponent(decision.value)}`} className="flex min-w-0 items-center gap-3 font-mono text-xs font-semibold hover:text-amber-300">
                  <span className="text-base">{decision.flag}</span>
                  <span className="truncate">{decision.value}</span>
                </Link>
                <div><Badge className="border-orange-500/30 bg-orange-500/10 text-orange-300">{decision.type}</Badge></div>
                <div className="flex min-w-0 items-center gap-2 max-xl:hidden"><Bot className="h-4 w-4 text-amber-300" /><span className="truncate">{decision.origin}</span></div>
                <div className={cn("max-xl:hidden", isSoon(decision) && "text-amber-400")}>{durationLabel(decision)}</div>
                <div className="flex min-w-0 items-center gap-2"><span>{iconForScenario(decision.scenarioLabel)}</span><span className="truncate">{decision.scenarioLabel}</span></div>
                <button className="grid justify-items-center text-muted-foreground transition hover:text-red-300" type="button" onClick={() => void removeDecision(decision.id)} aria-label={`Delete ${decision.value}`}><Trash2 className="h-4 w-4" /><span className="text-xs">({decision.events || 1})</span></button>
                <button className="text-muted-foreground transition hover:text-foreground" type="button" onClick={() => toggleExpanded(decision.id)} aria-label={`Expand ${decision.value}`}><ChevronDown className={cn("h-4 w-4 transition", expanded.has(decision.id) && "rotate-180")} /></button>
              </div>
              {expanded.has(decision.id) && (
                <div className="grid gap-3 border-t border-white/10 px-4 py-3 text-xs text-muted-foreground md:grid-cols-4">
                  <Detail label="Scope" value={decision.scope} />
                  <Detail label="Country" value={`${decision.flag} ${decision.countryLabel}`} />
                  <Detail label="AS" value={decision.asName ?? "Unknown"} />
                  <Detail label="Latest related alert" value={decision.latestSeen ? relativeTime(decision.latestSeen) : "Unknown"} />
                </div>
              )}
            </div>
          ))}
          {!loading && visible.length === 0 && <div className="rounded-xl border border-white/10 bg-white/[0.03] p-10 text-center text-sm text-muted-foreground"><ShieldBan className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />No decisions match the current filters.</div>}
        </CardContent>
      </Card>
    </main>
  );
}

function Detail({ label, value }: { label: string; value: string }): React.ReactElement {
  return <div className="rounded-md bg-black/20 p-3"><div className="mb-1 uppercase tracking-wide text-muted-foreground/70">{label}</div><div className="truncate text-foreground">{value}</div></div>;
}
