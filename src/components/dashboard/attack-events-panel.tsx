"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Activity, Clock3, Crosshair, Globe2, RadioTower, Route, ServerCrash } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ApiEnvelope, AttackEventSnapshot, Severity } from "@/lib/crowdsec/types";
import { formatNumber, relativeTime } from "@/lib/utils";

type SnapshotEnvelope = ApiEnvelope<AttackEventSnapshot>;

const emptySnapshot: AttackEventSnapshot = { events: [], campaigns: [] };

function severityVariant(severity: Severity): "destructive" | "warning" | "secondary" | "outline" {
  if (severity === "critical" || severity === "high") return "destructive";
  if (severity === "medium") return "warning";
  if (severity === "low") return "secondary";
  return "outline";
}

function methodVariant(method?: string): "destructive" | "warning" | "secondary" | "outline" {
  if (!method) return "outline";
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) return "warning";
  return "secondary";
}

function display(value?: string | number): string {
  return value === undefined || value === "" ? "-" : String(value);
}

async function getSnapshot(): Promise<SnapshotEnvelope> {
  const response = await fetch("/api/attack-events?limit=120", { cache: "no-store" });
  if (!response.ok) throw new Error(`attack-events returned ${response.status}`);
  return response.json() as Promise<SnapshotEnvelope>;
}

export function AttackEventsPanel(): React.ReactElement {
  const [snapshot, setSnapshot] = useState<AttackEventSnapshot>(emptySnapshot);
  const [source, setSource] = useState<SnapshotEnvelope["source"]>("partial");
  const [error, setError] = useState<string | null>(null);
  const [methodFilter, setMethodFilter] = useState("all");
  const [hostFilter, setHostFilter] = useState("all");
  const [serviceFilter, setServiceFilter] = useState("all");
  const [pathFilter, setPathFilter] = useState("");

  useEffect(() => {
    let active = true;
    getSnapshot()
      .then((envelope) => {
        if (!active) return;
        setSnapshot(envelope.data);
        setSource(envelope.source);
        setError(envelope.error ?? null);
      })
      .catch((err: unknown) => { if (active) setError(err instanceof Error ? err.message : "Unable to load attack events"); });

    const source = new EventSource("/api/attack-events/stream");
    source.addEventListener("attack-events", (event) => {
      const envelope = JSON.parse((event as MessageEvent<string>).data) as SnapshotEnvelope;
      setSnapshot(envelope.data);
      setSource(envelope.source);
      setError(envelope.error ?? null);
    });
    source.onerror = () => setError("Realtime attack event stream disconnected; retrying...");
    return () => {
      active = false;
      source.close();
    };
  }, []);

  const topTarget = useMemo(() => {
    const targets = new Map<string, number>();
    for (const event of snapshot.events) {
      const target = `${event.host ?? "unknown-host"}${event.path ?? ""}`;
      targets.set(target, (targets.get(target) ?? 0) + 1);
    }
    return [...targets.entries()].sort((a, b) => b[1] - a[1])[0];
  }, [snapshot.events]);

  const postCount = snapshot.events.filter((event) => ["POST", "PUT", "PATCH", "DELETE"].includes(event.method ?? "")).length;
  const uniqueTargets = new Set(snapshot.events.map((event) => `${event.host ?? "unknown"}${event.path ?? ""}`)).size;

  const methods = useMemo(() => ["all", ...Array.from(new Set(snapshot.events.map((event) => event.method).filter(Boolean) as string[])).sort()], [snapshot.events]);
  const hosts = useMemo(() => ["all", ...Array.from(new Set(snapshot.events.map((event) => event.host).filter(Boolean) as string[])).sort()], [snapshot.events]);
  const services = useMemo(() => ["all", ...Array.from(new Set(snapshot.events.map((event) => event.service).filter(Boolean) as string[])).sort()], [snapshot.events]);
  const filteredEvents = useMemo(() => {
    const pathNeedle = pathFilter.trim().toLowerCase();
    return snapshot.events.filter((event) => {
      const matchesMethod = methodFilter === "all" || event.method === methodFilter;
      const matchesHost = hostFilter === "all" || event.host === hostFilter;
      const matchesService = serviceFilter === "all" || event.service === serviceFilter;
      const matchesPath = !pathNeedle || `${event.path ?? ""} ${event.scenario} ${event.userAgent ?? ""}`.toLowerCase().includes(pathNeedle);
      return matchesMethod && matchesHost && matchesService && matchesPath;
    });
  }, [hostFilter, methodFilter, pathFilter, serviceFilter, snapshot.events]);

  return (
    <section className="grid min-w-0 gap-6 xl:grid-cols-[minmax(320px,.95fr)_minmax(0,1.35fr)]">
      <div className="grid min-w-0 gap-4">
        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><RadioTower className="h-4 w-4 text-red-300" /> Realtime attack intelligence</CardTitle>
            <CardDescription>Scenarios, domains, paths and HTTP methods extracted from CrowdSec events.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 text-sm">
            <Signal icon={Activity} label="Live events" value={formatNumber(snapshot.events.length)} detail={`source: ${source}${error ? ` · ${error}` : ""}`} />
            <Signal icon={Crosshair} label="Top target" value={topTarget?.[0] ?? "-"} detail={topTarget ? `${topTarget[1]} observed events` : "No target data yet"} />
            <Signal icon={Route} label="Write attempts" value={formatNumber(postCount)} detail="POST/PUT/PATCH/DELETE requests" />
            <Signal icon={Globe2} label="Unique targets" value={formatNumber(uniqueTargets)} detail="host + path combinations" />
          </CardContent>
        </Card>

        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader><CardTitle>Active campaigns</CardTitle><CardDescription>Grouped by scenario, domain and source.</CardDescription></CardHeader>
          <CardContent className="space-y-3">
            {snapshot.campaigns.map((campaign) => (
              <div key={campaign.id} className="space-y-2 rounded-lg border border-white/10 bg-black/20 p-3">
                <div className="flex items-center justify-between gap-2"><span className="truncate text-sm font-medium">{campaign.scenario}</span><Badge variant={severityVariant(campaign.severity)}>{campaign.severity}</Badge></div>
                <div className="text-xs text-muted-foreground">{campaign.sourceIp ? <Link className="font-mono text-foreground underline-offset-4 hover:text-amber-300 hover:underline" href={`/ip/${encodeURIComponent(campaign.sourceIp)}`}>{campaign.sourceIp}</Link> : "unknown source"} → <span className="font-mono text-foreground">{campaign.host ?? "unknown host"}</span></div>
                <div className="flex flex-wrap gap-1">{campaign.methods.map((method) => <Badge key={method} variant={methodVariant(method)}>{method}</Badge>)}</div>
                <div className="space-y-1 text-xs text-muted-foreground">{campaign.paths.slice(0, 4).map((path) => <div key={path} className="truncate font-mono">{path}</div>)}</div>
                <div className="flex justify-between text-xs text-muted-foreground"><span>{formatNumber(campaign.events)} events</span><span>{relativeTime(campaign.lastSeen)}</span></div>
              </div>
            ))}
            {snapshot.campaigns.length === 0 && <Empty icon={ServerCrash} text="No campaign data yet. CrowdSec alerts may not include raw HTTP event fields." />}
          </CardContent>
        </Card>
      </div>

      <Card className="flex min-h-[720px] min-w-0 flex-col overflow-hidden border-white/10 bg-white/[0.03]">
        <CardHeader className="shrink-0 space-y-4"><div><CardTitle>Live HTTP/event feed</CardTitle><CardDescription>Which domain/path is being attacked and with which method.</CardDescription></div>
          <div className="grid gap-2 md:grid-cols-4">
            <select className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring" value={methodFilter} onChange={(event) => setMethodFilter(event.target.value)}>
              {methods.map((method) => <option key={method} value={method}>{method === "all" ? "All methods" : method}</option>)}
            </select>
            <select className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring" value={hostFilter} onChange={(event) => setHostFilter(event.target.value)}>
              {hosts.map((host) => <option key={host} value={host}>{host === "all" ? "All domains" : host}</option>)}
            </select>
            <select className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring" value={serviceFilter} onChange={(event) => setServiceFilter(event.target.value)}>
              {services.map((service) => <option key={service} value={service}>{service === "all" ? "All services" : service}</option>)}
            </select>
            <Input placeholder="Filter path, scenario, user-agent…" value={pathFilter} onChange={(event) => setPathFilter(event.target.value)} />
          </div>
          <div className="text-xs text-muted-foreground">Showing {formatNumber(filteredEvents.length)} of {formatNumber(snapshot.events.length)} events</div>
        </CardHeader>
        <CardContent className="min-w-0 flex min-h-0 flex-1 overflow-hidden">
          <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden [scrollbar-color:rgba(245,158,11,.45)_rgba(255,255,255,.06)] [scrollbar-width:thin]">
          <Table className="table-fixed">
            <TableHeader className="sticky top-0 z-10"><TableRow><TableHead className="w-[110px]">Time</TableHead><TableHead className="w-[130px]">Source</TableHead><TableHead className="w-[86px]">Method</TableHead><TableHead className="w-[320px]">Target</TableHead><TableHead className="w-[220px]">Scenario</TableHead><TableHead className="w-[72px]">Status</TableHead></TableRow></TableHeader>
            <TableBody className="max-h-none overflow-visible">
              {filteredEvents.slice(0, 80).map((event) => (
                <TableRow key={event.id}>
                  <TableCell className="truncate whitespace-nowrap text-xs text-muted-foreground"><Clock3 className="mr-1 inline h-3 w-3" />{relativeTime(event.timestamp)}</TableCell>
                  <TableCell className="truncate font-mono text-xs">{event.sourceIp ? <Link className="underline-offset-4 hover:text-amber-300 hover:underline" href={`/ip/${encodeURIComponent(event.sourceIp)}`}>{event.sourceIp}</Link> : "-"}</TableCell>
                  <TableCell><Badge variant={methodVariant(event.method)}>{display(event.method)}</Badge></TableCell>
                  <TableCell className="max-w-[320px]"><div className="space-y-0.5"><div className="truncate font-mono text-xs text-foreground" title={display(event.host)}>{display(event.host)}</div>{event.service && <div className="truncate font-mono text-[11px] text-amber-200" title={`svc: ${event.service}`}>svc: {event.service}</div>}<div className="truncate font-mono text-xs text-muted-foreground" title={display(event.path)}>{display(event.path)}</div>{event.userAgent && <div className="truncate text-[11px] text-muted-foreground" title={`UA: ${event.userAgent}`}>UA: {event.userAgent}</div>}</div></TableCell>
                  <TableCell className="max-w-[220px]"><div className="flex min-w-0 items-center gap-2"><Badge variant={severityVariant(event.severity)}>{event.severity}</Badge><span className="truncate" title={event.scenario}>{event.scenario}</span></div></TableCell>
                  <TableCell>{display(event.status)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          </div>
          {snapshot.events.length === 0 && <Empty icon={ServerCrash} text="No raw attack events available yet." />}
          {snapshot.events.length > 0 && filteredEvents.length === 0 && <Empty icon={ServerCrash} text="No events match the current filters." />}
        </CardContent>
      </Card>
    </section>
  );
}

function Signal({ icon: Icon, label, value, detail }: { icon: typeof Activity; label: string; value: string; detail: string }): React.ReactElement {
  return <div className="rounded-lg border border-white/10 bg-black/20 p-3"><div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground"><Icon className="h-3.5 w-3.5" />{label}</div><div className="mt-1 break-words font-medium">{value}</div><div className="mt-1 text-xs text-muted-foreground">{detail}</div></div>;
}

function Empty({ icon: Icon, text }: { icon: typeof ServerCrash; text: string }): React.ReactElement {
  return <div className="rounded-lg border border-dashed border-white/10 p-6 text-center text-sm text-muted-foreground"><Icon className="mx-auto mb-2 h-6 w-6" />{text}</div>;
}
