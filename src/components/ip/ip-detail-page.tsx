"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowLeft, Ban, CalendarDays, CheckCircle2, ChevronDown, Database, Gauge, Globe2, Network, ShieldAlert, ShieldCheck, ShieldOff, Siren } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ApiEnvelope, CrowdSecAlert, CrowdSecDecision, DecisionType, Severity } from "@/lib/crowdsec/types";
import type { IpIntelProfile } from "@/lib/crowdsec/store";
import { cn, formatNumber, relativeTime } from "@/lib/utils";

function countryFlag(country?: string): string {
  const code = country?.trim().toUpperCase();
  if (!code || code.length !== 2) return "🏴";
  return String.fromCodePoint(0x1f1e6 + code.charCodeAt(0) - 65, 0x1f1e6 + code.charCodeAt(1) - 65);
}

function severityVariant(severity: Severity): "destructive" | "warning" | "secondary" | "outline" {
  if (severity === "critical" || severity === "high") return "destructive";
  if (severity === "medium") return "warning";
  if (severity === "low") return "secondary";
  return "outline";
}

function known(value?: string | number | boolean): string {
  if (value === undefined || value === null || value === "") return "Unknown";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function locationLabel(profile: IpIntelProfile): string {
  const parts = [profile.city, profile.region, profile.countryName ?? profile.country].filter(Boolean);
  return parts.length > 0 ? `${parts.join(", ")} ${countryFlag(profile.country)}` : "Unknown location";
}

function coordinateLabel(profile: IpIntelProfile): string {
  return profile.latitude !== undefined && profile.longitude !== undefined ? `${profile.latitude.toFixed(4)}, ${profile.longitude.toFixed(4)}` : "Unknown";
}

export function IpDetailPage({ ip }: { ip: string }): React.ReactElement {
  const [profile, setProfile] = useState<IpIntelProfile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decisionPanelOpen, setDecisionPanelOpen] = useState(false);
  const [decisionType, setDecisionType] = useState<Exclude<DecisionType, "unknown">>("ban");
  const [duration, setDuration] = useState("4h");
  const [reason, setReason] = useState("operator decision from IP intelligence profile");
  const [decisionBusy, setDecisionBusy] = useState(false);
  const [decisionMessage, setDecisionMessage] = useState<string | null>(null);
  const [actionsOpen, setActionsOpen] = useState(false);

  const fetchProfile = useCallback(async (): Promise<IpIntelProfile> => {
    const response = await fetch(`/api/ip/${encodeURIComponent(ip)}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`IP lookup failed with ${response.status}`);
    const envelope = await response.json() as ApiEnvelope<IpIntelProfile>;
    return envelope.data;
  }, [ip]);

  async function loadProfile(): Promise<void> {
    setProfile(await fetchProfile());
  }

  useEffect(() => {
    let active = true;
    fetchProfile()
      .then((nextProfile) => { if (active) setProfile(nextProfile); })
      .catch((err: unknown) => { if (active) setError(err instanceof Error ? err.message : "Unable to load IP profile"); });
    return () => { active = false; };
  }, [fetchProfile]);

  const maxActivity = useMemo(() => Math.max(1, ...(profile?.activity.map((item) => item.events) ?? [1])), [profile]);

  const activeBanDecisions = useMemo(() => profile?.decisions.filter((decision) => decision.scope === "ip" && decision.type === "ban") ?? [], [profile]);
  const isBanned = activeBanDecisions.length > 0;

  async function unbanIp(): Promise<void> {
    if (!profile || decisionBusy || activeBanDecisions.length === 0) return;
    setDecisionBusy(true);
    setDecisionMessage(null);
    setActionsOpen(false);
    try {
      await Promise.all(activeBanDecisions.map(async (decision) => {
        const response = await fetch(`/api/decisions/${encodeURIComponent(decision.id)}`, { method: "DELETE" });
        if (!response.ok) {
          const body = await response.json().catch(() => ({})) as { error?: string };
          throw new Error(body.error ?? `Unban failed with ${response.status}`);
        }
      }));
      setDecisionMessage(`Removed ${activeBanDecisions.length} ban decision(s) for ${profile.ip}`);
      await loadProfile();
    } catch (err) {
      setDecisionMessage(err instanceof Error ? err.message : "Unable to unban IP");
    } finally {
      setDecisionBusy(false);
    }
  }

  async function quickBanIp(): Promise<void> {
    setDecisionType("ban");
    setDuration("4h");
    setReason("operator ban from IP intelligence profile");
    setActionsOpen(false);
    setDecisionPanelOpen(false);
    await createDecision("ban", "4h", "operator ban from IP intelligence profile");
  }

  async function setAllowlisted(next: boolean): Promise<void> {
    if (!profile || decisionBusy) return;
    setDecisionBusy(true);
    setDecisionMessage(null);
    setActionsOpen(false);
    try {
      const requestInit: RequestInit = next
        ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ value: profile.ip, reason: "operator allowlist from IP profile" }) }
        : { method: "DELETE" };
      const response = await fetch(next ? "/api/allowlist" : `/api/allowlist/${encodeURIComponent(profile.ip)}`, requestInit);
      const body = await response.json().catch(() => ({})) as { error?: string };
      if (!response.ok) throw new Error(body.error ?? `Allowlist update failed with ${response.status}`);
      setDecisionMessage(next ? `${profile.ip} added to local allowlist` : `${profile.ip} removed from local allowlist`);
      await loadProfile();
    } catch (err) {
      setDecisionMessage(err instanceof Error ? err.message : "Unable to update allowlist");
    } finally {
      setDecisionBusy(false);
    }
  }

  async function createDecision(typeOverride = decisionType, durationOverride = duration, reasonOverride = reason): Promise<void> {
    if (!profile || decisionBusy) return;
    setDecisionBusy(true);
    setDecisionMessage(null);
    try {
      const response = await fetch("/api/decisions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          scope: "ip",
          value: profile.ip,
          type: typeOverride,
          duration: durationOverride,
          reason: reasonOverride,
          mode: "manual"
        })
      });
      const body = await response.json().catch(() => ({})) as { error?: string; issues?: { fieldErrors?: Record<string, string[]> } };
      if (!response.ok) {
        const firstIssue = body.issues?.fieldErrors ? Object.values(body.issues.fieldErrors).flat()[0] : undefined;
        throw new Error(firstIssue ?? body.error ?? `Decision create failed with ${response.status}`);
      }
      setDecisionMessage(`${typeOverride} decision created for ${profile.ip}`);
      setDecisionPanelOpen(false);
      await loadProfile();
    } catch (err) {
      setDecisionMessage(err instanceof Error ? err.message : "Unable to create decision");
    } finally {
      setDecisionBusy(false);
    }
  }

  if (error) return <main className="mx-auto min-h-screen max-w-[1200px] px-6 py-8"><Button variant="ghost" asChild><Link href="/"><ArrowLeft className="h-4 w-4" /> Back</Link></Button><Card className="mt-6 border-red-500/30 bg-red-500/10"><CardContent className="p-6 text-red-200">{error}</CardContent></Card></main>;
  if (!profile) return <main className="mx-auto min-h-screen max-w-[1200px] px-6 py-8 text-muted-foreground">Loading IP intelligence...</main>;

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-[1400px] flex-col gap-6 px-4 py-6 lg:px-8">
      <div className="flex items-center justify-between border-b border-white/10 pb-5">
        <Button variant="ghost" asChild><Link href="/" className="text-muted-foreground"><ArrowLeft className="h-4 w-4" /> Back</Link></Button>
        <Button variant="outline" asChild><Link href="/decisions">View all decisions</Link></Button>
      </div>

      <header className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-5">
          <div className="grid size-14 place-items-center rounded-full bg-red-500/20 shadow-[0_0_45px_rgba(248,113,113,.28)]"><span className="size-6 rounded-full bg-red-400" /></div>
          <div>
            <h1 className="font-mono text-3xl font-semibold tracking-tight md:text-4xl">{profile.ip}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              {isBanned ? <Badge variant="destructive"><ShieldAlert className="mr-1 h-3 w-3" /> Banned</Badge> : <Badge variant="warning"><ShieldAlert className="mr-1 h-3 w-3" /> Observed IP</Badge>}
              {profile.allowlisted && <Badge variant="success"><ShieldCheck className="mr-1 h-3 w-3" /> {profile.operatorAllowlisted ? "Operator allowlist" : "Allowlisted"}</Badge>}
              <span className="text-sm text-muted-foreground">{locationLabel(profile)}</span>
            </div>
          </div>
        </div>
        <div className="relative flex gap-2">
          <Button variant="outline" onClick={() => setActionsOpen((current) => !current)} disabled={decisionBusy}>IP actions <ChevronDown className={cn("h-4 w-4 transition", actionsOpen && "rotate-180")} /></Button>
          <Button onClick={() => setDecisionPanelOpen(true)} disabled={decisionBusy || profile.allowlisted}><Siren className="h-4 w-4" /> Custom decision</Button>
          {actionsOpen && (
            <div className="absolute right-0 top-11 z-30 w-72 overflow-hidden rounded-xl border border-white/10 bg-background shadow-2xl">
              <button type="button" className="flex w-full items-start gap-3 px-4 py-3 text-left text-sm transition hover:bg-white/[0.04]" onClick={() => void setAllowlisted(!profile.localAllowlisted)}>
                {profile.localAllowlisted ? <ShieldOff className="mt-0.5 h-4 w-4 text-amber-300" /> : <ShieldCheck className="mt-0.5 h-4 w-4 text-emerald-300" />}
                <span><span className="block font-medium">{profile.localAllowlisted ? "Remove from allowlist" : "Add to local allowlist"}</span><span className="mt-0.5 block text-xs text-muted-foreground">Prevents panel-created decisions for this IP.</span></span>
              </button>
              {isBanned ? (
                <button type="button" className="flex w-full items-start gap-3 px-4 py-3 text-left text-sm transition hover:bg-white/[0.04]" onClick={() => void unbanIp()}>
                  <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-300" />
                  <span><span className="block font-medium">Unban IP</span><span className="mt-0.5 block text-xs text-muted-foreground">Remove active CrowdSec ban decisions for this IP.</span></span>
                </button>
              ) : (
                <button type="button" className="flex w-full items-start gap-3 px-4 py-3 text-left text-sm transition hover:bg-white/[0.04] disabled:cursor-not-allowed disabled:opacity-50" onClick={() => void quickBanIp()} disabled={profile.allowlisted}>
                  <Ban className="mt-0.5 h-4 w-4 text-red-300" />
                  <span><span className="block font-medium">Ban IP for 4h</span><span className="mt-0.5 block text-xs text-muted-foreground">{profile.allowlisted ? "Remove allowlist before banning this IP." : "Creates a real CrowdSec IP ban decision."}</span></span>
                </button>
              )}
            </div>
          )}
        </div>
      </header>

      <Dialog open={decisionPanelOpen} onOpenChange={setDecisionPanelOpen}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><Siren className="h-4 w-4 text-amber-300" /> Create remediation decision</DialogTitle>
            <DialogDescription>Send a real CrowdSec decision for this IP. Defaults are conservative; change them deliberately.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4">
            <div className="rounded-lg border border-white/10 bg-black/20 p-3 text-sm">
              <div className="text-xs uppercase tracking-wide text-muted-foreground">Target</div>
              <div className="mt-1 font-mono font-semibold">{profile.ip}</div>
            </div>
            <div className="grid gap-3 md:grid-cols-[180px_160px_1fr]">
              <label className="grid gap-1 text-xs text-muted-foreground">
                Type
                <select className="h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring" value={decisionType} onChange={(event) => setDecisionType(event.target.value as Exclude<DecisionType, "unknown">)} disabled={decisionBusy}>
                  <option value="ban">ban</option>
                  <option value="captcha">captcha</option>
                  <option value="throttle">throttle</option>
                  <option value="enforce_mfa">enforce_mfa</option>
                </select>
              </label>
              <label className="grid gap-1 text-xs text-muted-foreground">
                Duration
                <Input value={duration} onChange={(event) => setDuration(event.target.value)} placeholder="4h" disabled={decisionBusy} />
              </label>
              <label className="grid gap-1 text-xs text-muted-foreground">
                Reason
                <Input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Why are we remediating this IP?" disabled={decisionBusy} />
              </label>
            </div>
            {decisionMessage && <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-100">{decisionMessage}</div>}
            <div className="flex justify-end gap-2 border-t border-white/10 pt-4">
              <Button type="button" variant="ghost" onClick={() => setDecisionPanelOpen(false)} disabled={decisionBusy}>Cancel</Button>
              <Button type="button" className="bg-amber-500 text-black hover:bg-amber-400" onClick={() => void createDecision()} disabled={decisionBusy || !duration.trim() || reason.trim().length < 3}>{decisionBusy ? "Sending..." : "Send to CrowdSec"}</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {profile.network.isSpecial && (
        <Card className="border-amber-500/30 bg-amber-500/10">
          <CardContent className="p-4 text-sm text-amber-100">
            <div className="font-semibold">{profile.network.specialName}: this is not a normal public attacker IP.</div>
            <div className="mt-1 text-amber-100/80">{profile.network.specialDescription}</div>
          </CardContent>
        </Card>
      )}

      <Card className="border-white/10 bg-white/[0.03]">
        <CardContent className="grid gap-6 p-5 lg:grid-cols-[1fr_auto]">
          <div className="grid gap-4 md:grid-cols-2">
            <Info label="Crowd Confidence" value={profile.confidence} strong />
            <Info label="Location" value={locationLabel(profile)} strong />
            <Info label="First Seen" value={relativeTime(profile.firstSeen)} />
            <Info label="Last Seen" value={relativeTime(profile.lastSeen)} />
            <TagGroup label="Known For" values={profile.knownFor} />
            <TagGroup label="MITRE Techniques" values={profile.mitreTechniques} />
          </div>
          <div className="min-w-[170px] self-center text-right"><div className="text-sm text-muted-foreground">Background Noise</div><div className="mt-4 text-xl font-semibold">{profile.backgroundNoise}</div></div>
        </CardContent>
      </Card>

      <section className="grid gap-6 lg:grid-cols-3">
        <MiniCard icon={Network} title="Network" value={profile.range} detail={profile.network.isPublic ? "Publicly routable IPv4" : profile.network.specialName ?? "Non-public/special range"} />
        <MiniCard icon={Globe2} title="Reverse DNS" value={profile.reverseDns ?? "Unknown"} detail={profile.provider ? `GeoIP source: ${profile.provider}` : "Not resolved locally"} />
        <MiniCard icon={Gauge} title="Observed Pressure" value={`${formatNumber(profile.totalEvents)} events`} detail={`${profile.totalAlerts} alerts · ${profile.activeDecisions} active decisions`} />
      </section>

      <section className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <IntelGrid title="Geo & network intelligence" rows={[
          ["Country", profile.countryName ? `${profile.countryName} (${profile.country}) ${countryFlag(profile.country)}` : known(profile.country)],
          ["Region", known(profile.region)],
          ["City", known(profile.city)],
          ["Coordinates", coordinateLabel(profile)],
          ["Timezone", known(profile.timezone)],
          ["Postal code", known(profile.postalCode)],
          ["Continent", profile.continent ? `${profile.continent} (${profile.continentCode ?? "-"})` : "Unknown"],
          ["Currency", known(profile.currency)],
          ["Languages", known(profile.languages)]
        ]} />
        <IntelGrid title="Ownership & risk signals" rows={[
          ["ASN", known(profile.asn)],
          ["AS name", known(profile.asName)],
          ["ISP", known(profile.isp)],
          ["Organization", known(profile.org)],
          ["Proxy/VPN", known(profile.isProxy)],
          ["Hosting/datacenter", known(profile.isHosting)],
          ["Mobile network", known(profile.isMobile)],
          ["Public route", known(profile.network.isPublic)],
          ["Last enriched", profile.updatedAt ? relativeTime(profile.updatedAt) : "Not cached"]
        ]} />
      </section>

      <Card className="border-white/10 bg-white/[0.03]">
        <CardHeader><CardTitle>Investigation signals</CardTitle><CardDescription>Local CrowdSec context plus third-party enrichment indicators.</CardDescription></CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {profile.riskSignals.length ? profile.riskSignals.map((signal) => <Badge key={signal} variant="outline" className="border-amber-400/40 bg-amber-500/10 text-amber-200">{signal}</Badge>) : <span className="text-sm text-muted-foreground">No extra risk signals yet.</span>}
        </CardContent>
      </Card>

      <Card className="border-white/10 bg-white/[0.03]">
        <CardHeader><CardTitle className="flex items-center gap-2"><CalendarDays className="h-4 w-4" /> Activity</CardTitle><CardDescription>Persisted local activity from SQLite while the container is alive.</CardDescription></CardHeader>
        <CardContent className="grid gap-6 lg:grid-cols-[1fr_.9fr]">
          <div className="grid grid-cols-12 gap-1">
            {profile.activity.slice(-72).map((item) => <div key={item.day} title={`${item.day}: ${item.events}`} className={cn("h-4 rounded-sm", item.events === 0 ? "bg-white/10" : "bg-red-400")} style={{ opacity: 0.25 + (item.events / maxActivity) * 0.75 }} />)}
            {profile.activity.length === 0 && Array.from({ length: 72 }, (_, index) => <div key={index} className="h-4 rounded-sm bg-white/10" />)}
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <Score label="Last 24 hours" value={profile.totalEvents > 0 ? profile.backgroundNoise : "Quiet"} />
            <Score label="Last month" value={profile.backgroundNoise} />
            <Score label="Last 7 days" value={profile.backgroundNoise} />
            <Score label="Last 3 months" value={profile.backgroundNoise} />
          </div>
        </CardContent>
      </Card>

      <section className="grid gap-6 xl:grid-cols-2">
        <ScenarioTable scenarios={profile.scenarios} />
        <DecisionsTable decisions={profile.decisions} />
      </section>
      <AlertsTable alerts={profile.recentAlerts} />
    </main>
  );
}

function Info({ label, value, strong }: { label: string; value: string; strong?: boolean }): React.ReactElement {
  return <div className="text-sm"><span className="text-muted-foreground">{label}: </span><span className={cn(strong && "font-semibold text-foreground")}>{value}</span></div>;
}
function TagGroup({ label, values }: { label: string; values: string[] }): React.ReactElement {
  return <div className="md:col-span-2"><div className="mb-2 text-sm text-muted-foreground">{label}:</div><div className="flex flex-wrap gap-2">{values.length ? values.map((value) => <Badge key={value} variant="outline" className="border-amber-400/35 bg-amber-500/10 text-amber-100">{value}</Badge>) : <span className="text-sm text-muted-foreground">No local data yet</span>}</div></div>;
}
function IntelGrid({ title, rows }: { title: string; rows: Array<[string, string]> }): React.ReactElement {
  return <Card className="border-white/10 bg-white/[0.03]"><CardHeader><CardTitle className="text-base">{title}</CardTitle></CardHeader><CardContent className="grid gap-2 text-sm">{rows.map(([label, value]) => <div key={label} className="grid grid-cols-[140px_1fr] gap-3 rounded-md bg-black/20 px-3 py-2"><span className="text-muted-foreground">{label}</span><span className="min-w-0 break-words font-medium">{value}</span></div>)}</CardContent></Card>;
}
function MiniCard({ icon: Icon, title, value, detail }: { icon: typeof Network; title: string; value: string; detail: string }): React.ReactElement {
  return <Card className="border-white/10 bg-white/[0.03]"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Icon className="h-4 w-4" /> {title}</CardTitle></CardHeader><CardContent><div className="font-semibold">{value}</div><div className="mt-2 text-sm text-muted-foreground">{detail}</div></CardContent></Card>;
}
function Score({ label, value }: { label: string; value: string }): React.ReactElement {
  return <div className="flex items-center justify-between rounded-lg bg-black/20 p-4"><div><div className="text-sm text-muted-foreground">{label}</div><div className="mt-1 font-semibold">{value}</div></div><div className="size-10 rounded-full border-[6px] border-red-400" /></div>;
}
function ScenarioTable({ scenarios }: { scenarios: IpIntelProfile["scenarios"] }): React.ReactElement {
  return <Card className="border-white/10 bg-white/[0.03]"><CardHeader><CardTitle>Top classifications</CardTitle></CardHeader><CardContent><Table><TableHeader><TableRow><TableHead>Scenario</TableHead><TableHead>Events</TableHead><TableHead>Severity</TableHead></TableRow></TableHeader><TableBody>{scenarios.map((row) => <TableRow key={row.scenario}><TableCell className="max-w-[320px] truncate">{row.scenario}</TableCell><TableCell>{formatNumber(row.events)}</TableCell><TableCell><Badge variant={severityVariant(row.severity)}>{row.severity}</Badge></TableCell></TableRow>)}</TableBody></Table></CardContent></Card>;
}
function DecisionsTable({ decisions }: { decisions: CrowdSecDecision[] }): React.ReactElement {
  return <Card className="border-white/10 bg-white/[0.03]"><CardHeader><CardTitle>Decisions taken</CardTitle></CardHeader><CardContent><Table><TableHeader><TableRow><TableHead>Type</TableHead><TableHead>Origin</TableHead><TableHead>Duration</TableHead></TableRow></TableHeader><TableBody>{decisions.map((row) => <TableRow key={row.id}><TableCell><Badge variant="destructive">{row.type}</Badge></TableCell><TableCell>{row.origin}</TableCell><TableCell>{row.duration ?? "unknown"}</TableCell></TableRow>)}</TableBody></Table></CardContent></Card>;
}
function AlertsTable({ alerts }: { alerts: CrowdSecAlert[] }): React.ReactElement {
  return <Card className="border-white/10 bg-white/[0.03]"><CardHeader><CardTitle className="flex items-center gap-2"><Database className="h-4 w-4" /> Recent persisted alerts</CardTitle></CardHeader><CardContent><Table><TableHeader><TableRow><TableHead>Scenario</TableHead><TableHead>Events</TableHead><TableHead>Seen</TableHead></TableRow></TableHeader><TableBody>{alerts.map((row) => <TableRow key={row.id}><TableCell>{row.scenario}</TableCell><TableCell>{formatNumber(row.events)}</TableCell><TableCell>{relativeTime(row.createdAt)}</TableCell></TableRow>)}</TableBody></Table></CardContent></Card>;
}
