import Link from "next/link";
import type { ReactNode } from "react";
import { Globe2, Network, RadioTower, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { CrowdSecAlert, CrowdSecDecision } from "@/lib/crowdsec/types";
import { formatNumber } from "@/lib/utils";

type CountryRow = { country: string; flag: string; alerts: number; events: number; topIp: string; blocked: number };
type IpRow = { ip: string; country: string; flag: string; alerts: number; events: number; scenarios: number; blocked: boolean };
type ScenarioRow = { scenario: string; alerts: number; events: number; topCountry: string; severity: "critical" | "high" | "medium" | "low" | "info" };

function countryFlag(country?: string): string {
  const code = country?.trim().toUpperCase();
  if (!code || code.length !== 2) return "🏴";
  const first = 0x1f1e6 + code.charCodeAt(0) - 65;
  const second = 0x1f1e6 + code.charCodeAt(1) - 65;
  return String.fromCodePoint(first, second);
}

function countryLabel(country?: string): string {
  const code = country?.trim().toUpperCase();
  return code && code.length === 2 ? code : "Unknown";
}

function severityRank(value: CrowdSecAlert["severity"]): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[value];
}

function aggregateCountries(alerts: readonly CrowdSecAlert[], decisions: readonly CrowdSecDecision[]): CountryRow[] {
  const blockedValues = new Set(decisions.map((decision) => decision.value));
  const countries = new Map<string, { alerts: number; events: number; ips: Map<string, number>; blocked: number }>();
  for (const alert of alerts) {
    const country = countryLabel(alert.sourceCountry);
    const current = countries.get(country) ?? { alerts: 0, events: 0, ips: new Map<string, number>(), blocked: 0 };
    current.alerts += 1;
    current.events += alert.events;
    if (alert.sourceIp) {
      current.ips.set(alert.sourceIp, (current.ips.get(alert.sourceIp) ?? 0) + alert.events);
      if (blockedValues.has(alert.sourceIp)) current.blocked += 1;
    }
    countries.set(country, current);
  }
  return [...countries.entries()]
    .map(([country, value]) => ({
      country,
      flag: countryFlag(country),
      alerts: value.alerts,
      events: value.events,
      blocked: value.blocked,
      topIp: [...value.ips.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "-"
    }))
    .sort((a, b) => b.events - a.events)
    .slice(0, 6);
}

function aggregateIps(alerts: readonly CrowdSecAlert[], decisions: readonly CrowdSecDecision[]): IpRow[] {
  const blockedValues = new Set(decisions.map((decision) => decision.value));
  const ips = new Map<string, { country: string; alerts: number; events: number; scenarios: Set<string> }>();
  for (const alert of alerts) {
    if (!alert.sourceIp) continue;
    const current = ips.get(alert.sourceIp) ?? { country: countryLabel(alert.sourceCountry), alerts: 0, events: 0, scenarios: new Set<string>() };
    current.alerts += 1;
    current.events += alert.events;
    current.scenarios.add(alert.scenario);
    ips.set(alert.sourceIp, current);
  }
  return [...ips.entries()]
    .map(([ip, value]) => ({ ip, country: value.country, flag: countryFlag(value.country), alerts: value.alerts, events: value.events, scenarios: value.scenarios.size, blocked: blockedValues.has(ip) }))
    .sort((a, b) => b.events - a.events)
    .slice(0, 8);
}

function aggregateScenarios(alerts: readonly CrowdSecAlert[]): ScenarioRow[] {
  const scenarios = new Map<string, { alerts: number; events: number; countries: Map<string, number>; severity: CrowdSecAlert["severity"] }>();
  for (const alert of alerts) {
    const current = scenarios.get(alert.scenario) ?? { alerts: 0, events: 0, countries: new Map<string, number>(), severity: alert.severity };
    current.alerts += 1;
    current.events += alert.events;
    const country = countryLabel(alert.sourceCountry);
    current.countries.set(country, (current.countries.get(country) ?? 0) + alert.events);
    if (severityRank(alert.severity) > severityRank(current.severity)) current.severity = alert.severity;
    scenarios.set(alert.scenario, current);
  }
  return [...scenarios.entries()]
    .map(([scenario, value]) => ({ scenario, alerts: value.alerts, events: value.events, severity: value.severity, topCountry: [...value.countries.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "Unknown" }))
    .sort((a, b) => b.events - a.events)
    .slice(0, 6);
}

function concentration(events: number, total: number): string {
  if (total <= 0) return "0%";
  return `${Math.round((events / total) * 100)}%`;
}

export function IntelligenceCards({ alerts, decisions }: { alerts: readonly CrowdSecAlert[]; decisions: readonly CrowdSecDecision[] }): React.ReactElement {
  const countries = aggregateCountries(alerts, decisions);
  const ips = aggregateIps(alerts, decisions);
  const scenarios = aggregateScenarios(alerts);
  const totalEvents = alerts.reduce((sum, alert) => sum + alert.events, 0);
  const topCountry = countries[0];
  const topIp = ips[0];
  const uniqueCountries = new Set(alerts.map((alert) => countryLabel(alert.sourceCountry))).size;
  const uniqueIps = ips.length;

  return (
    <section className="grid gap-6 xl:grid-cols-[1fr_1.1fr]">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-1">
        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Globe2 className="h-4 w-4" /> Attack geography</CardTitle>
            <CardDescription>Countries with the most normalized events from CrowdSec.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {countries.map((row) => (
              <div key={row.country} className="space-y-1 rounded-lg border border-white/10 bg-black/20 p-3">
                <div className="flex items-center justify-between gap-2 text-sm"><span className="flex items-center gap-2"><span className="text-lg">{row.flag}</span>{row.country}</span><span className="font-medium">{formatNumber(row.events)}</span></div>
                <div className="h-1.5 overflow-hidden rounded-full bg-white/10"><div className="h-full rounded-full bg-red-400" style={{ width: concentration(row.events, totalEvents) }} /></div>
                <div className="flex items-center justify-between text-xs text-muted-foreground"><span>Top IP: {row.topIp !== "-" ? <Link className="font-mono text-foreground underline-offset-4 hover:text-amber-300 hover:underline" href={`/ip/${encodeURIComponent(row.topIp)}`}>{row.topIp}</Link> : "-"}</span><span>{row.alerts} alerts · {row.blocked} blocked</span></div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><RadioTower className="h-4 w-4" /> Useful signals</CardTitle>
            <CardDescription>Derived metrics to prioritize investigation.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 text-sm">
            <Signal label="Top country pressure" value={topCountry ? `${topCountry.flag} ${topCountry.country}` : "-"} detail={topCountry ? `${concentration(topCountry.events, totalEvents)} of events` : "No country data"} />
            <Signal label="Noisiest source IP" value={topIp ? <Link className="font-mono underline-offset-4 hover:text-amber-300 hover:underline" href={`/ip/${encodeURIComponent(topIp.ip)}`}>{topIp.ip}</Link> : "-"} detail={topIp ? `${formatNumber(topIp.events)} events · ${topIp.scenarios} scenarios` : "No IP data"} />
            <Signal label="Observed spread" value={`${uniqueCountries} countries`} detail={`${uniqueIps} ranked source IPs visible`} />
            <Signal label="Decision coverage" value={`${decisions.length} active`} detail="Current remediation objects from CrowdSec" />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6">
        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader><CardTitle className="flex items-center gap-2"><Network className="h-4 w-4" /> Top source IPs</CardTitle><CardDescription>Source IPs with the most requests/events.</CardDescription></CardHeader>
          <CardContent className="overflow-x-auto">
            <Table><TableHeader><TableRow><TableHead>IP</TableHead><TableHead>Country</TableHead><TableHead>Events</TableHead><TableHead>Scenarios</TableHead><TableHead>Status</TableHead></TableRow></TableHeader><TableBody>
              {ips.map((row) => <TableRow key={row.ip}><TableCell className="font-mono text-xs"><Link className="underline-offset-4 hover:text-amber-300 hover:underline" href={`/ip/${encodeURIComponent(row.ip)}`}>{row.ip}</Link></TableCell><TableCell>{row.flag} {row.country}</TableCell><TableCell>{formatNumber(row.events)}</TableCell><TableCell>{row.scenarios}</TableCell><TableCell><Badge variant={row.blocked ? "destructive" : "secondary"}>{row.blocked ? "blocked" : "observed"}</Badge></TableCell></TableRow>)}
            </TableBody></Table>
          </CardContent>
        </Card>

        <Card className="border-white/10 bg-white/[0.03]">
          <CardHeader><CardTitle className="flex items-center gap-2"><ShieldAlert className="h-4 w-4" /> Top scenarios</CardTitle><CardDescription>Patterns generating the most noise right now.</CardDescription></CardHeader>
          <CardContent className="overflow-x-auto">
            <Table><TableHeader><TableRow><TableHead>Scenario</TableHead><TableHead>Top country</TableHead><TableHead>Events</TableHead><TableHead>Severity</TableHead></TableRow></TableHeader><TableBody>
              {scenarios.map((row) => <TableRow key={row.scenario}><TableCell className="max-w-[320px] truncate">{row.scenario}</TableCell><TableCell>{countryFlag(row.topCountry)} {row.topCountry}</TableCell><TableCell>{formatNumber(row.events)}</TableCell><TableCell><Badge variant={row.severity === "critical" || row.severity === "high" ? "destructive" : row.severity === "medium" ? "warning" : "secondary"}>{row.severity}</Badge></TableCell></TableRow>)}
            </TableBody></Table>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

function Signal({ label, value, detail }: { label: string; value: ReactNode; detail: string }): React.ReactElement {
  return <div className="rounded-lg border border-white/10 bg-black/20 p-3"><div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div><div className="mt-1 font-medium">{value}</div><div className="mt-1 text-xs text-muted-foreground">{detail}</div></div>;
}
