"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Gauge, Plus, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ApiEnvelope, CreateEdgeRateLimitRuleInput, EdgeRateLimitRule, EdgeRateLimitTarget } from "@/lib/crowdsec/types";
import { relativeTime } from "@/lib/utils";

const targetOptions: Array<{ value: EdgeRateLimitTarget; label: string; description: string; placeholder: string }> = [
  { value: "ip", label: "Source IP", description: "Exact IPv4, CIDR, or * for all sources.", placeholder: "198.51.100.10 or 198.51.100.0/24" },
  { value: "path", label: "Path prefix", description: "Per source IP for matching URL path prefixes.", placeholder: "/admin" },
  { value: "service", label: "Service / host", description: "Per source IP for a forwarded host. Supports *.example.com.", placeholder: "whoami.localhost" }
];

const defaultForm: CreateEdgeRateLimitRuleInput = {
  name: "Protect noisy edge",
  target: "path",
  value: "/",
  windowSeconds: 60,
  maxRequests: 60,
  enabled: true
};

async function fetchRules(): Promise<EdgeRateLimitRule[]> {
  const response = await fetch("/api/edge-rate-limits", { cache: "no-store" });
  if (!response.ok) throw new Error(`edge-rate-limits returned ${response.status}`);
  return ((await response.json()) as ApiEnvelope<EdgeRateLimitRule[]>).data;
}

export function EdgeRateLimitRulesPanel(): React.ReactElement {
  const [rules, setRules] = useState<EdgeRateLimitRule[]>([]);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<CreateEdgeRateLimitRuleInput>(defaultForm);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const selectedTarget = useMemo(() => targetOptions.find((option) => option.value === form.target) ?? targetOptions[0]!, [form.target]);
  const refresh = useCallback(async () => { setRules(await fetchRules()); }, []);

  useEffect(() => { void refresh().catch((error: unknown) => setMessage(error instanceof Error ? error.message : "Unable to load rate limit rules")); }, [refresh]);

  async function createRule(): Promise<void> {
    setBusy(true);
    setMessage(null);
    try {
      const response = await fetch("/api/edge-rate-limits", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(form) });
      const body = await response.json().catch(() => ({})) as { error?: string; issues?: { fieldErrors?: Record<string, string[]> } };
      if (!response.ok) {
        const firstIssue = body.issues?.fieldErrors ? Object.values(body.issues.fieldErrors).flat()[0] : undefined;
        throw new Error(firstIssue ?? body.error ?? `Create failed with ${response.status}`);
      }
      setOpen(false);
      setForm((current) => ({ ...defaultForm, target: current.target }));
      setMessage("Rate limit rule saved. It is enforced by Edge Gate on the next matching request.");
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to create rate limit rule");
    } finally {
      setBusy(false);
    }
  }

  async function removeRule(id: string): Promise<void> {
    setMessage(null);
    const response = await fetch(`/api/edge-rate-limits/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!response.ok) setMessage(`Unable to delete rule (${response.status})`);
    await refresh();
  }

  return (
    <Card className="border-white/10 bg-white/[0.03]">
      <CardHeader className="gap-3 md:flex-row md:items-start md:justify-between">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2"><Gauge className="h-4 w-4 text-amber-300" /> Edge rate limits</CardTitle>
          <CardDescription>Functional forwardAuth rules: by IP/CIDR, path prefix or service/host. When the window is exceeded, Edge Gate responds with 429.</CardDescription>
        </div>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger>
            <Button size="sm" type="button"><Plus className="h-4 w-4" /> Add rule</Button>
          </DialogTrigger>
          <DialogContent className="max-w-3xl">
            <DialogHeader>
              <DialogTitle>Add edge rate limit</DialogTitle>
              <DialogDescription>These rules apply in real time to any router using the <span className="font-mono">edge-gate@file</span>.</DialogDescription>
            </DialogHeader>
            <div className="grid gap-4">
              <label className="grid gap-2">
                <span className="text-sm font-medium">Name</span>
                <Input value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} />
              </label>
              <div className="grid gap-2 md:grid-cols-3">
                {targetOptions.map((option) => (
                  <button key={option.value} type="button" className={`rounded-lg border p-3 text-left transition ${form.target === option.value ? "border-amber-400/70 bg-amber-400/10" : "border-white/10 bg-black/20 hover:border-white/25"}`} onClick={() => setForm((current) => ({ ...current, target: option.value, value: option.value === "path" ? "/" : "" }))}>
                    <span className="block text-sm font-medium">{option.label}</span>
                    <span className="mt-1 block text-xs text-muted-foreground">{option.description}</span>
                  </button>
                ))}
              </div>
              <label className="grid gap-2">
                <span className="text-sm font-medium">Match value</span>
                <Input value={form.value} placeholder={selectedTarget.placeholder} onChange={(event) => setForm((current) => ({ ...current, value: event.target.value }))} />
              </label>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="grid gap-2">
                  <span className="text-sm font-medium">Window seconds</span>
                  <Input type="number" min={1} max={86_400} value={form.windowSeconds} onChange={(event) => setForm((current) => ({ ...current, windowSeconds: Number(event.target.value) }))} />
                </label>
                <label className="grid gap-2">
                  <span className="text-sm font-medium">Max requests per window</span>
                  <Input type="number" min={1} value={form.maxRequests} onChange={(event) => setForm((current) => ({ ...current, maxRequests: Number(event.target.value) }))} />
                </label>
              </div>
              <label className="flex items-center gap-2 rounded-lg border border-white/10 bg-black/20 p-3 text-sm">
                <input type="checkbox" className="h-4 w-4 accent-emerald-400" checked={form.enabled} onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))} />
                Enabled immediately
              </label>
              {message && <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-100">{message}</div>}
              <div className="flex justify-end gap-2">
                <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
                <Button type="button" onClick={() => void createRule()} disabled={busy || !form.name || !form.value}>{busy ? "Saving…" : "Save rule"}</Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </CardHeader>
      <CardContent className="space-y-3">
        {message && !open && <p className="text-sm text-amber-200">{message}</p>}
        <div className="overflow-x-auto">
          <Table>
            <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Target</TableHead><TableHead>Value</TableHead><TableHead>Limit</TableHead><TableHead>Updated</TableHead><TableHead /></TableRow></TableHeader>
            <TableBody>
              {rules.map((rule) => (
                <TableRow key={rule.id}>
                  <TableCell className="font-medium">{rule.name}</TableCell>
                  <TableCell><Badge variant={rule.enabled ? "success" : "secondary"}>{rule.target}</Badge></TableCell>
                  <TableCell className="font-mono text-xs">{rule.value}</TableCell>
                  <TableCell>{rule.maxRequests}/{rule.windowSeconds}s</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{relativeTime(rule.updatedAt)}</TableCell>
                  <TableCell className="text-right"><Button size="sm" variant="ghost" onClick={() => void removeRule(rule.id)}><Trash2 className="h-3.5 w-3.5" /></Button></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {rules.length === 0 && <div className="rounded-lg border border-white/10 bg-black/20 p-6 text-center text-sm text-muted-foreground">No dynamic edge rate limit rules yet.</div>}
        </div>
      </CardContent>
    </Card>
  );
}
