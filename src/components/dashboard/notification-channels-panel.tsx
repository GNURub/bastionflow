"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { BellRing, Plus, Send, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ApiEnvelope, CreateNotificationChannelInput, NotificationChannel, NotificationChannelType, NotificationWorkerStatus, Severity } from "@/lib/crowdsec/types";

const severities: Severity[] = ["info", "low", "medium", "high", "critical"];
const types: NotificationChannelType[] = ["slack", "discord", "webhook"];

async function getChannels(): Promise<NotificationChannel[]> {
  const response = await fetch("/api/notifications", { cache: "no-store" });
  if (!response.ok) throw new Error(`notifications returned ${response.status}`);
  return ((await response.json()) as ApiEnvelope<NotificationChannel[]>).data;
}

async function getWorkerStatus(): Promise<NotificationWorkerStatus> {
  const response = await fetch("/api/notifications/worker", { cache: "no-store" });
  if (!response.ok) throw new Error(`notification worker status returned ${response.status}`);
  return ((await response.json()) as ApiEnvelope<NotificationWorkerStatus>).data;
}

export function NotificationChannelsPanel(): React.ReactElement {
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [worker, setWorker] = useState<NotificationWorkerStatus | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<CreateNotificationChannelInput>({ name: "", type: "slack", url: "", enabled: true, minSeverity: "high" });
  const refreshInFlight = useRef(false);
  const workerStatusInFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    workerStatusInFlight.current = true;
    try {
      const [nextChannels, nextWorker] = await Promise.all([getChannels(), getWorkerStatus()]);
      setChannels(nextChannels);
      setWorker(nextWorker);
    } finally {
      refreshInFlight.current = false;
      workerStatusInFlight.current = false;
    }
  }, []);

  const refreshWorkerStatus = useCallback(async () => {
    if (refreshInFlight.current || workerStatusInFlight.current) return;
    workerStatusInFlight.current = true;
    try {
      setWorker(await getWorkerStatus());
    } catch {
      setWorker((current) => current ? { ...current, online: false } : null);
    } finally {
      workerStatusInFlight.current = false;
    }
  }, []);

  useEffect(() => {
    void refresh().catch((error: unknown) => setMessage(error instanceof Error ? error.message : "Unable to load notification channels"));
    const timer = setInterval(() => void refreshWorkerStatus(), 10_000);
    return () => clearInterval(timer);
  }, [refresh, refreshWorkerStatus]);

  const workerOnline = worker?.online === true;

  async function create(): Promise<void> {
    setBusy(true);
    setMessage(null);
    try {
      const response = await fetch("/api/notifications", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(form) });
      const body = await response.json().catch(() => ({})) as { error?: string };
      if (!response.ok) throw new Error(body.error ?? `Create failed with ${response.status}`);
      setForm({ name: "", type: form.type, url: "", enabled: true, minSeverity: form.minSeverity });
      setOpen(false);
      setMessage("Notification channel saved. Use Test before relying on it.");
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to create notification channel");
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string): Promise<void> {
    setMessage(null);
    const response = await fetch(`/api/notifications/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!response.ok) setMessage("Unable to delete notification channel");
    await refresh();
  }

  async function test(id: string): Promise<void> {
    setMessage(null);
    const response = await fetch(`/api/notifications/${encodeURIComponent(id)}/test`, { method: "POST" });
    const body = await response.json().catch(() => ({})) as { data?: { ok?: boolean; error?: string } };
    setMessage(body.data?.ok ? "Test notification sent." : body.data?.error ?? `Test failed with ${response.status}`);
    await refresh();
  }

  return (
    <Card className="border-white/10 bg-white/[0.03]">
      <CardHeader className="gap-3 md:flex-row md:items-start md:justify-between">
        <div className="space-y-1.5">
          <CardTitle className="flex flex-wrap items-center gap-2"><BellRing className="h-4 w-4 text-amber-300" /> Notification routes <Badge variant={workerOnline ? "success" : "secondary"}>{workerOnline ? "worker online" : "worker disabled"}</Badge></CardTitle>
          <CardDescription>{workerOnline ? "Slack, Discord or a generic webhook. The backend worker sends events even when the dashboard is closed." : "The bastionflow-notification-worker service is not active; background notifications are disabled."}</CardDescription>
        </div>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger>
            <Button size="sm" type="button" disabled={!workerOnline}><Plus className="h-4 w-4" /> Add route</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add notification route</DialogTitle>
              <DialogDescription>Configure Slack, Discord or a generic webhook. The URL is stored in SQLite and only shown masked.</DialogDescription>
            </DialogHeader>
            <div className="grid gap-3">
              <Input placeholder="Name" value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} />
              <select className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring" value={form.type} onChange={(event) => setForm((current) => ({ ...current, type: event.target.value as NotificationChannelType }))}>{types.map((type) => <option key={type} value={type}>{type}</option>)}</select>
              <Input placeholder="Webhook URL" value={form.url} onChange={(event) => setForm((current) => ({ ...current, url: event.target.value }))} />
              <select className="h-9 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring" value={form.minSeverity} onChange={(event) => setForm((current) => ({ ...current, minSeverity: event.target.value as Severity }))}>{severities.map((severity) => <option key={severity} value={severity}>min {severity}</option>)}</select>
              <label className="flex items-center gap-2 rounded-lg border border-white/10 bg-black/20 p-3 text-sm">
                <input type="checkbox" className="h-4 w-4 accent-emerald-400" checked={form.enabled} onChange={(event) => setForm((current) => ({ ...current, enabled: event.target.checked }))} />
                Enabled immediately
              </label>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
                <Button onClick={() => void create()} disabled={!workerOnline || busy || !form.name || !form.url}>{busy ? "Saving…" : "Save route"}</Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </CardHeader>
      <CardContent className="space-y-4">
        {!workerOnline && <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-100">Notification worker is optional and currently offline. Start it with <span className="font-mono">docker compose --profile notifications ... up -d</span> to enable background delivery.</div>}
        {message && <p className="text-sm text-amber-200">{message}</p>}
        <div className="overflow-x-auto">
          <Table>
            <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>URL</TableHead><TableHead>Min severity</TableHead><TableHead>Last test</TableHead><TableHead /></TableRow></TableHeader>
            <TableBody>
              {channels.map((channel) => (
                <TableRow key={channel.id}>
                  <TableCell className="font-medium">{channel.name}</TableCell>
                  <TableCell><Badge variant="secondary">{channel.type}</Badge></TableCell>
                  <TableCell className="max-w-[320px] truncate font-mono text-xs">{channel.urlMasked}</TableCell>
                  <TableCell><Badge variant={channel.minSeverity === "critical" || channel.minSeverity === "high" ? "destructive" : "warning"}>{channel.minSeverity}</Badge></TableCell>
                  <TableCell className="text-xs text-muted-foreground">{channel.lastError ? `error: ${channel.lastError}` : channel.lastTestAt ?? "not tested"}</TableCell>
                  <TableCell className="text-right"><Button size="sm" variant="outline" onClick={() => void test(channel.id)} disabled={!workerOnline}><Send className="h-3.5 w-3.5" /> Test</Button><Button size="sm" variant="ghost" onClick={() => void remove(channel.id)} disabled={!workerOnline}><Trash2 className="h-3.5 w-3.5" /></Button></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
