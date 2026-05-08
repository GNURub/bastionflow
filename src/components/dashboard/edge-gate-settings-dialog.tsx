"use client";

import { useEffect, useState } from "react";
import { Settings2, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { ApiEnvelope, EdgeGateSettings } from "@/lib/crowdsec/types";

interface FormState extends EdgeGateSettings {
  password: string;
}

const emptyForm: FormState = {
  enabled: true,
  botChallengeEnabled: true,
  authEnabled: false,
  passwordConfigured: false,
  password: "",
  maxAgeSeconds: 86_400
};

async function fetchSettings(): Promise<EdgeGateSettings> {
  const response = await fetch("/api/edge-gate/settings", { cache: "no-store" });
  if (!response.ok) throw new Error(`edge-gate settings returned ${response.status}`);
  return ((await response.json()) as ApiEnvelope<EdgeGateSettings>).data;
}

function ToggleRow({ title, description, checked, onChange }: { title: string; description: string; checked: boolean; onChange: (checked: boolean) => void }): React.ReactElement {
  return (
    <label className="flex cursor-pointer items-start justify-between gap-4 rounded-lg border border-white/10 bg-black/20 p-3">
      <span>
        <span className="block text-sm font-medium">{title}</span>
        <span className="mt-1 block text-xs text-muted-foreground">{description}</span>
      </span>
      <input
        type="checkbox"
        className="mt-1 h-4 w-4 accent-emerald-400"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
    </label>
  );
}

export function EdgeGateSettingsDialog({ onSaved }: { onSaved?: () => void }): React.ReactElement {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<FormState>(emptyForm);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    let active = true;
    setLoading(true);
    setError(null);
    fetchSettings()
      .then((settings) => {
        if (!active) return;
        setForm({ ...settings, password: "" });
      })
      .catch((err: unknown) => { if (active) setError(err instanceof Error ? err.message : "Unable to load Edge Gate settings"); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [open]);

  async function save(): Promise<void> {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      const response = await fetch("/api/edge-gate/settings", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          enabled: form.enabled,
          botChallengeEnabled: form.botChallengeEnabled,
          authEnabled: form.authEnabled,
          password: form.password,
          maxAgeSeconds: form.maxAgeSeconds
        })
      });
      const payload = await response.json().catch(() => ({})) as Partial<ApiEnvelope<EdgeGateSettings>> & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? `Unable to save settings (${response.status})`);
      if (payload.data) setForm({ ...payload.data, password: "" });
      setMessage("Edge Gate configuration saved. New requests will use these settings immediately.");
      onSaved?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to save Edge Gate settings");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger>
        <Button variant="outline" size="sm" type="button"><Settings2 className="h-4 w-4" /> Configure Edge Gate</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-300" /> Edge Gate settings</DialogTitle>
          <DialogDescription>Configure Traefik forwardAuth access controls without touching environment variables. Settings are persisted in SQLite.</DialogDescription>
        </DialogHeader>

        {loading ? <div className="rounded-lg border border-white/10 bg-black/20 p-4 text-sm text-muted-foreground">Loading settings…</div> : (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge variant={form.enabled ? "success" : "secondary"}>{form.enabled ? "Edge Gate enabled" : "Edge Gate disabled"}</Badge>
              <Badge variant={form.passwordConfigured ? "success" : "warning"}>{form.passwordConfigured ? "Password configured" : "No password"}</Badge>
            </div>

            <div className="grid gap-3">
              <ToggleRow
                title="Enable Edge Gate"
                description="Allows Traefik to query /api/edge-gate/verify before delivering traffic to the protected service."
                checked={form.enabled}
                onChange={(enabled) => setForm((current) => ({ ...current, enabled }))}
              />
              <ToggleRow
                title="Browser anti-bot challenge"
                description="Requires a lightweight JavaScript check before creating the access cookie. Useful against simple bots and noisy scanners."
                checked={form.botChallengeEnabled}
                onChange={(botChallengeEnabled) => setForm((current) => ({ ...current, botChallengeEnabled }))}
              />
              <ToggleRow
                title="Password challenge"
                description="Adds a second manual barrier for sensitive areas. The password is never exposed through the APIs."
                checked={form.authEnabled}
                onChange={(authEnabled) => setForm((current) => ({ ...current, authEnabled }))}
              />
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <label className="space-y-2">
                <span className="text-sm font-medium">Password</span>
                <Input
                  type="password"
                  value={form.password}
                  placeholder={form.passwordConfigured ? "Leave blank to keep current password" : "Set a password"}
                  onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                />
              </label>
              <label className="space-y-2">
                <span className="text-sm font-medium">Cookie TTL seconds</span>
                <Input
                  type="number"
                  min={300}
                  max={2_592_000}
                  value={form.maxAgeSeconds}
                  onChange={(event) => setForm((current) => ({ ...current, maxAgeSeconds: Number(event.target.value) }))}
                />
              </label>
            </div>

            {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">{error}</div>}
            {message && <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-200">{message}</div>}

            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
              <Button type="button" onClick={() => void save()} disabled={saving}>{saving ? "Saving…" : "Save settings"}</Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
