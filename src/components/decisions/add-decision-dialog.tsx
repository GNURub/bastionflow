"use client";

import { useMemo, useState } from "react";
import { Ban, Clock3, Plus, ShieldAlert, SlidersHorizontal, Target } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import type { CreateDecisionInput, DecisionScope, DecisionType } from "@/lib/crowdsec/types";
import { cn } from "@/lib/utils";

type WritableDecisionType = Exclude<DecisionType, "unknown">;

interface Option<T extends string> {
  value: T;
  label: string;
  description: string;
  placeholder?: string;
}

const scopeOptions: Array<Option<DecisionScope>> = [
  { value: "ip", label: "IP address", description: "Block one IPv4 source.", placeholder: "203.0.113.10" },
  { value: "range", label: "CIDR range", description: "Block a network range.", placeholder: "203.0.113.0/24" },
  { value: "country", label: "Country", description: "Apply to an ISO country code.", placeholder: "NL" },
  { value: "as", label: "ASN", description: "Apply to an autonomous system.", placeholder: "AS12345" },
  { value: "username", label: "Username", description: "Useful for app-level remediations.", placeholder: "alice" },
  { value: "session", label: "Session", description: "Useful for session-level remediations.", placeholder: "session-id" }
];

const typeOptions: Array<Option<WritableDecisionType>> = [
  { value: "ban", label: "Ban", description: "Hard block. Best for confirmed hostile traffic." },
  { value: "captcha", label: "Captcha", description: "Challenge instead of hard blocking when supported by bouncers." },
  { value: "throttle", label: "Throttle", description: "Rate-limit noisy clients when supported by bouncers." },
  { value: "enforce_mfa", label: "Enforce MFA", description: "App-level response when the protected app supports it." }
];

const durationOptions = [
  { value: "30m", label: "30 minutes", description: "Short containment" },
  { value: "2h", label: "2 hours", description: "Safe default" },
  { value: "4h", label: "4 hours", description: "Operator ban" },
  { value: "1d", label: "1 day", description: "Persistent attack" }
] as const;

const modeOptions = [
  { value: "manual", label: "Manual", description: "Operator-driven. No auto-rule evidence gate." },
  { value: "automatic", label: "Automatic guarded", description: "Uses allowlist, evidence and duration safety checks." }
] as const;

function OptionCard<T extends string>({ option, selected, onSelect }: { option: Option<T>; selected: boolean; onSelect: (value: T) => void }): React.ReactElement {
  return (
    <button
      type="button"
      className={cn("rounded-lg border p-3 text-left transition", selected ? "border-amber-400/70 bg-amber-400/10" : "border-white/10 bg-black/20 hover:border-white/25 hover:bg-white/[0.04]")}
      onClick={() => onSelect(option.value)}
    >
      <span className="block text-sm font-medium">{option.label}</span>
      <span className="mt-1 block text-xs text-muted-foreground">{option.description}</span>
    </button>
  );
}

export function AddDecisionDialog({ onCreated }: { onCreated: () => Promise<void> | void }): React.ReactElement {
  const [open, setOpen] = useState(false);
  const [scope, setScope] = useState<DecisionScope>("ip");
  const [type, setType] = useState<WritableDecisionType>("ban");
  const [duration, setDuration] = useState("2h");
  const [mode, setMode] = useState<CreateDecisionInput["mode"]>("manual");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("operator decision");
  const [evidenceCount, setEvidenceCount] = useState(3);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const selectedScope = useMemo(() => scopeOptions.find((option) => option.value === scope) ?? scopeOptions[0]!, [scope]);
  const canSubmit = value.trim().length > 0 && reason.trim().length >= 3 && !busy;

  async function createDecision(): Promise<void> {
    setBusy(true);
    setMessage(null);
    try {
      const payload: CreateDecisionInput = {
        scope,
        value: value.trim(),
        type,
        duration,
        reason: reason.trim(),
        mode,
        evidenceCount: mode === "automatic" ? evidenceCount : undefined
      };
      const response = await fetch("/api/decisions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload)
      });
      const body = await response.json().catch(() => ({})) as { error?: string; issues?: unknown };
      if (!response.ok) throw new Error(body.error ?? `Decision create failed with ${response.status}`);
      setValue("");
      setReason("operator decision");
      setOpen(false);
      await onCreated();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to create decision");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger>
        <Button variant="outline" type="button"><Plus className="h-4 w-4" /> Add a decision</Button>
      </DialogTrigger>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><ShieldAlert className="h-4 w-4 text-amber-300" /> Add remediation decision</DialogTitle>
          <DialogDescription>Define the target, remediation type and duration. The backend validates allowlists, formats and limits before sending anything to CrowdSec.</DialogDescription>
        </DialogHeader>

        <div className="grid gap-5">
          <section className="space-y-2">
            <div className="flex items-center gap-2 text-sm font-medium"><Target className="h-4 w-4 text-muted-foreground" /> Target scope</div>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {scopeOptions.map((option) => <OptionCard key={option.value} option={option} selected={scope === option.value} onSelect={(next) => { setScope(next); setValue(""); }} />)}
            </div>
          </section>

          <section className="grid gap-3 md:grid-cols-[1fr_1fr]">
            <label className="space-y-2">
              <span className="text-sm font-medium">Target value</span>
              <Input placeholder={selectedScope.placeholder} value={value} onChange={(event) => setValue(event.target.value)} />
            </label>
            <label className="space-y-2">
              <span className="text-sm font-medium">Reason</span>
              <Input placeholder="http-probing, manual incident response…" value={reason} onChange={(event) => setReason(event.target.value)} />
            </label>
          </section>

          <section className="space-y-2">
            <div className="flex items-center gap-2 text-sm font-medium"><Ban className="h-4 w-4 text-muted-foreground" /> Remediation type</div>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              {typeOptions.map((option) => <OptionCard key={option.value} option={option} selected={type === option.value} onSelect={setType} />)}
            </div>
          </section>

          <section className="grid gap-4 lg:grid-cols-[1fr_260px]">
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-medium"><Clock3 className="h-4 w-4 text-muted-foreground" /> Duration</div>
              <div className="grid gap-2 sm:grid-cols-4">
                {durationOptions.map((option) => <OptionCard key={option.value} option={option} selected={duration === option.value} onSelect={setDuration} />)}
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-medium"><SlidersHorizontal className="h-4 w-4 text-muted-foreground" /> Execution mode</div>
              <div className="grid gap-2">
                {modeOptions.map((option) => <OptionCard key={option.value} option={option} selected={mode === option.value} onSelect={setMode} />)}
              </div>
            </div>
          </section>

          {mode === "automatic" && (
            <label className="grid gap-2 rounded-lg border border-amber-500/20 bg-amber-500/10 p-3 md:grid-cols-[1fr_180px] md:items-center">
              <span>
                <span className="block text-sm font-medium">Correlated evidence count</span>
                <span className="mt-1 block text-xs text-muted-foreground">It must meet the minimum configured in the CrowdSec panel before accepting automatic decisions.</span>
              </span>
              <Input type="number" min={0} value={evidenceCount} onChange={(event) => setEvidenceCount(Number(event.target.value))} />
            </label>
          )}

          <div className="flex flex-col gap-3 border-t border-white/10 pt-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-wrap gap-2 text-xs">
              <Badge variant="secondary">{scope}</Badge>
              <Badge variant={type === "ban" ? "destructive" : "warning"}>{type}</Badge>
              <Badge variant="outline">{duration}</Badge>
              <Badge variant={mode === "automatic" ? "warning" : "secondary"}>{mode}</Badge>
            </div>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
              <Button type="button" onClick={() => void createDecision()} disabled={!canSubmit}>{busy ? "Sending…" : "Create decision"}</Button>
            </div>
          </div>
          {message && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">{message}</div>}
        </div>
      </DialogContent>
    </Dialog>
  );
}
