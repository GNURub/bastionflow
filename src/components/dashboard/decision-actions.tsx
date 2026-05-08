"use client";

import { useState } from "react";
import { ShieldBan, ShieldCheck, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function DecisionActions({ onChanged }: { onChanged: () => void }): React.ReactElement {
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("operator decision");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function create(mode: "manual" | "automatic"): Promise<void> {
    setBusy(true);
    setMessage(null);
    try {
      const response = await fetch("/api/decisions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ scope: "ip", value, type: "ban", duration: mode === "automatic" ? "2h" : "4h", reason, mode, evidenceCount: mode === "automatic" ? 3 : undefined })
      });
      if (!response.ok) throw new Error((await response.json() as { error?: string }).error ?? "Decision failed");
      setMessage(mode === "automatic" ? "Auto-rule accepted and decision sent" : "Decision sent");
      setValue("");
      onChanged();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to create decision");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
      <div className="mb-3 flex items-center gap-2 text-sm font-medium"><ShieldBan className="h-4 w-4 text-red-400" /> Block / unblock operations</div>
      <div className="grid gap-2 sm:grid-cols-[1fr_1fr_auto_auto]">
        <Input placeholder="IPv4 address" value={value} onChange={(event) => setValue(event.target.value)} />
        <Input placeholder="Reason" value={reason} onChange={(event) => setReason(event.target.value)} />
        <Button disabled={busy || !value} onClick={() => void create("manual")}><ShieldCheck className="h-4 w-4" /> Manual ban</Button>
        <Button variant="outline" disabled={busy || !value} onClick={() => void create("automatic")}><Sparkles className="h-4 w-4" /> Auto limited</Button>
      </div>
      {message && <p className="mt-2 text-xs text-muted-foreground">{message}</p>}
    </div>
  );
}
