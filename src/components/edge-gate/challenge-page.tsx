"use client";

import { useEffect, useMemo, useState } from "react";
import { LockKeyhole, ShieldCheck, ShieldQuestion } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

export function EdgeGateChallengePage({ next, required }: { next: string; required: string[] }): React.ReactElement {
  const [botReady, setBotReady] = useState(!required.includes("bot"));
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const needsAuth = required.includes("auth");

  const safeNext = useMemo(() => {
    try {
      const parsed = new URL(next);
      return parsed.toString();
    } catch {
      return "/";
    }
  }, [next]);

  useEffect(() => {
    if (!required.includes("bot")) return;
    const timer = setTimeout(() => {
      fetch("/api/edge-gate/pass-bot", { method: "POST" })
        .then((response) => {
          if (!response.ok) throw new Error(`Browser challenge failed with ${response.status}`);
          setBotReady(true);
          if (!needsAuth) window.location.assign(safeNext);
        })
        .catch((error: unknown) => setMessage(error instanceof Error ? error.message : "Browser challenge failed"));
    }, 900);
    return () => clearTimeout(timer);
  }, [needsAuth, required, safeNext]);

  async function login(): Promise<void> {
    setBusy(true);
    setMessage(null);
    try {
      const response = await fetch("/api/edge-gate/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ password }) });
      const body = await response.json().catch(() => ({})) as { error?: string };
      if (!response.ok) throw new Error(body.error ?? `Auth challenge failed with ${response.status}`);
      window.location.assign(safeNext);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Auth challenge failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-screen place-items-center bg-background px-4 text-foreground">
      <Card className="w-full max-w-md border-white/10 bg-white/[0.04] shadow-2xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><ShieldQuestion className="h-5 w-5 text-amber-300" /> Security challenge</CardTitle>
          <CardDescription>This resource is protected by the dashboard edge gate.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg border border-white/10 bg-black/20 p-3 text-sm">
            <div className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-300" /> Browser challenge: {botReady ? "passed" : "checking..."}</div>
          </div>
          {needsAuth && (
            <div className="space-y-2">
              <label className="text-xs text-muted-foreground">Access password</label>
              <Input type="password" value={password} onChange={(event) => setPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void login(); }} disabled={busy || !botReady} />
              <Button className="w-full" onClick={() => void login()} disabled={busy || !botReady || !password}><LockKeyhole className="h-4 w-4" /> {busy ? "Verifying..." : "Continue"}</Button>
            </div>
          )}
          {message && <p className="text-sm text-amber-200">{message}</p>}
        </CardContent>
      </Card>
    </main>
  );
}
