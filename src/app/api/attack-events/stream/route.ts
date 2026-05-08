import { listAttackEvents, summarizeCampaigns } from "@/lib/crowdsec/events";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  const encoder = new TextEncoder();
  let closed = false;
  let pushInFlight = false;
  let timer: ReturnType<typeof setInterval> | null = null;
  const stream = new ReadableStream({
    async start(controller) {
      async function push(): Promise<void> {
        if (closed || pushInFlight) return;
        pushInFlight = true;
        try {
          const events = listAttackEvents(120);
          const payload = { data: { events, campaigns: summarizeCampaigns(events) }, source: "crowdsec" };
          if (!closed) controller.enqueue(encoder.encode(`event: attack-events\ndata: ${JSON.stringify(payload)}\n\n`));
        } catch {
          // Keep the SSE connection alive; the next tick can retry.
        } finally {
          pushInFlight = false;
        }
      }
      await push();
      timer = setInterval(() => void push(), 5_000);
    },
    cancel() {
      closed = true;
      if (timer) clearInterval(timer);
    }
  });
  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive"
    }
  });
}
