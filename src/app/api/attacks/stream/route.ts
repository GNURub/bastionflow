import { getAttackArcs } from "@/lib/crowdsec/client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  const encoder = new TextEncoder();
  let closed = false;
  let timer: ReturnType<typeof setInterval> | null = null;
  const stream = new ReadableStream({
    async start(controller) {
      async function push(): Promise<void> {
        if (closed) return;
        const payload = await getAttackArcs();
        controller.enqueue(encoder.encode(`event: attacks\ndata: ${JSON.stringify(payload.data)}\n\n`));
      }
      await push();
      timer = setInterval(() => void push(), 3_000);
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
