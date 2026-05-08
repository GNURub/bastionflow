import type { ApiEnvelope } from "./types";

interface AsyncCacheEntry<T> {
  expiresAt: number;
  staleUntil: number;
  value?: ApiEnvelope<T> | undefined;
  inFlight?: Promise<ApiEnvelope<T>> | undefined;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

export async function cachedEnvelope<T>(
  entry: AsyncCacheEntry<T>,
  ttlMs: number,
  staleMs: number,
  loader: () => Promise<ApiEnvelope<T>>,
  fallbackData: T,
  fallbackError: string
): Promise<ApiEnvelope<T>> {
  const now = Date.now();
  if (entry.value && entry.expiresAt > now) return entry.value;
  if (entry.inFlight) return entry.inFlight;

  entry.inFlight = loader()
    .then((value) => {
      entry.value = value;
      entry.expiresAt = Date.now() + ttlMs;
      entry.staleUntil = Date.now() + staleMs;
      return value;
    })
    .catch((error: unknown) => {
      if (entry.value && entry.staleUntil > Date.now()) {
        return { ...entry.value, source: "partial", error: errorMessage(error, fallbackError) } satisfies ApiEnvelope<T>;
      }
      return { data: fallbackData, source: "partial", error: errorMessage(error, fallbackError) } satisfies ApiEnvelope<T>;
    })
    .finally(() => {
      entry.inFlight = undefined;
    });

  return entry.inFlight;
}

export function clearEnvelopeCache<T>(entry: AsyncCacheEntry<T>): void {
  entry.expiresAt = 0;
  entry.staleUntil = 0;
  entry.value = undefined;
  entry.inFlight = undefined;
}

export function createEnvelopeCache<T>(): AsyncCacheEntry<T> {
  return { expiresAt: 0, staleUntil: 0 };
}
