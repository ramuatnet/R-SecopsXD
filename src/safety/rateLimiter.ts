/**
 * Token-bucket rate limiter keyed per target origin.
 *
 * acquire() resolves when a token is available, or rejects when the passed
 * AbortSignal fires (scan cancelled / engine timeout).
 */
export class RateLimiter {
  private readonly ratePerSecond: number;
  private readonly burst: number;
  private readonly buckets = new Map<string, { tokens: number; last: number }>();

  constructor(ratePerSecond: number, burst: number) {
    this.ratePerSecond = ratePerSecond;
    this.burst = burst;
  }

  private bucketFor(key: string): { tokens: number; last: number } {
    let b = this.buckets.get(key);
    if (!b) {
      b = { tokens: this.burst, last: Date.now() };
      this.buckets.set(key, b);
    }
    return b;
  }

  /** Estimated wait until a token is free for key (ms), for logging only. */
  waitEstimateMs(key: string): number {
    const b = this.bucketFor(key);
    const now = Date.now();
    const refill = ((now - b.last) / 1000) * this.ratePerSecond;
    const tokens = Math.min(this.burst, b.tokens + refill);
    return tokens >= 1 ? 0 : ((1 - tokens) / this.ratePerSecond) * 1000;
  }

  async acquire(key: string, signal?: AbortSignal): Promise<void> {
    for (;;) {
      const b = this.bucketFor(key);
      const now = Date.now();
      const refill = ((now - b.last) / 1000) * this.ratePerSecond;
      b.tokens = Math.min(this.burst, b.tokens + refill);
      b.last = now;
      if (b.tokens >= 1) {
        b.tokens -= 1;
        return;
      }
      const waitMs = ((1 - b.tokens) / this.ratePerSecond) * 1000;
      await abortableDelay(Math.max(waitMs, 10), signal);
    }
  }
}

export function abortableDelay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    const t = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(t);
      reject(abortError());
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

export function abortError(): Error {
  const e = new Error('aborted');
  e.name = 'AbortError';
  return e;
}
