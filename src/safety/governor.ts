/**
 * Safety governor (newtask.md D3, section 3.2).
 *
 * Global + per-asset token buckets; separate discovery/fuzzing budgets;
 * adaptive throttle (429/503 or latency p95 breach → halve rate, exponential
 * backoff, never exceed the ceiling); gentle/normal/aggressive profiles with
 * fixed request ceilings; kill switch per target and global; circuit breaker
 * per sensor.
 *
 * Zero dependencies — the same policy surface the Kafka/Temporal deployment
 * will call; the in-process scanner integrates via httpClient later.
 */

export type ScanProfile = 'gentle' | 'normal' | 'aggressive';

export interface ProfileLimits {
  /** Requests per second per asset. */
  perAssetRps: number;
  /** Global requests per second across all assets. */
  globalRps: number;
  /** Hard request ceiling per scan. */
  maxRequestsPerScan: number;
}

const PROFILE_LIMITS: Record<ScanProfile, ProfileLimits> = {
  gentle: { perAssetRps: 1, globalRps: 5, maxRequestsPerScan: 100 },
  normal: { perAssetRps: 5, globalRps: 20, maxRequestsPerScan: 500 },
  aggressive: { perAssetRps: 20, globalRps: 100, maxRequestsPerScan: 2000 },
};

export function profileLimits(p: ScanProfile): ProfileLimits {
  return { ...PROFILE_LIMITS[p] };
}

interface BucketState {
  tokens: number;
  lastRefill: number;
  /** Current rate — halved adaptively, recovers toward the ceiling. */
  rate: number;
  backoffUntil: number;
}

export class TokenBucket {
  private readonly capacity: number;
  private readonly ceilingRate: number;
  private state: BucketState;
  constructor(capacity: number, ceilingRate: number) {
    this.capacity = capacity;
    this.ceilingRate = ceilingRate;
    this.state = { tokens: capacity, lastRefill: Date.now(), rate: ceilingRate, backoffUntil: 0 };
  }

  /** Try to take one token; false = throttled (caller must back off). */
  tryAcquire(now = Date.now()): boolean {
    if (now < this.state.backoffUntil) return false;
    const elapsed = (now - this.state.lastRefill) / 1000;
    if (elapsed > 0) {
      this.state.tokens = Math.min(this.capacity, this.state.tokens + elapsed * this.state.rate);
      this.state.lastRefill = now;
    }
    if (this.state.tokens < 1) return false;
    this.state.tokens -= 1;
    return true;
  }

  onThrottleSignal(): void {
    // halve, floor at 0.1 rps, exponential backoff window
    this.state.rate = Math.max(0.1, this.state.rate / 2);
    this.state.backoffUntil = Date.now() + Math.min(30_000, Math.round(1000 / this.state.rate));
  }

  onSuccess(): void {
    // recover 10% toward the ceiling per success burst
    this.state.rate = Math.min(this.ceilingRate, this.state.rate * 1.1);
  }

  currentRate(): number {
    return this.state.rate;
  }
}

export interface GovernorDecision { allowed: boolean; reason?: string; }

export class SafetyGovernor {
  private readonly globalBucket: TokenBucket;
  private readonly perAsset = new Map<string, TokenBucket>();
  private readonly killedTargets = new Set<string>();
  private globalKill = false;
  private readonly requestsPerScan = new Map<string, number>();
  private readonly breaker = new Map<string, { failures: number; openUntil: number }>();
  private readonly limits: ProfileLimits;

  constructor(profile: ScanProfile = 'normal', globalRpsCeiling?: number) {
    this.limits = profileLimits(profile);
    this.globalBucket = new TokenBucket(this.limits.globalRps * 2, globalRpsCeiling ?? this.limits.globalRps);
  }

  private assetBucket(assetKey: string): TokenBucket {
    let b = this.perAsset.get(assetKey);
    if (b === undefined) {
      b = new TokenBucket(this.limits.perAssetRps * 2, this.limits.perAssetRps);
      this.perAsset.set(assetKey, b);
    }
    return b;
  }

  /** Acquire permission for one request against an asset in a scan. */
  acquire(assetKey: string, scanId: string, sensorId = 'in-process'): GovernorDecision {
    if (this.globalKill) return { allowed: false, reason: 'global kill switch engaged' };
    if (this.killedTargets.has(assetKey)) return { allowed: false, reason: `kill switch engaged for ${assetKey}` };
    const br = this.breaker.get(sensorId);
    if (br !== undefined && Date.now() < br.openUntil) {
      return { allowed: false, reason: `circuit breaker open for sensor ${sensorId}` };
    }
    const used = this.requestsPerScan.get(scanId) ?? 0;
    if (used >= this.limits.maxRequestsPerScan) {
      return { allowed: false, reason: `scan request ceiling reached (${this.limits.maxRequestsPerScan})` };
    }
    if (!this.globalBucket.tryAcquire()) return { allowed: false, reason: 'global rate limit' };
    if (!this.assetBucket(assetKey).tryAcquire()) return { allowed: false, reason: `asset rate limit (${assetKey})` };
    this.requestsPerScan.set(scanId, used + 1);
    return { allowed: true };
  }

  /** Feed every response back — 429/503 halves the asset rate with backoff. */
  onResponse(assetKey: string, status: number, latencyMs: number): void {
    if (status === 429 || status === 503) {
      this.assetBucket(assetKey).onThrottleSignal();
      this.globalBucket.onThrottleSignal();
      return;
    }
    // latency p95-style breach (arbitrary 3s threshold) backs off without halving as hard
    if (latencyMs > 3000) {
      this.assetBucket(assetKey).onThrottleSignal();
      return;
    }
    if (status < 400) this.assetBucket(assetKey).onSuccess();
  }

  killSwitch(targetKey?: string): void {
    if (targetKey === undefined) this.globalKill = true;
    else this.killedTargets.add(targetKey);
  }

  resume(targetKey?: string): void {
    if (targetKey === undefined) this.globalKill = false;
    else this.killedTargets.delete(targetKey);
  }

  /** Circuit breaker per sensor: 3 consecutive failures open for 60s. */
  onSensorFailure(sensorId: string): void {
    const b = this.breaker.get(sensorId) ?? { failures: 0, openUntil: 0 };
    b.failures += 1;
    if (b.failures >= 3) {
      b.openUntil = Date.now() + 60_000;
      b.failures = 0;
    }
    this.breaker.set(sensorId, b);
  }

  onSensorSuccess(sensorId: string): void {
    this.breaker.set(sensorId, { failures: 0, openUntil: 0 });
  }

  requestsUsed(scanId: string): number {
    return this.requestsPerScan.get(scanId) ?? 0;
  }
}
