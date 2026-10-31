/**
 * edgectx models (edgetask.md §1.3, §3, §8) — vantage/surface, signals,
 * edge verdicts, scope manifest, canonical probe outcomes.
 *
 * I19-I22 and the RoE model from newtasks.md are unaffected; this layer adds
 * the edge/CDN dimension on top.
 */
import type { ExploitClass } from '../core/types.ts';

export type Vantage = 'edge' | 'origin' | 'unknown';
export type Surface = 'edge' | 'origin' | 'unknown';

/** §3: a weighted observation feeding the classifier. */
export interface Signal {
  kind: string;           // 'server-header' | 'cf-ray' | 'ip-range' | 'favicon' | 'tls-cert' | …
  value: string;
  weight: number;         // 0..1
}

export type EdgeVendor = 'cloudflare' | 'akamai' | 'fastly' | 'cloudfront' | 'azurefd' | 'none';

export interface EdgeFeedMeta {
  feedVersion: string;
  stale: boolean;         // true ⇒ DEGRADED + confidence ×0.7 (§8.1)
}

export interface EdgeVerdict {
  vendor: EdgeVendor;
  confidence: number;     // 0..1
  signals: Signal[];
  feed: EdgeFeedMeta;
  vantage: Vantage;
}

/** §1.1 — signed scope manifest, enforced at the bus ingress. */
export interface ScopeManifest {
  manifestId: string;
  signer: string;
  validFrom: string;
  validTo: string;
  domains: string[];
  cidrs: string[];
  ports: { include: number[]; exclude: number[] };
  classes: ExploitClass[];
  flags: { originDiscoveryAuthorized: boolean; directOriginProbingAuthorized: boolean };
  killSwitch: 'global' | 'per-engagement' | 'none';
}

/** §3 canonical probe outcome — every engine run maps onto exactly one. */
export type ProbeOutcome =
  | 'RAN_FINDINGS' | 'RAN_CLEAN' | 'SKIPPED_NOT_APPLICABLE' | 'SKIPPED_NO_CREDENTIALS'
  | 'NOT_EXECUTED_DEGRADED' | 'NO_OP_SUSPECT' | 'FAILED';

export interface ProbeCompleted {
  assetUid: string;
  probeClass: string;
  outcome: ProbeOutcome;
  inputsUsed: number;     // 0 ⇒ NO_OP_SUSPECT
  durationMs: number;
  vantage: Vantage;
  evidenceRefs: string[];
}

export function outcomeFor(probe: { inputsUsed: number; durationMs: number; ran: boolean; findings: number; degraded?: boolean | undefined; skippedReason?: string | undefined }): ProbeOutcome {
  if (probe.degraded === true) return 'NOT_EXECUTED_DEGRADED';
  if (!probe.ran) {
    if (probe.skippedReason !== undefined && probe.skippedReason.includes('credential')) return 'SKIPPED_NO_CREDENTIALS';
    return 'SKIPPED_NOT_APPLICABLE';
  }
  // Findings ⇒ inputs were consumed (the engine observed real responses) —
  // duration is irrelevant (http-observation over a warm corpus runs in 4 ms).
  if (probe.findings > 0) return 'RAN_FINDINGS';
  // 0 findings: a no-op suspect only when no inputs AND/OR sub-5 ms —
  // an engine that ran ≥5 ms consumed real inputs and ran clean (§3 HON-02).
  if (probe.inputsUsed === 0 || probe.durationMs < 5) return 'NO_OP_SUSPECT';
  return 'RAN_CLEAN';
}
