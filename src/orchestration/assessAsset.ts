/**
 * Trigger rules + AssessAsset workflow (newtask.md D5, D2, section 3.2).
 *
 * Triggers consume graph events and emit work:
 *   new web-ish port at the edge            → scan.request (DAST plan)
 *   new DB/management port at the edge      → approval.gate (operator must decide)
 *   unapproved scope expansion              → approval.gate (never auto-scanned, I13)
 *
 * AssessAsset is an idempotent, resumable state machine with per-step retry
 * and compensation. In this deployment it runs in-process; the Temporal port
 * maps each step to an activity with the same retry policy.
 */
import type { SafetyGovernor } from '../safety/governor.ts';
import type { ScopeGate } from '../safety/scopeGate.ts';
import type { Bus } from '../bus/bus.ts';
import { assetUid, portIdentity } from '../graph/uid.ts';
import { portSeverity } from '../engines/builtin/hostInfra.ts';

export interface ScanRequest {
  kind: 'dast' | 'service-assessment' | 'asset-review';
  assetUid: string;
  origin?: string;
  profile: 'gentle' | 'normal' | 'aggressive';
  reason: string;
}

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9000, 9090, 7001, 4848]);
const GATED_PORTS = new Set([21, 23, 445, 3389, 3306, 5432, 6379, 27017, 9200, 11211, 2375, 2376, 6443]);

/**
 * Pure trigger evaluation: given a freshly observed port on an IP, decide the
 * work item. Scope approval is consulted for anything that would touch a new
 * asset; unapproved expansions produce approval.gate events, never scans.
 */
export function triggerForPort(input: {
  ip: string; port: number; severity: 'info' | 'medium' | 'high';
  origin?: string | undefined;
  scope: ScopeGate;
  bus: Bus;
  profile?: 'gentle' | 'normal' | 'aggressive';
}): ScanRequest | { gated: string } {
  const portUid = assetUid('port', portIdentity(input.ip, input.port));
  if (GATED_PORTS.has(input.port)) {
    const reason = `high-exposure port ${input.port} on ${input.ip} (${input.severity}) — operator confirmation required`;
    input.bus.publish('approval.gate', portUid, { kind: 'risky-port', assetUid: portUid, reason });
    return { gated: reason };
  }
  if (!WEB_PORTS.has(input.port) || input.origin === undefined) {
    return { gated: `port ${input.port} has no web assessment plan` };
  }
  const origin = input.origin;
  if (!input.scope.isApproved('origin', origin)) {
    const reason = `origin ${origin} not in approved scope — registration/approval required (I13)`;
    input.bus.publish('approval.gate', portUid, { kind: 'scope-expansion', assetUid: portUid, reason });
    return { gated: reason };
  }
  const request: ScanRequest = {
    kind: 'dast',
    assetUid: portUid,
    origin,
    profile: input.profile ?? (input.severity === 'high' ? 'gentle' : 'normal'),
    reason: `web port ${input.port} observed on ${input.ip} (${input.severity}) — DAST plan selected`,
  };
  input.bus.publish('scan.request', portUid, request);
  return request;
}

// ---------- AssessAsset state machine ----------

export interface WorkflowStep {
  name: string;
  run: (state: Record<string, unknown>) => Promise<Record<string, unknown>>;
  /** Retry policy: attempts with fixed backoff (Temporal activity options on port). */
  retry: { attempts: number; backoffMs: number };
  /** Compensation for reversible steps (runs in reverse order on abort). */
  compensate?: (state: Record<string, unknown>) => Promise<void>;
}

export interface AssessAssetResult {
  status: 'completed' | 'aborted';
  completedSteps: string[];
  state: Record<string, unknown>;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * AssessAsset: resolve → fingerprint → classify exposure → select plan →
 * safety gate → execute → normalize → score → notify. Idempotent: steps read
 * and write the shared state object, so a re-run replays cleanly.
 */
export async function assessAsset(
  initialState: Record<string, unknown>,
  steps: WorkflowStep[],
  opts: { governor?: SafetyGovernor; assetKey?: string; onStep?: (name: string) => void } = {},
): Promise<AssessAssetResult> {
  const state: Record<string, unknown> = { ...initialState };
  const completed: string[] = [];
  for (const step of steps) {
    let attempt = 0;
    for (;;) {
      try {
        opts.onStep?.(step.name);
        const patch = await step.run(state);
        Object.assign(state, patch);
        completed.push(step.name);
        break;
      } catch (e) {
        attempt++;
        if (attempt >= step.retry.attempts) {
          // compensate completed steps in reverse (Temporal-style saga)
          for (const name of [...completed].reverse()) {
            const s = steps.find((x) => x.name === name);
            try { await s?.compensate?.(state); } catch { /* compensation is best-effort */ }
          }
          return { status: 'aborted', completedSteps: completed, state: { ...state, error: e instanceof Error ? e.message : String(e) } };
        }
        await sleep(step.retry.backoffMs * attempt);
      }
    }
  }
  return { status: 'completed', completedSteps: completed, state };
}

/** The canonical AssessAsset step list (steps wired to real subsystems at call sites). */
export function assessAssetSteps(assets: {
  resolve: (s: Record<string, unknown>) => Promise<Record<string, unknown>>;
  fingerprint: (s: Record<string, unknown>) => Promise<Record<string, unknown>>;
  classifyExposure: (s: Record<string, unknown>) => Promise<Record<string, unknown>>;
  selectPlan: (s: Record<string, unknown>) => Promise<Record<string, unknown>>;
  safetyGate: (s: Record<string, unknown>) => Promise<Record<string, unknown>>;
  execute: (s: Record<string, unknown>) => Promise<Record<string, unknown>>;
  normalize: (s: Record<string, unknown>) => Promise<Record<string, unknown>>;
  score: (s: Record<string, unknown>) => Promise<Record<string, unknown>>;
  notify: (s: Record<string, unknown>) => Promise<Record<string, unknown>>;
}): WorkflowStep[] {
  const step = (name: string, fn: (s: Record<string, unknown>) => Promise<Record<string, unknown>>): WorkflowStep =>
    ({ name, run: fn, retry: { attempts: 3, backoffMs: 200 } });
  return [
    step('resolve', assets.resolve),
    step('fingerprint', assets.fingerprint),
    step('classify-exposure', assets.classifyExposure),
    step('select-plan', assets.selectPlan),
    step('safety-gate', assets.safetyGate),
    step('execute', assets.execute),
    step('normalize', assets.normalize),
    step('score', assets.score),
    step('notify', assets.notify),
  ];
}

/** Default safety-gate step bound to the governor (D3 integration point). */
export function governorGateStep(governor: SafetyGovernor, assetKeyOf: (s: Record<string, unknown>) => string, scanId: string): WorkflowStep {
  return {
    name: 'safety-gate',
    retry: { attempts: 1, backoffMs: 0 },
    run: async (state) => {
      const decision = governor.acquire(assetKeyOf(state), scanId);
      if (!decision.allowed) throw new Error(`safety gate: ${decision.reason}`);
      return { safetyGate: 'passed' };
    },
  };
}

export { portSeverity };
