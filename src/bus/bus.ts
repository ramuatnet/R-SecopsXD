/**
 * In-process event bus (newtask.md D1).
 *
 * The six canonical topics carry typed envelopes. This implementation is an
 * in-memory pub/sub for the current single-process deployment; a Kafka /
 * Redpanda adapter implements the same Bus interface for the distributed
 * deployment (topics map 1:1, envelopes are the wire schema).
 */

export const TOPICS = [
  'discovery.asset',   // NormalizedEvent payloads from the graph sync
  'scan.request',      // AssessAsset / DAST / service scan requests
  'scan.result',       // completed scan summaries
  'finding.normalized',// merged findings
  'risk.changed',      // recomputed risk for an asset
  'approval.gate',     // scope expansion requests awaiting operator approval
  // edgetask.md §2 canonical edge topics (PLT-01):
  'asset.discovered', 'service.observed', 'edge.classified', 'origin.candidate',
  'origin.verified', 'fingerprint.resolved', 'probe.requested', 'probe.completed',
  'finding.candidate', 'finding.validated', 'finding.suppressed', 'engine.degraded',
  'governor.signal',
] as const;
export type Topic = (typeof TOPICS)[number];

export interface Envelope<T> {
  topic: Topic;
  key: string;          // partition/asset key for ordered delivery
  payload: T;
  emittedAt: string;
}

export type Handler<T> = (envelope: Envelope<T>) => void | Promise<void>;

export interface Bus {
  publish<T>(topic: Topic, key: string, payload: T): Envelope<T>;
  subscribe<T>(topic: Topic, handler: Handler<T>): () => void;
}

export interface BusIngressGate {
  /** §1.1: admission check — returns blocked_by_scope reason when rejected. */
  admit(topic: Topic, key: string): { allowed: boolean; reason?: string };
}

export class InProcessBus implements Bus {
  private readonly handlers = new Map<Topic, Set<Handler<never>>>();
  private readonly log: Array<Envelope<unknown>> = [];
  private readonly maxLog = 1000;
  private readonly gate: BusIngressGate | undefined;
  private readonly rejected: Array<{ topic: Topic; key: string; reason: string }> = [];

  constructor(gate?: BusIngressGate) {
    this.gate = gate;
  }

  /** §1.1: out-of-scope events rejected at ingress with blocked_by_scope. */
  rejectedEvents(): Array<{ topic: Topic; key: string; reason: string }> {
    return [...this.rejected];
  }

  publish<T>(topic: Topic, key: string, payload: T): Envelope<T> {
    if (this.gate !== undefined) {
      const verdict = this.gate.admit(topic, key);
      if (!verdict.allowed) {
        this.rejected.push({ topic, key, reason: verdict.reason ?? 'blocked_by_scope' });
        // Rejections are recorded, never delivered to subscribers.
        return { topic, key, payload, emittedAt: new Date().toISOString() };
      }
    }
    const envelope: Envelope<T> = { topic, key, payload, emittedAt: new Date().toISOString() };
    this.log.push(envelope as Envelope<unknown>);
    if (this.log.length > this.maxLog) this.log.shift();
    for (const h of this.handlers.get(topic) ?? []) {
      const r = (h as Handler<T>)(envelope);
      // handlers may be async — fire and forget with error containment
      if (r instanceof Promise) r.catch(() => { /* handler errors never break publishers */ });
    }
    return envelope;
  }

  subscribe<T>(topic: Topic, handler: Handler<T>): () => void {
    let set = this.handlers.get(topic);
    if (set === undefined) {
      set = new Set();
      this.handlers.set(topic, set);
    }
    set.add(handler as Handler<never>);
    return () => set.delete(handler as Handler<never>);
  }

  recent(topic?: Topic): Array<Envelope<unknown>> {
    return topic === undefined ? [...this.log] : this.log.filter((e) => e.topic === topic);
  }
}
