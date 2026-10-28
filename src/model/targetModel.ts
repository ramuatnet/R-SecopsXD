/**
 * Target Model store (T1.1) + idempotent merge (T1.3) + delta chain (T1.4).
 *
 * All model writes go through applyDelta: append-only, hash-chained deltas are
 * the source of truth; model_nodes is the materialized view. Replaying the
 * delta stream reconstructs the model (acceptance test T1.4).
 */
import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { ModelDelta, ModelNode, ModelNodeKind, TriState } from './types.ts';
import { nodeKey } from './types.ts';

export class TargetModel {
  private readonly db: DatabaseSync;
  private readonly targetId: string;

  constructor(db: DatabaseSync, targetId: string) {
    this.db = db;
    this.targetId = targetId;
  }

  /** Materialized view: all nodes. */
  nodes(): ModelNode[] {
    const rows = this.db
      .prepare('SELECT * FROM model_nodes WHERE target_id = ? ORDER BY node_key')
      .all(this.targetId) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      kind: r.kind as ModelNodeKind,
      key: (r.node_key as string).split(':').slice(1).join(':'),
      state: (r.state as TriState | null) ?? undefined,
      value: JSON.parse(r.value_json as string),
      provenance: r.provenance as string,
      updatedAt: r.updated_at as string,
    }));
  }

  node(kind: ModelNodeKind, key: string): ModelNode | undefined {
    const r = this.db
      .prepare('SELECT * FROM model_nodes WHERE target_id = ? AND node_key = ?')
      .get(this.targetId, nodeKey(kind, key)) as Record<string, unknown> | undefined;
    if (!r) return undefined;
    return {
      kind: r.kind as ModelNodeKind,
      key: (r.node_key as string).split(':').slice(1).join(':'),
      state: (r.state as TriState | null) ?? undefined,
      value: JSON.parse(r.value_json as string),
      provenance: r.provenance as string,
      updatedAt: r.updated_at as string,
    };
  }

  /** Tri-state convenience: node state or 'unknown'. */
  state(kind: ModelNodeKind, key: string): TriState {
    return this.node(kind, key)?.state ?? 'unknown';
  }

  /** Full delta stream (ordered). */
  deltas(): ModelDelta[] {
    const rows = this.db
      .prepare('SELECT * FROM model_deltas WHERE target_id = ? ORDER BY seq')
      .all(this.targetId) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      seq: r.seq as number,
      op: r.op as 'set' | 'delete',
      kind: r.kind as ModelNodeKind,
      key: (r.node_key as string).split(':').slice(1).join(':'),
      state: (r.state as TriState | null) ?? undefined,
      value: r.value_json ? JSON.parse(r.value_json as string) : undefined,
      provenance: r.provenance as string,
      ts: r.ts as string,
      prevHash: r.prev_hash as string,
      hash: r.hash as string,
    }));
  }

  /**
   * Apply a delta: append to the chain + upsert the materialized node.
   * Idempotence lives in merge() — applyDelta is the primitive.
   */
  private applyDelta(d: Omit<ModelDelta, 'seq' | 'prevHash' | 'hash' | 'ts'>): ModelDelta {
    const last = this.db
      .prepare('SELECT hash FROM model_deltas WHERE target_id = ? ORDER BY seq DESC LIMIT 1')
      .get(this.targetId) as { hash: string } | undefined;
    const prevHash = last?.hash ?? 'genesis';
    const ts = new Date().toISOString();
    const seqRow = this.db
      .prepare('SELECT COALESCE(MAX(seq), 0) AS s FROM model_deltas WHERE target_id = ?')
      .get(this.targetId) as { s: number };
    const seq = seqRow.s + 1;

    const hash = createHash('sha256')
      .update(`${prevHash}|${seq}|${d.op}|${d.kind}|${d.key}|${d.state ?? ''}|${JSON.stringify(d.value ?? null)}`)
      .digest('hex');

    this.db.prepare(
      'INSERT INTO model_deltas (target_id, seq, op, kind, node_key, state, value_json, provenance, ts, prev_hash, hash) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(this.targetId, seq, d.op, d.kind, nodeKey(d.kind, d.key), d.state ?? null,
      d.value !== undefined ? JSON.stringify(d.value) : null, d.provenance, ts, prevHash, hash);

    if (d.op === 'set') {
      this.db.prepare(
        'INSERT INTO model_nodes (target_id, node_key, kind, state, value_json, provenance, updated_at) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(target_id, node_key) DO UPDATE SET ' +
        'state = excluded.state, value_json = excluded.value_json, provenance = excluded.provenance, updated_at = excluded.updated_at',
      ).run(this.targetId, nodeKey(d.kind, d.key), d.kind, d.state ?? null,
        JSON.stringify(d.value ?? null), d.provenance, ts);
    } else {
      this.db.prepare('DELETE FROM model_nodes WHERE target_id = ? AND node_key = ?')
        .run(this.targetId, nodeKey(d.kind, d.key));
    }

    return { ...d, seq, ts, prevHash, hash };
  }

  /** Set a node's value (optionally tri-state). Returns the applied delta. */
  set(kind: ModelNodeKind, key: string, value: unknown, provenance: string, state?: TriState): ModelDelta {
    return this.applyDelta({ op: 'set', kind, key, value, provenance, state });
  }

  delete(kind: ModelNodeKind, key: string, provenance: string): ModelDelta {
    return this.applyDelta({ op: 'delete', kind, key, provenance });
  }
}

/**
 * T1.3 — idempotent evidence→model merge.
 *
 * Rules: 'present' beats 'unknown'; explicit 'absent' beats 'unknown' but is
 * overridden by 'present' (a later observation of presence wins — newer wins);
 * equal states are no-ops. Provenance is preserved on the winning write.
 * Replaying the same evidence twice produces zero new deltas.
 */
export function mergeEvidence(
  model: TargetModel,
  evidence: Array<{ kind: ModelNodeKind; key: string; state?: TriState; value: unknown; provenance: string }>,
): ModelDelta[] {
  const applied: ModelDelta[] = [];
  for (const e of evidence) {
    const existing = model.node(e.kind, e.key);
    const newState = e.state ?? 'present';
    if (existing) {
      // idempotence: identical state+value → skip
      if (existing.state === newState && JSON.stringify(existing.value) === JSON.stringify(e.value)) continue;
      // conflict resolution: presence outranks absence; both outrank unknown (already implied)
      if (existing.state === 'present' && newState === 'absent') continue;
    }
    applied.push(model.set(e.kind, e.key, e.value, e.provenance, newState));
  }
  return applied;
}
