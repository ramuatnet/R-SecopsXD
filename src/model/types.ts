/**
 * Target Model (v2 Phase 1) — the knowledge graph of a target.
 *
 * Tri-state knowledge (T1.2): every capability/capture is
 * 'present' | 'absent' | 'unknown' — the loop NEVER assumes. A fresh target
 * has zero present and N unknown.
 *
 * Model nodes are flat (kind, key) pairs with JSON values — a graph in DB
 * form. Deltas are append-only and hash-chained (T1.4): the ordered delta
 * stream reconstructs the model from empty.
 */
export type TriState = 'present' | 'absent' | 'unknown';

export type ModelNodeKind =
  | 'asset'
  | 'endpoint'
  | 'param'
  | 'tech'
  | 'auth-surface'
  | 'cloud-hint'
  | 'capability'
  | 'unknown'
  | 'exposure';

export interface ModelNode {
  kind: ModelNodeKind;
  key: string;
  /** Tri-state for capability/tech nodes; informational otherwise. */
  state?: TriState | undefined;
  value: unknown;
  provenance: string;
  updatedAt: string;
}

export interface ModelDelta {
  seq: number;
  op: 'set' | 'delete';
  kind: ModelNodeKind;
  key: string;
  state?: TriState | undefined;
  value?: unknown;
  provenance: string;
  ts: string;
  prevHash: string;
  hash: string;
}

/** Keys namespaced by kind, e.g. 'cap:api.rest', 'tech:server', 'endpoint:/api/x'. */
export function nodeKey(kind: ModelNodeKind, key: string): string {
  return `${kind}:${key}`;
}
