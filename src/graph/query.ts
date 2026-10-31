/**
 * Graph query API (newtask.md C4): traversal and blast radius.
 */
import type { GraphStore } from './graph.ts';
import type { AssetNode, EdgeType } from './types.ts';

export interface BlastRadius {
  origin: string;
  /** Reachable nodes (origin excluded), depth-capped. */
  affected: AssetNode[];
  /** Fan-out of the origin node (raw edge count). */
  fanout: number;
  /** The blast factor used by the risk model (capped 1.5). */
  blastFactor: number;
  maxDepth: number;
}

const BLAST_EDGE_TYPES: EdgeType[] = ['reachable_from', 'trusts', 'exposes', 'runs', 'resolves_to', 'hosts', 'found_on'];

export function blastRadius(store: GraphStore, originUid: string, maxDepth = 4): BlastRadius {
  const { nodes } = store.traverse(originUid, { maxDepth, edgeTypes: BLAST_EDGE_TYPES, maxNodes: 200 });
  const fanout = store.fanout(originUid, BLAST_EDGE_TYPES);
  // import avoided: blastFactor lives in risk (dependency direction: risk ← query is fine, but keep graph pure) — recompute locally
  const factor = Math.min(1.5, 0.155 + 0.445 * Math.log2(1 + Math.max(0, fanout)));
  return { origin: originUid, affected: nodes.filter((n) => n.uid !== originUid), fanout, blastFactor: factor, maxDepth };
}
