/**
 * Graph store (newtask.md C1) — bitemporal nodes/edges over node:sqlite.
 *
 * Nothing is deleted: nodes/edges are closed by setting valid_to. Upserts are
 * idempotent per (type, identity); re-observation updates last_seen/observed_at
 * and re-opens a closed node when a fresh assertion arrives (the closed
 * interval remains part of history).
 *
 * The Postgres deployment of the same schema lives in db/postgres/001_asset_graph.sql
 * (ltree adjacency + GIST index); this SQLite store keeps the single-file,
 * zero-dependency runtime for the current scale.
 */
import type { DatabaseSync } from 'node:sqlite';
import { assetUid, canonicalIdentity } from './uid.ts';
import type { AssetEdge, AssetNode, EdgeAssertion, EdgeType, NodeAssertion, NodeType } from './types.ts';

const NOW = (): string => new Date().toISOString();

interface NodeRow {
  uid: string; type: string; identity: string; display: string;
  attributes_json: string; first_seen: string; last_seen: string;
  valid_from: string; valid_to: string | null; observed_at: string; provenance_json: string;
}

interface EdgeRow {
  uid: string; edge_type: string; src_uid: string; dst_uid: string;
  first_seen: string; last_seen: string; valid_from: string; valid_to: string | null;
  observed_at: string; provenance_json: string;
}

export class GraphStore {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  /** Upsert a node assertion (idempotent per type+identity). Returns the uid. */
  upsertNode(a: NodeAssertion, at = NOW()): string {
    const uid = assetUid(a.type, a.identity);
    const identity = canonicalIdentity(a.type, a.identity);
    const prov = JSON.stringify(a.provenance ?? []);
    const attrs = JSON.stringify(a.attributes ?? {});
    const existing = this.db.prepare('SELECT uid, first_seen FROM graph_nodes WHERE uid = ?').get(uid) as { uid: string; first_seen: string } | undefined;
    if (existing === undefined) {
      this.db.prepare(
        `INSERT INTO graph_nodes (uid, type, identity, display, attributes_json, first_seen, last_seen, valid_from, valid_to, observed_at, provenance_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
      ).run(uid, a.type, identity, a.display, attrs, at, at, at, at, prov);
    } else {
      // Re-observation MERGES attributes (3.3: results merge into the same
      // node) — an edge assertion must not clobber previously merged context.
      const existing = this.db.prepare('SELECT attributes_json, provenance_json FROM graph_nodes WHERE uid = ?').get(uid) as { attributes_json: string; provenance_json: string };
      const mergedAttrs = { ...(JSON.parse(existing.attributes_json) as Record<string, unknown>), ...(a.attributes ?? {}) };
      const mergedProv = [...new Set([...(JSON.parse(existing.provenance_json) as string[]), ...(a.provenance ?? [])])];
      this.db.prepare(
        `UPDATE graph_nodes
         SET display = ?, attributes_json = ?, last_seen = ?, observed_at = ?, valid_to = NULL,
             provenance_json = ?
         WHERE uid = ?`,
      ).run(a.display, JSON.stringify(mergedAttrs), at, at, JSON.stringify(mergedProv), uid);
    }
    return uid;
  }

  getNode(uid: string): AssetNode | undefined {
    const r = this.db.prepare('SELECT * FROM graph_nodes WHERE uid = ?').get(uid) as NodeRow | undefined;
    return r === undefined ? undefined : rowToNode(r);
  }

  getNodeByIdentity(type: NodeType, identity: string): AssetNode | undefined {
    const uid = assetUid(type, identity);
    return this.getNode(uid);
  }

  /** Close a node (valid_to = at). History is retained; nothing is deleted. */
  closeNode(uid: string, at = NOW()): void {
    this.db.prepare('UPDATE graph_nodes SET valid_to = ? WHERE uid = ? AND valid_to IS NULL').run(at, uid);
  }

  upsertEdge(a: EdgeAssertion, at = NOW()): string {
    const srcUid = assetUid(a.src.type, a.src.identity);
    const dstUid = assetUid(a.dst.type, a.dst.identity);
    this.upsertNode(a.src, at);
    this.upsertNode(a.dst, at);
    const uid = `edge:${a.edgeType}:${srcUid}:${dstUid}`;
    const prov = JSON.stringify(a.provenance ?? []);
    const existing = this.db.prepare('SELECT uid FROM graph_edges WHERE uid = ?').get(uid) as { uid: string } | undefined;
    if (existing === undefined) {
      this.db.prepare(
        `INSERT INTO graph_edges (uid, edge_type, src_uid, dst_uid, first_seen, last_seen, valid_from, valid_to, observed_at, provenance_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
      ).run(uid, a.edgeType, srcUid, dstUid, at, at, at, at, prov);
    } else {
      this.db.prepare('UPDATE graph_edges SET last_seen = ?, observed_at = ?, valid_to = NULL, provenance_json = ? WHERE uid = ?')
        .run(at, at, prov, uid);
    }
    return uid;
  }

  getEdge(uid: string): AssetEdge | undefined {
    const r = this.db.prepare('SELECT * FROM graph_edges WHERE uid = ?').get(uid) as EdgeRow | undefined;
    return r === undefined ? undefined : rowToEdge(r);
  }

  /** Open out-edges from a node. */
  outEdges(uid: string, edgeTypes?: EdgeType[]): AssetEdge[] {
    const rows = this.db.prepare('SELECT * FROM graph_edges WHERE src_uid = ? AND valid_to IS NULL').all(uid) as unknown as EdgeRow[];
    return rows.map(rowToEdge).filter((e) => edgeTypes === undefined || edgeTypes.includes(e.edgeType));
  }

  inEdges(uid: string, edgeTypes?: EdgeType[]): AssetEdge[] {
    const rows = this.db.prepare('SELECT * FROM graph_edges WHERE dst_uid = ? AND valid_to IS NULL').all(uid) as unknown as EdgeRow[];
    return rows.map(rowToEdge).filter((e) => edgeTypes === undefined || edgeTypes.includes(e.edgeType));
  }

  neighbors(uid: string, edgeTypes?: EdgeType[]): AssetNode[] {
    const out = this.outEdges(uid, edgeTypes).map((e) => this.getNode(e.dstUid)).filter((n): n is AssetNode => n !== undefined);
    const inn = this.inEdges(uid, edgeTypes).map((e) => this.getNode(e.srcUid)).filter((n): n is AssetNode => n !== undefined);
    const seen = new Set<string>(out.map((n) => n.uid));
    return [...out, ...inn.filter((n) => !seen.has(n.uid))];
  }

  /** Bounded traversal (C4). Depth-capped; returns visited nodes and the edges used. */
  traverse(originUid: string, opts: { maxDepth?: number; edgeTypes?: EdgeType[]; maxNodes?: number } = {}): { nodes: AssetNode[]; edges: AssetEdge[] } {
    const maxDepth = opts.maxDepth ?? 3;
    const maxNodes = opts.maxNodes ?? 200;
    const nodes: AssetNode[] = [];
    const edges: AssetEdge[] = [];
    const seenNodes = new Set<string>([originUid]);
    let frontier = [originUid];
    for (let depth = 0; depth < maxDepth && frontier.length > 0 && nodes.length < maxNodes; depth++) {
      const next: string[] = [];
      for (const uid of frontier) {
        const out = this.outEdges(uid, opts.edgeTypes);
        const inn = this.inEdges(uid, opts.edgeTypes);
        for (const e of [...out, ...inn]) {
          if (edges.length < maxNodes * 3) edges.push(e);
          for (const nuid of [e.srcUid, e.dstUid]) {
            if (seenNodes.has(nuid)) continue;
            seenNodes.add(nuid);
            const n = this.getNode(nuid);
            if (n !== undefined && nodes.length < maxNodes) {
              nodes.push(n);
              next.push(nuid);
            }
          }
        }
      }
      frontier = next;
    }
    return { nodes, edges };
  }

  /** Fan-out count for the blast factor (capped). */
  fanout(uid: string, edgeTypes?: EdgeType[]): number {
    return this.outEdges(uid, edgeTypes).length + this.inEdges(uid, edgeTypes).length;
  }

  counts(): { nodes: number; edges: number } {
    const n = this.db.prepare('SELECT COUNT(*) c FROM graph_nodes').get() as { c: number };
    const e = this.db.prepare('SELECT COUNT(*) c FROM graph_edges').get() as { c: number };
    return { nodes: n.c, edges: e.c };
  }
}

function rowToNode(r: NodeRow): AssetNode {
  return {
    uid: r.uid,
    type: r.type as NodeType,
    identity: r.identity,
    display: r.display,
    attributes: JSON.parse(r.attributes_json) as Record<string, unknown>,
    firstSeen: r.first_seen,
    lastSeen: r.last_seen,
    validFrom: r.valid_from,
    validTo: r.valid_to,
    observedAt: r.observed_at,
    provenance: JSON.parse(r.provenance_json) as string[],
  };
}

function rowToEdge(r: EdgeRow): AssetEdge {
  return {
    uid: r.uid,
    edgeType: r.edge_type as EdgeType,
    srcUid: r.src_uid,
    dstUid: r.dst_uid,
    firstSeen: r.first_seen,
    lastSeen: r.last_seen,
    validFrom: r.valid_from,
    validTo: r.valid_to,
    observedAt: r.observed_at,
    provenance: JSON.parse(r.provenance_json) as string[],
  };
}
