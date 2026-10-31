/**
 * Graph sync seam (newtask.md C1–C3 wiring): findings from a completed scan
 * are routed through the source adapters, node/edge assertions are applied to
 * the GraphStore, and NormalizedEvents are recorded in the EventStore with
 * dedupe. Graph failures never break the scan (logged only).
 */
import type { Finding } from '../core/types.ts';
import { adapt } from './adapters.ts';
import { GraphStore } from './graph.ts';
import { EventStore } from './merger.ts';
import { log } from '../logging.ts';

export interface GraphSyncStats { findings: number; events: number; deduped: number; nodes: number; edges: number; }

export function syncFindingsToGraph(
  store: GraphStore,
  events: EventStore,
  findings: Finding[],
  scanId: string,
): GraphSyncStats {
  const stats: GraphSyncStats = { findings: findings.length, events: 0, deduped: 0, nodes: 0, edges: 0 };
  for (const f of findings) {
    try {
      const out = adapt(f);
      for (const n of out.nodes) {
        const prov = [...new Set(f.provenance.map((p) => p.engine))];
        store.upsertNode({ ...n, provenance: prov.length > 0 ? prov : ['unknown'] });
        stats.nodes++;
      }
      for (const e of out.edges) {
        const prov = [...new Set(f.provenance.map((p) => p.engine))];
        store.upsertEdge({ ...e, provenance: prov.length > 0 ? prov : ['unknown'] });
        stats.edges++;
      }
      for (const ev of out.events) {
        const withScan = ev.provenance.map((p) => ({ ...p, scanId }));
        const r = events.record({ ...ev, provenance: withScan });
        stats.events++;
        if (r.deduped) stats.deduped++;
      }
    } catch (e) {
      log.warn('graph sync skipped a finding', { scanId, finding: f.id, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return stats;
}
