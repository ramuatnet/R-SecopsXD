/**
 * Event store + merger (newtask.md C3).
 *
 * Dedupe key: (class_uid, asset_uid, observable-hash). A re-observation
 * updates last_seen and merges provenance — the raw severity of the FIRST
 * source is preserved verbatim and never overwritten (3.1 rule); only the
 * normalized severity may ratchet up.
 */
import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { NormalizedEvent, Observable } from './types.ts';

export function observableHash(observables: Observable[]): string {
  const canonical = [...observables]
    .map((o) => `${o.kind}=${o.value.trim().toLowerCase()}`)
    .sort()
    .join('|');
  return createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 32);
}

interface EventRow {
  class_uid: string; asset_uid: string; observable_hash: string; observables_json: string;
  severity_raw: string; severity_norm: string; first_seen: string; last_seen: string;
  provenance_json: string; times_seen: number;
}

const SEV_RANK: Record<string, number> = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };

export class EventStore {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  /** Record one event, merging into an existing dedupe row when present. */
  record(e: NormalizedEvent): { deduped: boolean } {
    const hash = observableHash(e.observables);
    const existing = this.db.prepare(
      'SELECT * FROM graph_events WHERE class_uid = ? AND asset_uid = ? AND observable_hash = ?',
    ).get(e.classUid, e.assetUid, hash) as EventRow | undefined;

    if (existing === undefined) {
      this.db.prepare(
        `INSERT INTO graph_events
         (class_uid, activity_id, asset_uid, source_uid, observables_json, observable_hash,
          severity_raw, severity_norm, confidence, time, first_seen, last_seen, evidence_ref, provenance_json, times_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      ).run(
        e.classUid, e.activityId, e.assetUid, e.sourceUid ?? null,
        JSON.stringify(e.observables), hash,
        e.severityRaw, e.severityNorm, e.confidence, e.time, e.firstSeen, e.lastSeen,
        e.evidenceRef ?? null, JSON.stringify(e.provenance),
      );
      return { deduped: false };
    }

    // merge: raw severity of the first source is NEVER overwritten
    const firstSeen = existing.first_seen <= e.firstSeen ? existing.first_seen : e.firstSeen;
    const lastSeen = existing.last_seen >= e.lastSeen ? existing.last_seen : e.lastSeen;
    const prov = JSON.parse(existing.provenance_json) as NormalizedEvent['provenance'];
    for (const p of e.provenance) {
      if (!prov.some((q) => q.engine === p.engine && q.rawId === p.rawId)) prov.push(p);
    }
    const norm = (SEV_RANK[e.severityNorm] ?? 0) > (SEV_RANK[existing.severity_norm] ?? 0) ? e.severityNorm : existing.severity_norm;
    this.db.prepare(
      `UPDATE graph_events SET last_seen = ?, first_seen = ?, severity_norm = ?,
       provenance_json = ?, times_seen = times_seen + 1
       WHERE class_uid = ? AND asset_uid = ? AND observable_hash = ?`,
    ).run(lastSeen, firstSeen, norm, JSON.stringify(prov), e.classUid, e.assetUid, hash);
    return { deduped: true };
  }

  list(assetUid?: string): Array<EventRow & { observables: Observable[] }> {
    const rows = (assetUid === undefined
      ? this.db.prepare('SELECT * FROM graph_events ORDER BY time DESC LIMIT 500').all()
      : this.db.prepare('SELECT * FROM graph_events WHERE asset_uid = ? ORDER BY time DESC LIMIT 500').all(assetUid)) as unknown as EventRow[];
    return rows.map((r) => ({ ...r, observables: JSON.parse(r.observables_json ?? '[]') as Observable[] }));
  }
}

/** Pure merger for in-memory event batches (same dedupe rule, used by tests and the bus). */
export function mergeEvents(events: NormalizedEvent[]): NormalizedEvent[] {
  const byKey = new Map<string, NormalizedEvent>();
  for (const e of events) {
    const key = `${e.classUid}|${e.assetUid}|${observableHash(e.observables)}`;
    const existing = byKey.get(key);
    if (existing === undefined) {
      byKey.set(key, structuredClone(e));
      continue;
    }
    existing.firstSeen = existing.firstSeen <= e.firstSeen ? existing.firstSeen : e.firstSeen;
    existing.lastSeen = existing.lastSeen >= e.lastSeen ? existing.lastSeen : e.lastSeen;
    for (const p of e.provenance) {
      if (!existing.provenance.some((q) => q.engine === p.engine && q.rawId === p.rawId)) existing.provenance.push(p);
    }
    if ((SEV_RANK[e.severityNorm] ?? 0) > (SEV_RANK[existing.severityNorm] ?? 0)) existing.severityNorm = e.severityNorm;
    // severityRaw stays from the FIRST source — never overwritten (3.1)
  }
  return [...byKey.values()];
}
