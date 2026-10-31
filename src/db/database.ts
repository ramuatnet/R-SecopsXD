/**
 * Persistence layer: node:sqlite connection, migrations and repositories.
 * All persistence in the platform goes through this module.
 */
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  randomUUID, createHash, randomBytes, timingSafeEqual,
  createCipheriv, createDecipheriv, createHmac,
} from 'node:crypto';
import type { Engagement, 
  AuditEntry, CoverageReport, EngineRunRecord, Finding, Scan, ScanStats, Target,
  ValidationStatus,
} from '../core/types.ts';
import { log } from '../logging.ts';

const MIGRATIONS: string[] = [
  // 001 initial schema
  `
  CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    source_path TEXT,
    approved INTEGER NOT NULL DEFAULT 0,
    approved_at TEXT,
    approved_by TEXT,
    notes TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    profile TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    engines_json TEXT NOT NULL DEFAULT '[]',
    coverage_json TEXT NOT NULL DEFAULT '[]',
    stats_json TEXT NOT NULL DEFAULT '{}',
    error TEXT
  );
  CREATE TABLE IF NOT EXISTS findings (
    id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL,
    cwe INTEGER,
    cve TEXT,
    asset TEXT NOT NULL,
    locator TEXT NOT NULL,
    engine TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    explanation TEXT NOT NULL,
    remediation TEXT NOT NULL,
    references_json TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, id)
  );
  CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
  CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
  CREATE TABLE IF NOT EXISTS triages (
    fingerprint TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    note TEXT
  );
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details_json TEXT
  );
  CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  `,
  // 002: credential profiles for authenticated testing (backlog B1)
  `
  CREATE TABLE IF NOT EXISTS credentials (
    target_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    password_enc TEXT NOT NULL,
    login_url TEXT,
    username_field TEXT,
    password_field TEXT,
    created_at TEXT NOT NULL
  );
  `,
  // 003: multiple roles per target (cross-role authorization matrix)
  `
  CREATE TABLE credentials_v3 (
    target_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'primary',
    username TEXT NOT NULL,
    password_enc TEXT NOT NULL,
    login_url TEXT,
    username_field TEXT,
    password_field TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (target_id, role)
  );
  INSERT INTO credentials_v3 (target_id, role, username, password_enc, login_url, username_field, password_field, created_at)
    SELECT target_id, 'primary', username, password_enc, login_url, username_field, password_field, created_at FROM credentials;
  DROP TABLE credentials;
  ALTER TABLE credentials_v3 RENAME TO credentials;
  `,
  // 005: JSON-API login support
  `
  ALTER TABLE credentials ADD COLUMN login_type TEXT DEFAULT 'form';
  ALTER TABLE credentials ADD COLUMN token_field TEXT;
  `,
  // 004: target model (v2 Phase 1) — knowledge graph + append-only delta chain
  `
  CREATE TABLE IF NOT EXISTS model_nodes (
    target_id TEXT NOT NULL,
    node_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT,
    value_json TEXT NOT NULL,
    provenance TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (target_id, node_key)
  );
  CREATE TABLE IF NOT EXISTS model_deltas (
    target_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    op TEXT NOT NULL,
    kind TEXT NOT NULL,
    node_key TEXT NOT NULL,
    state TEXT,
    value_json TEXT,
    provenance TEXT NOT NULL,
    ts TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    PRIMARY KEY (target_id, seq)
  );
  `,
  // 006: loop trace (T-W4) — per-iteration audit trail
  `
  CREATE TABLE IF NOT EXISTS scan_trace (
    target_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    iteration INTEGER NOT NULL,
    action_id TEXT,
    outcome TEXT NOT NULL,
    finding_count INTEGER NOT NULL DEFAULT 0,
    requests_after INTEGER NOT NULL DEFAULT 0,
    ts TEXT NOT NULL,
    PRIMARY KEY (scan_id, iteration)
  );
  `,
  // 007 unified asset graph (newtask.md C1) — bitemporal nodes/edges + normalized events.
  // Nothing is deleted: nodes/edges are closed via valid_to; history stays queryable.
  `
  CREATE TABLE IF NOT EXISTS graph_nodes (
    uid TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    identity TEXT NOT NULL,
    display TEXT NOT NULL,
    attributes_json TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    observed_at TEXT NOT NULL,
    provenance_json TEXT NOT NULL DEFAULT '[]'
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_nodes_type_identity ON graph_nodes(type, identity);
  CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(type);
  CREATE TABLE IF NOT EXISTS graph_edges (
    uid TEXT PRIMARY KEY,
    edge_type TEXT NOT NULL,
    src_uid TEXT NOT NULL,
    dst_uid TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    observed_at TEXT NOT NULL,
    provenance_json TEXT NOT NULL DEFAULT '[]'
  );
  CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(src_uid);
  CREATE INDEX IF NOT EXISTS idx_graph_edges_dst ON graph_edges(dst_uid);
  CREATE INDEX IF NOT EXISTS idx_graph_edges_type ON graph_edges(edge_type);
  CREATE TABLE IF NOT EXISTS graph_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    class_uid TEXT NOT NULL,
    activity_id TEXT NOT NULL,
    asset_uid TEXT NOT NULL,
    source_uid TEXT,
    observables_json TEXT NOT NULL,
    observable_hash TEXT NOT NULL,
    severity_raw TEXT NOT NULL,
    severity_norm TEXT NOT NULL,
    confidence TEXT NOT NULL,
    time TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    evidence_ref TEXT,
    provenance_json TEXT NOT NULL DEFAULT '[]',
    times_seen INTEGER NOT NULL DEFAULT 1
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_events_dedupe
    ON graph_events(class_uid, asset_uid, observable_hash);
  CREATE INDEX IF NOT EXISTS idx_graph_events_asset ON graph_events(asset_uid);
  `,
  // 008 (newtasks.md E1-E6): engagement/RoE entity + finding enrichment
  // (exploit artefacts, retest results, escalation records).
  `
  CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scope_json TEXT NOT NULL DEFAULT '[]',
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    contacts_technical TEXT NOT NULL DEFAULT '',
    contacts_emergency TEXT NOT NULL DEFAULT '',
    emergency_stop INTEGER NOT NULL DEFAULT 0,
    rate_ceiling INTEGER NOT NULL DEFAULT 0,
    permitted_classes_json TEXT NOT NULL DEFAULT '[]',
    signer TEXT NOT NULL DEFAULT '',
    attestation_ref TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS findings_enrichment (
    scan_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    exploit_json TEXT,
    retest_json TEXT,
    escalate_json TEXT,
    PRIMARY KEY (scan_id, finding_id)
  );
  `,
];

export class Database {
  private readonly db: DatabaseSync;
  /** Raw handle — used only by the TargetModel store (same process, same writer). */
  get handle(): DatabaseSync { return this.db; }
  readonly path: string;

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true });
    this.path = join(dataDir, 'platform.db');
    this.db = new DatabaseSync(this.path);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.migrate();
  }

  private migrate(): void {
    this.db.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)');
    const row = this.db.prepare('SELECT MAX(version) AS v FROM schema_migrations').get() as { v: number | null };
    const current = row?.v ?? 0;
    for (let i = 0; i < MIGRATIONS.length; i++) {
      const version = i + 1;
      if (version <= current) continue;
      this.db.exec('BEGIN');
      try {
        this.db.exec(MIGRATIONS[i]!);
        this.db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)').run(version, new Date().toISOString());
        this.db.exec('COMMIT');
        log.info('migration applied', { version });
      } catch (e) {
        this.db.exec('ROLLBACK');
        throw e;
      }
    }
  }

  close(): void {
    this.db.close();
  }

  // ---- auth token ----

  /**
   * Store/replace the auth token hash. Returns the sha256 hex stored.
   * The plaintext is intentionally never persisted in the DB.
   */
  setAuthToken(token: string): void {
    const h = createHash('sha256').update(token, 'utf8').digest('hex');
    this.db.prepare(
      "INSERT INTO config (key, value) VALUES ('auth_token_sha256', ?) " +
      'ON CONFLICT(key) DO UPDATE SET value = excluded.value',
    ).run(h);
  }

  verifyToken(candidate: string): boolean {
    const row = this.db.prepare('SELECT value FROM config WHERE key = ?').get('auth_token_sha256') as { value: string } | undefined;
    if (!row) return false;
    const a = Buffer.from(createHash('sha256').update(candidate, 'utf8').digest('hex'), 'hex');
    const b = Buffer.from(row.value, 'hex');
    return a.length === b.length && timingSafeEqual(a, b);
  }

  hasAuthToken(): boolean {
    const row = this.db.prepare('SELECT 1 AS x FROM config WHERE key = ?').get('auth_token_sha256') as { x: number } | undefined;
    return row !== undefined;
  }

  // ---- targets ----

  createTarget(t: Omit<Target, 'id' | 'createdAt'>): Target {
    const target: Target = { ...t, id: randomUUID(), createdAt: new Date().toISOString() };
    this.db.prepare(
      'INSERT INTO targets (id, name, origin, kind, source_path, approved, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(target.id, target.name, target.origin, target.kind, target.sourcePath ?? null, target.approved ? 1 : 0, target.notes ?? null, target.createdAt);
    return target;
  }

  getTarget(id: string): Target | undefined {
    const r = this.db.prepare('SELECT * FROM targets WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    return r ? rowToTarget(r) : undefined;
  }

  listTargets(): Target[] {
    const rows = this.db.prepare('SELECT * FROM targets ORDER BY created_at DESC').all() as Array<Record<string, unknown>>;
    return rows.map(rowToTarget);
  }

  approveTarget(id: string, by: string): Target | undefined {
    const t = this.getTarget(id);
    if (!t) return undefined;
    const at = new Date().toISOString();
    this.db.prepare('UPDATE targets SET approved = 1, approved_at = ?, approved_by = ? WHERE id = ?').run(at, by, id);
    return this.getTarget(id);
  }

  deleteTarget(id: string): boolean {
    this.deleteCredentials(id); // credentials do not outlive their target
    const info = this.db.prepare('DELETE FROM targets WHERE id = ?').run(id);
    return info.changes > 0;
  }

  // ---- credential profiles (authenticated testing, backlog B1) ----

  /**
   * The master key protects credential rows against casual DB-file browsing.
   * It does NOT protect against full-directory compromise (the key lives in the
   * same data directory) — documented residual risk in docs/THREAT-MODEL.md.
   */
  private credentialMasterKey(): Buffer {
    const row = this.db.prepare('SELECT value FROM config WHERE key = ?').get('cred_master_key') as { value: string } | undefined;
    if (row) return Buffer.from(row.value, 'hex');
    const key = randomBytes(32).toString('hex');
    this.db.prepare("INSERT INTO config (key, value) VALUES ('cred_master_key', ?)").run(key);
    return Buffer.from(key, 'hex');
  }

  private encryptSecret(plaintext: string): string {
    const key = this.credentialMasterKey();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${enc.toString('base64')}`;
  }

  private decryptSecret(blob: string): string {
    const [version, ivB64, tagB64, dataB64] = blob.split(':');
    if (version !== 'v1') throw new Error('unknown credential encryption version');
    const decipher = createDecipheriv('aes-256-gcm', this.credentialMasterKey(), Buffer.from(ivB64!, 'base64'));
    decipher.setAuthTag(Buffer.from(tagB64!, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(dataB64!, 'base64')), decipher.final()]).toString('utf8');
  }

  setCredentials(targetId: string, cred: {
    username: string; password: string; role?: string | undefined;
    loginType?: string | undefined; tokenField?: string | undefined;
    loginUrl?: string | undefined; usernameField?: string | undefined; passwordField?: string | undefined;
  }): void {
    const role = cred.role ?? 'primary';
    this.db.prepare(
      'INSERT INTO credentials (target_id, role, username, password_enc, login_url, username_field, password_field, login_type, token_field, created_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(target_id, role) DO UPDATE SET username = excluded.username, ' +
      'password_enc = excluded.password_enc, login_url = excluded.login_url, username_field = excluded.username_field, ' +
      'password_field = excluded.password_field, login_type = excluded.login_type, token_field = excluded.token_field, ' +
      'created_at = excluded.created_at',
    ).run(
      targetId, role, cred.username, this.encryptSecret(cred.password),
      cred.loginUrl ?? null, cred.usernameField ?? null, cred.passwordField ?? null,
      cred.loginType ?? 'form', cred.tokenField ?? null,
      new Date().toISOString(),
    );
    this.audit({ actor: 'operator', action: 'target.credentials.set', details: { targetId, username: cred.username, role } });
  }

  getCredentials(targetId: string, role = 'primary'): { username: string; password: string; role: string; loginType: string; tokenField?: string; loginUrl?: string; usernameField?: string; passwordField?: string } | undefined {
    const r = this.db.prepare('SELECT * FROM credentials WHERE target_id = ? AND role = ?').get(targetId, role) as Record<string, unknown> | undefined;
    if (!r) return undefined;
    const cred: { username: string; password: string; role: string; loginType: string; tokenField?: string; loginUrl?: string; usernameField?: string; passwordField?: string } = {
      username: r.username as string,
      password: this.decryptSecret(r.password_enc as string),
      role: r.role as string,
      loginType: (r.login_type as string) ?? 'form',
    };
    if (r.token_field) cred.tokenField = r.token_field as string;
    if (r.login_url) cred.loginUrl = r.login_url as string;
    if (r.username_field) cred.usernameField = r.username_field as string;
    if (r.password_field) cred.passwordField = r.password_field as string;
    return cred;
  }

  getRoles(targetId: string): string[] {
    const rows = this.db.prepare('SELECT role FROM credentials WHERE target_id = ?').all(targetId) as Array<{ role: string }>;
    return rows.map((r) => r.role);
  }

  hasCredentials(targetId: string): boolean {
    return this.db.prepare('SELECT 1 AS x FROM credentials WHERE target_id = ?').get(targetId) !== undefined;
  }

  deleteCredentials(targetId: string, role?: string): boolean {
    const info = role !== undefined
      ? this.db.prepare('DELETE FROM credentials WHERE target_id = ? AND role = ?').run(targetId, role)
      : this.db.prepare('DELETE FROM credentials WHERE target_id = ?').run(targetId);
    if (info.changes > 0) this.audit({ actor: 'operator', action: 'target.credentials.deleted', details: { targetId, role: role ?? 'all' } });
    return info.changes > 0;
  }

  writeTraceEntry(scanId: string, targetId: string, entry: { iteration: number; actionId?: string | undefined; outcome: string; findingCount: number; requestsAfter: number }): void {
    this.db.prepare(
      'INSERT OR REPLACE INTO scan_trace (target_id, scan_id, iteration, action_id, outcome, finding_count, requests_after, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(targetId, scanId, entry.iteration, entry.actionId ?? null, entry.outcome, entry.findingCount, entry.requestsAfter, new Date().toISOString());
  }

  readTrace(scanId: string): Array<{ iteration: number; actionId?: string | undefined; outcome: string; findingCount: number; requestsAfter: number; ts: string }> {
    return (this.db.prepare('SELECT * FROM scan_trace WHERE scan_id = ? ORDER BY iteration').all(scanId) as Array<Record<string, unknown>>).map((r) => ({
      iteration: r.iteration as number,
      actionId: (r.action_id as string | null) ?? undefined,
      outcome: r.outcome as string,
      findingCount: r.finding_count as number,
      requestsAfter: r.requests_after as number,
      ts: r.ts as string,
    }));
  }

  getConfigValue(key: string): string | undefined {
    const r = this.db.prepare('SELECT value FROM config WHERE key = ?').get(key) as { value: string } | undefined;
    return r?.value;
  }

  setConfigValue(key: string, value: string): void {
    this.db.prepare('INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run(key, value);
  }

  /** Key used for test-hashing credential identities in reports (never the secret itself). */
  credentialFingerprint(targetId: string, username: string): string {
    return createHmac('sha256', this.credentialMasterKey()).update(`${targetId}:${username}`).digest('hex').slice(0, 12);
  }

  // ---- scans ----

  insertScan(s: Scan): void {
    this.db.prepare(
      'INSERT INTO scans (id, target_id, target_name, profile, mode, status, started_at, finished_at, engines_json, coverage_json, stats_json, error) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(s.id, s.targetId, s.targetName, s.profile, s.mode, s.status, s.startedAt, s.finishedAt ?? null,
      JSON.stringify(s.engines), JSON.stringify(s.coverage), JSON.stringify(s.stats), s.error ?? null);
  }

  updateScan(id: string, fields: Partial<Pick<Scan, 'status' | 'finishedAt' | 'engines' | 'coverage' | 'stats' | 'error'>>): void {
    const sets: string[] = [];
    const vals: Array<string | number | null> = [];
    if (fields.status !== undefined) { sets.push('status = ?'); vals.push(fields.status); }
    if (fields.finishedAt !== undefined) { sets.push('finished_at = ?'); vals.push(fields.finishedAt); }
    if (fields.engines !== undefined) { sets.push('engines_json = ?'); vals.push(JSON.stringify(fields.engines)); }
    if (fields.coverage !== undefined) { sets.push('coverage_json = ?'); vals.push(JSON.stringify(fields.coverage)); }
    if (fields.stats !== undefined) { sets.push('stats_json = ?'); vals.push(JSON.stringify(fields.stats)); }
    if (fields.error !== undefined) { sets.push('error = ?'); vals.push(fields.error); }
    if (sets.length === 0) return;
    vals.push(id);
    this.db.prepare(`UPDATE scans SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
  }

  getScan(id: string): Scan | undefined {
    const r = this.db.prepare('SELECT * FROM scans WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    return r ? rowToScan(r) : undefined;
  }

  listScans(limit = 100): Scan[] {
    const rows = this.db.prepare('SELECT * FROM scans ORDER BY started_at DESC LIMIT ?').all(limit) as Array<Record<string, unknown>>;
    return rows.map(rowToScan);
  }

  latestCompletedScanForTarget(targetId: string): Scan | undefined {
    const r = this.db.prepare(
      "SELECT * FROM scans WHERE target_id = ? AND status = 'completed' ORDER BY started_at DESC LIMIT 1",
    ).get(targetId) as Record<string, unknown> | undefined;
    return r ? rowToScan(r) : undefined;
  }

  // ---- findings ----

  insertFindings(scanId: string, findings: Finding[]): void {
    const stmt = this.db.prepare(
      'INSERT OR REPLACE INTO findings (id, scan_id, fingerprint, title, category, severity, confidence, status, cwe, cve, asset, locator, engine, evidence_json, explanation, remediation, references_json, detected_at, provenance_json) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    );
    this.db.exec('BEGIN');
    try {
      for (const f of findings) {
        stmt.run(f.id, scanId, f.fingerprint, f.title, f.category, f.severity, f.confidence, f.status,
          f.cwe ?? null, f.cve ?? null, f.asset, f.locator, f.engine, JSON.stringify(f.evidence),
          f.explanation, f.remediation, JSON.stringify(f.references), f.detectedAt, JSON.stringify(f.provenance));
      }
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  getFindings(scanId: string): Finding[] {
    const rows = this.db.prepare('SELECT * FROM findings WHERE scan_id = ?').all(scanId) as Array<Record<string, unknown>>;
    const enr = this.db.prepare('SELECT * FROM findings_enrichment WHERE scan_id = ?').all(scanId) as Array<Record<string, unknown>>;
    const byId = new Map(enr.map((r) => [r.finding_id as string, r]));
    return rows.map((r) => rowToFinding(r, byId.get(r.id as string)));
  }

  /**
   * E2/E3/E6 (newtasks.md): persist finding enrichment — exploit artefacts,
   * retest outcomes, escalation records (separate table; base rows immutable).
   */
  setFindingEnrichment(scanId: string, findingId: string, patch: { exploit?: unknown; retest?: unknown; escalate?: unknown }): void {
    const existing = this.db.prepare('SELECT * FROM findings_enrichment WHERE scan_id = ? AND finding_id = ?').get(scanId, findingId) as Record<string, unknown> | undefined;
    const cur = existing ?? { scan_id: scanId, finding_id: findingId, exploit_json: null, retest_json: null, escalate_json: null };
    const enc = (v: unknown, curCol: unknown): string | null => v === undefined ? (curCol as string | null) : JSON.stringify(v);
    this.db.prepare(
      `INSERT INTO findings_enrichment (scan_id, finding_id, exploit_json, retest_json, escalate_json)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(scan_id, finding_id) DO UPDATE SET exploit_json = excluded.exploit_json, retest_json = excluded.retest_json, escalate_json = excluded.escalate_json`,
    ).run(scanId, findingId,
      enc(patch.exploit, cur.exploit_json),
      enc(patch.retest, cur.retest_json),
      enc(patch.escalate, cur.escalate_json));
    this.audit({ actor: 'system', action: 'finding.enriched', details: { scanId, findingId, keys: Object.keys(patch) } });
  }

  /** E6.2: escalation queue across all scans. */
  getEscalated(): Array<{ scanId: string; finding: Finding }> {
    const rows = this.db.prepare('SELECT scan_id, finding_id, escalate_json, exploit_json, retest_json FROM findings_enrichment WHERE escalate_json IS NOT NULL').all() as Array<Record<string, unknown>>;
    const out: Array<{ scanId: string; finding: Finding }> = [];
    for (const r of rows) {
      const f = this.getFindings(r.scan_id as string).find((x) => x.id === r.finding_id);
      if (f !== undefined) out.push({ scanId: r.scan_id as string, finding: f });
    }
    return out;
  }

  // ---- engagements (E1) ----

  createEngagement(e: Engagement): Engagement {
    this.db.prepare(
      `INSERT INTO engagements (id, name, scope_json, window_start, window_end, contacts_technical, contacts_emergency, emergency_stop, rate_ceiling, permitted_classes_json, signer, attestation_ref, active, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(e.id, e.name, JSON.stringify(e.scope), e.windowStart, e.windowEnd, e.contactsTechnical, e.contactsEmergency,
      e.emergencyStop ? 1 : 0, e.rateCeiling, JSON.stringify(e.permittedClasses), e.signer, e.attestationRef, e.active ? 1 : 0, e.createdAt);
    this.audit({ actor: 'operator', action: 'engagement.created', details: { engagementId: e.id, scope: e.scope.length } });
    return e;
  }

  getEngagement(id: string): Engagement | undefined {
    const r = this.db.prepare('SELECT * FROM engagements WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    return r === undefined ? undefined : rowToEngagement(r);
  }

  listEngagements(): Engagement[] {
    const rows = this.db.prepare('SELECT * FROM engagements ORDER BY created_at DESC').all() as Array<Record<string, unknown>>;
    return rows.map(rowToEngagement);
  }

  /** E1.4: emergency stop — flag + deactivate; caller aborts in-flight scans. */
  stopEngagement(id: string): Engagement | undefined {
    const e = this.getEngagement(id);
    if (e === undefined) return undefined;
    this.db.prepare('UPDATE engagements SET emergency_stop = 1, active = 0 WHERE id = ?').run(id);
    this.audit({ actor: 'operator', action: 'engagement.stopped', details: { engagementId: id } });
    return this.getEngagement(id);
  }

  /** The engagement covering a target (by target id or origin in scope). */
  engagementForTarget(targetId: string, origin: string): Engagement | undefined {
    return this.listEngagements().find((e) =>
      e.scope.includes(targetId) || (origin !== '' && e.scope.includes(origin)));
  }

  /**
   * Apply a human triage to a finding: updates the row and records a
   * fingerprint-level override so future scans inherit the decision.
   */
  triageFinding(scanId: string, findingId: string, status: ValidationStatus, actor: string, note?: string): Finding | undefined {
    const f = this.getFindings(scanId).find((x) => x.id === findingId);
    if (!f) return undefined;
    this.db.prepare('UPDATE findings SET status = ? WHERE scan_id = ? AND id = ?').run(status, scanId, findingId);
    this.db.prepare(
      'INSERT INTO triages (fingerprint, status, updated_at, note) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT(fingerprint) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at, note = excluded.note',
    ).run(f.fingerprint, status, new Date().toISOString(), note ?? null);
    this.audit({ actor, action: 'finding.triage', details: { findingId, status } });
    return this.getFindings(scanId).find((x) => x.id === findingId);
  }

  /** E3 (newtasks.md): retest status update — deliberately NOT a triage override. */
  updateFindingStatus(scanId: string, findingId: string, status: ValidationStatus): void {
    this.db.prepare('UPDATE findings SET status = ? WHERE scan_id = ? AND id = ?').run(status, scanId, findingId);
  }

  getTriages(): Map<string, ValidationStatus> {
    const rows = this.db.prepare('SELECT fingerprint, status FROM triages').all() as Array<{ fingerprint: string; status: ValidationStatus }>;
    return new Map(rows.map((r) => [r.fingerprint, r.status]));
  }

  // ---- audit ----

  audit(entry: Omit<AuditEntry, 'id' | 'ts'> & { ts?: string }): void {
    this.db.prepare('INSERT INTO audit_log (ts, actor, action, details_json) VALUES (?, ?, ?, ?)')
      .run(entry.ts ?? new Date().toISOString(), entry.actor, entry.action, entry.details ? JSON.stringify(entry.details) : null);
  }

  listAudit(limit = 200): AuditEntry[] {
    const rows = this.db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: r.id as number,
      ts: r.ts as string,
      actor: r.actor as string,
      action: r.action as string,
      details: r.details_json ? JSON.parse(r.details_json as string) : undefined,
    }));
  }
}

function rowToTarget(r: Record<string, unknown>): Target {
  return {
    id: r.id as string,
    name: r.name as string,
    origin: r.origin as string,
    kind: r.kind as Target['kind'],
    sourcePath: (r.source_path as string | null) ?? undefined,
    approved: (r.approved as number) === 1,
    approvedAt: (r.approved_at as string | null) ?? undefined,
    approvedBy: (r.approved_by as string | null) ?? undefined,
    notes: (r.notes as string | null) ?? undefined,
    createdAt: r.created_at as string,
  };
}

function rowToScan(r: Record<string, unknown>): Scan {
  return {
    id: r.id as string,
    targetId: r.target_id as string,
    targetName: r.target_name as string,
    profile: r.profile as string,
    mode: r.mode as Scan['mode'],
    status: r.status as Scan['status'],
    startedAt: r.started_at as string,
    finishedAt: (r.finished_at as string | null) ?? undefined,
    engines: JSON.parse(r.engines_json as string) as EngineRunRecord[],
    coverage: JSON.parse(r.coverage_json as string) as CoverageReport[],
    stats: JSON.parse(r.stats_json as string) as ScanStats,
    error: (r.error as string | null) ?? undefined,
  };
}

function rowToFinding(r: Record<string, unknown>, enr?: Record<string, unknown>): Finding {
  const base: Finding = {
    id: r.id as string,
    fingerprint: r.fingerprint as string,
    title: r.title as string,
    category: r.category as Finding['category'],
    severity: r.severity as Finding['severity'],
    confidence: r.confidence as Finding['confidence'],
    status: r.status as Finding['status'],
    cwe: (r.cwe as number | null) ?? undefined,
    cve: (r.cve as string | null) ?? undefined,
    asset: r.asset as string,
    locator: r.locator as string,
    engine: r.engine as string,
    evidence: JSON.parse(r.evidence_json as string),
    explanation: r.explanation as string,
    remediation: r.remediation as string,
    references: JSON.parse(r.references_json as string),
    detectedAt: r.detected_at as string,
    provenance: JSON.parse(r.provenance_json as string),
  };
  if (enr !== undefined) {
    if (enr.exploit_json !== null && enr.exploit_json !== undefined) base.exploit = JSON.parse(enr.exploit_json as string) as Finding['exploit'];
    if (enr.retest_json !== null && enr.retest_json !== undefined) base.retest = JSON.parse(enr.retest_json as string) as Finding['retest'];
    if (enr.escalate_json !== null && enr.escalate_json !== undefined) base.escalate = JSON.parse(enr.escalate_json as string) as Finding['escalate'];
  }
  return base;
}

function rowToEngagement(r: Record<string, unknown>): Engagement {
  return {
    id: r.id as string,
    name: r.name as string,
    scope: JSON.parse(r.scope_json as string) as string[],
    windowStart: r.window_start as string,
    windowEnd: r.window_end as string,
    contactsTechnical: r.contacts_technical as string,
    contactsEmergency: r.contacts_emergency as string,
    emergencyStop: r.emergency_stop === 1,
    rateCeiling: r.rate_ceiling as number,
    permittedClasses: JSON.parse(r.permitted_classes_json as string) as Engagement['permittedClasses'],
    signer: r.signer as string,
    attestationRef: r.attestation_ref as string,
    active: r.active === 1,
    createdAt: r.created_at as string,
  };
}

/** Generate a human-friendly opaque token. */
export function generateToken(): string {
  return `ova_${randomBytes(24).toString('base64url')}`;
}
