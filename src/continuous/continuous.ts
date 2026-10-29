/**
 * Continuous security (v2 Phase 9, T9.1–T9.2) + SARIF export (T10.3).
 *
 * T9.1 scheduler: interval-based rescans of registered+approved targets with
 *   change-triggered targeted rescans (ETag/Last-Modified hash of the origin
 *   root). Every fire is audited; I2 applies (approved targets only).
 * T9.2 delta alerting: new findings since the previous completed scan →
 *   webhook POST with PoC refs + score factors. Failures logged, never fatal.
 * T10.3 SARIF export: findings → SARIF 2.1.0 run for CI integration.
 */
import type { Database } from '../db/database.ts';
import type { Finding } from '../core/types.ts';
import { log } from '../logging.ts';

// ---------- T9.1 scheduler ----------

export interface SchedulerOptions {
  intervalMs: number;
  onFire: (targetId: string) => Promise<void>;
  onError?: (targetId: string, error: unknown) => void;
}

export class ScanScheduler {
  private timers: Array<NodeJS.Timeout> = [];
  private running = false;
  private readonly options: SchedulerOptions;

  constructor(options: SchedulerOptions) {
    this.options = options;
  }

  start(targetIds: string[]): void {
    if (this.running) return;
    this.running = true;
    for (const id of targetIds) {
      const t = setInterval(() => {
        void this.fire(id);
      }, this.options.intervalMs);
      this.timers.push(t);
    }
    log.info('scheduler started', { targets: targetIds.length, intervalMs: this.options.intervalMs });
  }

  private async fire(targetId: string): Promise<void> {
    try {
      await this.options.onFire(targetId);
    } catch (e) {
      log.warn('scheduled scan failed', { targetId, error: e instanceof Error ? e.message : String(e) });
      this.options.onError?.(targetId, e);
    }
  }

  stop(): void {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    this.running = false;
  }
}

/** T9.1 change watcher: hash the origin root; a change triggers a targeted rescan. */
export async function originChanged(
  db: Database,
  targetId: string,
  origin: string,
  client: { get: (url: string) => Promise<{ ok: boolean; body: string; headers: Record<string, string> }> },
): Promise<boolean> {
  const key = `watch:${targetId}`;
  const prev = db.getConfigValue(key);
  try {
    const res = await client.get(origin + '/');
    if (!res.ok) return false;
    const etag = res.headers['etag'] ?? res.headers['last-modified'] ?? undefined;
    const hashInput = etag ?? `len:${res.body.length}`;
    if (prev !== undefined && prev !== hashInput) {
      db.setConfigValue(key, hashInput);
      return true;
    }
    if (prev === undefined) {
      db.setConfigValue(key, hashInput);
    }
    return false;
  } catch {
    return false;
  }
}

// ---------- T9.2 delta alerting ----------

export interface WebhookPayload {
  event: 'new_findings';
  target: { id: string; name: string };
  scanId: string;
  newFindings: Array<{
    id: string;
    title: string;
    category: string;
    severity: string;
    status: string;
    score?: number;
    evidenceRef?: string;
  }>;
}

export async function deliverWebhook(
  url: string,
  payload: WebhookPayload,
  timeoutMs = 10_000,
): Promise<{ delivered: boolean; status?: number; error?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    return { delivered: res.ok, status: res.status };
  } catch (e) {
    return { delivered: false, error: e instanceof Error ? e.message : String(e) };
  } finally {
    clearTimeout(timer);
  }
}

/** T9.2 — diff the last two completed scans and alert on new findings. */
export async function alertOnNewFindings(
  db: Database,
  targetId: string,
  scorer?: (f: Finding) => number,
  webhookUrl?: string,
): Promise<{ alerted: boolean; newCount: number }> {
  const completed = db.listScans(200).filter((s) => s.targetId === targetId && s.status === 'completed');
  if (completed.length < 2 || !webhookUrl) return { alerted: false, newCount: 0 };
  const to = completed[0]!;
  const from = completed[1]!;
  const toFps = new Set(db.getFindings(to.id).map((f) => f.fingerprint));
  // Alert-dedup: fingerprints already alerted for this target are skipped,
  // so repeated diffs against the same scan pair do not re-alert (T9.2).
  const alertKey = `alerted:${targetId}`;
  const alertedFps = new Set((db.getConfigValue(alertKey) ?? '').split(',').filter(Boolean));
  const newFindings = db.getFindings(from.id).filter(
    (f) => !toFps.has(f.fingerprint) && !alertedFps.has(f.fingerprint),
  );
  if (newFindings.length === 0) return { alerted: false, newCount: 0 };
  for (const f of newFindings) alertedFps.add(f.fingerprint);
  db.setConfigValue(alertKey, [...alertedFps].join(','));

  const payload: WebhookPayload = {
    event: 'new_findings',
    target: { id: targetId, name: to.targetName },
    scanId: to.id,
    newFindings: newFindings.map((f) => {
      const score = scorer?.(f);
      return {
        id: f.id, title: f.title, category: f.category as string,
        severity: f.severity as string, status: f.status as string,
        ...(score !== undefined ? { score } : {}),
      };
    }),
  };
  const result = await deliverWebhook(webhookUrl, payload);
  db.audit({ actor: 'system', action: 'alert.new_findings', details: { targetId, count: newFindings.length, delivered: result.delivered } });
  log.info('delta alert', { targetId, newFindings: newFindings.length, delivered: result.delivered });
  return { alerted: result.delivered, newCount: newFindings.length };
}

// ---------- T10.3 SARIF export ----------

const SEV_MAP: Record<string, string> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

/** T10.3 — SARIF 2.1.0 run for CI integration. */
export function toSarif(findings: Finding[], toolVersion = '0.2.0'): object {
  const rules = findings.map((f) => ({
    id: f.id,
    name: f.title.slice(0, 120),
    shortDescription: { text: f.title },
    fullDescription: { text: f.explanation.slice(0, 1024) },
    defaultConfiguration: { level: SEV_MAP[f.severity] ?? 'note' },
    properties: {
      'owasp-category': f.category,
      cwe: f.cwe,
      'security-severity': String({ critical: 9.5, high: 8, medium: 5, low: 3, info: 1 }[f.severity] ?? 1),
    },
  }));
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'R-SecopsXD',
          version: toolVersion,
          informationUri: 'https://github.com/ramuatnet/R-SecopsXD',
          rules,
        },
      },
      results: findings.map((f) => ({
        ruleId: f.id,
        ruleIndex: ruleIndex.get(f.id) ?? 0,
        level: SEV_MAP[f.severity] ?? 'note',
        message: { text: `${f.title} — ${f.explanation.slice(0, 400)}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.locator.startsWith('/') ? f.locator : `/${f.locator}` },
          },
        }],
        partialFingerprints: { fingerprint: f.fingerprint },
        properties: { status: f.status, confidence: f.confidence, cve: f.cve },
      })),
    }],
  };
}
