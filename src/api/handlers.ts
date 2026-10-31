/**
 * REST API handlers. All routes except /api/health require a bearer token
 * (wrapped with withAuth at registration in server.ts).
 */
import { ApiError, jsonResponse, readJsonBody, type Handler, type RequestContext } from './router.ts';
import { withAuth } from './auth.ts';
import type { Orchestrator } from '../scan/orchestrator.ts';
import type { EngineRegistry } from '../engines/registry.ts';
import type { Database } from '../db/database.ts';
import type { Config } from '../config.ts';
import { parseOrigin, isPrivateHost, ScopeError } from '../safety/guard.ts';
import { PROFILES, getProfile, enginePlan } from '../core/profiles.ts';
import { OWASP_CATEGORIES, ALL_CATEGORIES } from '../core/owasp.ts';
import type { Finding,  OwaspCategory, ScanMode, Target, ValidationStatus } from '../core/types.ts';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { renderReport } from '../reports/registry.ts';
import { buildDeliverableReport } from '../reports/deliverable.ts';
import { RetestService } from '../retest/retest.ts';
import type { Engagement, ExploitClass } from '../core/types.ts';
import { randomUUID } from 'node:crypto';
import type { ScopeManifest } from '../edgectx/models.ts';
import { GraphStore } from '../graph/graph.ts';
import { assetUid } from '../graph/uid.ts';
import { scoreAgainstTruth, type ScanQuality } from '../verify/metrics.ts';
import { diffScanFindings } from '../scan/diff.ts';
import { TargetModel } from '../model/targetModel.ts';

export interface App {
  config: Config;
  db: Database;
  orchestrator: Orchestrator;
  registry: EngineRegistry;
  version: string;
  retest: RetestService;
}

// ---------- helpers ----------

function bad(status: number, code: string, message: string): never {
  throw new ApiError(status, code, message);
}

function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

// ---------- routes ----------

export function health(app: App): Handler {
  return () => jsonResponse({
    ok: true, name: 'owasp-assessment-platform', version: app.version,
    time: new Date().toISOString(),
  });
}

export function listTargets(app: App): Handler {
  return () => jsonResponse({
    targets: app.db.listTargets().map((t) => ({
      ...t,
      hasCredentials: app.db.hasCredentials(t.id),
      configuredRoles: app.db.getRoles(t.id),
    })),
  });
}

export const createTarget = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const body = await readJsonBody(ctx.req) as Record<string, unknown>;
  const name = asString(body.name)?.trim();
  const kindRaw = asString(body.kind);
  const kind = kindRaw === 'source' ? 'source' : kindRaw === 'webapp' ? 'webapp' : kindRaw === 'cidr' ? 'cidr' : undefined;
  const originRaw = asString(body.origin)?.trim();
  const sourcePath = asString(body.sourcePath)?.trim();
  const notes = asString(body.notes);

  if (!name || name.length > 100) bad(400, 'invalid_name', 'name is required (max 100 chars)');
  if (kind === undefined) bad(400, 'invalid_kind', "kind must be 'webapp' or 'source'");

  let origin = '';
  if (kind === 'webapp') {
    if (!originRaw) bad(400, 'origin_required', 'origin is required for webapp targets');
    let parsed;
    try {
      parsed = parseOrigin(originRaw!);
    } catch (e) {
      bad(400, 'invalid_origin', e instanceof ScopeError ? e.message : 'invalid origin URL');
    }
    if (!app.config.allowPublicTargets && !isPrivateHost(parsed!.host)) {
      bad(403, 'public_target_forbidden',
        `refusing public-internet target ${parsed!.host}: set OWASP_ALLOW_PUBLIC_TARGETS=1 and ensure written authorization before registering public targets`);
    }
    origin = `${parsed!.scheme}://${parsed!.host}:${parsed!.port}`;
  } else if (kind === 'cidr') {
    if (!originRaw) bad(400, 'cidr_required', 'origin is the CIDR block (e.g. 192.168.1.0/24)');
    const cidrMatch = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(originRaw!);
    if (!cidrMatch) bad(400, 'invalid_cidr', 'origin must be a CIDR block like 192.168.1.0/24');
    const prefix = Number(cidrMatch[2]);
    if (prefix < 24 || prefix > 32) bad(400, 'cidr_too_large', 'CIDR block must be /24 or smaller');
    origin = originRaw!;
  } else if (kind === 'source') {
    if (!sourcePath) bad(400, 'source_path_required', 'sourcePath is required for source targets');
  }

  const target = app.db.createTarget({ name: name!, origin, kind, sourcePath, notes, approved: false });
  app.db.audit({ actor: 'operator', action: 'target.registered', details: { targetId: target.id, origin, kind } });
  return jsonResponse({ target }, 201);
});

export const approveTarget = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), (ctx: RequestContext) => {
  const id = ctx.params.id!;
  const existing = app.db.getTarget(id);
  if (!existing) bad(404, 'not_found', 'target not found');
  const target = app.db.approveTarget(id, 'operator');
  app.db.audit({ actor: 'operator', action: 'target.approved', details: { targetId: id, origin: existing!.origin } });
  return jsonResponse({ target });
});

export const deleteTarget = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), (ctx: RequestContext) => {
  const id = ctx.params.id!;
  const ok = app.db.deleteTarget(id);
  if (!ok) bad(404, 'not_found', 'target not found');
  app.db.audit({ actor: 'operator', action: 'target.deleted', details: { targetId: id } });
  return jsonResponse({ deleted: true });
});

export function listProfiles(app: App): Handler {
  return () => jsonResponse({
    profiles: PROFILES.map((p) => ({ ...p, enginePlan: enginePlan(p, 'active') })),
  });
}

export function listEngines(app: App): Handler {
  return async () => {
    const engines = await Promise.all(app.registry.allEngineIds().map(async (id) => {
      const engine = app.registry.create(id, app.config.maxCrawlPages);
      const availability = await app.registry.availability(id);
      return {
        id, name: engine?.info.name ?? id, kind: engine?.info.kind ?? 'adapter',
        capabilities: engine?.info.capabilities ?? {},
        modes: engine?.info.modes ?? [],
        targetKinds: engine?.info.targetKinds ?? [],
        availability,
      };
    }));
    return jsonResponse({ engines });
  };
}

export function listOwasp(app: App): Handler {
  void app;
  return () => jsonResponse({
    categories: ALL_CATEGORIES.map((c) => OWASP_CATEGORIES[c]),
  });
}

export const startScan = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const body = await readJsonBody(ctx.req) as Record<string, unknown>;
  const targetId = asString(body.targetId);
  // K1 (hardtask.md): accept BOTH field names, never silently default — a
  // missing or unknown profile is a 400, not a surprise standard-active scan.
  const profile = asString(body.profile) ?? asString(body.profileId);
  const mode = (asString(body.mode) === 'active' ? 'active' : asString(body.mode) === 'passive' ? 'passive' : undefined) as ScanMode | undefined;

  if (!targetId) bad(400, 'target_required', 'targetId is required');
  if (!mode) bad(400, 'invalid_mode', "mode must be 'passive' or 'active'");
  if (profile === undefined) bad(400, 'profile_required', 'profile (or profileId) is required — no silent default');
  if (!getProfile(profile)) bad(400, 'unknown_profile', `unknown profile: ${profile}`);

  try {
    const scan = await app.orchestrator.startScan(targetId!, profile, mode!);
    return jsonResponse({ scan }, 202);
  } catch (e) {
    if (e instanceof Error) {
      if (e.message.includes('not approved')) bad(409, 'target_not_approved', e.message);
      if (e.message.includes('not found')) bad(404, 'not_found', e.message);
      if (e.message.includes('does not support')) bad(400, 'profile_target_mismatch', e.message);
    }
    throw e;
  }
});

export function listScans(app: App): Handler {
  return () => jsonResponse({ scans: app.orchestrator ? app.db.listScans(100) : [] });
}

export function getScan(app: App): Handler {
  return (ctx: RequestContext) => {
    const scan = app.db.getScan(ctx.params.id!);
    if (!scan) bad(404, 'not_found', 'scan not found');
    const findings = app.db.getFindings(scan.id);
    return jsonResponse({ scan, findings });
  };
}

export const cancelScan = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), (ctx: RequestContext) => {
  const scan = app.db.getScan(ctx.params.id!);
  if (!scan) bad(404, 'not_found', 'scan not found');
  if (scan.status !== 'running' && scan.status !== 'queued') {
    bad(409, 'not_cancellable', `scan is ${scan.status}`);
  }
  const ok = app.orchestrator.cancelScan(scan.id);
  if (!ok) bad(409, 'not_cancellable', 'scan is not controlled by this process');
  app.db.audit({ actor: 'operator', action: 'scan.cancel_requested', details: { scanId: scan.id } });
  return jsonResponse({ cancelling: true });
});

export function listFindings(app: App): Handler {
  return (ctx: RequestContext) => {
    const scan = app.db.getScan(ctx.params.id!);
    if (!scan) bad(404, 'not_found', 'scan not found');
    return jsonResponse({ findings: app.db.getFindings(scan.id) });
  };
}

export const triageFinding = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const body = await readJsonBody(ctx.req) as Record<string, unknown>;
  const status = asString(body.status) as ValidationStatus | undefined;
  const note = asString(body.note);
  const valid: ValidationStatus[] = ['confirmed', 'probable', 'informational', 'false_positive', 'untested'];
  if (!status || !valid.includes(status)) {
    bad(400, 'invalid_status', `status must be one of ${valid.join(', ')}`);
  }
  const updated = app.db.triageFinding(ctx.params.scanId!, ctx.params.findingId!, status!, 'operator', note);
  if (!updated) bad(404, 'not_found', 'finding not found in this scan');
  return jsonResponse({ finding: updated });
});

export function listAudit(app: App): Handler {
  return () => jsonResponse({ entries: app.db.listAudit(200) });
}

export const getReport = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const scan = app.db.getScan(ctx.params.id!);
  if (!scan) bad(404, 'not_found', 'scan not found');
  const format = (ctx.url.searchParams.get('format') ?? 'json').toLowerCase();
  const findings = app.db.getFindings(scan.id);
  // L2 (hardtask.md): blast factor from REAL graph fan-out when the graph has
  // edges for the finding's asset node; neutral 1.0 otherwise.
  try {
    const graph = new GraphStore(app.db.handle);
    const fanoutOf = (f: Finding): number => graph.fanout(assetUid('finding', f.fingerprint));
    // I3: quality against ground truth only when explicitly requested
    let quality: ScanQuality | undefined;
    const truthPath = ctx.url.searchParams.get('truth');
    if (truthPath !== null && truthPath.startsWith('fixtures/') && !truthPath.includes('..')) {
      try {
        const truth = JSON.parse(readFileSync(join(process.cwd(), truthPath), 'utf8')) as { items?: Array<{ id?: string; match?: { cwe?: number; locatorContains?: string; titleContains?: string; port?: number } }> };
        quality = scoreAgainstTruth(findings, truth.items ?? []);
      } catch { /* truth file unreadable — quality stays unavailable */ }
    }
    if (format === 'deliverable') {
      // E4.2 (newtasks.md): blocked without a signed engagement — a stated
      // reason, never an empty report.
      const engagement = app.db.engagementForTarget(scan.targetId, scan.targetName);
      if (engagement === undefined || engagement.signer === '' || engagement.attestationRef === '') {
        bad(400, 'blocked_by_roe', 'deliverable report requires a signed engagement (signer + attestation_ref) covering this target — none found');
      }
      const { html } = buildDeliverableReport({ scan, findings, engagement });
      return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'content-disposition': 'attachment; filename="deliverable-' + scan.id.slice(0, 8) + '.html"' } });
    }
    if (format === 'evidence-pack') {
      // E5: evidence pack — timestamps, control ids, retest status, coverage
      // verdicts; unmapped categories appear as gaps.
      const { controlsForCategory } = await import('../compliance/controls.ts');
      const pack = {
        schema: 'rsec/evidence-pack/1',
        generatedAt: new Date().toISOString(),
        scan: { id: scan.id, target: scan.targetName, started: scan.startedAt, finished: scan.finishedAt, mode: scan.mode, profile: scan.profile },
        engagement: app.db.engagementForTarget(scan.targetId, scan.targetName) ?? null,
        findings: findings.map((f) => ({
          id: f.id, title: f.title, category: f.category, severity: f.severity, status: f.status,
          detectedAt: f.detectedAt,
          retest: f.retest ?? null,
          exploit: f.exploit ?? null,
          controls: controlsForCategory(f.category),
        })),
        coverage: scan.coverage.map((c) => ({ ...c, controls: controlsForCategory(c.category) })),
        gaps: scan.coverage.filter((c) => c.verdict === 'manual-only').map((c) => c.category),
      };
      return jsonResponse(pack);
    }
    const report: string | Uint8Array = renderReport(scan, findings, format, new Date().toISOString(), { fanoutOf, quality });
    const mime = format === 'pdf' ? 'application/pdf'
      : format === 'html' ? 'text/html; charset=utf-8'
      : 'application/json; charset=utf-8';
    const ext = format === 'pdf' ? 'pdf' : format === 'html' ? 'html' : 'json';
    return new Response(report, {
      headers: {
        'content-type': mime,
        'content-disposition': `attachment; filename="assessment-${scan.id.slice(0, 8)}.${ext}"`,
      },
    });
  } catch (e) {
    bad(400, 'invalid_format', `unsupported report format: ${format} (${e instanceof Error ? e.message : ''})`);
  }
});

export const setCredentials = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const target = app.db.getTarget(ctx.params.id!);
  if (!target) bad(404, 'not_found', 'target not found');
  const body = await readJsonBody(ctx.req) as Record<string, unknown>;
  const username = asString(body.username)?.trim();
  const password = asString(body.password);
  if (!username || !password) bad(400, 'invalid_credentials', 'username and password are required');
  const role = asString(body.role)?.trim() || 'primary';
  if (!/^[\w-]{1,40}$/.test(role)) bad(400, 'invalid_role', 'role must be 1-40 word characters');
  app.db.setCredentials(target.id, {
    username: username!, password: password!, role,
    loginUrl: asString(body.loginUrl)?.trim() || undefined,
    usernameField: asString(body.usernameField)?.trim() || undefined,
    passwordField: asString(body.passwordField)?.trim() || undefined,
  });
  // Response deliberately contains no password material.
  return jsonResponse({
    targetId: target.id,
    username: username,
    role,
    hasCredentials: true,
    note: 'Stored encrypted at rest; never returned or included in reports.',
  }, 201);
});

export const deleteCredentials = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), (ctx: RequestContext) => {
  const target = app.db.getTarget(ctx.params.id!);
  if (!target) bad(404, 'not_found', 'target not found');
  const ok = app.db.deleteCredentials(target.id);
  return jsonResponse({ deleted: ok });
});

export function targetDiff(app: App): Handler {
  return (ctx: RequestContext) => {
    const target = app.db.getTarget(ctx.params.id!);
    if (!target) bad(404, 'not_found', 'target not found');
    const completed = app.db.listScans(200).filter((sc) => sc.targetId === target.id && sc.status === 'completed');
    if (completed.length < 2) bad(409, 'insufficient_history', 'need at least two completed scans to diff');

    const fromScan = asString(ctx.url.searchParams.get('from'))
      ? app.db.getScan(asString(ctx.url.searchParams.get('from'))!)
      : completed[1];
    const toScan = asString(ctx.url.searchParams.get('to'))
      ? app.db.getScan(asString(ctx.url.searchParams.get('to'))!)
      : completed[0];
    if (!fromScan || !toScan) bad(404, 'not_found', 'scan not found');

    const diff = diffScanFindings(
      app.db.getFindings(fromScan.id), app.db.getFindings(toScan.id), fromScan.id, toScan.id,
    );
    return jsonResponse({
      target: { id: target.id, name: target.name },
      fromScan: { id: fromScan.id, startedAt: fromScan.startedAt },
      toScan: { id: toScan.id, startedAt: toScan.startedAt },
      summary: { added: diff.added.length, removed: diff.removed.length, unchanged: diff.unchanged.length },
      added: diff.added,
      removed: diff.removed,
      unchanged: diff.unchanged,
    });
  };
}

export function targetModel(app: App): Handler {
  return (ctx: RequestContext) => {
    const target = app.db.getTarget(ctx.params.id!);
    if (!target) bad(404, 'not_found', 'target not found');
    const model = new TargetModel(app.db.handle, target.id);
    const nodes = model.nodes();
    return jsonResponse({
      target: { id: target.id, name: target.name },
      summary: {
        present: nodes.filter((n) => n.state === 'present').length,
        absent: nodes.filter((n) => n.state === 'absent').length,
        unknown: nodes.filter((n) => n.state === 'unknown').length,
      },
      nodes,
      deltas: model.deltas().length,
      note: 'unknown never means absent — every unknown capability is a probe that has not run yet.',
    });
  };
}

export function sseTrace(app: App): Handler {
  return (ctx: RequestContext) => {
    const scan = app.db.getScan(ctx.params.id!);
    if (!scan) bad(404, 'not_found', 'scan not found');
    const encoder = new TextEncoder();
    let interval: ReturnType<typeof setInterval> | undefined;
    const stream = new ReadableStream({
      start(controller) {
        const send = (event: string, data: unknown): void => {
          controller.enqueue(encoder.encode(`event: ${event}
data: ${JSON.stringify(data)}

`));
        };
        // T-W4: read the persistent trace table
        const trace = app.db.readTrace(scan.id);
        for (const entry of trace) {
          send('trace', entry);
        }
        send('status', { status: scan.status, findings: scan.stats.totalFindings });
        // If scan is still running, poll for new trace entries
        if (!['completed', 'failed', 'cancelled'].includes(scan.status)) {
          let lastIteration = trace.length;
          interval = setInterval(() => {
            const fresh = app.db.getScan(scan.id);
            if (!fresh) { clearInterval(interval); controller.close(); return; }
            const freshTrace = app.db.readTrace(scan.id);
            for (const entry of freshTrace.slice(lastIteration)) {
              send('trace', entry);
              lastIteration++;
            }
            if (['completed', 'failed', 'cancelled'].includes(fresh.status)) {
              send('done', { status: fresh.status, findings: fresh.stats.totalFindings });
              clearInterval(interval);
              controller.close();
            }
          }, 2000);
        }
      },
      cancel() { if (interval) clearInterval(interval); },
    });
    return new Response(stream, {
      headers: {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
        'connection': 'keep-alive',
      },
    });
  };
}

export function targetSummary(app: App): Handler {
  return (ctx: RequestContext) => {
    const target: Target | undefined = app.db.getTarget(ctx.params.id!);
    if (!target) bad(404, 'not_found', 'target not found');
    const scan = app.db.latestCompletedScanForTarget(target.id);
    const findings = scan ? app.db.getFindings(scan.id) : [];
    return jsonResponse({ target, latestScan: scan, findings });
  };
}

export function notFound(app: App): Handler {
  void app;
  return () => jsonResponse({ error: 'not_found', message: 'no such route' }, 404);
}

export function methodNotAllowed(): Handler {
  return () => jsonResponse({ error: 'method_not_allowed' }, 405);
}

export type { OwaspCategory };


// ---------- E1: engagements (newtasks.md) ----------

export const createEngagement = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const body = await readJsonBody(ctx.req) as Record<string, unknown>;
  const name = asString(body.name);
  const scope = Array.isArray(body.scope) ? body.scope.map(String) : undefined;
  const windowStart = asString(body.windowStart);
  const windowEnd = asString(body.windowEnd);
  if (name === undefined || scope === undefined || scope.length === 0) bad(400, 'engagement_fields', 'name and non-empty scope are required');
  if (windowStart === undefined || windowEnd === undefined || Number.isNaN(Date.parse(windowStart)) || Number.isNaN(Date.parse(windowEnd))) {
    bad(400, 'engagement_window', 'windowStart/windowEnd must be ISO timestamps');
  }
  const permitted = Array.isArray(body.permittedClasses) ? (body.permittedClasses as unknown[]).map(String) : [];
  const permittedClasses = permitted.filter((c): c is ExploitClass => ['sqli', 'ssrf', 'traversal', 'idor', 'xss-reflection', 'open-redirect'].includes(c));
  const engagement: Engagement = {
    id: randomUUID(),
    name: name as string,
    scope: scope as string[],
    windowStart: windowStart as string,
    windowEnd: windowEnd as string,
    contactsTechnical: asString(body.contactsTechnical) ?? '',
    contactsEmergency: asString(body.contactsEmergency) ?? '',
    emergencyStop: false,
    rateCeiling: typeof body.rateCeiling === 'number' ? body.rateCeiling : 0,
    permittedClasses,
    signer: asString(body.signer) ?? '',
    attestationRef: asString(body.attestationRef) ?? '',
    active: true,
    createdAt: new Date().toISOString(),
  };
  const created = app.db.createEngagement(engagement);
  return jsonResponse({ engagement: created }, 201);
});

export const getEngagement = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const e = app.db.getEngagement(ctx.params.id as string);
  if (e === undefined) bad(404, 'not_found', 'engagement not found');
  return jsonResponse({ engagement: e });
});

export const stopEngagement = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const e = app.db.stopEngagement(ctx.params.id as string);
  if (e === undefined) bad(404, 'not_found', 'engagement not found');
  // E1.4: emergency stop aborts all in-flight scans for the engagement scope.
  const scopeSet = new Set(e.scope);
  let cancelled = 0;
  for (const scan of app.db.listScans(100)) {
    if (!['queued', 'running'].includes(scan.status)) continue;
    const t = app.db.getTarget(scan.targetId);
    if (t === undefined) continue;
    if (scopeSet.has(t.id) || scopeSet.has(t.origin)) {
      if (app.orchestrator.cancelScan(scan.id)) cancelled += 1;
    }
  }
  return jsonResponse({ engagement: e, cancelled });
});

// ---------- E3: fix-triggered retest ----------

export const retestTarget = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const body = await readJsonBody(ctx.req) as Record<string, unknown>;
  const locator = asString(body.locator);
  const outcomes = await app.retest.retest(ctx.params.id as string, locator);
  return jsonResponse({ outcomes });
});

// ---------- E6: escalation queue ----------

export const escalateFinding = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const body = await readJsonBody(ctx.req) as Record<string, unknown>;
  const reason = asString(body.reason);
  if (reason === undefined) bad(400, 'reason_required', 'escalation reason is required');
  const scanId = ctx.params.id as string;
  const findingId = ctx.params.fid as string;
  const finding = app.db.getFindings(scanId).find((x) => x.id === findingId);
  if (finding === undefined) bad(404, 'not_found', 'finding not found');
  const escalate = { reason: reason as string, context: asString(body.context) ?? '', at: new Date().toISOString(), by: 'operator' };
  app.db.setFindingEnrichment(scanId, findingId, { escalate });
  return jsonResponse({ escalated: true, findingId, escalate });
});

export const createManifest = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  const body = await readJsonBody(ctx.req) as Record<string, unknown>;
  const signer = asString(body.signer);
  const domains = Array.isArray(body.domains) ? body.domains.map(String) : undefined;
  if (signer === undefined || domains === undefined || domains.length === 0) {
    bad(400, 'manifest_fields', 'signer and non-empty domains are required');
  }
  const ports = (body.ports ?? {}) as { include?: unknown; exclude?: unknown };
  const manifest: ScopeManifest = {
    manifestId: `mf_${randomUUID().slice(0, 13)}`,
    signer: signer as string,
    validFrom: asString(body.validFrom) ?? new Date().toISOString(),
    validTo: asString(body.validTo) ?? new Date(Date.now() + 7 * 86400_000).toISOString(),
    domains: domains as string[],
    cidrs: Array.isArray(body.cidrs) ? body.cidrs.map(String) : [],
    ports: {
      include: Array.isArray(ports.include) ? ports.include.map(Number) : [],
      exclude: Array.isArray(ports.exclude) ? ports.exclude.map(Number) : [],
    },
    classes: Array.isArray(body.classes) ? (body.classes as unknown[]).map(String).filter((c): c is ExploitClass => ['sqli', 'ssrf', 'traversal', 'idor', 'xss-reflection', 'open-redirect'].includes(String(c))) : [],
    flags: {
      originDiscoveryAuthorized: body.flags !== undefined && (body.flags as { originDiscoveryAuthorized?: boolean }).originDiscoveryAuthorized === true,
      directOriginProbingAuthorized: body.flags !== undefined && (body.flags as { directOriginProbingAuthorized?: boolean }).directOriginProbingAuthorized === true,
    },
    killSwitch: (asString(body.killSwitch) === 'per-engagement' ? 'per-engagement' : asString(body.killSwitch) === 'none' ? 'none' : 'global') as ScopeManifest['killSwitch'],
    active: true,
    createdAt: new Date().toISOString(),
  };
  const created = app.db.createManifest(manifest);
  return jsonResponse({ manifest: created }, 201);
});

export const listManifests = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async () => {
  const active = app.db.getActiveManifest();
  return jsonResponse({ active: active ?? null, note: active !== undefined ? undefined : 'no valid manifest — bus ingress unrestricted, RoE still applies downstream' });
});

export const listOriginCandidates = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async () => {
  return jsonResponse({ candidates: app.db.getOriginCandidates() });
});

export const approveOriginCandidate = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async (ctx: RequestContext) => {
  app.db.approveOriginCandidate(ctx.params.id as string, 'operator');
  return jsonResponse({ approved: true, candidateId: ctx.params.id });
});

export const listEscalations = (app: App): Handler => withAuth(app.db.verifyToken.bind(app.db), async () => {
  const queue = app.db.getEscalated();
  return jsonResponse({ queue: queue.map((q) => ({
    scanId: q.scanId,
    findingId: q.finding.id,
    title: q.finding.title,
    asset: q.finding.asset,
    locator: q.finding.locator,
    escalate: q.finding.escalate,
    evidenceCount: q.finding.evidence.length,
    why: q.finding.escalate !== undefined && q.finding.escalate.context !== '' ? q.finding.escalate.context : 'business logic / chained impact / ambiguous authorization',
  })) });
});
