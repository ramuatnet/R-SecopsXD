"""One-shot patcher: newtasks.md API handlers + routes + retest db method."""
import io

# 1. Database: add updateFindingStatus (retest must not write triage overrides)
p = 'src/db/database.ts'
s = io.open(p, encoding='utf8').read()
anchor = "  getTriages(): Map<string, ValidationStatus> {"
addition = """  /** E3 (newtasks.md): retest status update — deliberately NOT a triage override. */
  updateFindingStatus(scanId: string, findingId: string, status: ValidationStatus): void {
    this.db.prepare('UPDATE findings SET status = ? WHERE scan_id = ? AND id = ?').run(status, scanId, findingId);
  }

  getTriages(): Map<string, ValidationStatus> {"""
assert anchor in s, 'db anchor'
s = s.replace(anchor, addition, 1)
io.open(p, 'w', encoding='utf8', newline='\n').write(s)
print('db.updateFindingStatus added')

# 2. retest.ts: use the new method
p = 'src/retest/retest.ts'
s = io.open(p, encoding='utf8').read()
old = "    this.db.prepare('UPDATE findings SET status = ? WHERE scan_id = ? AND id = ?').run(newStatus, scanId, f.id);"
new = "    this.db.updateFindingStatus(scanId, f.id, newStatus);"
assert old in s, 'retest db call'
s = s.replace(old, new)
io.open(p, 'w', encoding='utf8', newline='\n').write(s)
print('retest db call fixed')

# 3. handlers: append E1/E3/E6 handlers (plain python string, no backticks)
p = 'src/api/handlers.ts'
s = io.open(p, encoding='utf8').read()
if 'createEngagement' not in s:
    imports_anchor = "import { renderReport } from '../reports/registry.ts';"
    additions = "import { renderReport } from '../reports/registry.ts';\nimport { buildDeliverableReport } from '../reports/deliverable.ts';\nimport { RetestService } from '../retest/retest.ts';\nimport type { Engagement, ExploitClass } from '../core/types.ts';\nimport { randomUUID } from 'node:crypto';"
    assert imports_anchor in s
    s = s.replace(imports_anchor, additions, 1)

    app_anchor = """export interface App {
  config: Config;
  db: Database;
  orchestrator: Orchestrator;
  registry: EngineRegistry;
  version: string;
}"""
    app_new = """export interface App {
  config: Config;
  db: Database;
  orchestrator: Orchestrator;
  registry: EngineRegistry;
  version: string;
  retest: RetestService;
}"""
    assert app_anchor in s, 'App'
    s = s.replace(app_anchor, app_new, 1)

    handlers = '''

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
'''
    s += handlers
    io.open(p, 'w', encoding='utf8', newline='\n').write(s)
    print('handlers appended')
