/**
 * Coverage computation v2 — evidence-based, derived from assessment-task
 * execution results (automation program Phases 2 + 13).
 *
 * Per category: every task required for the profile/mode/target-kind gets a
 * status derived from the engine run record and attributed findings. Category
 * status aggregates task states — an unexecuted task is never a pass, and a
 * manual task keeps MANUAL_REVIEW_REQUIRED even when other tasks ran clean.
 *
 * The legacy v1 verdict (capability-based) is preserved for backward
 * compatibility and re-exported from computeCoverageV1.
 */
import { ALL_CATEGORIES, OWASP_CATEGORIES } from '../core/owasp.ts';
import type {
  CategoryCoverage, CategoryCoverageStatus, CoverageReport, CoverageTaskResult,
  EngineRunRecord, Finding, OwaspCategory, ScanMode, TargetKind,
} from '../core/types.ts';
import { TASKS, getTask, type AssessmentTask, type TaskStatus } from '../core/tasks.ts';
import { getProfile } from '../core/profiles.ts';

/** v1 capability map — kept verbatim for the legacy verdict and regression tests. */
function capabilitiesFor(engineId: string): Partial<Record<OwaspCategory, { note: string; strength: 'strong' | 'heuristic' }>> {
  switch (engineId) {
    case 'builtin.http-observation':
      return {
        A02: { note: 'headers/cookies/banners/listings, CORS policy (active)', strength: 'strong' },
        A04: { note: 'cleartext transport observation, JWT handling observation', strength: 'strong' },
        A10: { note: 'verbose error responses', strength: 'strong' },
        A01: { note: 'info exposure in served content', strength: 'heuristic' },
        A08: { note: 'SRI on external scripts', strength: 'strong' },
        A09: { note: 'log-correlation indicators on error responses', strength: 'heuristic' },
        A07: { note: 'secrets in served JavaScript bundles', strength: 'heuristic' },
        A03: { note: 'vulnerable frontend library versions (curated advisories)', strength: 'strong' },
      };
    case 'builtin.crawler-lite':
      return {};
    case 'builtin.tls-analysis':
      return {
        A04: { note: 'certificate validity/self-signing/hostname, protocol version, legacy-TLS acceptance', strength: 'strong' },
      };
    case 'builtin.openapi-policy':
      return {
        A06: { note: 'exposed API spec policy signals (spec-level, not enforcement proof)', strength: 'heuristic' },
        A02: { note: 'publicly exposed API documentation', strength: 'strong' },
      };
    case 'builtin.authenticated-probe':
      return {
        A01: { note: 'authenticated surface inventory (single test account)', strength: 'strong' },
        A07: { note: 'logout invalidation verification', strength: 'strong' },
        A04: { note: 'JWT forgery acceptance (alg=none / stripped signature)', strength: 'strong' },
      };
    case 'builtin.redirect-probe':
      return {
        A01: { note: 'open redirect detection on discovered redirect parameters', strength: 'strong' },
      };
    case 'builtin.graphql-probe':
      return {
        A01: { note: 'GraphQL introspection/playground exposure (bounded, read-only)', strength: 'strong' },
      };
    case 'builtin.endpoint-discovery':
      return {
        A01: { note: 'hidden API endpoint discovery from JS bundles (informational inventory)', strength: 'strong' },
      };
    case 'builtin.path-probe':
      return {
        A01: { note: 'unauthenticated admin/sensitive path exposure (bounded), source-map exposure', strength: 'strong' },
        A02: { note: 'exposed config/backup files', strength: 'strong' },
        A03: { note: 'exposed dependency manifests/lockfiles', strength: 'strong' },
      };
    case 'builtin.reflection-probe':
      return {
        A05: { note: 'unencoded reflection markers (no JS execution)', strength: 'strong' },
      };
    case 'builtin.auth-probe':
      return {
        A07: { note: 'enumeration differential; missing login rate limiting (bounded)', strength: 'strong' },
      };
    case 'builtin.source-scan':
      return {
        A04: { note: 'weak crypto patterns (regex, no dataflow)', strength: 'heuristic' },
        A05: { note: 'SQL concat / eval patterns (regex, no dataflow)', strength: 'heuristic' },
        A07: { note: 'hardcoded credential patterns (regex)', strength: 'heuristic' },
      };
    case 'builtin.dep-manifest':
      return {
        A03: { note: 'inventory only; CVE matching needs SCA adapter', strength: 'heuristic' },
      };
    case 'adapter.semgrep':
      return {
        A02: { note: 'config patterns (rule-dependent)', strength: 'heuristic' },
        A04: { note: 'crypto patterns (rule-dependent)', strength: 'heuristic' },
        A05: { note: 'injection sinks (pattern + limited taint)', strength: 'heuristic' },
        A07: { note: 'credential patterns (rule-dependent)', strength: 'heuristic' },
        A08: { note: 'deserialization sinks (rule-dependent)', strength: 'heuristic' },
        A10: { note: 'fail-open patterns (rule-dependent)', strength: 'heuristic' },
      };
    case 'adapter.trivy':
      return {
        A03: { note: 'CVE advisory matching on lockfiles', strength: 'strong' },
        A02: { note: 'misconfiguration checks', strength: 'heuristic' },
        A07: { note: 'secret detection', strength: 'heuristic' },
      };
    case 'adapter.grype':
      return {
        A03: { note: 'CVE advisory matching on lockfiles', strength: 'strong' },
      };
    case 'adapter.nuclei':
      return {
        A02: { note: 'misconfig/exposure templates (deny-listed tags)', strength: 'strong' },
        A01: { note: 'exposure templates', strength: 'heuristic' },
        A03: { note: 'sensitive file templates', strength: 'heuristic' },
        A04: { note: 'weak TLS templates (limited)', strength: 'heuristic' },
        A05: { note: 'injection templates (non-destructive subset)', strength: 'heuristic' },
        A07: { note: 'auth templates (deny-listed tags)', strength: 'heuristic' },
        A10: { note: 'error disclosure templates', strength: 'heuristic' },
      };
    case 'adapter.zap':
      return {
        A02: { note: 'header/cookie alerts', strength: 'strong' },
        A01: { note: 'access-control alerts (limited unauthenticated)', strength: 'heuristic' },
        A05: { note: 'injection alerts (non-destructive set)', strength: 'heuristic' },
        A07: { note: 'session/auth alerts', strength: 'heuristic' },
        A08: { note: 'CSRF/integrity alerts', strength: 'heuristic' },
        A10: { note: 'info disclosure alerts', strength: 'heuristic' },
      };
    case 'builtin.host-infra':
      return {
        A01: { note: 'DNS resolution + open-port mapping + tech-stack/WAF identification of the registered target\u2019s infrastructure', strength: 'strong' },
        A02: { note: 'management interface / admin console exposure on non-standard ports', strength: 'strong' },
        A03: { note: 'infrastructure service version → CVE matching (offline advisories)', strength: 'strong' },
      };
    case 'builtin.asset-discovery':
      return {
        A01: { note: 'DNS records, CT-log subdomains, cert SANs, IP attribution (ASN/owner) for the registered domain space', strength: 'strong' },
        A02: { note: 'AXFR zone-transfer attempt + public cloud bucket listability (active mode)', strength: 'strong' },
      };
    default:
      return {};
  }
}

/** v1 capability-based verdict — retained for backward compatibility and rollback. */
export function computeCoverageV1(ranEngines: EngineRunRecord[], profileId: string): Array<Pick<CoverageReport, 'category' | 'verdict' | 'engines'>> {
  const ran = new Set(ranEngines.filter((e) => e.status === 'ran').map((e) => e.engine));
  const perCategory = new Map<OwaspCategory, { strong: string[]; heuristic: string[] }>();
  for (const cat of ALL_CATEGORIES) perCategory.set(cat, { strong: [], heuristic: [] });
  for (const engineId of ran) {
    const profile = getProfile(profileId);
    const engineIds = profile ? [...profile.passiveEngines, ...profile.activeEngines] : [];
    if (!engineIds.includes(engineId) && !engineId.startsWith('adapter.')) continue;
    const caps = capabilitiesFor(engineId);
    for (const [cat, capability] of Object.entries(caps)) {
      const entry = perCategory.get(cat as OwaspCategory);
      if (!entry) continue;
      if (capability.strength === 'strong') entry.strong.push(engineId);
      else entry.heuristic.push(engineId);
    }
  }
  return ALL_CATEGORIES.map((cat) => {
    const entry = perCategory.get(cat)!;
    const engines = [...entry.strong, ...entry.heuristic];
    const verdict: CategoryCoverage = entry.strong.length > 0 ? 'covered'
      : entry.heuristic.length > 0 ? 'partial' : 'manual-only';
    return { category: cat, verdict, engines };
  });
}

interface EngineStatusById {
  ran: Set<string>;
  unavailable: Set<string>;
  failed: Set<string>;
  skipped: Set<string>;
  /** HON-01/02 (edgetask.md): canonical outcome per engine, when recorded. */
  outcomeByEngine: Map<string, NonNullable<EngineRunRecord['outcome']>>;
}

function engineStatusIndex(records: EngineRunRecord[]): EngineStatusById {
  const idx: EngineStatusById = { ran: new Set(), unavailable: new Set(), failed: new Set(), skipped: new Set(), outcomeByEngine: new Map() };
  for (const r of records) {
    if (r.status === 'ran') idx.ran.add(r.engine);
    else if (r.status === 'unavailable') idx.unavailable.add(r.engine);
    else if (r.status === 'failed') idx.failed.add(r.engine);
    else if (r.status === 'skipped') idx.skipped.add(r.engine);
    if (r.outcome !== undefined) idx.outcomeByEngine.set(r.engine, r.outcome);
  }
  return idx;
}

function taskStatus(
  task: AssessmentTask,
  engines: EngineStatusById,
  findings: Finding[],
  scanCancelled: boolean,
): { status: TaskStatus; matchedFindings: number; detail?: string } {
  if (task.manual) {
    return { status: 'MANUAL_REVIEW_REQUIRED', matchedFindings: 0, detail: task.requires?.length ? `requires: ${task.requires.join(', ')}` : 'by-design human task' };
  }
  if (engines.failed.has(task.engine) && !engines.ran.has(task.engine)) {
    return { status: 'ERROR', matchedFindings: 0, detail: 'implementing engine failed' };
  }
  if (engines.unavailable.has(task.engine) && !engines.ran.has(task.engine)) {
    return { status: 'ENGINE_UNAVAILABLE', matchedFindings: 0, detail: 'implementing engine not installed' };
  }
  // HON-01/HON-02 (edgetask.md): canonical outcomes flow into the ledger.
  const outcome = engines.outcomeByEngine.get(task.engine);
  if (engines.ran.has(task.engine) && outcome === 'NOT_EXECUTED_DEGRADED') {
    return { status: 'NOT_EXECUTED_DEGRADED', matchedFindings: 0, detail: 'engine degraded (dependency failure) — never clean (§1.4)' };
  }
  if (engines.ran.has(task.engine) && outcome === 'NO_OP_SUSPECT') {
    return { status: 'NO_OP_SUSPECT', matchedFindings: 0, detail: 'ran with 0 inputs or <5 ms — suspect no-op (§3)' };
  }
  if (!engines.ran.has(task.engine)) {
    if (outcome === 'NOT_EXECUTED_DEGRADED') {
      return { status: 'NOT_EXECUTED_DEGRADED', matchedFindings: 0, detail: 'engine degraded before execution (§1.4)' };
    }
    return { status: 'NOT_EXECUTED', matchedFindings: 0, detail: scanCancelled ? 'scan cancelled before engine ran' : 'engine not part of this scan' };
  }
  // Engine ran — attribute findings to this task by rawId pattern (if declared) or engine match.
  const matched = findings.filter((f) =>
    f.provenance.some((p) =>
      p.engine === task.engine &&
      (task.rawIdPattern === undefined || task.rawIdPattern === '' || (p.rawId ?? '').includes(task.rawIdPattern)),
    ),
  );
  if (matched.length > 0) {
    return { status: 'FINDING_DETECTED', matchedFindings: matched.length };
  }
  return { status: 'AUTOMATED_PASS', matchedFindings: 0 };
}

function aggregate(tasks: Array<{ status: TaskStatus }>): CategoryCoverageStatus {
  const executed = tasks.filter((t) => t.status === 'AUTOMATED_PASS' || t.status === 'FINDING_DETECTED').length;
  const errored = tasks.filter((t) => t.status === 'ERROR').length;
  const manual = tasks.filter((t) => t.status === 'MANUAL_REVIEW_REQUIRED').length;
  const notExecuted = tasks.filter((t) => t.status === 'NOT_EXECUTED' || t.status === 'ENGINE_UNAVAILABLE' || t.status === 'INCONCLUSIVE').length;
  const degraded = tasks.filter((t) => t.status === 'NOT_EXECUTED_DEGRADED').length;
  const suspect = tasks.filter((t) => t.status === 'NO_OP_SUSPECT').length;
  if (executed > 0 && executed === tasks.length) return 'COVERED_WITH_EVIDENCE';
  if (executed > 0) return 'PARTIALLY_COVERED';
  if (errored > 0 && executed === 0) return 'ASSESSMENT_FAILED';
  // HON-01/02: degradation and no-op runs are first-class ledger states — never clean.
  if (degraded > 0) return 'NOT_EXECUTED_DEGRADED';
  if (suspect > 0) return 'NO_OP_SUSPECT';
  if (manual > 0) return 'MANUAL_REVIEW_REQUIRED';
  if (notExecuted > 0) return 'MANUAL_REVIEW_REQUIRED';
  return 'NOT_ASSESSED';
}

function legacyVerdict(status: CategoryCoverageStatus, engines: string[]): CategoryCoverage {
  if (status === 'COVERED_WITH_EVIDENCE') return 'covered';
  // A4: ran-but-empty categories never claim 'covered'.
  if (status === 'RAN_CLEAN' || status === 'PARTIALLY_COVERED') return engines.length > 0 ? 'partial' : 'manual-only';
  return 'manual-only';
}

export function computeCoverage(
  ranEngines: EngineRunRecord[],
  profileId: string,
  findings: Finding[] = [],
  targetKind: TargetKind = 'webapp',
  mode: ScanMode = 'passive',
  scanCancelled = false,
): CoverageReport[] {
  const engines = engineStatusIndex(ranEngines);
  const reports: CoverageReport[] = [];
  const v1 = computeCoverageV1(ranEngines, profileId);

  for (const cat of ALL_CATEGORIES) {
    const catTasks = TASKS.filter((t) => t.category === cat && t.targetKinds.includes(targetKind));
    // Required tasks: manual tasks always (they are the honest "remaining human work");
    // passive tasks in every scan (their engines run in both modes); active tasks
    // only when the scan itself is active.
    const required = catTasks.filter((t) => t.manual || t.mode === 'passive' || mode === 'active');
    const results: CoverageTaskResult[] = required.map((task) => {
      const { status, matchedFindings, detail } = taskStatus(task, engines, findings, scanCancelled);
      return { taskId: task.id, title: task.title, status, findings: matchedFindings, detail };
    });
    const status = aggregate(results);
    const v1entry = v1.find((v) => v.category === cat);
    const enginesList = [...new Set([...(v1entry?.engines ?? []), ...required.filter((t) => !t.manual && engines.ran.has(t.engine)).map((t) => t.engine)])];
    const catInfo = OWASP_CATEGORIES[cat];
    const executedCount = results.filter((r) => r.status === 'AUTOMATED_PASS' || r.status === 'FINDING_DETECTED').length;
    const detectedCount = results.reduce((sum, r) => sum + r.findings, 0);
    // A4 (newtask): ran-but-empty honesty — a category where every required
    // task executed cleanly but ZERO findings were attributed must not read
    // as fully covered. It gets its own state and never the 'covered' verdict.
    const finalStatus: CategoryCoverageStatus =
      status === 'COVERED_WITH_EVIDENCE' && detectedCount === 0 ? 'RAN_CLEAN' : status;
    const cleanNote = finalStatus === 'RAN_CLEAN'
      ? ' All required tasks ran clean with zero findings (ran-but-empty): absence of findings here is not evidence of absence.'
      : '';
    const note = `${catInfo.automation} Executed ${executedCount}/${results.length} required ${mode} tasks ` +
      `(${detectedCount} finding(s) attributed); remaining tasks require manual review or are not applicable to this profile.${cleanNote}`;
    reports.push({
      category: cat,
      verdict: legacyVerdict(finalStatus, enginesList),
      status: finalStatus,
      tasks: results,
      engines: enginesList,
      note,
    });
  }
  return reports;
}

// keep getTask referenced for external consumers
export { getTask };
