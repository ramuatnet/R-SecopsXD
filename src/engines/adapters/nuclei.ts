/**
 * Nuclei template-based testing adapter (webapp targets) — in-house pack.
 *
 * Phase B (newtask.md N1–N8): runs ONLY the curated in-house templates/
 * directory (no auto-downloaded template sets), gated by declared target
 * capabilities (N5) so templates never burn requests on absent surface
 * (V3-class waste). The pinned binary is integrity-checked at startup (N6)
 * and its version is recorded in every finding's provenance. The deny list
 * and rate limits keep the no-DoS / no-bruteforce policy. Nuclei executes its
 * own HTTP client: scope is enforced at the entry URL (residual risk noted in
 * THREAT-MODEL).
 */
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding, Severity } from '../../core/types.ts';
import { classifyFinding } from '../../core/cweMap.ts';
import { BinaryNotFoundError, detectVersion, resolveBinary, runProcess } from './common.ts';
import { redactText } from '../../core/redact.ts';

const INFO: EngineInfo = {
  id: 'adapter.nuclei',
  name: 'Nuclei (in-house template pack)',
  kind: 'adapter',
  capabilities: {
    A02: cap('in-house exposure/admin-console templates (deny-listed tags only)', 'strong'),
    A01: cap('in-house sensitive-file and API-surface templates (capability-gated)', 'strong'),
    A03: cap('in-house dependency/key-disclosure templates', 'strong'),
    A07: cap('in-house default-credential-page template', 'heuristic'),
    A10: cap('in-house verbose-error templates', 'strong'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['webapp'],
};

const DENY_TAGS = 'dos,fuzz,brute-force,intrusive,destructive';

export function templatesDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'templates');
}

interface TemplateIndexEntry { file: string; id: string; severity?: string; requires?: string[]; }
interface TemplateIndex { schema: string; templates: TemplateIndexEntry[]; }

export async function loadTemplateIndex(dir = templatesDir()): Promise<TemplateIndex> {
  const raw = JSON.parse(await readFile(join(dir, 'index.json'), 'utf8')) as TemplateIndex;
  return raw;
}

/**
 * N5: infer target capabilities from the crawl corpus. Unknown stays unknown
 * (I8) — a capability that cannot be confirmed never unlocks gated templates.
 */
export function inferCapabilities(crawl: ScanContext['crawl']): Set<string> {
  const caps = new Set<string>();
  if (!crawl) return caps;
  const hay = [
    ...crawl.pages.map((p) => `${p.url}\n${p.body.slice(0, 4000)}`),
    ...(crawl.discoveredEndpoints ?? []),
  ].join('\n').toLowerCase();
  if (hay.includes('/graphql') || hay.includes('graphiql')) caps.add('graphql');
  if (hay.includes('/openapi') || hay.includes('swagger')) caps.add('openapi');
  return caps;
}

/** N5: keep ungated templates + gated templates whose capability is confirmed. */
export function gateTemplates(entries: TemplateIndexEntry[], caps: Set<string>): TemplateIndexEntry[] {
  return entries.filter((e) => (e.requires ?? []).every((r) => caps.has(r)));
}

/** N8: pure argv construction — auditable. Exactly one target: -u origin. */
export function buildNucleiArgs(
  origin: string,
  mode: 'passive' | 'active',
  templateFiles: string[],
  dir = templatesDir(),
): string[] {
  const args: string[] = ['-u', origin];
  if (templateFiles.length === 0) {
    args.push('-t', dir);
  } else {
    for (const f of templateFiles) args.push('-t', join(dir, f));
  }
  args.push('-jsonl', '-silent', '-duc', '-etags', DENY_TAGS);
  args.push('-rate-limit', '50', '-concurrency', '10', '-timeout', '10', '-retries', '1');
  if (mode === 'passive') args.push('-passive');
  return args;
}

// ---------- N6: binary integrity ----------

export interface IntegrityResult { available: boolean; reason?: string | undefined; version?: string | undefined; }

export async function checkBinaryIntegrity(binary = 'nuclei'): Promise<IntegrityResult> {
  let version: string | undefined;
  try {
    version = await detectVersion(binary, ['-version'], 20_000);
  } catch (e) {
    if (e instanceof BinaryNotFoundError) {
      return { available: false, reason: 'nuclei is not installed (in-house templates require the pinned binary)' };
    }
    return { available: false, reason: `nuclei probe failed: ${e instanceof Error ? e.message : String(e)}` };
  }
  try {
    const pin = JSON.parse(await readFile(join(templatesDir(), 'nuclei-pin.json'), 'utf8')) as {
      version?: string; sha256?: Record<string, string>;
    };
    const pinnedVersion = (pin.version ?? '').trim();
    if (pinnedVersion !== '' && version !== undefined && !version.includes(pinnedVersion)) {
      return { available: false, reason: `nuclei version mismatch: pinned ${pinnedVersion}, found ${version}`, version };
    }
    const binaryPath = resolveBinary(binary);
    const pinnedHash = pin.sha256?.[process.platform];
    if (binaryPath !== undefined && pinnedHash !== undefined && pinnedHash !== '') {
      const hash = createHash('sha256').update(await readFile(binaryPath)).digest('hex');
      if (hash !== pinnedHash) {
        return { available: false, reason: `nuclei binary SHA-256 mismatch — refusing to execute (supply-chain guard, N6)`, version };
      }
    }
    return { available: true, version };
  } catch (e) {
    return { available: false, reason: `integrity check failed: ${e instanceof Error ? e.message : String(e)}`, version };
  }
}

interface NucleiEvent {
  'template-id'?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    reference?: string | string[];
    classification?: {
      'cve-id'?: string[];
      'cwe-id'?: string[];
    };
  };
  host?: string;
  'matched-at'?: string;
  type?: string;
}

function nucleiSeverity(s: string | undefined): Severity {
  switch ((s ?? '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return 'info';
  }
}

function parseCwe(ids: string[] | undefined): number | undefined {
  const first = ids?.[0];
  if (!first) return undefined;
  const m = /CWE-(\d+)/i.exec(first);
  return m ? Number(m[1]) : undefined;
}

export class NucleiAdapter implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    const integrity = await checkBinaryIntegrity();
    if (!integrity.available) {
      return {
        available: false,
        reason: integrity.reason ?? 'unavailable',
        installHint: 'place the pinned nuclei binary on PATH and record its version + sha256 in templates/nuclei-pin.json',
      };
    }
    return { available: true, version: integrity.version };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const integrity = await checkBinaryIntegrity();
    if (!integrity.available) {
      return { findings: [], notExecutedReason: integrity.reason ?? 'nuclei unavailable (integrity)' };
    }

    const index = await loadTemplateIndex();
    const caps = inferCapabilities(ctx.crawl);
    const eligible = gateTemplates(index.templates, caps);
    if (eligible.length === 0) {
      return { findings: [], notExecutedReason: 'no templates eligible: capability requirements not confirmed for this target (N5 gating)' };
    }

    const args = buildNucleiArgs(ctx.target.origin, ctx.mode, eligible.map((e) => e.file));
    const proc = await runProcess('nuclei', args, { timeoutMs: 600_000, signal: ctx.signal });
    if (proc.timedOut) return { findings: [], detail: 'nuclei timed out' };
    if (proc.exitCode !== 0 && proc.stdout.trim() === '') {
      return { findings: [], detail: `nuclei exited ${proc.exitCode}: ${proc.stderr.slice(0, 300)}` };
    }

    const findings = NucleiAdapter.parseEvents(proc.stdout, ctx.target.origin, `nuclei ${args.join(' ')} (binary: ${integrity.version ?? 'unknown'})`);
    const gated = index.templates.length - eligible.length;
    return {
      findings,
      version: integrity.version,
      detail: `${findings.length} match(es) from ${eligible.length} in-house template(s)${gated > 0 ? ` (${gated} capability-gated off)` : ''}`,
    };
  }

  /** Pure mapping from nuclei JSONL output to raw findings. */
  static parseEvents(stdout: string, origin: string, commandLine: string): RawFinding[] {
    const findings: RawFinding[] = [];
    for (const line of stdout.split('\n')) {
      const trimmed = line.trim();
      if (trimmed === '' || !trimmed.startsWith('{')) continue;
      let ev: NucleiEvent;
      try {
        ev = JSON.parse(trimmed) as NucleiEvent;
      } catch {
        continue;
      }
      const cwe = parseCwe(ev.info?.classification?.['cwe-id']);
      const title = ev.info?.name ?? ev['template-id'] ?? 'nuclei finding';
      const matchedAt = ev['matched-at'] ?? ev.host ?? origin;
      let path = matchedAt;
      try { path = new URL(matchedAt).pathname; } catch { /* keep raw */ }
      findings.push({
        rawId: ev['template-id'] ?? 'nuclei-template',
        title,
        category: classifyFinding(cwe, title),
        cwe,
        cve: ev.info?.classification?.['cve-id']?.[0],
        severity: nucleiSeverity(ev.info?.severity),
        confidence: 'medium',
        status: 'probable',
        asset: origin,
        locator: path,
        evidence: [{
          kind: 'process' as const,
          command: commandLine,
          stdoutExcerpt: redactText(trimmed, 800),
          observation: `nuclei in-house template matched at ${matchedAt}`,
        }],
        explanation: (ev.info?.description ?? `Template ${ev['template-id']} matched this target.`).slice(0, 1000),
        remediation: 'Review the matched template\'s cited source and verify the exposed behavior; apply the corresponding hardening.',
        references: Array.isArray(ev.info?.reference)
          ? ev.info.reference.slice(0, 3)
          : ev.info?.reference ? [ev.info.reference] : [],
      });
    }
    return findings;
  }
}
