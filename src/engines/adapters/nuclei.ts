/**
 * Nuclei template-based testing adapter (webapp targets).
 *
 * Passive mode uses `-passive` (response analysis only). Active mode runs
 * the full engine but ALWAYS with the deny list `-etags dos,fuzz,brute-force`
 * plus a rate limit, honoring the platform's no-DoS / no-bruteforce policy.
 * Nuclei executes its own HTTP client: scope is enforced at the entry URL
 * (see THREAT-MODEL residual risk note).
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding, Severity } from '../../core/types.ts';
import { classifyFinding } from '../../core/cweMap.ts';
import { BinaryNotFoundError, detectVersion, runProcess } from './common.ts';
import { redactText } from '../../core/redact.ts';

const INFO: EngineInfo = {
  id: 'adapter.nuclei',
  name: 'Nuclei (template scanning)',
  kind: 'adapter',
  capabilities: {
    A02: cap('misconfiguration and exposure templates (deny-listed tags only)', 'strong'),
    A01: cap('exposure/IDOR-surface templates (deny-listed tags only)', 'heuristic'),
    A03: cap('disclosed sensitive files/tech-stack templates', 'heuristic'),
    A04: cap('weak TLS/crypto templates (limited without dedicated TLS tooling)', 'heuristic'),
    A05: cap('injection detection templates (non-destructive subset)', 'heuristic'),
    A07: cap('auth-bypass and default-credential templates (deny-listed tags only)', 'heuristic'),
    A10: cap('error/stack-trace disclosure templates', 'heuristic'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['webapp'],
};

const DENY_TAGS = 'dos,fuzz,brute-force,intrusive,destructive';

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
  const m = /CWE-(\d+)/.exec(first);
  return m ? Number(m[1]) : undefined;
}

export class NucleiAdapter implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    try {
      const version = await detectVersion('nuclei', ['-version'], 20_000);
      return { available: true, version };
    } catch (e) {
      if (e instanceof BinaryNotFoundError) {
        return {
          available: false,
          reason: 'nuclei is not installed or not on PATH (templates are downloaded on first run)',
          installHint: 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest  |  https://docs.projectdiscovery.io/tools/nuclei/install',
        };
      }
      return { available: false, reason: `nuclei probe failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const args: string[] = [
      '-u', ctx.target.origin,
      '-jsonl', '-silent',
      '-etags', DENY_TAGS, // hard safety policy: no DoS/fuzz/bruteforce templates
      '-rate-limit', '50',
      '-concurrency', '10',
      '-timeout', '10',
      '-retries', '1',
    ];
    if (ctx.mode === 'passive') args.push('-passive');

    const proc = await runProcess('nuclei', args, { timeoutMs: 600_000, signal: ctx.signal });
    if (proc.timedOut) return { findings: [], detail: 'nuclei timed out' };
    if (proc.exitCode !== 0 && proc.stdout.trim() === '') {
      return { findings: [], detail: `nuclei exited ${proc.exitCode}: ${proc.stderr.slice(0, 300)}` };
    }

    const findings = NucleiAdapter.parseEvents(proc.stdout, ctx.target.origin, args.join(' '));
    return { findings, version: await detectVersion('nuclei', ['-version'], 20_000).catch(() => undefined), detail: `${findings.length} nuclei matches` };
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
          observation: `nuclei template matched at ${matchedAt}`,
        }],
        explanation: (ev.info?.description ?? `Template ${ev['template-id']} matched this target.`).slice(0, 1000),
        remediation: 'Review the matched template\'s documentation and verify the exposed behavior; apply the corresponding hardening.',
        references: Array.isArray(ev.info?.reference)
          ? ev.info.reference.slice(0, 3)
          : ev.info?.reference ? [ev.info.reference] : [],
      });
    }
    return findings;
  }
}
