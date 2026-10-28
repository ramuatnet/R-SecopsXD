/**
 * Semgrep SAST adapter (source targets).
 *
 * Requires a ruleset: OWASP_SEMGREP_CONFIG (e.g. "p/owasp-top-ten" or a
 * local directory of YAML rules). Falls back to the bundled minimal ruleset
 * shipped in rules/semgrep/ so the adapter works fully offline. Findings are
 * heuristic SAST output: normalized with confidence=medium, status=probable
 * unless the rule itself is high-confidence.
 */
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding, Severity } from '../../core/types.ts';
import { classifyFinding, severityFromCvss } from '../../core/cweMap.ts';
import { BinaryNotFoundError, detectVersion, runProcess } from './common.ts';
import { log } from '../../logging.ts';

const INFO: EngineInfo = {
  id: 'adapter.semgrep',
  name: 'Semgrep (SAST)',
  kind: 'adapter',
  capabilities: {
    A02: cap('insecure configuration patterns (rule-dependent)', 'heuristic'),
    A04: cap('weak crypto primitives, hardcoded keys (rule-dependent)', 'heuristic'),
    A05: cap('injection sinks via pattern + limited taint rules', 'heuristic'),
    A07: cap('hardcoded credentials, weak auth patterns (rule-dependent)', 'heuristic'),
    A08: cap('insecure deserialization, dangerous template sinks (rule-dependent)', 'heuristic'),
    A10: cap('fail-open error handling patterns (rule-dependent)', 'heuristic'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['source'],
};

interface SemgrepResult {
  results?: Array<{
    check_id: string;
    path: string;
    start: { line: number; col: number };
    end: { line: number; col: number };
    extra: {
      message: string;
      severity: 'INFO' | 'WARNING' | 'ERROR';
      lines?: string;
      metadata?: {
        cwe?: string | string[];
        owasp?: string | string[];
        confidence?: 'LOW' | 'MEDIUM' | 'HIGH';
      };
      fix?: string;
    };
  }>;
  errors?: Array<{ message?: string }>;
}

function semgrepSeverity(s: 'INFO' | 'WARNING' | 'ERROR'): Severity {
  switch (s) {
    case 'ERROR': return 'high';
    case 'WARNING': return 'medium';
    default: return 'low';
  }
}

function parseCwes(raw: string | string[] | undefined): number | undefined {
  if (!raw) return undefined;
  const list = Array.isArray(raw) ? raw : [raw];
  for (const item of list) {
    const m = /CWE-(\d+)/.exec(item);
    if (m) return Number(m[1]);
  }
  return undefined;
}

function firstOwaspTag(raw: string | string[] | undefined): string | undefined {
  if (!raw) return undefined;
  const list = Array.isArray(raw) ? raw : [raw];
  return list[0];
}

export class SemgrepAdapter implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    try {
      const version = await detectVersion('semgrep', ['--version']);
      return { available: true, version };
    } catch (e) {
      if (e instanceof BinaryNotFoundError) {
        return {
          available: false,
          reason: 'semgrep is not installed or not on PATH',
          installHint: 'pip install semgrep  (https://semgrep.dev/docs/getting-started)',
        };
      }
      return { available: false, reason: `semgrep probe failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const root = ctx.target.sourcePath;
    if (!root) return { findings: [], detail: 'no sourcePath on target' };

    const outDir = join(ctx.workDir, 'semgrep');
    mkdirSync(outDir, { recursive: true });
    const outFile = join(outDir, 'semgrep.json');

    const config = process.env.OWASP_SEMGREP_CONFIG;
    const args: string[] = ['scan', '--json', '--quiet'];
    if (config) {
      args.push('--config', config);
    } else {
      // bundled offline ruleset (see rules/semgrep/)
      args.push('--config', join(process.cwd(), 'rules', 'semgrep'));
    }
    args.push('--output', outFile, root);

    let proc;
    try {
      proc = await runProcess('semgrep', args, { timeoutMs: 600_000, signal: ctx.signal });
    } catch (e) {
      if (e instanceof BinaryNotFoundError) {
        return { findings: [], detail: 'semgrep disappeared mid-scan' };
      }
      throw e;
    }
    if (proc.timedOut) return { findings: [], detail: 'semgrep timed out' };

    let parsed: SemgrepResult;
    try {
        parsed = JSON.parse(readFileSync(outFile, 'utf8')) as SemgrepResult;
    } catch (e) {
      if (proc.exitCode !== 0) {
        log.warn('semgrep failed', { exitCode: proc.exitCode, stderr: proc.stderr.slice(0, 500) });
        return { findings: [], detail: `semgrep exited ${proc.exitCode}: ${proc.stderr.slice(0, 300)}` };
      }
      throw e;
    }

    const findings = SemgrepAdapter.parseReport(parsed);
    return {
      findings,
      version: (await detectVersion('semgrep', ['--version'], 10_000)) ?? 'unknown',
      detail: proc.exitCode !== 0 && findings.length === 0
        ? `semgrep exited ${proc.exitCode}`
        : `${findings.length} semgrep findings`,
    };
  }

  /** Pure mapping from parsed semgrep JSON to raw findings. */
  static parseReport(parsed: SemgrepResult): RawFinding[] {
    return (parsed.results ?? []).map((r) => {
      const cwe = parseCwes(r.extra.metadata?.cwe);
      const title = r.extra.message.split('\n')[0]?.slice(0, 160) || r.check_id;
      return {
        rawId: r.check_id,
        title,
        category: classifyFinding(cwe, r.check_id, firstOwaspTag(r.extra.metadata?.owasp)),
        cwe,
        severity: semgrepSeverity(r.extra.severity),
        confidence: r.extra.metadata?.confidence === 'HIGH' ? 'high' : 'medium',
        status: 'probable' as const,
        asset: 'SOURCE',
        locator: `${r.path}:${r.start.line}`,
        evidence: [{
          kind: 'file' as const,
          path: r.path,
          lineStart: r.start.line,
          lineEnd: r.end.line,
          excerpt: (r.extra.lines ?? '').slice(0, 300),
          observation: `semgrep rule ${r.check_id} matched`,
        }],
        explanation: r.extra.message.slice(0, 1000),
        remediation: r.extra.fix
          ? `Apply the suggested fix: ${r.extra.fix.slice(0, 400)}`
          : 'Review the match against the rule documentation and apply a context-appropriate fix.',
        references: [`https://semgrep.dev/r/${r.check_id}`],
      };
    });
  }
}
