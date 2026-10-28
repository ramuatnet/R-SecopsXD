/**
 * OWASP ZAP adapter (webapp targets, active mode).
 *
 * Runs ZAP's headless quick scan (`-cmd -quickurl … -quickout file.json`),
 * then parses the JSON report. ZAP performs its own spidering and active
 * scanning inside its process — the platform enforces scope on the entry
 * URL and records the residual in docs/THREAT-MODEL.md.
 *
 * ZAP risk codes: 3=High 2=Medium 1=Low 0=Informational.
 * ZAP confidence: 3=High 2=Medium 1=Low 0=FalsePositive.
 */
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding, Severity } from '../../core/types.ts';
import { classifyFinding } from '../../core/cweMap.ts';
import { redactText } from '../../core/redact.ts';
import { detectVersion, resolveBinary, runProcess } from './common.ts';

const INFO: EngineInfo = {
  id: 'adapter.zap',
  name: 'OWASP ZAP (DAST)',
  kind: 'adapter',
  capabilities: {
    A01: cap('active scan alerts for access control/IDOR surfaces (limited without authenticated sessions)', 'heuristic'),
    A02: cap('security headers, cookie flags, XE, directory browsing alerts', 'strong'),
    A05: cap('injection alerts from ZAP active rules (non-destructive set)', 'heuristic'),
    A07: cap('session management and auth alerts', 'heuristic'),
    A08: cap('anti-CSRF and integrity-related alerts', 'heuristic'),
    A10: cap('info disclosure and error handling alerts', 'heuristic'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

interface ZapReport {
  site?: string;
  alerts?: Array<{
    pluginid?: string;
    alert?: string;
    riskcode?: string;
    confidence?: string;
    cweid?: string;
    wascid?: string;
    url?: string;
    param?: string;
    attack?: string;
    evidence?: string;
    description?: string;
    solution?: string;
    reference?: string;
    otherinfo?: string;
  }>;
}

function zapRisk(riskcode: string | undefined): Severity {
  switch (riskcode) {
    case '3': return 'high';
    case '2': return 'medium';
    case '1': return 'low';
    default: return 'info';
  }
}

function zapConfidence(confidence: string | undefined): 'high' | 'medium' | 'low' {
  switch (confidence) {
    case '3': return 'high';
    case '2': return 'medium';
    default: return 'low';
  }
}

export class ZapAdapter implements Engine {
  info = INFO;
  private binary?: string;

  async availability(): Promise<EngineAvailability> {
    const found = this.locateBinary();
    if (!found) {
      return {
        available: false,
        reason: 'OWASP ZAP is not installed (zap.sh/zap.bat not found on PATH or in default locations)',
        installHint: 'https://www.zaproxy.org/download/ — or install the "ZAP" package; requires Java 11+',
      };
    }
    try {
      const version = await detectVersion(found, ['-version'], 60_000);
      this.binary = found;
      return { available: true, version: version ?? 'unknown' };
    } catch (e) {
      return { available: false, reason: `ZAP found at ${found} but version check failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  }

  private locateBinary(): string | undefined {
    if (this.binary) return this.binary;
    const names = process.platform === 'win32'
      ? ['zap.bat', 'zap.cmd', 'zap.exe']
      : ['zap.sh'];
    for (const n of names) {
      const p = resolveBinary(n);
      if (p) { this.binary = p; return p; }
    }
    // default install locations
    const defaults = process.platform === 'win32'
      ? ['C:\\Program Files\\OWASP ZAP\\zap.bat', 'C:\\Program Files (x86)\\OWASP ZAP\\zap.bat']
      : ['/usr/local/bin/zap.sh', '/opt/zaproxy/zap.sh', '/snap/bin/zap.sh'];
    for (const d of defaults) {
      try {
        readFileSync(d); // existence probe (throws if missing)
        this.binary = d;
        return d;
      } catch { /* keep looking */ }
    }
    return undefined;
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const binary = this.locateBinary();
    if (!binary) return { findings: [], detail: 'ZAP binary not found at run time' };

    const outDir = join(ctx.workDir, 'zap');
    mkdirSync(outDir, { recursive: true });
    const reportFile = join(outDir, 'zap-report.json');

    const proc = await runProcess(binary, [
      '-cmd', '-quickurl', ctx.target.origin,
      '-quickout', reportFile,
      '-quickprogress',
      '-config', 'database.recoverylog=false',
      '-config', 'connection.timeoutInSecs=15',
    ], { timeoutMs: 900_000, signal: ctx.signal });

    if (proc.timedOut) return { findings: [], detail: 'ZAP quick scan timed out' };

    let report: ZapReport;
    try {
      report = JSON.parse(readFileSync(reportFile, 'utf8')) as ZapReport;
    } catch {
      return { findings: [], detail: `ZAP exited ${proc.exitCode}; no parseable JSON report (stderr: ${proc.stderr.slice(0, 200)})` };
    }

    const findings = ZapAdapter.parseReport(report, ctx.target.origin, `${binary} -cmd -quickurl ${ctx.target.origin} -quickout <report>`, proc.exitCode);
    return { findings, version: await detectVersion(binary, ['-version'], 60_000).catch(() => undefined), detail: `${findings.length} ZAP alerts` };
  }

  /** Pure mapping from a parsed ZAP JSON report to raw findings. */
  static parseReport(report: ZapReport, origin: string, commandLine: string, exitCode: number | null): RawFinding[] {
    return (report.alerts ?? []).map((a) => {
      const cwe = a.cweid && a.cweid !== '-1' ? Number(a.cweid) : undefined;
      let path = a.url ?? origin;
      try { path = new URL(a.url ?? origin).pathname; } catch { /* keep */ }
      const paramSuffix = a.param && a.param !== '' ? ` [${a.param}]` : '';
      return {
        rawId: `zap-${a.pluginid ?? 'alert'}`,
        title: `${a.alert ?? 'ZAP alert'}${paramSuffix}`,
        category: classifyFinding(cwe, a.alert ?? ''),
        cwe,
        severity: zapRisk(a.riskcode),
        confidence: zapConfidence(a.confidence),
        status: 'probable',
        asset: origin,
        locator: path,
        evidence: [{
          kind: 'process' as const,
          command: commandLine,
          exitCode: exitCode ?? undefined,
          stdoutExcerpt: redactText(
            `alert=${a.alert} url=${a.url} param=${a.param ?? ''} evidence=${(a.evidence ?? '').slice(0, 200)}`,
            600,
          ),
          observation: `ZAP alert ${a.pluginid} at ${a.url ?? ''}`,
        }],
        explanation: (a.description ?? '').slice(0, 1000) || 'ZAP active scan alert.',
        remediation: (a.solution ?? 'Follow the ZAP alert solution guidance.').slice(0, 800),
        references: a.reference ? [a.reference] : [],
      };
    });
  }
}
