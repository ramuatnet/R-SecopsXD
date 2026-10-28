/**
 * Trivy SCA/misconfig/secret adapter (source targets).
 *
 * Runs `trivy fs --scanners vuln,secret,misconfig --format json`.
 * - Vulnerabilities → A03 (dependency, CVE, deterministic advisory match)
 * - Misconfigurations → classified by title/CWE (usually A02)
 * - Secrets → A07 hardcoded credentials (match text is redacted)
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding, Severity } from '../../core/types.ts';
import { classifyFinding } from '../../core/cweMap.ts';
import { redactText } from '../../core/redact.ts';
import { BinaryNotFoundError, detectVersion, runProcess } from './common.ts';

const INFO: EngineInfo = {
  id: 'adapter.trivy',
  name: 'Trivy (SCA + misconfig + secrets)',
  kind: 'adapter',
  capabilities: {
    A03: cap('known CVEs in dependency lockfiles/manifests (advisory-database match)', 'strong'),
    A02: cap('infrastructure/file misconfigurations (built-in checks)', 'heuristic'),
    A07: cap('secrets detected in source files (pattern match)', 'heuristic'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['source'],
};

interface TrivyReport {
  Results?: Array<{
    Target: string;
    Class?: string;
    Type?: string;
    Vulnerabilities?: Array<{
      VulnerabilityID: string;
      PkgName: string;
      InstalledVersion: string;
      FixedVersion?: string;
      Severity?: string;
      Title?: string;
      Description?: string;
      PrimaryURL?: string;
      CweIds?: string[];
    }>;
    Misconfigurations?: Array<{
      ID: string;
      AVDID?: string;
      Title: string;
      Description?: string;
      Message?: string;
      Resolution?: string;
      Severity?: string;
      CauseMetadata?: { StartLine?: number; EndLine?: number; FilePath?: string };
    }>;
    Secrets?: Array<{
      RuleID: string;
      Category?: string;
      Severity?: string;
      Title?: string;
      Match?: string;
      StartLine?: number;
      EndLine?: number;
    }>;
  }>;
}

function trivySeverity(s: string | undefined): Severity {
  switch ((s ?? '').toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    default: return 'info';
  }
}

export class TrivyAdapter implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    try {
      const version = await detectVersion('trivy');
      return { available: true, version };
    } catch (e) {
      if (e instanceof BinaryNotFoundError) {
        return {
          available: false,
          reason: 'trivy is not installed or not on PATH',
          installHint: 'winget install AquaSecurity.Trivy  |  brew install trivy  |  https://trivy.dev/latest/docs/getting-started/installation/',
        };
      }
      return { available: false, reason: `trivy probe failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  }

  /** Pure mapping from a parsed trivy JSON report to raw findings. */
  static parseReport(report: TrivyReport): RawFinding[] {
    const findings: RawFinding[] = [];
    for (const result of report.Results ?? []) {
      for (const v of result.Vulnerabilities ?? []) {
        const cweParsed = v.CweIds?.[0] ? Number(/(\d+)/.exec(v.CweIds[0]!)?.[1]) : NaN;
        findings.push({
          rawId: v.VulnerabilityID,
          title: v.Title ?? `${v.VulnerabilityID} in ${v.PkgName}@${v.InstalledVersion}`,
          category: 'A03',
          cwe: Number.isFinite(cweParsed) ? cweParsed : undefined,
          cve: v.VulnerabilityID.startsWith('CVE-') ? v.VulnerabilityID : undefined,
          severity: trivySeverity(v.Severity),
          confidence: 'high',
          status: 'confirmed',
          asset: result.Target,
          locator: `${v.PkgName}@${v.InstalledVersion}`,
          evidence: [{
            kind: 'dependency',
            ecosystem: result.Type ?? 'unknown',
            packageName: v.PkgName,
            installedVersion: v.InstalledVersion,
            fixedVersion: v.FixedVersion,
            observation: `${v.VulnerabilityID} affects ${v.PkgName}@${v.InstalledVersion}${v.FixedVersion ? `; fixed in ${v.FixedVersion}` : ''}`,
          }],
          explanation: (v.Description ?? v.Title ?? 'Known vulnerability in an imported dependency.').slice(0, 1200),
          remediation: v.FixedVersion
            ? `Upgrade ${v.PkgName} to ${v.FixedVersion} or later.`
            : `Review ${v.PrimaryURL ?? 'the advisory'} for mitigations; no fixed version is published.`,
          references: v.PrimaryURL ? [v.PrimaryURL] : [`https://nvd.nist.gov/vuln/search/results?query=${v.VulnerabilityID}`],
        });
      }

      for (const m of result.Misconfigurations ?? []) {
        const line = m.CauseMetadata?.StartLine;
        findings.push({
          rawId: m.AVDID ?? m.ID,
          title: m.Title,
          category: classifyFinding(undefined, m.Title),
          severity: trivySeverity(m.Severity),
          confidence: 'medium',
          status: 'probable',
          asset: result.Target,
          locator: line !== undefined ? `${m.CauseMetadata?.FilePath ?? result.Target}:${line}` : result.Target,
          evidence: [{
            kind: 'file',
            path: m.CauseMetadata?.FilePath ?? result.Target,
            lineStart: line,
            lineEnd: m.CauseMetadata?.EndLine,
            excerpt: (m.Message ?? '').slice(0, 300),
            observation: `trivy check ${m.ID}: ${m.Title}`,
          }],
          explanation: (m.Description ?? m.Title).slice(0, 1000),
          remediation: (m.Resolution ?? 'Apply the check resolution guidance.').slice(0, 800),
          references: m.AVDID ? [`https://avd.aquasec.com/misconfig/${m.AVDID.toLowerCase()}`] : [],
        });
      }

      for (const s of result.Secrets ?? []) {
        findings.push({
          rawId: s.RuleID,
          title: s.Title ?? 'Potential secret in source file',
          category: 'A07',
          cwe: 798,
          severity: trivySeverity(s.Severity) === 'info' ? 'high' : trivySeverity(s.Severity),
          confidence: 'medium',
          status: 'probable',
          asset: result.Target,
          locator: `${result.Target}:${s.StartLine ?? 0}`,
          evidence: [{
            kind: 'file',
            path: result.Target,
            lineStart: s.StartLine,
            lineEnd: s.EndLine,
            excerpt: redactText(s.Match ?? '', 200),
            observation: `trivy secret rule ${s.RuleID} matched (match text redacted)`,
          }],
          explanation: 'A string matching a known secret pattern is embedded in a source file. Verify whether it is a real credential.',
          remediation: 'If real: revoke/rotate the secret, remove it from source and history, move to a secret manager. If a test fixture: allowlist it for the scanner.',
          references: [],
        });
      }
    }
    return findings;
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const root = ctx.target.sourcePath;
    if (!root) return { findings: [], detail: 'no sourcePath on target' };

    const proc = await runProcess('trivy', [
      'fs',
      '--scanners', 'vuln,secret,misconfig',
      '--format', 'json',
      '--quiet',
    ], { timeoutMs: 600_000, signal: ctx.signal });
    if (proc.exitCode !== 0) {
      return { findings: [], detail: `trivy exited ${proc.exitCode}: ${proc.stderr.slice(0, 300)}` };
    }
    let report: TrivyReport;
    try {
      report = JSON.parse(proc.stdout) as TrivyReport;
    } catch {
      return { findings: [], detail: 'trivy produced unparseable output' };
    }
    const findings = TrivyAdapter.parseReport(report);
    return { findings, version: await detectVersion('trivy').catch(() => undefined), detail: `${findings.length} trivy findings` };
  }
}
