/**
 * Grype SCA adapter (source targets) — included because it is commonly
 * available via winget/homebrew and validates the adapter architecture
 * against a real external tool. Runs `grype dir:<path> -o json`.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding, Severity } from '../../core/types.ts';
import { severityFromCvss } from '../../core/cweMap.ts';
import { BinaryNotFoundError, detectVersion, runProcess } from './common.ts';

const INFO: EngineInfo = {
  id: 'adapter.grype',
  name: 'Grype (SCA)',
  kind: 'adapter',
  capabilities: {
    A03: cap('known CVEs in dependency lockfiles/manifests (advisory-database match)', 'strong'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['source'],
};

interface GrypeReport {
  matches?: Array<{
    vulnerability: {
      id: string;
      severity?: string;
      description?: string;
      cvss?: Array<{ metrics?: { baseScore?: number } }>;
      fix?: { versions?: string[] };
      relatedVulnerabilities?: Array<{ id?: string }>;
    };
    artifact: {
      name: string;
      version: string;
      type?: string;
      locations?: Array<{ path?: string; line?: number }>;
    };
  }>;
}

function grypeSeverity(s: string | undefined): Severity {
  switch ((s ?? '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    case 'negligible': return 'info';
    default: return 'medium';
  }
}

export class GrypeAdapter implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    try {
      const version = await detectVersion('grype', ['--version'], 20_000);
      return { available: true, version };
    } catch (e) {
      if (e instanceof BinaryNotFoundError) {
        return {
          available: false,
          reason: 'grype is not installed or not on PATH',
          installHint: 'winget install anchore.grype  |  brew install grype  |  https://github.com/anchore/grype',
        };
      }
      return { available: false, reason: `grype probe failed: ${e instanceof Error ? e.message : String(e)}` };
    }
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const root = ctx.target.sourcePath;
    if (!root) return { findings: [], detail: 'no sourcePath on target' };

    const proc = await runProcess('grype', [`dir:${root}`, '-o', 'json', '--quiet'], {
      timeoutMs: 600_000,
      signal: ctx.signal,
    });
    if (proc.exitCode !== 0) {
      return { findings: [], detail: `grype exited ${proc.exitCode}: ${proc.stderr.slice(0, 300)}` };
    }

    let report: GrypeReport;
    try {
      report = JSON.parse(proc.stdout) as GrypeReport;
    } catch {
      return { findings: [], detail: 'grype produced unparseable output' };
    }

    const findings = GrypeAdapter.parseReport(report);
    return { findings, version: await detectVersion('grype', ['--version'], 20_000).catch(() => undefined), detail: `${findings.length} grype findings` };
  }

  /** Pure mapping from parsed grype JSON to raw findings. */
  static parseReport(report: GrypeReport): RawFinding[] {
    return (report.matches ?? []).map((m) => {
      const score = m.vulnerability.cvss?.[0]?.metrics?.baseScore;
      const fixed = m.vulnerability.fix?.versions?.[0];
      // Grype may match via GHSA/advisory ids; surface a CVE when one is linked.
      const cve = [m.vulnerability.id, ...(m.vulnerability.relatedVulnerabilities ?? []).map((r) => r.id ?? '')]
        .find((id) => id.startsWith('CVE-'));
      return {
        rawId: m.vulnerability.id,
        title: `${m.vulnerability.id} in ${m.artifact.name}@${m.artifact.version}`,
        category: 'A03' as const,
        cve,
        severity: score !== undefined ? severityFromCvss(score) : grypeSeverity(m.vulnerability.severity),
        confidence: 'high' as const,
        status: 'confirmed' as const,
        asset: m.artifact.locations?.[0]?.path ?? 'dependencies',
        locator: `${m.artifact.name}@${m.artifact.version}`,
        evidence: [{
          kind: 'dependency' as const,
          ecosystem: m.artifact.type ?? 'unknown',
          packageName: m.artifact.name,
          installedVersion: m.artifact.version,
          fixedVersion: fixed,
          observation: `${m.vulnerability.id} affects ${m.artifact.name}@${m.artifact.version}${fixed ? `; fixed in ${fixed}` : ''}`,
        }],
        explanation: (m.vulnerability.description ?? 'Known vulnerability in an imported dependency.').slice(0, 1200),
        remediation: fixed
          ? `Upgrade ${m.artifact.name} to ${fixed} or later.`
          : `Review the advisory for ${m.vulnerability.id}; no fixed version is published.`,
        references: cve
          ? [`https://nvd.nist.gov/vuln/detail/${cve}`]
          : [],
      };
    });
  }
}
