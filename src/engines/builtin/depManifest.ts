/**
 * Built-in dependency manifest engine (source targets).
 *
 * Produces a dependency INVENTORY finding (informational) from
 * package.json/package-lock.json and warns when no lockfile pins versions.
 * It does NOT match CVEs — that is the job of the Trivy/Grype SCA adapters;
 * this engine only guarantees an inventory exists even without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { DependencyEvidence, EngineInfo, RawFinding } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.dep-manifest',
  name: 'Dependency Manifest Inventory',
  kind: 'builtin',
  capabilities: {
    A03: cap('dependency inventory from manifests/lockfiles; CVE matching requires an SCA adapter (Trivy/Grype)'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['source'],
};

interface DepEntry { name: string; version: string; dev: boolean }

export class DepManifestEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const root = ctx.target.sourcePath;
    if (!root) return { findings: [], detail: 'no sourcePath on target' };
    const findings: RawFinding[] = [];

    const pkgJsonPath = join(root, 'package.json');
    const lockPath = join(root, 'package-lock.json');
    const hasPkg = existsSync(pkgJsonPath);
    const hasLock = existsSync(lockPath);

    if (!hasPkg && !hasLock) {
      return { findings: [], detail: 'no package.json/package-lock.json found' };
    }

    const deps: DepEntry[] = [];
    let lockCount = 0;
    if (hasLock) {
      try {
        const lock = JSON.parse(readFileSync(lockPath, 'utf8')) as {
          packages?: Record<string, { version?: string; dev?: boolean }>;
          dependencies?: Record<string, { version?: string; dev?: boolean }>;
        };
        if (lock.packages) {
          for (const [key, meta] of Object.entries(lock.packages)) {
            if (key === '' || !key.startsWith('node_modules/')) continue;
            const name = key.replace(/^node_modules\//, '');
            deps.push({ name, version: meta.version ?? 'unknown', dev: meta.dev === true });
            lockCount++;
          }
        } else if (lock.dependencies) {
          for (const [name, meta] of Object.entries(lock.dependencies)) {
            deps.push({ name, version: meta.version ?? 'unknown', dev: meta.dev === true });
            lockCount++;
          }
        }
      } catch {
        return { findings: [], detail: 'package-lock.json unparseable' };
      }
    }

    const runtimeDeps = deps.filter((d) => !d.dev);
    const evidence: DependencyEvidence = {
      kind: 'dependency',
      ecosystem: 'npm',
      packageName: `${lockCount} locked packages (${runtimeDeps.length} runtime, ${deps.length - runtimeDeps.length} dev)`,
      observation:
        `Inventory from ${hasLock ? 'package-lock.json' : 'package.json'}: ` +
        `${lockCount} locked packages, ${runtimeDeps.length} runtime dependencies`,
    };

    findings.push({
      rawId: 'dependency-inventory',
      title: `Dependency inventory: ${lockCount} packages (${runtimeDeps.length} runtime)`,
      category: 'A03',
      severity: 'info',
      confidence: 'high',
      status: 'informational',
      asset: ctx.target.sourcePath ?? ctx.target.name,
      locator: hasLock ? 'package-lock.json' : 'package.json',
      evidence: [evidence],
      explanation:
        'This is an inventory observation, not a vulnerability. Known-vulnerability matching ' +
        'against advisory databases is performed by the SCA adapters (Trivy, Grype) when ' +
        'installed. Without an SCA adapter the platform cannot conclude whether these ' +
        'dependencies have known CVEs.',
      remediation: hasLock
        ? 'Run an SCA scan (Trivy/Grype) to match this inventory against vulnerability advisories; keep dependencies updated.'
        : 'Commit a lockfile so dependency versions are pinned and reproducible; then run an SCA scan.',
      references: ['https://owasp.org/Top10/2025/en/A03_2025-Software_Supply_Chain_Failures/'],
    });

    if (hasPkg && !hasLock) {
      findings.push({
        rawId: 'no-lockfile',
        title: 'No lockfile: dependency versions are not pinned',
        category: 'A03',
        cwe: 1357,
        severity: 'medium',
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.sourcePath ?? ctx.target.name,
        locator: 'package.json',
        evidence: [{
          kind: 'file',
          path: 'package.json',
          observation: 'package.json present without package-lock.json',
        }],
        explanation:
          'Without a lockfile, builds resolve dependency versions at install time, so builds ' +
          'are not reproducible and a compromised or broken upstream release silently changes ' +
          'the application (supply-chain integrity, CWE-1357).',
        remediation: 'Commit package-lock.json (or equivalent) and install with `npm ci` in CI and production builds.',
        references: ['https://owasp.org/Top10/2025/en/A03_2025-Software_Supply_Chain_Failures/'],
      });
    }

    ctx.log('dep manifest finished', { packages: lockCount, findings: findings.length });
    return { findings, version: 'builtin' };
  }
}
