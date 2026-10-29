/**
 * CycloneDX SBOM export (v2 T10.3) — from dependency-inventory findings.
 */
import type { Finding } from '../core/types.ts';

export function toCycloneDX(findings: Finding[], targetName: string): object {
  const components: Array<Record<string, unknown>> = [];
  for (const f of findings) {
    if (f.category !== 'A03') continue;
    for (const ev of f.evidence) {
      if (ev.kind !== 'dependency') continue;
      const dep = ev as { ecosystem?: string; packageName?: string; installedVersion?: string };
      if (!dep.packageName) continue;
      // Skip aggregate inventory entries (e.g. "3 locked packages")
      if (/\d+ (locked|package)/.test(dep.packageName)) continue;
      const version = dep.installedVersion;
      const purl = dep.ecosystem && dep.packageName
        ? `pkg:${dep.ecosystem}/${dep.packageName}${version ? `@${version}` : ''}`
        : undefined;
      components.push({
        type: 'library',
        'bom-ref': `${dep.packageName}@${version ?? 'unknown'}`,
        name: dep.packageName,
        ...(version ? { version } : {}),
        ...(purl ? { purl } : {}),
        properties: [
          { name: 'found-by', value: f.engine },
          { name: 'owasp-category', value: f.category },
        ],
      });
    }
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${Date.now().toString(36)}-rsecopsxd`,
    version: 1,
    metadata: {
      component: { type: 'application', name: targetName },
      tools: [{ vendor: 'R-SecopsXD', name: 'owasp-assessment-platform', version: '0.2.0' }],
    },
    components,
  };
}
