/**
 * Scope manifest (edgetask.md §1.1) + shared-IP scope guard (§1.2, EDGE-04).
 *
 * The manifest is the authorization artifact: domains, CIDRs, a port
 * include/exclude policy, classes, flags (origin discovery/probing) and a
 * kill switch. EDGE-04: on an IP classified edge, only manifest-permitted
 * ports are scanned, and findings attribute to (hostname, vantage) — never to
 * the bare IP.
 *
 * Enforcement points:
 *  - bus ingress: out-of-scope events are rejected with blocked_by_scope (§1.1);
 *  - probe executor: the shared-IP guard filters non-manifest ports on edge IPs.
 */
import type { ScopeManifest } from './models.ts';
import type { Finding } from '../core/types.ts';
import { cidrContains } from './classifier.ts';

export interface ScopeVerdict { inScope: boolean; reason?: string; }

/** §1.1 validity: window + signer present. */
export function manifestValid(m: ScopeManifest, now = new Date()): ScopeVerdict {
  if (m.signer === '') return { inScope: false, reason: 'blocked_by_scope: manifest unsigned' };
  const t = now.getTime();
  if (Number.isFinite(Date.parse(m.validFrom)) && t < Date.parse(m.validFrom)) {
    return { inScope: false, reason: `blocked_by_scope: manifest not yet valid (from ${m.validFrom})` };
  }
  if (Number.isFinite(Date.parse(m.validTo)) && t > Date.parse(m.validTo)) {
    return { inScope: false, reason: `blocked_by_scope: manifest expired (${m.validTo})` };
  }
  if (m.killSwitch === 'global') return { inScope: false, reason: 'blocked_by_scope: global kill switch engaged' };
  return { inScope: true };
}

/** Is this asset (hostname or IP) inside the manifest scope? */
export function assetInScope(m: ScopeManifest, hostnameOrIp: string): ScopeVerdict {
  const base = manifestValid(m);
  if (!base.inScope) return base;
  const host = hostnameOrIp.trim().toLowerCase();
  if (m.domains.some((d) => host === d.toLowerCase() || host.endsWith(`.${d.toLowerCase()}`))) return { inScope: true };
  if (m.cidrs.some((c) => cidrContains(host, c))) return { inScope: true };
  return { inScope: false, reason: `blocked_by_scope: ${hostnameOrIp} is not in manifest domains/cidrs` };
}

/** §1.1 port policy: include list wins; exclude always subtracts. */
export function portPermitted(m: ScopeManifest, port: number): ScopeVerdict {
  if (m.ports.exclude.includes(port)) {
    return { inScope: false, reason: `blocked_by_scope: port ${port} excluded by manifest` };
  }
  if (m.ports.include.length > 0 && !m.ports.include.includes(port)) {
    return { inScope: false, reason: `blocked_by_scope: port ${port} not in manifest include list` };
  }
  return { inScope: true };
}

/**
 * EDGE-04 shared-IP guard: on an edge-classified IP, only manifest-permitted
 * ports survive; out-of-policy port findings are dropped with an audit record
 * (the caller logs them). Findings keep (hostname, vantage) attribution.
 */
export function applySharedIpGuard(
  findings: Finding[],
  manifest: ScopeManifest | undefined,
  isEdge: boolean,
  hostname: string,
): { findings: Finding[]; dropped: Array<{ findingId: string; reason: string }> } {
  if (!isEdge || manifest === undefined) return { findings, dropped: [] };
  const kept: Finding[] = [];
  const dropped: Array<{ findingId: string; reason: string }> = [];
  for (const f of findings) {
    const portM = /:(\d+)/.exec(f.locator ?? '');
    const port = portM === null ? undefined : Number(portM[1]);
    if (port !== undefined) {
      const v = portPermitted(manifest, port);
      if (!v.inScope) {
        dropped.push({ findingId: f.id, reason: v.reason ?? 'blocked_by_scope' });
        continue;
      }
    }
    // §1.2: attribute to (hostname, vantage), never the bare IP.
    if (f.asset !== undefined && /^\d+\.\d+\.\d+\.\d+$/.test(f.asset)) f.asset = hostname;
    if (f.surface === undefined) f.surface = 'edge';
    kept.push(f);
  }
  return { findings: kept, dropped };
}
