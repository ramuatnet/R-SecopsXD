/**
 * §1.1 bus-ingress gate (edgetask.md) — admission control driven by the
 * signed scope manifest. Enforced at the BUS, not the scanner: any event
 * whose key (asset) is outside the manifest domains/CIDRs is rejected with
 * blocked_by_scope and recorded, never delivered.
 */
import type { BusIngressGate } from '../bus/bus.ts';
import type { Topic } from '../bus/bus.ts';
import { assetInScope, portPermitted, type ScopeManifestView } from './manifest.ts';

export class ManifestIngressGate implements BusIngressGate {
  private readonly manifestView: () => ScopeManifestView | undefined;
  constructor(manifestView: () => ScopeManifestView | undefined) {
    this.manifestView = manifestView;
  }

  admit(topic: Topic, key: string): { allowed: boolean; reason?: string } {
    const m = this.manifestView();
    if (m === undefined) return { allowed: true }; // no manifest = no ingress restriction (RoE still applies downstream)
    const verdict = assetInScope(m, key);
    if (!verdict.inScope) {
      // The key may be a finding id / scan id rather than an asset — only
      // asset-shaped keys (domains, IPs) are gate-enforced here.
      const assetShaped = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(key) || /^\d{1,3}(\.\d{1,3}){3}$/.test(key);
      if (!assetShaped) return { allowed: true };
      const reason = verdict.reason ?? 'blocked_by_scope';
      return { allowed: false, reason };
    }
    // Port policy on probe/finding topics when the key carries a port.
    if (topic === 'probe.requested' || topic === 'probe.completed' || topic === 'finding.candidate' || topic === 'finding.validated') {
      const portM = /:(\d+)$/.exec(key);
      if (portM !== null) {
        const pv = portPermitted(m, Number(portM[1]));
        if (!pv.inScope) {
          const preason = pv.reason ?? 'blocked_by_scope';
          return { allowed: false, reason: preason };
        }
      }
    }
    return { allowed: true };
  }
}
