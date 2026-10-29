/**
 * External Attack Surface Management (v2 Phase 8, T8.1–T8.2).
 *
 * T8.1: subdomain/asset discovery via DNS + certificate SANs.
 * T8.2: cloud storage public-access probes (S3, GCS, Azure).
 *
 * Safety: DNS queries are passive; cloud probes are bounded GETs to
 * candidate URLs. No credentials required — only publicly observable state.
 */
import { resolveCname, resolveMx, resolveNs, resolveTxt } from 'node:dns/promises';
import { connect as tlsConnect } from 'node:tls';

export interface DiscoveredAsset {
  type: 'subdomain' | 'cert-san' | 'mx' | 'nameserver' | 'txt-record' | 'cloud-bucket';
  value: string;
  source: string;
}

/** T8.1 — DNS-based subdomain/asset discovery for a domain. */
export async function discoverDnsAssets(domain: string): Promise<DiscoveredAsset[]> {
  const assets: DiscoveredAsset[] = [];
  const safeDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

  const tasks = [
    resolveCname(safeDomain).then(
      (r) => { for (const c of r) assets.push({ type: 'subdomain', value: c, source: 'CNAME' }); },
      () => {},
    ),
    resolveMx(safeDomain).then(
      (r) => { for (const m of r) assets.push({ type: 'mx', value: m.exchange, source: 'MX' }); },
      () => {},
    ),
    resolveNs(safeDomain).then(
      (r) => { for (const ns of r) assets.push({ type: 'nameserver', value: ns, source: 'NS' }); },
      () => {},
    ),
    resolveTxt(safeDomain).then(
      (r) => { for (const rr of r) assets.push({ type: 'txt-record', value: rr.join(' ').slice(0, 200), source: 'TXT' }); },
      () => {},
    ),
  ];
  await Promise.allSettled(tasks);
  return assets;
}

/** T8.1 — certificate SAN extraction (discovers subdomains from TLS certs). */
export async function discoverCertSans(host: string, port = 443): Promise<DiscoveredAsset[]> {
  return new Promise<DiscoveredAsset[]>((resolve) => {
    const { connect } = require('node:tls') as typeof import('node:tls');
    const socket = connect({ host, port, servername: host, rejectUnauthorized: false });
    const timer = setTimeout(() => { socket.destroy(); resolve([]); }, 10_000);
    socket.once('secureConnect', () => {
      clearTimeout(timer);
      const cert = socket.getPeerCertificate(true);
      const sans = cert.subjectaltname?.split(', ').filter((s) => s.startsWith('DNS:')) ?? [];
      socket.destroy();
      resolve(sans.map((san) => ({
        type: 'cert-san' as const,
        value: san.replace('DNS:', ''),
        source: `certificate CN=${cert.subject?.CN ?? 'unknown'}`,
      })));
    });
    socket.once('error', () => { clearTimeout(timer); resolve([]); });
  });
}

/** T8.2 — cloud storage public-access probes (bounded GETs, no credentials). */
export async function probeCloudStorage(bucketNames: string[]): Promise<DiscoveredAsset[]> {
  const assets: DiscoveredAsset[] = [];
  const probes: Array<{ url: string; provider: string; public: string }> = [];

  for (const bucket of bucketNames.slice(0, 10)) {
    probes.push({ url: `https://${bucket}.s3.amazonaws.com/`, provider: 'AWS S3', public: 'listable' });
    probes.push({ url: `https://${bucket}.storage.googleapis.com/`, provider: 'GCS', public: 'listable' });
    probes.push({ url: `https://${bucket}.blob.core.windows.net/`, provider: 'Azure Blob', public: 'listable' });
  }

  for (const probe of probes) {
    try {
      const res = await fetch(probe.url, { signal: AbortSignal.timeout(5000), redirect: 'manual' });
      if (res.status === 200) {
        const body = await res.text();
        if (body.includes('<ListBucketResult') || body.includes('<?xml') || body.length > 0) {
          assets.push({
            type: 'cloud-bucket',
            value: `${probe.provider}: ${probe.url} (publicly listable)`,
            source: `status=${res.status}`,
          });
        }
      }
    } catch { /* unreachable or DNS failure — skip */ }
  }
  return assets;
}
