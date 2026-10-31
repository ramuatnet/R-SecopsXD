/**
 * Source adapters (newtask.md C2) — one adapter per source family; each emits
 * ONLY NormalizedEvent + node/edge assertions. Raw severity is carried verbatim
 * (severityRaw) and never overwritten; normalization happens in the merger.
 *
 * Routing: findings are attributed to a source family by their provenance
 * engine; the cloud-bucket finding is routed to CSPM by rawId regardless of
 * engine (it is a cloud-config observation, not host recon).
 */
import type { Finding } from '../core/types.ts';
import { assetUid, portIdentity, serviceIdentity } from './uid.ts';
import type { AdapterOutput, NodeAssertion, NormalizedEvent, Observable } from './types.ts';

export type SourceFamily = 'easm' | 'scanner' | 'dast' | 'cspm';

const EASM_ENGINES = new Set(['builtin.host-infra', 'builtin.asset-discovery', 'builtin.internal-scan']);
const SCANNER_ENGINES = new Set(['adapter.nuclei', 'adapter.trivy', 'adapter.grype', 'adapter.semgrep', 'adapter.zap']);

export function sourceFamily(f: Finding): SourceFamily {
  const rawIds = f.provenance.map((p) => p.rawId ?? '');
  if (rawIds.some((r) => r === 'cloud-bucket-public')) return 'cspm';
  const engines = f.provenance.map((p) => p.engine);
  if (engines.some((e) => EASM_ENGINES.has(e))) return 'easm';
  if (engines.some((e) => SCANNER_ENGINES.has(e))) return 'scanner';
  return 'dast';
}

function ev(
  family: SourceFamily,
  what: string,
  activityId: NormalizedEvent['activityId'],
  assetUidValue: string,
  f: Finding,
  observables: Observable[],
  evidenceRef?: string,
): NormalizedEvent {
  const t = f.detectedAt ?? new Date().toISOString();
  return {
    classUid: `${family}.${what}`,
    activityId,
    time: t,
    assetUid: assetUidValue,
    observables,
    evidenceRef,
    confidence: f.confidence === 'high' ? 'high' : f.confidence === 'medium' ? 'medium' : 'low',
    severityRaw: f.severity,
    severityNorm: f.severity,
    firstSeen: t,
    lastSeen: t,
    provenance: f.provenance.map((p) => ({ engine: p.engine, ...(p.rawId !== undefined ? { rawId: p.rawId } : {}) })),
  };
}

const hostNode = (ip: string): NodeAssertion => ({ type: 'ip', identity: ip, display: ip });
const domainNode = (domain: string): NodeAssertion => ({ type: 'domain', identity: domain, display: domain });
const portNode = (ip: string, port: number, severity: string): NodeAssertion => ({
  type: 'port', identity: portIdentity(ip, port), display: `${ip}:${port}`,
  attributes: { severity },
});
const webappNode = (origin: string): NodeAssertion => ({ type: 'webapp', identity: origin, display: origin });

function parseIpPort(locator: string): { ip: string; port: number } | undefined {
  const m = /^([\d.]+):(\d+)$/.exec(locator.trim());
  if (m === null) return undefined;
  return { ip: m[1]!, port: Number(m[2]) };
}

/** EASM adapter: host-infra / asset-discovery / internal-scan findings. */
export function easmAdapter(f: Finding): AdapterOutput {
  const nodes: NodeAssertion[] = [];
  const edges: AdapterOutput['edges'] = [];
  const rawIds = f.provenance.map((p) => p.rawId ?? '');

  if (rawIds.includes('host-resolved')) {
    // locator = hostname; evidence observation lists "ip (PTR: x); ..."
    const domain = f.asset.trim().toLowerCase();
    const ips = (f.evidence[0]?.observation ?? '').match(/\d+\.\d+\.\d+\.\d+/g) ?? [];
    nodes.push(domainNode(domain));
    const events = [ev('easm', 'host.resolved', 'observed', assetUid('domain', domain), f,
      ips.map((ip) => ({ kind: 'ip' as const, value: ip })))];
    for (const ip of ips) {
      nodes.push(hostNode(ip));
      edges.push({ edgeType: 'resolves_to', src: domainNode(domain), dst: hostNode(ip), provenance: ['easm'] });
    }
    return { events, nodes, edges };
  }

  if (rawIds.includes('port-open')) {
    const parsed = parseIpPort(f.locator);
    if (parsed === undefined) return { events: [], nodes: [], edges: [] };
    nodes.push(hostNode(parsed.ip), portNode(parsed.ip, parsed.port, f.severity));
    edges.push({ edgeType: 'exposes', src: hostNode(parsed.ip), dst: portNode(parsed.ip, parsed.port, f.severity), provenance: ['easm'] });
    const events = [ev('easm', 'port.open', 'opened', assetUid('port', portIdentity(parsed.ip, parsed.port)), f,
      [{ kind: 'port' as const, value: String(parsed.port) }])];
    return { events, nodes, edges };
  }

  if (rawIds.includes('service-identified')) {
    const parsed = parseIpPort(f.locator);
    if (parsed === undefined) return { events: [], nodes: [], edges: [] };
    const product = /Server:\s*([^\s;]+)/i.exec(f.evidence[0]?.observation ?? '')?.[1] ?? 'http';
    const svc = { type: 'service' as const, identity: serviceIdentity(parsed.ip, parsed.port, 'tcp', product), display: `${product} on ${parsed.ip}:${parsed.port}`, attributes: { capabilities: (f.evidence[0]?.observation ?? '').slice(0, 300) } };
    nodes.push(svc, portNode(parsed.ip, parsed.port, 'info'));
    edges.push({ edgeType: 'runs', src: portNode(parsed.ip, parsed.port, 'info'), dst: svc, provenance: ['easm'] });
    const events = [ev('easm', 'service.identified', 'observed', assetUid('service', svc.identity), f,
      [{ kind: 'version' as const, value: product }, { kind: 'port' as const, value: String(parsed.port) }])];
    return { events, nodes, edges };
  }

  // everything else (cert SANs, DNS records, OS hints, ...) is an observation on the domain asset
  const domain = f.asset.trim().toLowerCase();
  return {
    events: [ev('easm', 'dns.observed', 'observed', assetUid('domain', domain), f,
      [{ kind: 'text' as const, value: (f.evidence[0]?.observation ?? '').slice(0, 200) }])],
    nodes: [domainNode(domain)],
    edges: [],
  };
}

/** CSPM adapter: cloud-config observations. */
export function cspmAdapter(f: Finding): AdapterOutput {
  const domain = f.asset.trim().toLowerCase();
  const bucket = { type: 'cloud_resource' as const, identity: f.locator.slice(0, 120), display: f.locator.slice(0, 120), attributes: { severity: f.severity } };
  return {
    events: [ev('cspm', 'bucket.exposed', 'opened', assetUid('cloud_resource', bucket.identity), f,
      [{ kind: 'url' as const, value: f.locator.slice(0, 200) }])],
    nodes: [bucket, domainNode(domain)],
    edges: [{ edgeType: 'found_on', src: bucket, dst: domainNode(domain), provenance: ['cspm'] }],
  };
}

/** DAST adapter: web application findings. */
export function dastAdapter(f: Finding): AdapterOutput {
  const origin = f.asset;
  const finding = { type: 'finding' as const, identity: f.fingerprint, display: f.title, attributes: { severity: f.severity, status: f.status, category: f.category } };
  return {
    events: [ev('dast', 'finding.observed', 'observed', assetUid('finding', f.fingerprint), f,
      [{ kind: 'url' as const, value: f.locator.slice(0, 200) }, ...(f.cwe !== undefined ? [{ kind: 'cwe' as const, value: `CWE-${f.cwe}` }] : [])], f.id),
    ],
    nodes: [finding, webappNode(origin)],
    edges: [{ edgeType: 'found_on', src: finding, dst: webappNode(origin), provenance: ['dast'] }],
  };
}

/** Scanner adapter: template/version-scanner findings (nuclei, internal-scan CVEs...). */
export function scannerAdapter(f: Finding): AdapterOutput {
  const origin = f.asset;
  const finding = { type: 'finding' as const, identity: f.fingerprint, display: f.title, attributes: { severity: f.severity, status: f.status, category: f.category, cve: f.cve } };
  const observables: Observable[] = [{ kind: 'url' as const, value: f.locator.slice(0, 200) }];
  if (f.cve !== undefined) observables.push({ kind: 'cve', value: f.cve });
  return {
    events: [ev('scanner', 'finding.observed', 'observed', assetUid('finding', f.fingerprint), f, observables, f.id)],
    nodes: [finding, webappNode(origin)],
    edges: [{ edgeType: 'found_on', src: finding, dst: webappNode(origin), provenance: ['scanner'] }],
  };
}

export function adapt(f: Finding): AdapterOutput {
  switch (sourceFamily(f)) {
    case 'easm': return easmAdapter(f);
    case 'cspm': return cspmAdapter(f);
    case 'scanner': return scannerAdapter(f);
    default: return dastAdapter(f);
  }
}
