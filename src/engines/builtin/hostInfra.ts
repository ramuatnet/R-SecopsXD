/**
 * Host infrastructure reconnaissance (context-based) — runs as part of a
 * webapp scan. The registered URL's hostname is resolved (nslookup-equivalent)
 * and the resolved IPs are port-scanned, service-fingerprinted and matched
 * against the offline CVE list. No separate CIDR target registration is
 * needed: scan scope is anchored to the target's own DNS records.
 *
 * Passive mode: DNS resolution only (no packets to the host).
 * Active mode: DNS + bounded TCP port scan + TLS probe + fingerprint + CVE.
 *
 * Safety: only IPs the registered target's hostname resolves to are scanned
 * (max 4, IPv4 first); bounded port list; honors ctx.signal; unresolvable
 * hostnames produce no findings (unknown is never assumed — I8).
 */
import { lookup, reverse, resolveCname } from 'node:dns/promises';
import { connect as tlsConnect, type TLSSocket } from 'node:tls';
import { scanPort } from './internalScan.ts';
import { fingerprint, matchServiceCves, type ServiceFingerprint } from './internalScanEngine.ts';
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, Evidence, RawFinding } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.host-infra',
  name: 'Host Infrastructure Recon',
  kind: 'builtin',
  capabilities: {
    A01: cap("DNS resolution, live host discovery and open-port mapping of the registered target's own infrastructure"),
    A02: cap('management interface exposure on non-standard ports'),
    A03: cap('service version → CVE matching on scanned infrastructure services (offline advisory list)'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

const WEB_PORTS = [80, 443, 8080, 8443, 8000, 5000, 3000, 8888, 9090];
const INFRA_PORTS = [22, 21, 25, 3389, 3306, 5432, 6379, 27017];
const TLS_PORTS = new Set([443, 8443]);
const MAX_IPS = 4;
const PORT_BATCH = 32;
const PROBE_TIMEOUT_MS = 3000;

// ---------- DNS resolution (nslookup-equivalent, passive-safe) ----------

interface Resolution {
  ips: string[];
  cname?: string;
  ptrs: Map<string, string>;
}

function isIpv4Literal(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

/** Bound a DNS operation — resolvers can hang for many seconds on missing records. */
function dnsTimeout<T>(p: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(fallback), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, () => { clearTimeout(t); resolve(fallback); });
  });
}

export async function resolveHost(hostname: string): Promise<Resolution> {
  const ptrs = new Map<string, string>();
  if (isIpv4Literal(hostname)) return { ips: [hostname], ptrs };
  // lookup() uses the OS resolver (hosts file + DNS) — primary source.
  const addrs = await dnsTimeout(
    lookup(hostname, { all: true }).catch(() => [] as Array<{ address: string; family: number }>),
    5_000,
    [] as Array<{ address: string; family: number }>,
  );
  const v4 = addrs.filter((a) => a.family === 4).map((a) => a.address);
  const v6 = addrs.filter((a) => a.family === 6).map((a) => a.address);
  const cname = await dnsTimeout(resolveCname(hostname).then((r) => r[0]), 3_000, undefined);
  const ips = [...new Set([...v4, ...v6])].slice(0, MAX_IPS);
  await Promise.allSettled(ips.map(async (ip) => {
    const ptr = await dnsTimeout(reverse(ip).then((r) => r[0]), 2_000, undefined);
    if (ptr) ptrs.set(ip, ptr);
  }));
  const r: Resolution = { ips, ptrs };
  if (cname !== undefined) r.cname = cname;
  return r;
}

// ---------- TLS probe (plain-HTTP probes elicit nothing from TLS ports) ----------

interface TlsProbe {
  open: boolean;
  protocol?: string | undefined;
  cn?: string | undefined;
  issuer?: string | undefined;
  sans: string[];
}

export function probeTls(host: string, port: number, timeoutMs: number): Promise<TlsProbe> {
  return new Promise((resolve) => {
    const socket: TLSSocket = tlsConnect({ host, port, servername: host, rejectUnauthorized: false });
    let settled = false;
    let timer: NodeJS.Timeout;
    const done = (r: TlsProbe) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(r);
      }
    };
    timer = setTimeout(() => done({ open: false, sans: [] }), timeoutMs);
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate(true);
      const cnRaw = cert.subject?.CN;
      const issuerRaw = cert.issuer?.O ?? cert.issuer?.OU;
      done({
        open: true,
        protocol: socket.getProtocol() ?? undefined,
        cn: typeof cnRaw === 'string' ? cnRaw : Array.isArray(cnRaw) ? cnRaw.join(', ') : undefined,
        issuer: typeof issuerRaw === 'string' ? issuerRaw : Array.isArray(issuerRaw) ? issuerRaw.join(', ') : undefined,
        sans: (cert.subjectaltname ?? '').split(', ').filter((s: string) => s.startsWith('DNS:')).map((s: string) => s.slice(4)),
      });
    });
    socket.once('error', () => done({ open: false, sans: [] }));
    socket.once('timeout', () => done({ open: false, sans: [] }));
  });
}

// ---------- banner-derived OS hint (honest: low confidence, unknown stays unknown) ----------

function osHint(banner: string): string | undefined {
  if (/microsoft-iis|asp\.net|windows-server/i.test(banner)) return 'Windows';
  if (/ubuntu|debian|centos|red\s*hat|fedora/i.test(banner)) return 'Linux/Unix';
  return undefined;
}

const EDGE_INDICATORS = /cloudflare|cloudfront|akamai|fastly|sucuri|envoy|gws/i;

// ---------- Engine ----------

export class HostInfraEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const findings: RawFinding[] = [];
    let hostname: string;
    let targetPort: number;
    try {
      const u = new URL(ctx.target.origin);
      hostname = u.hostname;
      targetPort = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
    } catch {
      return { findings: [], detail: 'target origin is not a valid URL' };
    }
    const asset = hostname;

    // ---- DNS resolution ----
    const res = await resolveHost(hostname);
    if (res.ips.length === 0) {
      return { findings: [], detail: `hostname ${hostname} could not be resolved — infrastructure recon skipped (unknown, not assumed)` };
    }

    const dnsLines: string[] = [];
    for (const ip of res.ips) {
      const ptr = res.ptrs.get(ip);
      dnsLines.push(`${ip}${ptr ? ` (PTR: ${ptr})` : ''}`);
    }
    if (res.cname !== undefined) dnsLines.push(`CNAME → ${res.cname}`);
    findings.push({
      rawId: 'host-resolved',
      title: `Target hostname ${hostname} resolves to ${res.ips.join(', ')}`,
      category: 'A01',
      severity: 'info',
      confidence: 'high',
      status: 'informational',
      asset,
      locator: res.ips[0]!,
      evidence: [{
        kind: 'process',
        command: `DNS lookup ${hostname} (A/AAAA/CNAME/PTR)`,
        observation: dnsLines.join('; '),
      }],
      explanation: 'Infrastructure context for the registered web target: these IPs are where the hostname points. Port scanning scope is anchored to exactly these records — no other hosts are touched.',
      remediation: 'Ensure DNS records only point at infrastructure intended to be reachable.',
      references: [],
    });

    if (ctx.mode !== 'active' || ctx.signal.aborted) {
      return { findings, detail: `resolved ${res.ips.length} IP(s) — passive mode: no port probes sent` };
    }

    // ---- active: bounded port scan of resolved IPs ----
    const ports = [...new Set([targetPort, ...WEB_PORTS, ...INFRA_PORTS])];
    interface OpenPort { port: number; banner?: string; tls?: TlsProbe }
    const byIp = new Map<string, OpenPort[]>();

    for (const ip of res.ips) {
      if (ctx.signal.aborted) break;
      for (let i = 0; i < ports.length; i += PORT_BATCH) {
        if (ctx.signal.aborted) break;
        const batch = ports.slice(i, i + PORT_BATCH);
        const results = await Promise.allSettled(batch.map(async (port) => {
          if (TLS_PORTS.has(port)) {
            const tls = await probeTls(ip, port, PROBE_TIMEOUT_MS);
            return tls.open ? { port, tls } : null;
          }
          const { open, banner } = await scanPort(ip, port, PROBE_TIMEOUT_MS);
          const r: { port: number; banner?: string } | null = open ? { port } : null;
          if (r && banner !== undefined) r.banner = banner;
          return r;
        }));
        for (const r of results) {
          if (r.status !== 'fulfilled' || r.value === null) continue;
          const v = r.value as { port: number; banner?: string; tls?: TlsProbe };
          const list = byIp.get(ip) ?? [];
          const entry: OpenPort = { port: v.port };
          if (v.tls !== undefined) entry.tls = v.tls;
          else if (v.banner !== undefined) entry.banner = v.banner;
          list.push(entry);
          byIp.set(ip, list);
        }
      }
    }

    if (byIp.size === 0) {
      return { findings, detail: `resolved ${res.ips.length} IP(s); ${ports.length} ports probed per IP — none answered (closed or filtered)` };
    }

    let edgeNoted = false;
    for (const [ip, ops] of byIp) {
      const portList = ops.map((o) => `${o.port}${o.tls ? '/tls' : '/tcp'}`).join(', ');
      const evidence: Evidence[] = [];
      for (const op of ops) {
        if (op.tls !== undefined) {
          evidence.push({
            kind: 'process',
            command: `TLS handshake ${ip}:${op.port}`,
            observation: `protocol=${op.tls.protocol ?? 'unknown'} CN=${op.tls.cn ?? 'n/a'} issuer=${op.tls.issuer ?? 'n/a'} SANs=${op.tls.sans.slice(0, 8).join(',') || 'none'}`,
          });
        } else {
          evidence.push({
            kind: 'process',
            command: `TCP connect ${ip}:${op.port}`,
            observation: `Banner: ${(op.banner ?? '').slice(0, 200) || '(no banner)'}`,
          });
        }
      }
      findings.push({
        rawId: 'host-discovered',
        title: `Live host ${ip} — open ports: ${portList}`,
        category: 'A01',
        severity: 'info',
        confidence: 'high',
        status: 'informational',
        asset,
        locator: ip,
        evidence,
        explanation: 'The host answered TCP connection attempts on these ports. Every scanned IP is an A/AAAA record of the registered target hostname.',
        remediation: 'Verify each reachable service is intended to be exposed; restrict the rest at the firewall.',
        references: [],
      });

      for (const op of ops) {
        const bannerStr = op.banner ?? '';
        const fp: ServiceFingerprint = op.tls !== undefined ? { service: 'https' } : fingerprint(op.port, bannerStr);
        const cves = matchServiceCves(fp);

        if (fp.product !== undefined || fp.version !== undefined) {
          findings.push({
            rawId: 'service-version-disclosed',
            title: `Service version disclosed: ${fp.service} ${fp.version ?? ''} on ${ip}:${op.port}`.replace(/\s+/g, ' '),
            category: 'A01',
            severity: 'low',
            confidence: 'high',
            status: 'confirmed',
            asset,
            locator: `${ip}:${op.port}`,
            evidence: [{
              kind: 'process',
              command: `Banner grab ${ip}:${op.port}`,
              observation: `Banner: ${bannerStr.slice(0, 200)}`,
            }],
            explanation: 'The service discloses its product and version in its banner. This is reconnaissance information.',
            remediation: 'Suppress version banners or restrict access to the service.',
            references: [],
          });
        }

        for (const cve of cves) {
          findings.push({
            rawId: 'service-cve',
            title: `${cve.cve}: ${cve.description} — ${fp.service} ${fp.version} on ${ip}:${op.port}`,
            category: 'A03',
            severity: cve.severity,
            confidence: 'medium',
            status: 'probable',
            asset,
            locator: `${ip}:${op.port}`,
            evidence: [{
              kind: 'process',
              command: `CVE match: ${fp.service} ${fp.version} < ${cve.versionBelow}`,
              observation: cve.description,
            }],
            explanation: `The service version (${fp.service} ${fp.version}) falls below the fixed version for ${cve.cve}. Version banners can be inaccurate (backports) — verify before treating as confirmed.`,
            remediation: `Upgrade ${fp.service} to ${cve.versionBelow} or later.`,
            references: [`https://nvd.nist.gov/vuln/detail/${cve.cve}`],
          });
        }

        if (fp.service === 'http' && (op.port === 8080 || op.port === 8443)) {
          findings.push({
            rawId: 'management-interface-exposed',
            title: `Management interface exposed on ${ip}:${op.port}`,
            category: 'A02',
            severity: 'high',
            confidence: 'medium',
            status: 'probable',
            asset,
            locator: `${ip}:${op.port}`,
            evidence: [{
              kind: 'process',
              command: `HTTP probe ${ip}:${op.port}`,
              observation: `HTTP service detected on non-standard port ${op.port} — may be a management interface`,
            }],
            explanation: 'A HTTP service was found on a port commonly used for management interfaces. Verify it is not a Tomcat Manager, JBoss JMX, or similar admin console.',
            remediation: 'Restrict management interfaces to internal networks and require strong authentication.',
            references: [],
          });
        }

        const os = osHint(bannerStr);
        if (os !== undefined) {
          findings.push({
            rawId: 'os-hint',
            title: `OS hint: ${os} on ${ip} (banner-derived, low confidence)`,
            category: 'A01',
            severity: 'info',
            confidence: 'low',
            status: 'informational',
            asset,
            locator: ip,
            evidence: [{
              kind: 'process',
              command: `Banner analysis ${ip}:${op.port}`,
              observation: `Banner suggests ${os}: ${bannerStr.slice(0, 120)}`,
            }],
            explanation: 'Banner strings hint at the operating system family. Banners can be spoofed or proxied — treat as a lead, not a fact.',
            remediation: 'Suppress version banners and platform indicators in service responses.',
            references: [],
          });
        }

        const serverM = /server:\s*([^\r\n]+)/i.exec(bannerStr);
        if (!edgeNoted && serverM?.[1] !== undefined && EDGE_INDICATORS.test(serverM[1])) {
          edgeNoted = true;
          findings.push({
            rawId: 'edge-proxy-detected',
            title: `Target is fronted by an edge proxy (${serverM[1].trim().slice(0, 40)}) — port surface reflects the edge, not the origin`,
            category: 'A01',
            severity: 'info',
            confidence: 'medium',
            status: 'informational',
            asset,
            locator: res.ips[0]!,
            evidence: [{
              kind: 'process',
              command: 'Server header analysis',
              observation: `Server: ${serverM[1].trim().slice(0, 80)}`,
            }],
            explanation: 'The resolved IPs belong to a CDN/edge network. Open ports observed here are the edge\u2019s, and origin infrastructure is not directly reachable — scan results describe the public edge only.',
            remediation: 'No action required; this is context for interpreting the port scan.',
            references: [],
          });
        }
      }
    }

    ctx.log('host infra recon finished', { ips: res.ips.length, openPorts: [...byIp.values()].reduce((n, l) => n + l.length, 0), findings: findings.length });
    return { findings, version: 'builtin', detail: `resolved ${res.ips.length} IP(s), scanned ${ports.length} ports/IP, ${findings.length} finding(s)` };
  }
}
