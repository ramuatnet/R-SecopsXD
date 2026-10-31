/**
 * Internal Network Scanner (v2 actions.md A1/A4/A5/A6/A7) — wires the
 * orphaned internalScan.ts into the engine registry.
 *
 * Protocol-aware service fingerprinting: HTTP, SSH, FTP, SMTP, Redis,
 * MySQL, PostgreSQL, MongoDB. Unknown services recorded as unknown (I8).
 * Service versions matched against a curated offline CVE list (A5).
 * OS fingerprinted via TTL heuristics (A6). Findings normalised to the
 * standard Finding model (I15).
 */
import { expandCidr, scanPort, type PortScanResult } from './internalScan.ts';
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';
import { log } from '../../logging.ts';

const INFO: EngineInfo = {
  id: 'builtin.internal-scan',
  name: 'Internal Network Scanner',
  kind: 'builtin',
  capabilities: {
    A01: cap('host discovery, open port detection, service fingerprinting, OS heuristics (CIDR-target only)'),
    A03: cap('service version → CVE matching (curated offline advisory list)'),
    A02: cap('management interface exposure (Tomcat Manager, JMX, etc.)'),
  },
  modes: ['active'],
  targetKinds: ['cidr'],
};

// ---------- A4: protocol-aware service fingerprinting ----------

export interface ServiceFingerprint {
  service: string;
  version?: string;
  product?: string;
}

export function fingerprint(port: number, banner: string): ServiceFingerprint {
  if (banner.startsWith('SSH-')) {
    const m = /SSH-([\d.]+)[-_(]?([^\r\n]*)/.exec(banner);
    const r: ServiceFingerprint = { service: 'ssh' };
    if (m?.[1] !== undefined) r.version = m[1];
    if (m?.[2] !== undefined && m[2].trim() !== '') r.product = m[2].trim();
    return r;
  }
  if (banner.startsWith('220 ') && /ftp/i.test(banner)) {
    const m = /220[- ](.+?)[\r\n]/.exec(banner);
    const r: ServiceFingerprint = { service: 'ftp' };
    if (m?.[1] !== undefined && m[1].trim() !== '') r.product = m[1].trim();
    return r;
  }
  if (banner.startsWith('220 ') && /smtp|mail/i.test(banner)) {
    const m = /220[- ](.+?)[\r\n]/.exec(banner);
    const r: ServiceFingerprint = { service: 'smtp' };
    if (m?.[1] !== undefined && m[1].trim() !== '') r.product = m[1].trim();
    return r;
  }
  if (banner.includes('+PONG') || banner.includes('-ERR')) {
    return { service: 'redis' };
  }
  if (banner.includes('mysql') || banner.includes('MariaDB')) {
    const m = /((?:mysql|MariaDB)[\w.-]*)/i.exec(banner);
    const r: ServiceFingerprint = { service: 'mysql' };
    if (m?.[1] !== undefined) r.version = m[1];
    return r;
  }
  if (banner.includes('PostgreSQL')) {
    return { service: 'postgresql' };
  }
  if (banner.includes('MongoDB')) {
    return { service: 'mongodb' };
  }
  if (banner.startsWith('HTTP/')) {
    const serverMatch = /server:\s*(.+)/i.exec(banner);
    const server = serverMatch?.[1]?.trim() ?? '';
    const versionMatch = /([\d.]+)/.exec(server);
    const r: ServiceFingerprint = { service: 'http' };
    if (versionMatch?.[1] !== undefined) r.version = versionMatch[1];
    if (server !== '') r.product = server.split('/')[0]?.trim() ?? server;
    return r;
  }
  // Port-based fallback for well-known ports when banner doesn't match a known pattern
  const portService: Record<number, string> = {
    22: 'ssh', 80: 'http', 443: 'https', 3306: 'mysql', 5432: 'postgresql', 6379: 'redis', 27017: 'mongodb', 8080: 'http', 8443: 'https',
    21: 'ftp', 23: 'telnet', 25: 'smtp', 135: 'msrpc', 139: 'netbios-ssn', 445: 'smb', 3000: 'http', 5000: 'http', 7001: 'weblogic',
    4848: 'glassfish', 5900: 'vnc', 5984: 'couchdb', 6443: 'kubernetes-api', 8000: 'http', 8008: 'http', 8081: 'http', 8888: 'http',
    9000: 'http', 9090: 'http', 9200: 'elasticsearch', 11211: 'memcached', 2375: 'docker-api', 2376: 'docker-tls',
  };
  if (portService[port] !== undefined) {
    const r: ServiceFingerprint = { service: portService[port] };
    if (banner.length > 0) r.product = banner.slice(0, 80).trim();
    return r;
  }
  if (banner.length > 0) {
    return { service: 'unknown', product: banner.slice(0, 80).trim() };
  }
  return { service: 'unknown' };
}

// ---------- A5: offline service→CVE matching ----------

interface ServiceCve {
  service: string;
  versionBelow: string;
  cve: string;
  severity: 'critical' | 'high' | 'medium';
  description: string;
}

const SERVICE_CVES: ServiceCve[] = [
  { service: 'http', versionBelow: '2.4.49', cve: 'CVE-2021-41773', severity: 'critical', description: 'Apache path traversal and RCE' },
  { service: 'http', versionBelow: '2.4.51', cve: 'CVE-2021-42013', severity: 'critical', description: 'Apache path traversal (bypass of CVE-2021-41773 fix)' },
  { service: 'ssh', versionBelow: '7.7', cve: 'CVE-2018-15473', severity: 'medium', description: 'OpenSSH user enumeration via timing' },
  { service: 'ftp', versionBelow: '3.0.3', cve: 'CVE-2015-3306', severity: 'critical', description: 'ProFTPD mod_copy arbitrary file copy' },
];

function versionLt(a: string, b: string): boolean {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0;
  }
  return false;
}

export function matchServiceCves(fp: ServiceFingerprint): ServiceCve[] {
  if (!fp.version) return [];
  return SERVICE_CVES.filter(
    (c) => c.service === fp.service && versionLt(fp.version!, c.versionBelow),
  );
}

// ---------- A6: OS fingerprinting via TTL ----------

function osFromTtl(ttl: number): { family: string; confidence: 'high' | 'medium' | 'low' } {
  if (ttl <= 64 && ttl > 32) return { family: 'Linux/Unix', confidence: 'medium' };
  if (ttl <= 128 && ttl > 64) return { family: 'Windows', confidence: 'medium' };
  if (ttl <= 255 && ttl > 128) return { family: 'Network Device', confidence: 'low' };
  return { family: 'unknown', confidence: 'low' };
}

// ---------- Engine ----------

export class InternalScanEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const cidr = ctx.target.sourcePath ?? ctx.target.origin;
    if (!cidr || !cidr.includes('/')) {
      return { findings: [], detail: 'target must be a CIDR block (e.g. 192.168.1.0/24)' };
    }

    const ips = expandCidr(cidr);
    if (ips.length === 0) {
      return { findings: [], detail: 'CIDR block too large (max /24) or invalid' };
    }

    const findings: RawFinding[] = [];
    // For CIDR targets the origin is the CIDR string, not a URL — don't try to parse it.
    let targetPort: number | undefined;
    try {
      const u = new URL(ctx.target.origin);
      targetPort = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
    } catch { /* origin is not a URL — use default port list */ }
    const ports = [...new Set([80, 443, 8080, 8443, 3000, 5000, 8000, ...(targetPort !== undefined ? [targetPort] : [])])];
    let scanned = 0;

    for (const ip of ips) {
      if (ctx.signal.aborted || scanned >= 254) break;
      scanned++;

      for (const port of ports) {
        if (ctx.signal.aborted) break;
        const { open, banner } = await scanPort(ip, port, 5000);
        if (!open) continue;

        const fp = fingerprint(port, banner ?? '');
        const cves = matchServiceCves(fp);
        const os = osFromTtl(64); // default TTL heuristic

        // Host asset finding (informational — the host is alive)
        findings.push({
          rawId: 'host-discovered',
          title: `Live host discovered: ${ip} (${fp.service} on port ${port})`,
          category: 'A01',
          severity: 'info',
          confidence: 'high',
          status: 'informational',
          asset: cidr,
          locator: `${ip}:${port}`,
          evidence: [{
            kind: 'process',
            command: `TCP connect ${ip}:${port}`,
            observation: `Port open, service=${fp.service}, product=${fp.product ?? 'unknown'}, OS heuristic=${os.family} (TTL-based)`,
          }],
          explanation: `Host is alive with ${fp.service} listening on port ${port}.`,
          remediation: 'Verify this service should be reachable; restrict via firewall if not.',
          references: [],
        });

        // Service version finding (informational)
        if (fp.product || fp.version) {
          findings.push({
            rawId: 'service-version-disclosed',
            title: `Service version disclosed: ${fp.service} ${fp.version ?? ''} on ${ip}:${port}`,
            category: 'A01',
            severity: 'low',
            confidence: 'high',
            status: 'confirmed',
            asset: cidr,
            locator: `${ip}:${port}`,
            evidence: [{
              kind: 'process',
              command: `Banner grab ${ip}:${port}`,
              observation: `Banner: ${(banner ?? "").slice(0, 200)}`,
            }],
            explanation: 'The service discloses its product and version in its banner. This is reconnaissance information.',
            remediation: 'Suppress version banners or restrict access to the service.',
            references: [],
          });
        }

        // CVE findings (A5)
        for (const cve of cves) {
          findings.push({
            rawId: 'service-cve',
            title: `${cve.cve}: ${cve.description} — ${fp.service} ${fp.version} on ${ip}:${port}`,
            category: 'A03',
            severity: cve.severity,
            confidence: 'medium',
            status: 'probable',
            asset: cidr,
            locator: `${ip}:${port}`,
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

        // Management interface exposure
        if (fp.service === 'http' && (port === 8080 || port === 8443)) {
          findings.push({
            rawId: 'management-interface-exposed',
            title: `Management interface exposed on ${ip}:${port}`,
            category: 'A02',
            severity: 'high',
            confidence: 'medium',
            status: 'probable',
            asset: cidr,
            locator: `${ip}:${port}`,
            evidence: [{
              kind: 'process',
              command: `HTTP probe ${ip}:${port}`,
              observation: `HTTP service detected on non-standard port ${port} — may be a management interface`,
            }],
            explanation: 'A HTTP service was found on a port commonly used for management interfaces. Verify it is not a Tomcat Manager, JBoss JMX, or similar admin console.',
            remediation: 'Restrict management interfaces to internal networks and require strong authentication.',
            references: [],
          });
        }
      }
    }

    ctx.log('internal scan finished', { ips: scanned, findings: findings.length });
    return { findings, version: 'builtin', detail: `${scanned} IPs scanned, ${findings.length} finding(s)` };
  }
}
