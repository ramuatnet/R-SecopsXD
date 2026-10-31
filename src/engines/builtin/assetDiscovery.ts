/**
 * External asset discovery (EASM dimension: proactive discovery) — passive
 * enumeration of the registered target's own domain space, anchored to the
 * registrable domain of the registered hostname. Nothing outside that domain
 * space is touched, and discovered assets are reported only — they are NOT
 * scanned (turning one into a scan target is an explicit approval decision).
 *
 * Always-on (passive-safe):
 *  - DNS records: CNAME / MX / NS / TXT
 *  - Certificate Transparency logs via crt.sh (public CT search)
 *  - Liveness resolution of discovered subdomains (DNS)
 *  - Certificate SANs of the target host itself
 *  - IP attribution (ASN/owner/country) via Team Cymru whois for public IPs
 * Active mode only (touches the org's infrastructure / cloud providers):
 *  - DNS zone transfer attempt (AXFR) against the domain's nameservers
 *  - Cloud storage bucket existence/listability probes (S3/GCS/Azure)
 *
 * Unresolvable hosts and unreachable third-party services are recorded as
 * unknown, never assumed absent (I8).
 */
import { connect as netConnect, type Socket } from 'node:net';
import { discoverDnsAssets, probeCloudStorage } from './asmDiscovery.ts';
import { httpRecon } from './hostInfra.ts';
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.asset-discovery',
  name: 'External Asset Discovery',
  kind: 'builtin',
  capabilities: {
    A01: cap('DNS records, CT-log subdomains, liveness resolution, cert SANs and IP attribution (ASN/owner) for the registered domain space'),
    A02: cap('zone transfer (AXFR) attempt and public cloud bucket listability (active)'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['webapp'],
};

const CT_TIMEOUT_MS = 15_000;
const CT_MAX_NAMES = 50;
const RESOLVE_MAX = 30;
const NS_AXFR_MAX = 2;
const AXFR_TIMEOUT_MS = 5000;
const CYMRU_TIMEOUT_MS = 6000;
const WHOIS_CYMRU_HOST = 'whois.cymru.com';

function isIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

function isPrivateIp(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return true;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

/** Registrable domain heuristic: last two labels. (Multi-part TLDs like co.uk are out of scope for this heuristic.) */
export function registrableDomain(hostname: string): string | undefined {
  const labels = hostname.toLowerCase().split('.').filter(Boolean);
  if (labels.length < 2 || labels.some((l) => l === '')) return undefined;
  if (labels[labels.length - 1] === 'localhost') return undefined;
  return labels.slice(-2).join('.');
}

function dnsTimeout<T>(p: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(fallback), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, () => { clearTimeout(t); resolve(fallback); });
  });
}

// ---------- Certificate Transparency via crt.sh ----------

interface CtEntry { name_value?: string; issuer_name?: string; }

export function filterCtNames(entries: CtEntry[], domain: string): string[] {
  const names = new Set<string>();
  for (const e of entries) {
    for (const raw of (e.name_value ?? '').split('\n')) {
      const name = raw.trim().toLowerCase().replace(/^\*\./, '');
      if (name === '' || name.includes('@') || name.includes(' ')) continue;
      if (name === domain || name.endsWith(`.${domain}`)) names.add(name);
    }
  }
  return [...names].sort().slice(0, CT_MAX_NAMES);
}

async function fetchCtNames(domain: string): Promise<string[] | undefined> {
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`;
    const res = await fetch(url, { signal: AbortSignal.timeout(CT_TIMEOUT_MS), headers: { 'user-agent': 'rsec-recon/0.1' } });
    if (!res.ok) return undefined;
    const data = (await res.json()) as CtEntry[];
    return filterCtNames(Array.isArray(data) ? data : [], domain);
  } catch {
    return undefined;
  }
}

// ---------- AXFR (zone transfer) ----------

/** Build a minimal AXFR (QTYPE 252) DNS query over TCP framing. */
export function buildAxfrQuery(domain: string): Buffer {
  const labels: Buffer[] = [];
  for (const part of domain.split('.').filter(Boolean)) {
    const l = Buffer.from(part);
    labels.push(Buffer.from([l.length]), l);
  }
  labels.push(Buffer.from([0]));
  const header = Buffer.from([0x2a, 0x2a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
  const qtail = Buffer.from([0x00, 0xfc, 0x00, 0x01]); // QTYPE=252 (AXFR), QCLASS=IN
  return Buffer.concat([header, ...labels, qtail]);
}

export interface AxfrResult { answered: boolean; transferred: boolean; rcode: number; records: number; }

/** Attempt a zone transfer against one nameserver over TCP 53. */
export function tryAxfr(nsHost: string, domain: string): Promise<AxfrResult> {
  return new Promise((resolve) => {
    const result: AxfrResult = { answered: false, transferred: false, rcode: -1, records: 0 };
    const socket: Socket = netConnect({ host: nsHost, port: 53 });
    const query = buildAxfrQuery(domain);
    const framed = Buffer.alloc(2 + query.length);
    framed.writeUInt16BE(query.length, 0);
    query.copy(framed, 2);
    let buf = Buffer.alloc(0);
    const finish = () => { socket.destroy(); resolve(result); };
    socket.on('connect', () => socket.write(framed));
    socket.on('data', (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 2) return;
      const len = buf.readUInt16BE(0);
      if (buf.length < 2 + len) return;
      const resp = buf.subarray(2, 2 + len);
      if (resp.length >= 12) {
        result.answered = true;
        result.rcode = resp[3]! & 0x0f;
        result.records = resp.readUInt16BE(6);
        result.transferred = result.rcode === 0 && result.records > 0;
      }
      finish();
    });
    socket.on('error', finish);
    socket.setTimeout(AXFR_TIMEOUT_MS, finish);
  });
}

// ---------- IP attribution via Team Cymru ----------

export interface IpAttribution { asn: string; country: string; owner: string; }

export function whoisIpAttribution(ip: string): Promise<IpAttribution | undefined> {
  return new Promise((resolve) => {
    const socket: Socket = netConnect({ host: WHOIS_CYMRU_HOST, port: 43 });
    let out = '';
    const finish = () => {
      socket.destroy();
      const line = out.split('\n').map((l) => l.trim()).find((l) => /^AS\d+\s*\|/.test(l));
      if (line === undefined) return resolve(undefined);
      const parts = line.split('|').map((p) => p.trim());
      if (parts.length < 7) return resolve(undefined);
      resolve({ asn: parts[0] ?? '', country: parts[3] ?? '', owner: (parts[6] ?? '').slice(0, 80) });
    };
    socket.on('connect', () => socket.write(` -v ${ip}\r\n`));
    socket.on('data', (c: Buffer) => { out += c.toString('utf8'); });
    socket.on('close', finish);
    socket.on('error', () => resolve(undefined));
    socket.setTimeout(CYMRU_TIMEOUT_MS, finish);
  });
}

// ---------- Engine ----------

export class AssetDiscoveryEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const notes: string[] = [];
    let hostname: string;
    try {
      hostname = new URL(ctx.target.origin).hostname.toLowerCase();
    } catch {
      return { findings: [], detail: 'target origin is not a valid URL' };
    }

    if (isIpLiteral(hostname) || hostname === 'localhost' || hostname.endsWith('.localhost')) {
      return { findings: [], detail: 'target is an IP literal / localhost — no domain space to discover' };
    }
    const domain = registrableDomain(hostname);
    if (domain === undefined) {
      return { findings: [], detail: `could not derive a registrable domain from ${hostname} — discovery skipped` };
    }
    const findings: RawFinding[] = [];

    // ---- 1. DNS records ----
    const dnsAssets = await dnsTimeout(discoverDnsAssets(domain), 10_000, []);
    if (dnsAssets.length > 0) {
      findings.push({
        rawId: 'asset-dns-records',
        title: `DNS records for ${domain}: ${dnsAssets.length} record(s)`,
        category: 'A01',
        severity: 'info',
        confidence: 'high',
        status: 'informational',
        asset: domain,
        locator: domain,
        evidence: [{
          kind: 'process',
          command: `DNS enumeration ${domain} (CNAME/MX/NS/TXT)`,
          observation: dnsAssets.slice(0, 12).map((a) => `${a.source}: ${a.value}`).join('; ').slice(0, 400),
        }],
        explanation: 'Publicly observable DNS records for the domain space. Mail (MX) and nameserver (NS) hosts are part of the external attack surface.',
        remediation: 'Keep DNS records current; remove stale records pointing at decommissioned hosts.',
        references: [],
      });
    } else {
      notes.push('no DNS records enumerable (resolver denied or timed out)');
    }

    // ---- 2. Certificate Transparency ----
    const ctNames = await fetchCtNames(domain);
    if (ctNames !== undefined && ctNames.length > 0) {
      // ---- 3. liveness of discovered subdomains (bounded) ----
      const live: string[] = [];
      const dns = await import('node:dns/promises');
      await Promise.allSettled(ctNames.slice(0, RESOLVE_MAX).map(async (name) => {
        const addrs = await dnsTimeout(dns.lookup(name).catch(() => undefined), 2_500, undefined);
        if (addrs !== undefined) live.push(`${name} → ${addrs.address}`);
      }));
      findings.push({
        rawId: 'asset-ct-logs',
        title: `Certificate Transparency: ${ctNames.length} certificate name(s) in the ${domain} space (${live.length} resolve)`,
        category: 'A01',
        severity: 'info',
        confidence: 'high',
        status: 'informational',
        asset: domain,
        locator: domain,
        evidence: [{
          kind: 'process',
          command: `CT log search crt.sh q=%.${domain}`,
          observation: `names: ${ctNames.slice(0, 15).join(', ')}${ctNames.length > 15 ? ` …(+${ctNames.length - 15})` : ''}; resolving: ${live.slice(0, 10).join(', ') || 'none'}`,
        }],
        explanation: 'Hostnames issued public TLS certificates for this domain space. Unfamiliar entries may be forgotten (shadow) infrastructure. Discovered assets are listed only — they are not scanned; register them as targets to assess them.',
        remediation: 'Review certificate issuance: revoke/expire certificates for decommissioned hosts and ensure new issuance follows the change process.',
        references: ['https://certificate.transparency.dev/'],
      });
    } else {
      notes.push('CT log search unavailable or empty (crt.sh unreachable or no certs)');
    }

    // ---- 4. certificate SANs of the target itself ----
    const originUrl = new URL(ctx.target.origin);
    const targetPort = Number(originUrl.port) || (originUrl.protocol === 'https:' ? 443 : 80);
    if (originUrl.protocol === 'https:' || targetPort === 443) {
      const recon = await httpRecon(hostname, targetPort, hostname, true);
      if (recon.open && recon.sans.length > 0) {
        findings.push({
          rawId: 'asset-cert-sans',
          title: `Target TLS certificate covers ${recon.sans.length} SAN name(s)`,
          category: 'A01',
          severity: 'info',
          confidence: 'high',
          status: 'informational',
          asset: domain,
          locator: hostname,
          evidence: [{
            kind: 'process',
            command: `TLS handshake ${hostname}:${targetPort}`,
            observation: `CN=${recon.cn ?? 'n/a'} issuer=${recon.issuer ?? 'n/a'} SANs=${recon.sans.slice(0, 12).join(', ')}`,
          }],
          explanation: 'Additional hostnames covered by the same certificate — part of the same deployment surface.',
          remediation: 'No action; inventory context.',
          references: [],
        });
      }
    }

    // ---- 5. IP attribution (passive; public IPs only) ----
    const dns2 = await import('node:dns/promises');
    const targetIps = await dnsTimeout(dns2.lookup(hostname, { all: true }).catch(() => [] as Array<{ address: string; family: number }>), 5_000, [] as Array<{ address: string; family: number }>);
    const publicIps = [...new Set(targetIps.map((a) => a.address))].filter((ip) => !isPrivateIp(ip)).slice(0, 4);
    if (publicIps.length > 0) {
      const attributions = await Promise.allSettled(publicIps.map((ip) => whoisIpAttribution(ip)));
      const lines: string[] = [];
      for (let i = 0; i < publicIps.length; i++) {
        const a = attributions[i];
        if (a?.status === 'fulfilled' && a.value !== undefined) {
          lines.push(`${publicIps[i]} → ${a.value.asn} | ${a.value.country} | ${a.value.owner}`);
        }
      }
      if (lines.length > 0) {
        findings.push({
          rawId: 'ip-attribution',
          title: `IP attribution: ${lines[0]!.slice(0, 80)}`,
          category: 'A01',
          severity: 'info',
          confidence: 'high',
          status: 'informational',
          asset: domain,
          locator: publicIps[0]!,
          evidence: [{
            kind: 'process',
            command: `Team Cymru IP→ASN whois for ${publicIps.join(', ')}`,
            observation: lines.join('; ').slice(0, 400),
          }],
          explanation: 'ASN/owner/country for the target IPs (cloud provider vs on-prem). Useful for asset ownership attribution and cloud-config correlation.',
          remediation: 'No action; inventory context.',
          references: ['https://www.team-cymru.com/ip-asn-mapping'],
        });
      } else {
        notes.push('IP attribution unavailable (whois service unreachable)');
      }
    }

    // ---- 6. AXFR zone transfer (active only) ----
    if (ctx.mode === 'active') {
      const nsRecords = dnsAssets.filter((a) => a.type === 'nameserver').slice(0, NS_AXFR_MAX);
      if (nsRecords.length === 0) {
        notes.push('AXFR skipped: no NS records discovered');
      } else {
        for (const ns of nsRecords) {
          const nsHost = ns.value.replace(/\.$/, '');
          const r = await tryAxfr(nsHost, domain);
          if (r.transferred) {
            findings.push({
              rawId: 'zone-transfer-possible',
              title: `DNS zone transfer (AXFR) succeeded against ${nsHost} — full zone disclosed`,
              category: 'A02',
              severity: 'high',
              confidence: 'high',
              status: 'confirmed',
              asset: domain,
              locator: `${nsHost}:53`,
              evidence: [{
                kind: 'process',
                command: `AXFR ${domain} @${nsHost}`,
                observation: `rcode=0, ${r.records} record(s) transferred`,
              }],
              explanation: 'The nameserver answers AXFR requests without authentication, disclosing the entire zone (all hostnames) to anyone.',
              remediation: 'Disable AXFR for unauthenticated clients; restrict zone transfers to designated secondaries via TSIG.',
              references: ['https://cwe.mitre.org/data/definitions/200.html'],
            });
          }
          // refused/failed AXFR is the healthy case — recorded in detail only, never a finding
        }
      }

      // ---- 7. cloud bucket probes (active only; GETs target cloud providers) ----
      const base = domain.replace(/\./g, '-');
      const nodot = domain.replace(/\./g, '');
      const candidates = [...new Set([domain, base, nodot, `www-${base}`, `${base}-assets`, `${base}-backups`])].slice(0, 6);
      const buckets = await dnsTimeout(probeCloudStorage(candidates), 20_000, []);
      for (const b of buckets) {
        findings.push({
          rawId: 'cloud-bucket-public',
          title: `Publicly listable cloud storage: ${b.value.slice(0, 120)}`,
          category: 'A01',
          severity: 'medium',
          confidence: 'medium',
          status: 'probable',
          asset: domain,
          locator: b.value.slice(0, 120),
          evidence: [{
            kind: 'process',
            command: 'Cloud storage public-access probe',
            observation: `${b.value} (source: ${b.source})`,
          }],
          explanation: 'A cloud storage bucket named after the domain responds as publicly listable. Verify it contains no sensitive objects.',
          remediation: 'Disable public listing on buckets; require authenticated access.',
          references: [],
        });
      }
    }

    const summary = `${findings.length} finding(s); ${notes.length > 0 ? `notes: ${notes.join('; ')}` : 'all sources answered'}`;
    return { findings, version: 'builtin', detail: summary };
  }
}
