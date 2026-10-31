/**
 * Host infrastructure reconnaissance (context-based) — runs as part of a
 * webapp scan. The registered URL's hostname is resolved (nslookup-equivalent)
 * and the resolved IPs are port-scanned, service-fingerprinted and matched
 * against the offline CVE list. No separate CIDR target registration is
 * needed: scan scope is anchored to the target's own DNS records.
 *
 * Passive mode: DNS resolution only (no packets to the host).
 * Active mode: DNS + bounded TCP port scan (~35 ports) + TLS probe
 * (certificate + HTTP recon) + tech-stack/WAF signature identification +
 * favicon hash + fingerprint + CVE.
 *
 * Safety: only IPs the registered target's hostname resolves to are scanned
 * (max 4, IPv4 first); bounded port list; honors ctx.signal; unresolvable
 * hostnames produce no findings (unknown is never assumed — I8).
 */
import { connect as netConnect, type Socket } from 'node:net';
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
    A01: cap("DNS resolution, live host discovery, open-port mapping and tech-stack/WAF identification of the registered target's own infrastructure"),
    A02: cap('management interface / admin console exposure on non-standard ports (product-identified)'),
    A03: cap('service version → CVE matching on scanned infrastructure services (offline advisory list)'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

// ---------- port universe (bounded, service-annotated) ----------

const WEB_PORTS = [80, 443, 8080, 8443, 8000, 8008, 8081, 5000, 3000, 8888, 9000, 9090, 9200, 7001, 4848, 6443, 2375, 2376, 5984];
const INFRA_PORTS = [22, 21, 23, 25, 135, 139, 445, 3389, 3306, 5432, 6379, 27017, 11211, 5900];
const TLS_PORTS = new Set([443, 8443, 2376, 6443]);
const HTTP_PORTS = new Set([80, 8080, 8443, 8000, 8008, 8081, 5000, 3000, 8888, 9000, 9090, 9200, 7001, 4848, 5984]);
const MGMT_PORTS = new Set([8080, 8443, 9000, 4848, 7001, 6443, 2375, 2376, 11211]);

// A1 (newtask): port exposure classes. Findings are emitted PER PORT —
// info for normal web ports, medium for risky-by-default app/dev ports,
// high for databases / remote access / cluster APIs reachable at the edge.
const HIGH_PORTS = new Set([21, 23, 135, 139, 445, 3389, 5900, 2375, 2376, 3306, 5432, 6379, 6443, 9200, 11211, 27017, 5984]);
const MEDIUM_PORTS = new Set([3000, 5000, 7001, 8000, 8008, 8080, 8081, 8888, 9000, 9090]);

export function portSeverity(port: number): 'info' | 'medium' | 'high' {
  if (HIGH_PORTS.has(port)) return 'high';
  if (MEDIUM_PORTS.has(port)) return 'medium';
  return 'info';
}
const MAX_IPS = 4;
const PORT_BATCH = 40;
const PROBE_TIMEOUT_MS = 3000;
const RECON_TIMEOUT_MS = 6000;
const RECON_BODY_CAP = 32 * 1024;
const FAVICON_CAP = 64 * 1024;

// ---------- DNS resolution (nslookup-equivalent, passive-safe) ----------

interface Resolution {
  ips: string[];
  cname?: string | undefined;
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
    (await import('node:dns/promises')).lookup(hostname, { all: true }).catch(() => [] as Array<{ address: string; family: number }>),
    5_000,
    [] as Array<{ address: string; family: number }>,
  );
  const v4 = addrs.filter((a) => a.family === 4).map((a) => a.address);
  const v6 = addrs.filter((a) => a.family === 6).map((a) => a.address);
  const cname = await dnsTimeout((await import('node:dns/promises')).resolveCname(hostname).then((r) => r[0]), 3_000, undefined);
  const ips = [...new Set([...v4, ...v6])].slice(0, MAX_IPS);
  await Promise.allSettled(ips.map(async (ip) => {
    const ptr = await dnsTimeout((await import('node:dns/promises')).reverse(ip).then((r) => r[0]), 2_000, undefined);
    if (ptr) ptrs.set(ip, ptr);
  }));
  const r: Resolution = { ips, ptrs };
  if (cname !== undefined) r.cname = cname;
  return r;
}

// ---------- TLS probe + HTTP recon in one connection ----------

interface HttpRecon {
  open: boolean;
  protocol?: string | undefined;
  cn?: string | undefined;
  issuer?: string | undefined;
  sans: string[];
  isHttp: boolean;
  status: number;
  headers: Record<string, string>;
  body: string;
}

function parseHttpResponse(raw: string): { isHttp: boolean; status: number; headers: Record<string, string>; body: string } {
  const idx = raw.indexOf('\r\n\r\n');
  const head = idx >= 0 ? raw.slice(0, idx) : raw;
  const body = idx >= 0 ? raw.slice(idx + 4) : '';
  const lines = head.split('\r\n');
  const statusLine = lines[0] ?? '';
  const sm = /^HTTP\/[\d.]+\s+(\d{3})/.exec(statusLine);
  if (!sm) return { isHttp: false, status: 0, headers: {}, body: '' };
  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    const c = line.indexOf(':');
    if (c > 0) headers[line.slice(0, c).trim().toLowerCase()] = line.slice(c + 1).trim();
  }
  return { isHttp: true, status: Number(sm[1]), headers, body };
}

const HTTP_PROBE_REQUEST = (host: string, path: string): string =>
  `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: rsec-recon/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n`;

function collect(sock: Socket, capBytes: number, timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    let settled = false;
    const finish = () => {
      if (!settled) { settled = true; sock.destroy(); resolve(data); }
    };
    sock.on('data', (chunk: Buffer) => {
      data += chunk.toString('latin1');
      if (data.length >= capBytes) finish();
    });
    sock.on('close', finish);
    sock.on('error', finish);
    setTimeout(finish, timeoutMs);
  });
}

/**
 * One connection per port: TLS handshake (cert details) + HTTP GET /
 * (headers + bounded body). For plain ports, plain socket.
 */
export function httpRecon(host: string, port: number, hostname: string, useTls: boolean): Promise<HttpRecon> {
  return new Promise((resolve) => {
    const req = HTTP_PROBE_REQUEST(hostname, '/');
    const finishTls = (socket: TLSSocket) => {
      const cert = socket.getPeerCertificate(true);
      collect(socket, RECON_BODY_CAP + 4096, RECON_TIMEOUT_MS).then((raw) => {
        const parsed = parseHttpResponse(raw);
        resolve({
          open: true,
          protocol: socket.getProtocol() ?? undefined,
          cn: typeof cert.subject?.CN === 'string' ? cert.subject.CN : Array.isArray(cert.subject?.CN) ? cert.subject.CN.join(', ') : undefined,
          issuer: typeof cert.issuer?.O === 'string' ? cert.issuer.O : Array.isArray(cert.issuer?.O) ? cert.issuer.O.join(', ') : undefined,
          sans: (cert.subjectaltname ?? '').split(', ').filter((s: string) => s.startsWith('DNS:')).map((s: string) => s.slice(4)),
          isHttp: parsed.isHttp,
          status: parsed.status,
          headers: parsed.headers,
          body: parsed.body,
        });
      });
    };
    if (useTls) {
      const socket: TLSSocket = tlsConnect({ host, port, servername: hostname, rejectUnauthorized: false });
      let settled = false;
      const fail = () => { if (!settled) { settled = true; socket.destroy(); resolve({ open: false, sans: [], isHttp: false, status: 0, headers: {}, body: '' }); } };
      socket.once('secureConnect', () => {
        settled = true;
        finishTls(socket);
      });
      socket.once('error', fail);
      socket.setTimeout(RECON_TIMEOUT_MS, fail);
    } else {
      const socket: Socket = netConnect({ host, port });
      let settled = false;
      const fail = () => { if (!settled) { settled = true; socket.destroy(); resolve({ open: false, sans: [], isHttp: false, status: 0, headers: {}, body: '' }); } };
      socket.on('connect', () => {
        if (!settled) {
          settled = true;
          socket.write(req);
          collect(socket, RECON_BODY_CAP + 4096, RECON_TIMEOUT_MS).then((raw) => {
            const parsed = parseHttpResponse(raw);
            // A SYN-ACK with zero response bytes is NOT evidence of an open
            // port — port-forwarding middleboxes accept every connect. Only
            // an actual protocol answer (HTTP or any banner bytes) counts.
            if (!parsed.isHttp && raw.trim() === '') {
              resolve({ open: false, sans: [], isHttp: false, status: 0, headers: {}, body: '' });
              return;
            }
            resolve({ open: true, sans: [], isHttp: parsed.isHttp, status: parsed.status, headers: parsed.headers, body: parsed.body });
          });
        }
      });
      socket.on('error', fail);
      // Filtered ports never connect or error — the timeout must resolve the promise.
      socket.setTimeout(RECON_TIMEOUT_MS, fail);
    }
  });
}

/** Favicon fetch + murmur3 hash (shodan-style favicon3 lookup value). */
export function fetchFaviconHash(host: string, port: number, hostname: string, useTls: boolean): Promise<string | undefined> {
  return new Promise((resolve) => {
    const req = HTTP_PROBE_REQUEST(hostname, '/favicon.ico');
    const finish = (raw: string) => {
      const idx = raw.indexOf('\r\n\r\n');
      const body = idx >= 0 ? raw.slice(idx + 4) : '';
      // Only hash an actual favicon — an HTML 404 page would produce a meaningless hash.
      const trimmed = body.trimStart();
      const isHtml = /^<(!doctype|html|\?xml)/i.test(trimmed);
      const clean = body.length > 4 && !isHtml ? body.slice(0, FAVICON_CAP) : undefined;
      resolve(clean !== undefined ? murmur3Hex(clean) : undefined);
    };
    if (useTls) {
      const socket: TLSSocket = tlsConnect({ host, port, servername: hostname, rejectUnauthorized: false });
      socket.once('secureConnect', () => socket.write(req));
      collect(socket, FAVICON_CAP + 4096, RECON_TIMEOUT_MS).then((raw) => { socket.destroy(); finish(raw); });
      socket.once('error', () => resolve(undefined));
    } else {
      const socket: Socket = netConnect({ host, port });
      socket.on('connect', () => socket.write(req));
      collect(socket, FAVICON_CAP + 4096, RECON_TIMEOUT_MS).then((raw) => { socket.destroy(); finish(raw); });
      socket.once('error', () => resolve(undefined));
      socket.setTimeout(RECON_TIMEOUT_MS, () => socket.destroy());
    }
  });
}

// ---------- murmur3 x86_32 (shodan favicon-hash compatible) ----------

export function murmur3Hex(input: string): string {
  const data = Buffer.from(input, 'latin1');
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  let h1 = 0;
  const rounded = Math.floor(data.length / 4);
  const read32 = (i: number): number => data.readUInt32LE(i * 4);
  const rotl = (x: number, r: number): number => ((x << r) | (x >>> (32 - r))) >>> 0;
  const mix = (k1: number): void => {
    h1 = (h1 ^ Math.imul(rotl(Math.imul(k1, c1) >>> 0, 15), c2)) >>> 0;
    h1 = ((h1 << 13) | (h1 >>> 19)) >>> 0;
    h1 = (((Math.imul(h1, 5) >>> 0) + 0xe6546b64) >>> 0);
  };
  for (let i = 0; i < rounded; i++) mix(read32(i));
  const tail = data.slice(rounded * 4);
  let k1 = 0;
  if (tail.length >= 3) k1 ^= tail[2]! << 16;
  if (tail.length >= 2) k1 ^= tail[1]! << 8;
  if (tail.length >= 1) {
    k1 ^= tail[0]!;
    h1 = (h1 ^ Math.imul(rotl(Math.imul(k1, c1) >>> 0, 15), c2)) >>> 0;
  }
  h1 = (h1 ^ data.length) >>> 0;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b) >>> 0;
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35) >>> 0;
  h1 ^= h1 >>> 16;
  return (h1 >>> 0).toString(16).padStart(8, '0');
}

// ---------- tech-stack / WAF / CDN signatures ----------

const EDGE_HEADER_SIGS: Array<[RegExp, string]> = [
  [/^cf-ray$/i, 'Cloudflare (CDN/WAF)'],
  [/^cf-cache-status$/i, 'Cloudflare (CDN/WAF)'],
  [/^x-amz-cf-/i, 'AWS CloudFront (CDN)'],
  [/^x-akamai-/i, 'Akamai (CDN/WAF)'],
  [/^x-sucuri-id$/i, 'Sucuri (WAF)'],
  [/^x-vercel-id$/i, 'Vercel (edge)'],
  [/^x-fastly-/i, 'Fastly (CDN)'],
  [/^x-msedge-ref$/i, 'Azure Front Door (edge)'],
  [/^x-github-request-id$/i, 'GitHub Pages'],
  [/^x-litespeed-cache$/i, 'LiteSpeed (server/CDN)'],
];

interface TechSig {
  re: RegExp;
  product: string;
  note?: string | undefined;
}

const TECH_SIGNATURES: TechSig[] = [
  { re: /^x-jenkins:\s*(.+)$/im, product: 'Jenkins', note: 'CI/CD controller — high-value target, must not be publicly writable' },
  { re: /<title>[^<]*Grafana/i, product: 'Grafana', note: 'dashboard/login exposed' },
  { re: /<title>[^<]*Jenkins/i, product: 'Jenkins', note: 'CI/CD controller' },
  { re: /Apache Tomcat\/([\d.]+)/i, product: 'Apache Tomcat' },
  { re: /Kubernetes Dashboard/i, product: 'Kubernetes Dashboard', note: 'cluster control plane UI' },
  { re: /"kind"\s*:\s*"Status"[\s\S]{0,400}Forbidden/, product: 'Kubernetes API (unauth)', note: 'API server answers unauthenticated requests' },
  { re: /You Know, for Search/i, product: 'Elasticsearch', note: 'HTTP API reachable' },
  { re: /phpMyAdmin/i, product: 'phpMyAdmin', note: 'database admin UI exposed' },
  { re: /WebLogic/i, product: 'Oracle WebLogic' },
  { re: /GlassFish/i, product: 'GlassFish' },
  { re: /Kibana/i, product: 'Kibana' },
  { re: /SonarQube/i, product: 'SonarQube' },
  { re: /Powered by Jetty/i, product: 'Jetty' },
  { re: /MinIO/i, product: 'MinIO console' },
  { re: /Welcome to nginx/i, product: 'nginx default page', note: 'default landing page — deployment not customized' },
  { re: /Apache2 Default Page|<title>Apache2/i, product: 'Apache default page', note: 'default landing page — deployment not customized' },
  { re: /<title>IIS Windows Server/i, product: 'IIS default page', note: 'default landing page — deployment not customized' },
];

// ---------- interception detection (middleboxes that answer every port) ----------

const INTERCEPTION_MIN_PORTS = 5;

interface InterceptionInput { port: number; recon?: HttpRecon; banner?: string; }

/**
 * Some gateways SYN-ACK every port and answer HTTP (block pages) uniformly.
 * If >=5 probed ports return the exact same response signature, those are
 * interception artifacts, not individual services — suppress them and report
 * the interference itself. Real distinct services never share one response.
 */
export function detectInterception(
  ops: InterceptionInput[],
): { suppressed: Set<number>; sample: string | undefined } {
  const bySig = new Map<string, InterceptionInput[]>();
  for (const op of ops) {
    const sig = op.recon !== undefined && op.recon.isHttp
      ? `http:${op.recon.status}:${op.recon.body.slice(0, 400)}`
      : `banner:${(op.recon !== undefined ? JSON.stringify(op.recon.headers) : (op.banner ?? '')).slice(0, 400)}`;
    const list = bySig.get(sig) ?? [];
    list.push(op);
    bySig.set(sig, list);
  }
  const suppressed = new Set<number>();
  let sample: string | undefined;
  for (const group of bySig.values()) {
    if (group.length >= INTERCEPTION_MIN_PORTS) {
      for (const op of group) suppressed.add(op.port);
      if (sample === undefined) {
        const g0 = group[0]!;
        sample = g0.recon !== undefined && g0.recon.isHttp
          ? `HTTP ${g0.recon.status} body: ${g0.recon.body.slice(0, 120).replace(/\s+/g, ' ')}`
          : `banner: ${(g0.banner ?? '(uniform non-HTTP answer)').slice(0, 120)}`;
      }
    }
  }
  return { suppressed, sample };
}

function osHint(banner: string): string | undefined {
  if (/microsoft-iis|asp\.net|windows-server/i.test(banner)) return 'Windows';
  if (/ubuntu|debian|centos|red\s*hat|fedora/i.test(banner)) return 'Linux/Unix';
  return undefined;
}

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
      locator: hostname,
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
    interface OpenPort { port: number; banner?: string; recon?: HttpRecon }
    const byIp = new Map<string, OpenPort[]>();

    for (const ip of res.ips) {
      if (ctx.signal.aborted) break;
      for (let i = 0; i < ports.length; i += PORT_BATCH) {
        if (ctx.signal.aborted) break;
        const batch = ports.slice(i, i + PORT_BATCH);
        const results = await Promise.allSettled(batch.map(async (port) => {
          if (TLS_PORTS.has(port) || HTTP_PORTS.has(port) || port === targetPort) {
            // one connection: TLS handshake (if TLS) + GET / recon
            const recon = await httpRecon(ip, port, hostname, TLS_PORTS.has(port));
            return recon.open ? { port, recon } : null;
          }
          const { open, banner } = await scanPort(ip, port, PROBE_TIMEOUT_MS);
          const r: { port: number; banner?: string } | null = open ? { port } : null;
          if (r && banner !== undefined) r.banner = banner;
          return r;
        }));
        for (const r of results) {
          if (r.status !== 'fulfilled' || r.value === null) continue;
          const v = r.value as { port: number; banner?: string; recon?: HttpRecon };
          const list = byIp.get(ip) ?? [];
          const entry: OpenPort = { port: v.port };
          if (v.recon !== undefined) entry.recon = v.recon;
          else if (v.banner !== undefined) entry.banner = v.banner;
          list.push(entry);
          byIp.set(ip, list);
        }
      }
    }

    if (byIp.size === 0) {
      return { findings, detail: `resolved ${res.ips.length} IP(s); ${ports.length} ports probed per IP — none answered (closed or filtered)` };
    }

    // Suppression: identical answers across many ports = middlebox, not services.
    let suppressedCount = 0;
    let interferenceSample: string | undefined;
    for (const [ip, ops] of byIp) {
      const { suppressed, sample } = detectInterception(ops);
      if (suppressed.size === 0) continue;
      suppressedCount += suppressed.size;
      interferenceSample = interferenceSample ?? sample;
      byIp.set(ip, ops.filter((op) => !suppressed.has(op.port)));
      if (byIp.get(ip)!.length === 0) byIp.delete(ip);
    }
    if (suppressedCount > 0) {
      findings.push({
        rawId: 'port-scan-interference',
        title: `Port-scan interference: ${suppressedCount} port(s) returned an identical response — middlebox answers for the whole set, individual services not confirmed`,
        category: 'A01',
        severity: 'info',
        confidence: 'medium',
        status: 'informational',
        asset,
        locator: res.ips[0]!,
        evidence: [{
          kind: 'process',
          command: 'Cross-port response comparison',
          observation: `${suppressedCount} probed ports share one response signature: ${interferenceSample ?? '(uniform answer)'}. A gateway/DPI middlebox is answering for ports it does not forward; they are treated as not confirmed rather than open.`,
        }],
        explanation: 'A middlebox SYN-ACKs (and answers) every probed port. Treating those as open ports would flood the report with false positives; the uniform answer itself indicates filtering/monitoring in front of the host.',
        remediation: 'No direct action; interpret port results accordingly. Re-verify from a different network path if confirmation is required.',
        references: [],
      });
    }

    if (byIp.size === 0) {
      return { findings, detail: `resolved ${res.ips.length} IP(s); ${ports.length} ports probed — ${suppressedCount} suppressed as middlebox interception, no confirmed services` };
    }

    let edgeNoted = false;
    for (const [ip, ops] of byIp) {
      const portList = ops.map((o) => `${o.port}${o.recon?.protocol !== undefined ? '/tls' : 'tcp'}`).join(', ');
      const evidence: Evidence[] = [];
      for (const op of ops) {
        if (op.recon !== undefined && op.recon.protocol !== undefined) {
          evidence.push({
            kind: 'process',
            command: `TLS handshake ${ip}:${op.port}`,
            observation: `protocol=${op.recon.protocol} CN=${op.recon.cn ?? 'n/a'} issuer=${op.recon.issuer ?? 'n/a'} SANs=${op.recon.sans.slice(0, 8).join(',') || 'none'} HTTP status=${op.recon.isHttp ? op.recon.status : 'non-http'}`,
          });
        } else {
          const bannerStr = op.recon?.isHttp ? `HTTP ${op.recon.status}` : (op.banner ?? '(no banner)');
          evidence.push({
            kind: 'process',
            command: `TCP connect ${ip}:${op.port}`,
            observation: `Banner: ${bannerStr.slice(0, 200)}`,
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
        // A1: per-port finding with exposure-class severity — open ports must
        // surface as first-class results, not only inside the host summary.
        const sev = portSeverity(op.port);
        const portSvc = op.recon !== undefined && op.recon.isHttp
          ? `HTTP ${op.recon.status}`
          : (op.banner ?? '').split('\r\n')[0]?.slice(0, 60) || 'tcp';
        findings.push({
          rawId: 'port-open',
          title: `Port ${op.port} open on ${ip} (${portSvc})`,
          category: 'A01',
          severity: sev,
          confidence: 'high',
          status: 'confirmed',
          asset,
          locator: `${ip}:${op.port}`,
          evidence: [{
            kind: 'process',
            command: `TCP connect ${ip}:${op.port}`,
            observation: `Port answers. Exposure class: ${sev}${HIGH_PORTS.has(op.port) ? ' (database/remote-access/cluster API reachable at the edge)' : MEDIUM_PORTS.has(op.port) ? ' (risky-by-default app/dev port)' : ''}`,
          }],
          explanation:
            sev === 'high'
              ? 'This port exposes a service that should normally never be reachable from the public internet (database, remote access, message queue or cluster API). Its presence at the edge is itself the finding — even if authentication currently holds.'
              : sev === 'medium'
                ? 'This port commonly hosts development servers, alternate app instances or admin tooling. Confirm the service is intended to be public and hardened.'
                : 'Standard web port reachable at the edge. Expected for a public site; review only in combination with what answers on it.',
          remediation:
            sev === 'high'
              ? 'Restrict this port at the firewall/security group to known source ranges (VPN/bastion). If it must stay reachable, put it behind authenticated proxies and alert on new bindings.'
              : 'Verify the service on this port is intended and up to date; suppress version banners.',
          references: [],
        });

        const bannerStr = op.banner ?? '';
        const fp: ServiceFingerprint = op.recon !== undefined && op.recon.protocol !== undefined
          ? { service: 'https' }
          : fingerprint(op.port, bannerStr || (op.recon?.isHttp ? 'HTTP/' : ''));
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

        // ---- deep HTTP recon findings ----
        if (op.recon !== undefined && op.recon.isHttp) {
          const r = op.recon;
          const techHits: string[] = [];
          // header-derived products
          if (r.headers['server'] !== undefined) techHits.push(`Server: ${r.headers['server'].slice(0, 80)}`);
          if (r.headers['x-powered-by'] !== undefined) techHits.push(`X-Powered-By: ${r.headers['x-powered-by'].slice(0, 80)}`);
          for (const sig of TECH_SIGNATURES) {
            const m = sig.re.exec(r.headers['x-jenkins'] !== undefined ? `${r.body}\nx-jenkins: ${r.headers['x-jenkins']}` : r.body);
            if (m !== null && !techHits.some((t) => t.startsWith(sig.product))) {
              techHits.push(`${sig.product}${m[1] ? ` ${m[1].trim().slice(0, 40)}` : ''}${sig.note !== undefined ? ` (${sig.note})` : ''}`);
            }
          }
          // favicon hash (once per port)
          if (ctx.signal.aborted === false) {
            const fh = await fetchFaviconHash(ip, op.port, hostname, op.recon.protocol !== undefined);
            if (fh !== undefined) techHits.push(`favicon mmh3=${fh} (look up on public favicon-hash indexes to correlate)`);
          }
          // WAF/CDN from response headers
          const edgeProducts = new Set<string>();
          for (const [re, product] of EDGE_HEADER_SIGS) {
            for (const h of Object.keys(r.headers)) {
              if (re.test(h)) edgeProducts.add(product);
            }
          }
          const serverHeader = r.headers['server'] ?? '';
          if (/cloudflare|cloudfront|akamai|fastly|sucuri|envoy|gws/i.test(serverHeader)) edgeProducts.add(serverHeader.trim().slice(0, 40));

          if (techHits.length > 0) {
            findings.push({
              rawId: 'service-identified',
              title: `Service identified on ${ip}:${op.port}: ${techHits.slice(0, 3).join('; ').slice(0, 120)}`,
              category: 'A01',
              severity: 'info',
              confidence: 'high',
              status: 'confirmed',
              asset,
              locator: `${ip}:${op.port}`,
              evidence: [{
                kind: 'process',
                command: `HTTP recon GET / ${ip}:${op.port}`,
                observation: `HTTP ${r.status}; ${techHits.join('; ').slice(0, 400)}`,
              }],
              explanation: 'Technology stack identified from response headers, body signatures and favicon hash. This narrows CVE hunting and shows accidental exposure of admin/dev tooling.',
              remediation: 'Remove or restrict tooling that should not face the internet; suppress version-revealing headers.',
              references: [],
            });
          }

          if (!edgeNoted && edgeProducts.size > 0) {
            edgeNoted = true;
            findings.push({
              rawId: 'edge-proxy-detected',
              title: `Target fronted by edge/WAF: ${[...edgeProducts].slice(0, 2).join(', ')} — port surface reflects the edge, not the origin`,
              category: 'A01',
              severity: 'info',
              confidence: 'high',
              status: 'confirmed',
              asset,
              locator: res.ips[0]!,
              evidence: [{
                kind: 'process',
                command: 'Response header analysis',
                observation: `edge indicators: ${[...edgeProducts].join(', ')}`,
              }],
              explanation: 'CDN/WAF edge signatures were detected in response headers. Open ports observed here belong to the edge network; origin infrastructure is not directly reachable — scan results describe the public edge only.',
              remediation: 'No action required; context for interpreting the port scan.',
              references: [],
            });
          }

          const adminProduct = techHits.find((t) =>
            /jenkins|grafana|kubernetes|kibana|phpmyadmin|sonarqube|weblogic|glassfish|minio|tomcat/i.test(t));
          if (MGMT_PORTS.has(op.port) || adminProduct !== undefined) {
            findings.push({
              rawId: 'management-interface-exposed',
              title: `Management interface exposed on ${ip}:${op.port}${adminProduct !== undefined ? ` — ${adminProduct.slice(0, 80)}` : ''}`,
              category: 'A02',
              severity: 'high',
              confidence: 'medium',
              status: 'probable',
              asset,
              locator: `${ip}:${op.port}`,
              evidence: [{
                kind: 'process',
                command: `HTTP probe ${ip}:${op.port}`,
                observation: `HTTP ${op.recon.status} on port ${op.port}${adminProduct !== undefined ? `; signature: ${adminProduct}` : ' — port commonly used for management interfaces'}`,
              }],
              explanation: 'A HTTP service was found on a management-typical port or matched an admin-console signature (CI/CD, dashboards, cluster APIs, DB UIs). Verify it is intended to be publicly reachable.',
              remediation: 'Restrict management interfaces to internal networks/VPN and require strong authentication + MFA.',
              references: [],
            });
          }
        } else if (fp.product !== undefined && /tomcat|weblogic|glassfish/i.test(fp.product)) {
          findings.push({
            rawId: 'management-interface-exposed',
            title: `Application server banner exposed on ${ip}:${op.port} — ${fp.product}`,
            category: 'A02',
            severity: 'high',
            confidence: 'medium',
            status: 'probable',
            asset,
            locator: `${ip}:${op.port}`,
            evidence: [{
              kind: 'process',
              command: `Banner grab ${ip}:${op.port}`,
              observation: `Banner: ${bannerStr.slice(0, 200)}`,
            }],
            explanation: 'An application-server banner was identified on this port. Such consoles/deploys frequently expose management endpoints.',
            remediation: 'Restrict management interfaces to internal networks and require strong authentication.',
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
      }
    }

    ctx.log('host infra recon finished', { ips: res.ips.length, openPorts: [...byIp.values()].reduce((n, l) => n + l.length, 0), findings: findings.length });
    return { findings, version: 'builtin', detail: `resolved ${res.ips.length} IP(s), scanned ${ports.length} ports/IP, ${findings.length} finding(s)` };
  }
}
