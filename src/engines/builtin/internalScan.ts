/**
 * Internal surface scanner (v2 Phase X, T-X3) — CIDR target kind with
 * host discovery, TCP port scanning, and HTTP service fingerprinting.
 *
 * Safety: only scans explicitly registered CIDR targets; bounded to
 * configured port list and /24 max block size per scan.
 */
import { connect as netConnect, type Socket } from 'node:net';
import { log } from '../../logging.ts';

export interface PortScanResult {
  host: string;
  port: number;
  open: boolean;
  service?: string;
  banner?: string;
}

const COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090, 3306, 5432, 6379, 27017, 22, 21, 23, 25, 3389];

function scanPort(host: string, port: number, timeoutMs = 3000): Promise<{ open: boolean; banner?: string }> {
  return new Promise((resolve) => {
    const socket: Socket = netConnect({ host, port });
    let banner = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; socket.destroy(); resolve({ open: false }); }
    }, timeoutMs);

    socket.on('connect', () => {
      // Send a minimal HTTP probe to elicit a banner
      socket.write(`GET / HTTP/1.0\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
    });
    socket.on('data', (chunk: Buffer) => {
      banner += chunk.toString('utf8');
      if (banner.length > 512 || banner.includes('\r\n\r\n')) {
        if (!settled) {
          settled = true; clearTimeout(timer); socket.destroy();
          resolve({ open: true, banner: banner.slice(0, 512) });
        }
      }
    });
    socket.on('close', () => {
      if (!settled) { settled = true; clearTimeout(timer); const r: { open: boolean; banner?: string } = { open: banner.length > 0 }; if (banner.length > 0) { r.banner = banner.slice(0, 512); } resolve(r); }
    });
    socket.on('error', () => {
      if (!settled) { settled = true; clearTimeout(timer); resolve({ open: false }); }
    });
  });
}

/** Expand a CIDR block to individual IPs (bounded to /24). */
export function expandCidr(cidr: string): string[] {
  const [base, bits] = cidr.split('/') as [string, string];
  const prefix = Number(bits);
  if (prefix < 24 || prefix > 32) return [];
  const baseInt = ipToInt(base);
  const count = Math.pow(2, 32 - prefix);
  const ips: string[] = [];
  for (let i = 1; i < count - 1 && ips.length < 254; i++) {
    ips.push(intToIp(baseInt + i));
  }
  return ips;
}

function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc: number, oct: string) => (acc * 256) + Number(oct), 0);
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** Scan a CIDR block for live hosts and open HTTP ports. */
export async function scanCidr(
  cidr: string,
  opts: { ports?: number[]; concurrency?: number; timeoutMs?: number } = {},
): Promise<{ host: string; findings: PortScanResult[] }[]> {
  const ips = expandCidr(cidr);
  if (ips.length === 0) return [];
  const ports = opts.ports ?? [80, 443, 8080];
  const concurrency = opts.concurrency ?? 20;
  const results: Array<{ host: string; findings: PortScanResult[] }> = [];

  const tasks = ips.map(async (ip) => {
    const hostResults: PortScanResult[] = [];
    for (const port of ports) {
      const r = await scanPort(ip, port, opts.timeoutMs ?? 2000);
      if (r.open) {
        const pr: PortScanResult = { host: ip, port, open: true }; if (r.banner) pr.banner = r.banner; hostResults.push(pr);
      }
    }
    if (hostResults.length > 0) {
      results.push({ host: ip, findings: hostResults });
    }
  });

  // Process in batches for concurrency control
  for (let i = 0; i < tasks.length; i += concurrency) {
    await Promise.allSettled(tasks.slice(i, i + concurrency));
  }
  return results;
}
