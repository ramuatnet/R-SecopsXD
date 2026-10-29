/**
 * Raw socket probes (v2 Phase 4, T4.2) — host-header injection and
 * cache-poisoning detection using node:net (bypasses fetch's header restrictions).
 *
 * Safety: only sends probe requests with identifiable markers; never modifies
 * cached content destructively; bounded to 3 requests per check.
 */
import { connect as netConnect, type Socket } from 'node:net';
import { log } from '../../logging.ts';

export interface RawResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export function rawRequest(
  host: string, port: number, rawHttpRequest: string, timeoutMs = 10_000,
  useTls = false,
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const socket: Socket = useTls
      ? require('node:tls').connect({ host, port, rejectUnauthorized: false, servername: host })
      : netConnect({ host, port });
    let data = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; socket.destroy(); reject(new Error('raw request timeout')); }
    }, timeoutMs);

    socket.on('connect', () => { socket.write(rawHttpRequest); });
    socket.on('data', (chunk: Buffer) => { data += chunk.toString('utf8'); });
    socket.on('close', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const headerEnd = data.indexOf('\r\n\r\n');
      if (headerEnd < 0) { resolve({ status: 0, headers: {}, body: data }); return; }
      const headerBlock = data.slice(0, headerEnd);
      const statusLine = headerBlock.split('\r\n')[0] ?? '';
      const status = Number(/HTTP\/[\d.]+\s+(\d+)/.exec(statusLine)?.[1] ?? 0);
      const headers: Record<string, string> = {};
      for (const line of headerBlock.split('\r\n').slice(1)) {
        const idx = line.indexOf(':');
        if (idx > 0) headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
      }
      resolve({ status, headers, body: data.slice(headerEnd + 4) });
    });
    socket.on('error', (e) => {
      if (!settled) { settled = true; clearTimeout(timer); reject(e); }
    });
  });
}

/**
 * Host-header injection probe: sends a request with an attacker-controlled
 * Host header and checks if the response reflects it (e.g. in a redirect
 * Location header or a link).
 */
export async function probeHostHeaderInjection(
  origin: string,
): Promise<{ vulnerable: boolean; evidence: string } | undefined> {
  const u = new URL(origin);
  const host = u.hostname;
  const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
  const attackerHost = 'ovap-host-injection.example';
  const useTls = u.protocol === 'https:';

  const raw = [
    `GET / HTTP/1.1`,
    `Host: ${attackerHost}`,
    `Connection: close`,
    ``,
    ``,
  ].join('\r\n');

  try {
    const res = await rawRequest(host, port, raw, 10_000, useTls);
    const bodyCheck = res.body.includes(attackerHost);
    const locationCheck = res.headers['location']?.includes(attackerHost) ?? false;
    if (bodyCheck || locationCheck) {
      return {
        vulnerable: true,
        evidence: `Response reflects attacker Host header (${attackerHost})${locationCheck ? ' in Location header' : ''}${bodyCheck ? ' in body' : ''}`,
      };
    }
    return { vulnerable: false, evidence: 'Host header not reflected' };
  } catch (e) {
    log.debug('host-header probe failed', { error: e instanceof Error ? e.message : String(e) });
    return undefined;
  }
}
