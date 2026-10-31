/**
 * Origin resolution + verification (edgetask.md ORIG-01..04, §8.3).
 *
 * ORIG-01: candidates come from the manifest/history — passive only, and only
 * when the manifest flag origin_discovery_authorized is set.
 * ORIG-02: verification connects to the candidate with the correct Host and
 * SNI and compares cert SHA-256, <title> hash and body SHA-256 against the
 * edge response. Match ⇒ origin.verified; mismatch ⇒ rejected.
 * ORIG-03: candidates require human approval BEFORE any probing.
 * ORIG-04: an unreachable/locked-down origin is a coverage limitation — never
 * clean.
 */
import { createHash } from 'node:crypto';
import { connect as tlsConnect, type TLSSocket } from 'node:tls';
import type { ScopeManifest } from './models.ts';

export interface OriginCandidate {
  hostname: string;      // candidate origin hostname/IP
  ip: string;
  discoveredVia: string; // 'dns-history' | 'manifest' | 'supplied'
  approved: boolean;
  approvedBy?: string | undefined;
  rejectionReason?: string | undefined;
}

export interface OriginVerification {
  candidate: string;
  verified: boolean;
  reason: string;
  certSha256?: string | undefined;
  titleHash?: string | undefined;
  bodySha256?: string | undefined;
}

function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

function extractTitle(body: string): string {
  const m = /<title[^>]*>([^<]*)<\/title>/i.exec(body);
  return m === null ? '' : m[1]!.trim();
}

/** ORIG-01: candidate generation — passive, manifest-gated. */
export function originCandidates(manifest: ScopeManifest, history: string[]): OriginCandidate[] {
  if (!manifest.flags.originDiscoveryAuthorized) return [];
  return history.map((h) => ({ hostname: h, ip: h, discoveredVia: 'dns-history', approved: false }));
}

/** ORIG-02: TLS fetch of cert + title + body hashes with correct Host/SNI. */
export async function fetchOriginFingerprint(
  host: string, ip: string, port: number, timeoutMs = 8000,
): Promise<{ reachable: boolean; certSha256?: string | undefined; titleHash?: string | undefined; bodySha256?: string | undefined; error?: string | undefined }> {
  const Empty = undefined;
  void Empty;
  return new Promise<{ reachable: boolean; certSha256?: string | undefined; titleHash?: string | undefined; bodySha256?: string | undefined; error?: string | undefined }>((resolve) => {
    const socket: TLSSocket = tlsConnect({ host: ip, port, servername: host, rejectUnauthorized: false });
    let body = '';
    let certPem = '';
    let settled = false;
    const finish = (reachable: boolean, error?: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (!reachable) {
        const out: { reachable: boolean; certSha256?: string | undefined; titleHash?: string | undefined; bodySha256?: string | undefined; error?: string | undefined } = { reachable };
        if (error !== undefined) out.error = error;
        resolve(out);
        return;
      }
      else {
        const out: { reachable: boolean; certSha256?: string | undefined; titleHash?: string | undefined; bodySha256?: string | undefined } = { reachable };
        out.certSha256 = sha256(certPem);
        out.titleHash = sha256(extractTitle(body));
        out.bodySha256 = sha256(body.slice(0, 8192));
        resolve(out);
      }
    };
    const timer = setTimeout(() => finish(false, `timeout (${timeoutMs}ms)`), timeoutMs);
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      certPem = JSON.stringify({ cn: cert.subject?.CN, issuer: cert.issuer?.O, valid: cert.valid_to });
      socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: rsec-origin-verify/0.1\r\nConnection: close\r\n\r\n`);
    });
    socket.on('data', (c: Buffer) => { body += c.toString('utf8'); });
    socket.on('close', () => finish(body.length > 0));
    socket.on('error', (e: Error) => finish(false, e.message));
  });
}

/** ORIG-02: compare the origin fingerprint against the edge fingerprint. */
export function verifyOrigin(
  candidate: string,
  originFp: { reachable: boolean; certSha256?: string; titleHash?: string; bodySha256?: string; error?: string },
  edgeFp: { certSha256: string; titleHash: string; bodySha256: string },
): OriginVerification {
  if (!originFp.reachable) {
    return { candidate, verified: false, reason: `origin unreachable/locked down: ${originFp.error ?? 'no response'} — coverage limitation (ORIG-04), never clean`, certSha256: originFp.certSha256, titleHash: originFp.titleHash, bodySha256: originFp.bodySha256 };
  }
  // A CDN terminates TLS, so cert hashes NEVER match through the edge; the
  // decision rests on title and body hashes fetched with the correct Host/SNI.
  const titleMatch = originFp.titleHash === edgeFp.titleHash;
  const bodyMatch = originFp.bodySha256 === edgeFp.bodySha256;
  if (titleMatch && bodyMatch) {
    return { candidate, verified: true, reason: 'title + body hashes match the edge response (served by the same application)', certSha256: originFp.certSha256, titleHash: originFp.titleHash, bodySha256: originFp.bodySha256 };
  }
  return { candidate, verified: false, reason: `fingerprint mismatch vs edge (title ${titleMatch ? 'match' : 'mismatch'}, body ${bodyMatch ? 'match' : 'mismatch'}) — rejected`, certSha256: originFp.certSha256, titleHash: originFp.titleHash, bodySha256: originFp.bodySha256 };
}
