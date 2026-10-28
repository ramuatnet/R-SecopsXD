/**
 * Built-in TLS analysis engine (A04) — handshake-level assessment using
 * node:tls. No external tool required.
 *
 * Checks: certificate expiry, self-signed certificates, hostname mismatch,
 * negotiated protocol version, and whether legacy TLS (<= 1.1) is still
 * accepted. Exhaustive cipher-suite enumeration is out of scope (noted in
 * the task registry) — this replaces the previous "manual" TLS task with a
 * real, deterministic baseline.
 */
import { connect as tlsConnect, type PeerCertificate, type ConnectionOptions } from 'node:tls';
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.tls-analysis',
  name: 'TLS Handshake Analysis',
  kind: 'builtin',
  capabilities: {
    A04: cap('certificate validity/self-signing/hostname match, protocol version, legacy-TLS acceptance'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['webapp'],
};

interface TlsProbeResult {
  protocol?: string;
  cipher?: string;
  cert?: PeerCertificate;
  error?: string;
}

function probe(host: string, port: number, opts: ConnectionOptions = {}, timeoutMs: number): Promise<TlsProbeResult> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (r: TlsProbeResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { socket.destroy(); } catch { /* already gone */ }
      resolve(r);
    };
    const socket = tlsConnect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false, // we observe bad certificates instead of failing
      ...opts,
    });
    const timer = setTimeout(() => finish({ error: 'handshake timeout' }), timeoutMs);
    socket.once('secureConnect', () => {
      const protocol = socket.getProtocol();
      const result: TlsProbeResult = { cipher: socket.getCipher()?.name ?? 'unknown' };
      if (protocol !== undefined && protocol !== null) result.protocol = protocol;
      result.cert = socket.getPeerCertificate(true) as PeerCertificate;
      finish(result);
    });
    socket.once('error', (e) => finish({ error: e.message }));
  });
}

export interface CertAnalysis {
  findings: Array<{ rawId: string; title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; detail: string }>;
}

/** Pure certificate/protocol analysis — unit-testable without a socket. */
export function analyzeHandshake(host: string, port: number, result: TlsProbeResult, now = new Date()): CertAnalysis {
  const findings: CertAnalysis['findings'] = [];
  if (result.error !== undefined) {
    // Connection-level failure is reported as detail, not a finding — the
    // origin may simply be plain HTTP (handled by the engine caller).
    return { findings };
  }
  const cert = result.cert;
  if (cert?.valid_to) {
    const validTo = new Date(cert.valid_to);
    const daysLeft = Math.floor((validTo.getTime() - now.getTime()) / 86_400_000);
    if (daysLeft < 0) {
      findings.push({
        rawId: 'tls-cert-expired', title: `TLS certificate expired ${Math.abs(daysLeft)} days ago`,
        severity: 'high', detail: `notAfter=${cert.valid_to}`,
      });
    } else if (daysLeft < 30) {
      findings.push({
        rawId: 'tls-cert-expiring', title: `TLS certificate expires in ${daysLeft} days`,
        severity: 'low', detail: `notAfter=${cert.valid_to}`,
      });
    }
    if (cert.subject && cert.issuer && cert.subject.CN === cert.issuer.CN) {
      findings.push({
        rawId: 'tls-cert-self-signed', title: 'TLS certificate is self-signed',
        severity: 'medium', detail: `issuer CN=${cert.issuer.CN ?? 'unknown'}`,
      });
    }
    if (cert.subjectaltname) {
      const sans = cert.subjectaltname.split(', ').map((s) => s.replace(/^(DNS|IP Address):/, '').toLowerCase());
      if (!certMatchesHost(sans, host.toLowerCase())) {
        findings.push({
          rawId: 'tls-cert-hostname-mismatch', title: `TLS certificate does not match hostname ${host}`,
          severity: 'high', detail: `SANs: ${sans.slice(0, 6).join(', ')}`,
        });
      }
    }
  }
  if (result.protocol && !/TLSv1\.[23]/.test(result.protocol)) {
    findings.push({
      rawId: 'tls-legacy-protocol', title: `Connection negotiated legacy protocol ${result.protocol}`,
      severity: 'high', detail: 'TLS 1.2+ is the modern baseline',
    });
  }
  void port;
  return { findings };
}

export class TlsAnalysisEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const origin = new URL(ctx.target.origin);
    if (origin.protocol === 'http:') {
      return { findings: [], version: 'builtin', detail: 'origin is plain HTTP; TLS analysis not applicable (cleartext exposure reported separately)' };
    }
    const host = origin.hostname;
    const port = origin.port ? Number(origin.port) : 443;

    const findings: RawFinding[] = [];
    const main = await probe(host, port, {}, 10_000);
    if (main.error !== undefined) {
      ctx.log('tls probe failed', { host, error: main.error });
      return { findings: [], detail: `TLS probe failed: ${main.error}` };
    }

    const analysis = analyzeHandshake(host, port, main);
    const baseEvidence = {
      kind: 'process' as const,
      command: `node:tls handshake to ${host}:${port}`,
      stdoutExcerpt: `protocol=${main.protocol ?? 'unknown'} cipher=${main.cipher ?? 'unknown'}`,
      observation: `TLS handshake with ${host}:${port}`,
    };

    for (const f of analysis.findings) {
      findings.push({
        rawId: f.rawId,
        title: f.title,
        category: 'A04',
        cwe: f.rawId === 'tls-legacy-protocol' ? 327 : 298,
        severity: f.severity,
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.origin,
        locator: `${host}:${port}`,
        evidence: [{ ...baseEvidence, stdoutExcerpt: `${baseEvidence.stdoutExcerpt} ${f.detail}`, observation: f.title }],
        explanation:
          f.rawId === 'tls-cert-expired' || f.rawId === 'tls-cert-expiring'
            ? `The TLS certificate ${f.rawId === 'tls-cert-expired' ? 'has expired' : 'is about to expire'}. Expired certificates break trust, cause outages and train users to ignore warnings.`
            : f.rawId === 'tls-cert-self-signed'
              ? 'The certificate is self-signed, so clients cannot verify the server identity against a trusted authority — enabling impersonation unless the certificate is pinned out-of-band.'
              : f.rawId === 'tls-cert-hostname-mismatch'
                ? 'The certificate was not issued for this hostname, so the identity presented does not match the endpoint being accessed.'
                : 'A legacy TLS protocol version was negotiated. TLS 1.0/1.1 are deprecated (RFC 8996) and have known weaknesses.',
        remediation:
          f.rawId === 'tls-legacy-protocol'
            ? 'Disable TLS 1.0/1.1 at the server/load balancer; allow TLS 1.2+ only (TLS 1.3 preferred).'
            : 'Renew/reissue the certificate from a trusted CA covering the exact hostname before it impacts users.',
        references: ['https://owasp.org/Top10/2025/en/A04_2025-Cryptographic_Failures/', 'https://datatracker.ietf.org/doc/html/rfc8996'],
      });
    }

    // Legacy-TLS acceptance probe: does the server still complete a TLS 1.1 handshake?
    const legacy = await probe(host, port, { maxVersion: 'TLSv1.1', minVersion: 'TLSv1' }, 8_000);
    if (legacy.protocol && /TLSv1(\.1)?$/.test(legacy.protocol)) {
      findings.push({
        rawId: 'tls-legacy-accepted',
        title: `Server accepts deprecated ${legacy.protocol} handshakes`,
        category: 'A04',
        cwe: 327,
        severity: 'medium',
        confidence: 'high',
        status: 'confirmed',
        asset: ctx.target.origin,
        locator: `${host}:${port}`,
        evidence: [{ ...baseEvidence, stdoutExcerpt: `downgrade probe negotiated ${legacy.protocol}`, observation: 'Server completed a deprecated-TLS handshake' }],
        explanation: 'The server still completes TLS 1.0/1.1 handshakes, allowing downgrade attacks against legacy clients (RFC 8996 deprecates both).',
        remediation: 'Set the minimum accepted version to TLS 1.2 at the server/load balancer.',
        references: ['https://datatracker.ietf.org/doc/html/rfc8996'],
      });
    }

    return {
      findings,
      version: 'builtin',
      detail: `handshake OK: ${main.protocol ?? '?'}, ${analysis.findings.length} certificate/protocol findings`,
    };
  }
}

/**
 * RFC 6125 hostname verification: exact match, or wildcard `*.domain`
 * matching exactly ONE leftmost label (`vwad.owasp.org` matches `*.owasp.org`;
 * `a.b.owasp.org` and the bare apex `owasp.org` do not).
 */
export function certMatchesHost(sans: string[], host: string): boolean {
  for (const san of sans) {
    if (san === host) return true;
    if (san.startsWith('*.')) {
      const suffix = san.slice(1); // '.owasp.org'
      if (!host.endsWith(suffix)) continue;
      const label = host.slice(0, host.length - suffix.length);
      if (label.length > 0 && !label.includes('.')) return true;
    }
  }
  return false;
}
