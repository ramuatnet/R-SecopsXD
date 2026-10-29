/**
 * Blind SSRF probe (v2 T-X1) — injects OOB callback URLs into discovered
 * URL parameters and checks for callbacks. Detects blind SSRF that returns
 * no observable response to the attacker.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';
import { OOBServer } from './oobServer.ts';

const INFO: EngineInfo = {
  id: 'builtin.blind-ssrf-probe',
  name: 'Blind SSRF Probe (OOB)',
  kind: 'builtin',
  capabilities: {
    A01: cap('blind SSRF detection via OOB callback correlation (unique tokens per attempt)'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

const URL_PARAMS = ['url', 'uri', 'redirect', 'return', 'next', 'dest', 'destination', 'target', 'fetch', 'load', 'proxy', 'site', 'path', 'resource'];
const MAX_PROBES = 5;
const CALLBACK_WAIT_MS = 5000;

export class BlindSsrfProbeEngine implements Engine {
  info = INFO;
  private oob: OOBServer | undefined;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const findings: RawFinding[] = [];
    const oob = new OOBServer();
    await oob.start('127.0.0.1', 0);
    this.oob = oob;

    try {
      // Discover URL-ish parameters from crawled pages
      const candidates: Array<{ pageUrl: string; param: string }> = [];
      for (const page of ctx.crawl?.pages ?? []) {
        const u = new URL(page.url);
        for (const param of [...u.searchParams.keys()]) {
          if (URL_PARAMS.includes(param.toLowerCase()) && candidates.length < MAX_PROBES) {
            candidates.push({ pageUrl: page.url, param });
          }
        }
      }
      // Also check discovered endpoints
      for (const ep of ctx.crawl?.discoveredEndpoints ?? []) {
        if (candidates.length >= MAX_PROBES) break;
        const u = new URL(ep, ctx.target.origin + '/');
        const param = URL_PARAMS.find((p) => u.searchParams.has(p));
        if (param) candidates.push({ pageUrl: u.toString(), param });
      }

      if (candidates.length === 0) {
        return { findings: [], detail: 'no URL-accepting parameters discovered for SSRF probing' };
      }

      let probes = 0;
      for (const { pageUrl, param } of candidates) {
        if (probes >= MAX_PROBES || ctx.signal.aborted) break;
        probes++;
        const token = `ssrf-${probes}-${Date.now().toString(36)}`;
        const callbackUrl = `${oob.url}/${token}`;
        oob.generateCallback(`ssrf-${probes}`);

        const probeUrl = new URL(pageUrl);
        probeUrl.searchParams.set(param, callbackUrl);
        await ctx.client.get(probeUrl.toString());

        // Wait briefly for the callback
        await new Promise((r) => setTimeout(r, CALLBACK_WAIT_MS / candidates.length));

        if (oob.hasHit(token)) {
          const hits = oob.getHits(token);
          findings.push({
            rawId: 'blind-ssrf-oob',
            title: `Blind SSRF confirmed via OOB callback on parameter "${param}"`,
            category: 'A01',
            cwe: 918,
            severity: 'critical',
            confidence: 'high',
            status: 'confirmed',
            asset: ctx.target.origin,
            locator: `${new URL(pageUrl).pathname}?${param}=`,
            evidence: [{
              kind: 'process',
              command: `OOB probe: ${callbackUrl} injected into ${param}`,
              observation: `Target made ${hits.length} outbound request(s) to our callback server (token: ${token}, source: ${hits[0]?.sourceIp})`,
            }],
            explanation:
              'The server made an outbound HTTP request to our callback URL, confirming server-side ' +
              'request forgery. The response to the original request was blind (no indication of success), ' +
              'which is why OOB correlation is required. An attacker can use this to scan internal networks, ' +
              'access cloud metadata endpoints, or exfiltrate data.',
            remediation:
              'Validate URLs against an allow-list of trusted origins; block requests to internal/private IP ranges; ' +
              'disable unnecessary URL-fetching functionality.',
            references: ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
          });
        }
      }

      return { findings, version: 'builtin', detail: `${probes} SSRF probe(s) sent, ${findings.length} callback(s) received` };
    } finally {
      oob.stop();
    }
  }
}
