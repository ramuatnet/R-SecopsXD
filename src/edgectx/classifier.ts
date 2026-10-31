/**
 * Edge classifier (edgetask.md EDGE-01/02, §5, §8.1) — weighted multi-signal
 * quorum. Favicon alone never wins; two weak signals never win; one strong
 * signal does. Stale vendor feed multiplies confidence by 0.7 and the caller
 * must emit engine.degraded (EDGE-02).
 */
import type { EdgeVendor, EdgeVerdict, Signal, EdgeFeedMeta } from './models.ts';
export type { EdgeVerdict };

export interface VendorPack {
  vendor: EdgeVendor;
  feedVersion: string;
  /** Header signature → weight. */
  headerSignals: Array<{ header: RegExp; value?: RegExp; kind: string; weight: number }>;
  /** Published IP ranges (representative snapshot; refreshed by feed job). */
  cidrs: string[];
}

/**
 * EDGE-02: versioned vendor signature packs. Weights: TLS-terminating headers
 * (cf-ray, x-amz-cf-id) are strong (≥0.30) because they are vendor-specific
 * and hard to spoof accidentally; generic Server banners are weaker.
 */
export const VENDOR_PACKS: VendorPack[] = [
  {
    vendor: 'cloudflare', feedVersion: 'cf-sig-2026-10-31',
    headerSignals: [
      { header: /^cf-ray$/i, kind: 'cf-ray', weight: 0.5 },
      { header: /^cf-cache-status$/i, kind: 'cf-cache-status', weight: 0.45 },
      { header: /^server$/i, value: /cloudflare/i, kind: 'server-header', weight: 0.35 },
      { header: /^cf-chl-/i, kind: 'cf-challenge', weight: 0.4 },
    ],
    cidrs: [
      '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
      '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
      '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
      '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    ],
  },
  {
    vendor: 'cloudfront', feedVersion: 'cfr-sig-2026-10-31',
    headerSignals: [
      { header: /^x-amz-cf-id$/i, kind: 'x-amz-cf-id', weight: 0.5 },
      { header: /^x-amz-cf-pop$/i, kind: 'x-amz-cf-pop', weight: 0.45 },
      { header: /^server$/i, value: /cloudfront/i, kind: 'server-header', weight: 0.35 },
    ],
    cidrs: ['13.32.0.0/15', '13.224.0.0/14', '52.46.0.0/18', '52.82.0.0/15', '99.86.0.0/16', '205.251.208.0/20'],
  },
  {
    vendor: 'fastly', feedVersion: 'fsly-sig-2026-10-31',
    headerSignals: [
      { header: /^x-served-by$/i, value: /cache-/i, kind: 'x-served-by', weight: 0.45 },
      { header: /^x-fastly-/i, kind: 'x-fastly', weight: 0.5 },
      { header: /^via$/i, value: /varnish/i, kind: 'via-varnish', weight: 0.3 },
    ],
    cidrs: ['23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '146.75.0.0/16', '151.101.0.0/16', '199.27.72.0/21'],
  },
  {
    vendor: 'akamai', feedVersion: 'akm-sig-2026-10-31',
    headerSignals: [
      { header: /^x-akamai-/i, kind: 'x-akamai', weight: 0.5 },
      { header: /^server$/i, value: /akamai/i, kind: 'server-header', weight: 0.35 },
    ],
    cidrs: ['23.0.0.0/12', '2.16.0.0/13', '95.100.0.0/15', '104.64.0.0/10'],
  },
  {
    vendor: 'azurefd', feedVersion: 'azfd-sig-2026-10-31',
    headerSignals: [
      { header: /^x-msedge-ref$/i, kind: 'x-msedge-ref', weight: 0.5 },
      { header: /^x-azure-ref/i, kind: 'x-azure-ref', weight: 0.5 },
    ],
    cidrs: ['13.107.213.0/24', '13.107.214.0/24', '51.10.0.0/15'],
  },
];

/** cidrContains — minimal IPv4 CIDR membership (no deps). */
export function cidrContains(ip: string, cidr: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  const c = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (m === null || c === null) return false;
  const toInt = (o: [string, string, string, string]): number =>
    ((Number(o[0]) << 24) | (Number(o[1]) << 16) | (Number(o[2]) << 8) | Number(o[3])) >>> 0;
  const ipInt = toInt([m[1]!, m[2]!, m[3]!, m[4]!]);
  const cidrInt = toInt([c[1]!, c[2]!, c[3]!, c[4]!]);
  const mask = c[5] === '0' ? 0 : (0xffffffff << (32 - Number(c[5]))) >>> 0;
  return (ipInt & mask) === (cidrInt & mask);
}

/** EDGE-02: IP-range membership signal (vendor feed with staleness TTL). */
export function ipRangeSignal(ip: string, feedStale: boolean): Signal | undefined {
  for (const pack of VENDOR_PACKS) {
    if (pack.cidrs.some((c) => cidrContains(ip, c))) {
      return { kind: 'ip-range', value: pack.vendor, weight: feedStale ? 0.25 : 0.35 };
    }
  }
  return undefined;
}

/** Header signals from a response header set. */
export function headerSignals(headers: Record<string, string>): Signal[] {
  const out: Signal[] = [];
  for (const pack of VENDOR_PACKS) {
    for (const sig of pack.headerSignals) {
      const value = Object.keys(headers).find((k) => sig.header.test(k));
      if (value === undefined) continue;
      if (sig.value !== undefined && !sig.value.test(String(headers[value] ?? ''))) continue;
      out.push({ kind: sig.kind, value: String(headers[value] ?? '').slice(0, 80), weight: sig.weight });
    }
  }
  return out;
}

/** TLS certificate signal (SAN/issuer naming the vendor). */
export function certSignal(certText: string): Signal | undefined {
  const m = /(cloudflare|akamai|fastly|amazon|azure)/i.exec(certText);
  if (m === null) return undefined;
  const vendor = m[1]!.toLowerCase();
  const known: Record<string, EdgeVendor> = { amazon: 'cloudfront', azure: 'azurefd' };
  return { kind: 'tls-cert', value: known[vendor] ?? vendor, weight: 0.3 };
}

/**
 * EDGE-01: the quorum rule (§8.1), verbatim semantics.
 * score  = Σ weight of non-favicon signals (×0.7 when the feed is stale)
 * strong = count of signals with weight ≥ 0.30
 * favicon alone never classifies; two weak signals never classify.
 */
export function classify(
  signals: Signal[],
  feed: EdgeFeedMeta,
  ip?: string,
): EdgeVerdict {
  let score = signals.filter((s) => s.kind !== 'favicon').reduce((sum, s) => sum + s.weight, 0);
  const favicon = signals.some((s) => s.kind === 'favicon');
  const strong = signals.filter((s) => s.weight >= 0.3).length;
  if (feed.stale) score *= 0.7;
  if (strong === 0 && !(favicon && score >= 0.5)) {
    return { vendor: 'none', confidence: Math.min(score, 1), signals, feed, vantage: 'unknown' };
  }
  // EDGE-02: corroborate with the IP-range feed (added, not required)
  if (ip !== undefined) {
    const ipSig = ipRangeSignal(ip, feed.stale);
    if (ipSig !== undefined && !signals.some((s) => s.kind === 'ip-range')) signals.push(ipSig);
  }
  // argmax vendor by accumulated weight across packs
  const byVendor = new Map<EdgeVendor, number>();
  for (const pack of VENDOR_PACKS) {
    let v = 0;
    for (const sig of signals) {
      if (pack.headerSignals.some((hs) => hs.kind === sig.kind)) v += sig.weight;
      if (sig.kind === 'ip-range' && pack.cidrs.length > 0 && sig.value === pack.vendor) v += sig.weight;
    }
    if (v > 0) byVendor.set(pack.vendor, v);
  }
  let vendor: EdgeVendor = 'none';
  let best = 0;
  for (const [v, w] of byVendor) {
    if (w > best) { vendor = v; best = w; }
  }
  const confidence = Math.min(score, 1);
  return { vendor, confidence, signals, feed, vantage: vendor !== 'none' ? 'edge' : 'unknown' };
}

/** Classify from a response header set + optional IP/cert text. */
export function classifyFromResponse(
  headers: Record<string, string>,
  ip: string | undefined,
  feed: EdgeFeedMeta,
): EdgeVerdict {
  const signals = headerSignals(headers);
  if (ip !== undefined) {
    const ipSig = ipRangeSignal(ip, feed.stale);
    if (ipSig !== undefined) signals.push(ipSig);
  }
  return classify(signals, feed, ip);
}
