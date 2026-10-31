/**
 * Stable finding IDs and dedup fingerprints.
 *
 * - `fingerprint` groups *the same issue on the same asset* across engines:
 *   sha256(category | cwe | asset | locator-normalized). Two engines
 *   reporting missing CSP for one origin produce one finding.
 * - `id` is stable across rescans for the same issue: sha256(fingerprint |
 *   title-normalized) rendered as FND-<cat>-<base32(10 chars)>.
 */
import { createHash } from 'node:crypto';
import type { Finding, OwaspCategory, Severity, ValidationStatus } from './types.ts';

const B32 = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // no I,L,O,0,1 — transcription-safe (31 chars)

function b32(bytes: Uint8Array, len: number): string {
  let out = '';
  for (let i = 0; i < len; i++) {
    out += B32[bytes[i]! % B32.length];
  }
  return out;
}

function sha256(input: string): Buffer {
  return createHash('sha256').update(input, 'utf8').digest();
}

/** Normalize a locator so trivial differences don't split fingerprints. */
export function normalizeLocator(locator: string): string {
  let l = locator.trim().toLowerCase();
  if (/^https?:\/\//.test(l)) {
    try {
      const u = new URL(l);
      return u.pathname.replace(/\/+$/, '') || '/';
    } catch { /* not a URL after all — fall through to generic handling */ }
  }
  l = l.replace(/\/+$/, '');
  // file locators: strip trailing :line(-line) — but only for real file paths.
  // host:port locators (ip:3306) MUST keep their port: stripping it collapsed
  // every port finding on one host into a single fingerprint (newtask V1).
  if (l.includes('/')) l = l.replace(/:\d+(-\d+)?$/, '');
  return l;
}

export function makeFingerprint(
  category: OwaspCategory,
  cwe: number | undefined,
  asset: string,
  locator: string,
): string {
  return sha256(
    [category, cwe ?? '', asset.trim().toLowerCase(), normalizeLocator(locator)].join('|'),
  ).toString('hex');
}

export function makeFindingId(fingerprint: string, title: string, category: OwaspCategory): string {
  const h = sha256(`${fingerprint}|${title.trim().toLowerCase()}`);
  return `FND-${category}-${b32(new Uint8Array(h.subarray(0, 10)), 10)}`;
}

/**
 * Merge a list of findings by fingerprint. The first (highest-confidence, as
 * sorted by the caller) finding is kept; later ones contribute provenance and
 * evidence (capped) and may raise severity to the maximum observed.
 */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const rankConf = (c: Finding['confidence']) => ({ high: 3, medium: 2, low: 1 })[c];
  const rankSev = (s: Severity) => ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 })[s];
  const statusPrecedence: ValidationStatus[] = [
    'confirmed', 'probable', 'informational', 'untested', 'false_positive',
  ];

  const order = [...findings].sort((a, b) =>
    (rankConf(b.confidence) - rankConf(a.confidence)) ||
    (rankSev(b.severity) - rankSev(a.severity)) ||
    a.id.localeCompare(b.id),
  );

  const byFp = new Map<string, Finding>();
  for (const f of order) {
    const existing = byFp.get(f.fingerprint);
    if (!existing) {
      byFp.set(f.fingerprint, structuredClone(f));
      continue;
    }
    // merge provenance (unique by engine+rawId)
    for (const p of f.provenance) {
      if (!existing.provenance.some((q) => q.engine === p.engine && q.rawId === p.rawId)) {
        existing.provenance.push(p);
      }
    }
    // merge evidence (cap 6, unique by JSON)
    for (const ev of f.evidence) {
      if (existing.evidence.length >= 6) break;
      const key = JSON.stringify(ev);
      if (!existing.evidence.some((e2) => JSON.stringify(e2) === key)) {
        existing.evidence.push(ev);
      }
    }
    if (rankSev(f.severity) > rankSev(existing.severity)) existing.severity = f.severity;
    if (statusPrecedence.indexOf(f.status) < statusPrecedence.indexOf(existing.status)) {
      existing.status = f.status;
    }
    if (existing.cve === undefined && f.cve !== undefined) existing.cve = f.cve;
    if (existing.cwe === undefined && f.cwe !== undefined) existing.cwe = f.cwe;
    // references union
    const refs = new Set(existing.references);
    for (const r of f.references) refs.add(r);
    existing.references = [...refs];
  }
  return [...byFp.values()];
}
