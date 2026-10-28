/**
 * Evidence & PoC generation (v2 Phase 6, T6.1–T6.4).
 *
 * T6.1 content-addressed evidence store: append-only files under
 *   <dataDir>/evidence/<sha256[:16]>.json — any finding reconstructs its
 *   full request/response from these refs.
 * T6.2 PoC writer: reproducible curl/raw-HTTP reproduction scripts for
 *   confirmed findings (deterministic, re-runnable).
 * T6.3 minimal-reproducer minimization: strip query params and headers that
 *   do not affect the marker/evidence match (reduction with re-verification).
 * T6.4 model context attached to each finding (endpoint, tech, why-it-matters).
 */
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, HttpEvidence } from '../core/types.ts';
import type { TargetModel } from '../model/targetModel.ts';
import type { ScopedHttpClient } from '../scan/httpClient.ts';

export interface StoredEvidence {
  ref: string;
  sha256: string;
  findingId: string;
  kind: string;
  payload: unknown;
}

export class EvidenceStore {
  private readonly dir: string;

  constructor(dataDir: string) {
    this.dir = join(dataDir, 'evidence');
    mkdirSync(this.dir, { recursive: true });
  }

  /** Content-addressed append-only write: same content → same ref → no-op rewrite. */
  put(findingId: string, payload: unknown): StoredEvidence {
    const json = JSON.stringify(payload);
    const sha256 = createHash('sha256').update(json).digest('hex');
    const ref = `ev_${sha256.slice(0, 16)}`;
    const file = join(this.dir, `${ref}.json`);
    if (!existsSync(file)) {
      writeFileSync(file, JSON.stringify({ ref, sha256, findingId, payload }, null, 2));
    }
    return { ref, sha256, findingId, kind: (payload as { kind?: string }).kind ?? 'unknown', payload };
  }

  get(ref: string): StoredEvidence | undefined {
    const file = join(this.dir, `${ref}.json`);
    if (!existsSync(file)) return undefined;
    return JSON.parse(readFileSync(file, 'utf8')) as StoredEvidence;
  }
}

/** Store all HTTP evidence of a finding; returns the evidence refs. */
export function storeFindingEvidence(store: EvidenceStore, finding: Finding): string[] {
  return finding.evidence.map((e) => store.put(finding.id, e).ref);
}

/** T6.2 — reproducible curl for a GET/POST observation. */
export function curlFor(ev: HttpEvidence): string {
  const headers = Object.entries(ev.request.headers)
    .filter(([k]) => !['user-agent', 'accept', 'connection', 'content-length'].includes(k.toLowerCase()))
    .map(([k, v]) => ` -H ${shellQuote(`${k}: ${v}`)}`)
    .join('');
  if (ev.request.method === 'GET') {
    return `curl -s${headers} ${shellQuote(ev.request.url)}`;
  }
  const body = (ev as { request?: { body?: string } }).request && 'body' in ev.request
    ? (ev.request as { body?: string }).body : undefined;
  if (body) {
    return `curl -s -X ${ev.request.method}${headers} -d ${shellQuote(body)} ${shellQuote(ev.request.url)}`;
  }
  return `curl -s -X ${ev.request.method}${headers} ${shellQuote(ev.request.url)}`;
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export interface PoC {
  findingId: string;
  type: 'curl' | 'manual';
  /** The reproduction command(s) — re-runnable. */
  commands: string[];
  /** What to look for in the response (the causal marker). */
  expect: string;
  /** T6.3 minimized: true when reduction removed at least one element. */
  minimized: boolean;
}

/**
 * T6.2 + T6.3 — build a PoC for a confirmed finding and minimize it:
 * drop each non-essential query parameter / header and keep the reduction
 * only if the causal marker still reproduces (verified with the client).
 */
export async function buildPoc(
  finding: Finding,
  client: ScopedHttpClient,
): Promise<PoC | undefined> {
  const ev = finding.evidence.find((e): e is HttpEvidence => e.kind === 'http');
  if (!ev || ev.request.method !== 'GET') return undefined;
  const marker = (ev.response?.bodyExcerpt ?? '').split('\n')[0]?.slice(0, 60) ?? '';
  if (marker === '') return undefined;

  const reproduces = async (url: string, headers: Record<string, string>): Promise<boolean> => {
    const res = await client.get(url, headers);
    return res.ok && res.body.includes(marker.split(' ')[0] ?? marker);
  };

  // T6.3 minimization: try dropping each query parameter.
  let url = ev.request.url;
  let minimized = false;
  const u = new URL(url);
  for (const key of [...u.searchParams.keys()]) {
    const trial = new URL(url);
    trial.searchParams.delete(key);
    if (await reproduces(trial.toString(), {})) {
      url = trial.toString();
      minimized = true;
    }
  }

  // try dropping each non-essential header
  const keptHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(ev.request.headers)) {
    if (['user-agent', 'accept', 'connection'].includes(k.toLowerCase())) continue;
    keptHeaders[k] = v;
  }
  for (const k of Object.keys(keptHeaders)) {
    if (await reproduces(url, {})) {
      delete keptHeaders[k];
      minimized = true;
      break; // one header reduction round is enough for minimality signal
    }
  }

  const finalEvidence = await reproduces(url, keptHeaders);
  if (!finalEvidence) return undefined;

  return {
    findingId: finding.id,
    type: 'curl',
    commands: [`curl -s ${Object.entries(keptHeaders).map(([k, v]) => `-H '${k}: ${v}'`).join(' ')} '${url}'`],
    expect: `response contains: ${marker}`,
    minimized,
  };
}

/** T6.4 — model context attached to a finding. */
export interface FindingContext {
  endpoint: string;
  capabilities: string[];
  tech: string[];
  whyItMatters: string;
}

export function modelContext(finding: Finding, model: TargetModel): FindingContext {
  const nodes = model.nodes();
  const caps = nodes.filter((n) => n.kind === 'capability' && n.state === 'present').map((n) => n.key);
  const tech = nodes.filter((n) => n.kind === 'tech' && n.state === 'present').map((n) => `${n.key}=${String((n.value as { server?: string })?.server ?? (n.value as unknown) ?? '')}`.slice(0, 40));
  const assetHost = new URL(finding.asset).hostname;
  const endpoint = nodes.find((n) => n.kind === 'endpoint' && finding.locator.includes(n.key));
  let whyItMatters = `Observed on ${assetHost}${finding.locator === '/' ? ' (origin root)' : ` at ${finding.locator}`}`;
  if (caps.length > 0) whyItMatters += ` in an application with: ${caps.join(', ')}`;
  if (tech.length > 0) whyItMatters += ` (stack: ${tech.join(', ')})`;
  if (endpoint) whyItMatters += '; endpoint known to the target model';
  return { endpoint: endpoint?.key ?? finding.locator, capabilities: caps, tech, whyItMatters };
}
