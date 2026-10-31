/**
 * TTL probe (hardtask.md M2) — OS-family hypothesis from the IP TTL of an
 * ICMP echo, executed via the SYSTEM ping binary (runProcess pattern — the
 * same external-tool discipline as nuclei/ssh: argument array, no shell,
 * timeout + abort). Rescinds the earlier "TTL fingerprinting impossible in
 * Node userspace" claim: node:net cannot read IP headers, but the system
 * ping can.
 *
 * Initial TTL heuristics: 64 → Linux/Unix, 128 → Windows, 255 → network
 * device. REMOTE hosts decrement TTL per hop, so the hypothesis is low
 * confidence by construction and clearly labelled.
 */
import { runProcess, resolveBinary } from '../engines/adapters/common.ts';

export interface TtlHypothesis { ttl: number; family: string; confidence: 'low'; }

export function familyFromTtl(ttl: number): string {
  if (ttl <= 64 && ttl > 32) return 'Linux/Unix';
  if (ttl <= 128 && ttl > 64) return 'Windows';
  if (ttl <= 255 && ttl > 128) return 'Network Device';
  return 'unknown';
}

export function pingAvailable(): boolean {
  return resolveBinary('ping') !== undefined;
}

export async function probeTtl(host: string, signal?: AbortSignal): Promise<TtlHypothesis | undefined> {
  if (!pingAvailable()) return undefined;
  const args = process.platform === 'win32' ? ['-n', '1', '-w', '3000', host] : ['-c', '1', '-W', '3', host];
  const res = await runProcess('ping', args, { timeoutMs: 10_000, ...(signal !== undefined ? { signal } : {}) });
  const m = /[Tt][Tt][Ll][=:]\s*(\d+)/.exec(res.stdout);
  if (m === null) return undefined;
  const ttl = Number(m[1]);
  return { ttl, family: familyFromTtl(ttl), confidence: 'low' };
}
