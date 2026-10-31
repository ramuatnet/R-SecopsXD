/**
 * Deterministic, source-independent asset UIDs (newtask.md 3.1).
 *
 * uid = <type>:<base32(sha256(identity))> — the same asset arriving from DNS,
 * CT logs and a port scan collapses to one node because the canonical
 * identity is normalized before hashing.
 */
import { createHash } from 'node:crypto';
import type { NodeType } from './types.ts';

const B32 = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // transcription-safe (matches finding ids)

/** Canonicalize an identity per node type before hashing. */
export function canonicalIdentity(type: NodeType, identity: string): string {
  const l = identity.trim().toLowerCase();
  switch (type) {
    case 'ip':
      return l;
    case 'domain':
    case 'subdomain':
      return l.replace(/\.$/, '');
    case 'port':
      return l; // already "ip:port"
    case 'service':
      return l; // already "ip:port:proto:product"
    case 'webapp':
    case 'api': {
      try {
        const u = new URL(l.includes('://') ? l : `https://${l}`);
        return `${u.protocol}//${u.hostname}${u.port !== '' ? `:${u.port}` : ''}`;
      } catch {
        return l;
      }
    }
    default:
      return l;
  }
}

/** uid = "<type>:<10 transcription-safe chars of sha256(canonical identity)>" */
export function assetUid(type: NodeType, identity: string): string {
  const canonical = canonicalIdentity(type, identity);
  const h = createHash('sha256').update(`${type}|${canonical}`, 'utf8').digest();
  let out = '';
  for (let i = 0; i < 10; i++) out += B32[h[i]! % B32.length];
  return `${type}:${out}`;
}

/** Identity of a port node: "<ip>:<port>" (the ip node is its parent). */
export function portIdentity(ip: string, port: number): string {
  return `${ip}:${port}`;
}

/** Identity of a service node: "<ip>:<port>:<proto>:<product>". */
export function serviceIdentity(ip: string, port: number, proto: string, product: string): string {
  return `${ip}:${port}:${proto}:${product.trim().toLowerCase() || 'unknown'}`;
}
