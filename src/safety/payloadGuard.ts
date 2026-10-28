/**
 * Payload guard — refuses destructive or dangerous outbound payloads before a
 * request is ever sent. Applies to every request the platform itself
 * constructs (builtin engines and adapter arguments).
 *
 * Policy: the platform sends only benign probe markers. It never transmits
 * destructive commands, traversal chains, DoS artifacts or exploit payloads —
 * verification stops at "evidence of the vulnerability", by design.
 */
export type PayloadVerdict = { ok: true } | { ok: false; reason: string };

const DESTRUCTIVE_PATTERNS: Array<[RegExp, string]> = [
  [/\brm\s+-rf?\b/i, 'filesystem deletion command'],
  [/\bdel\s+\/[fqs]/i, 'filesystem deletion command'],
  [/\bformat\s+[a-z]:/i, 'filesystem format command'],
  [/\bmkfs\b/i, 'filesystem format command'],
  [/\bdd\s+if=/i, 'raw disk write command'],
  [/shutdown|reboot|halt\s+-p/i, 'host shutdown command'],
  [/:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;/, 'fork bomb'],
  [/\b(drop|truncate)\s+(table|database)\b/i, 'database destruction statement'],
  [/\bdelete\s+from\s+\w+\s*(;|$)/i, 'database deletion statement'],
  [/\.\.\/\.\.\//, 'path traversal chain'],
  [/[\/\\]etc[\/\\](passwd|shadow)/, 'sensitive system file access'],
  [/%s%s%s%s%s%s/, 'format string bomb'],
  [/\{\{7\*7\}\}|\$\{7\*7\}/, 'template injection payload'],
  [/(union\s+select\s+.*from\s+information_schema)/i, 'database enumeration exploit'],
  [/<!ENTITY\s+/i, 'XXE payload'],
];

const MAX_BODY_BYTES = 8 * 1024;

export function validateOutbound(
  method: string,
  url: string,
  body?: string,
): PayloadVerdict {
  const m = method.toUpperCase();
  if (!['GET', 'HEAD', 'POST'].includes(m)) {
    return { ok: false, reason: `method ${m} not permitted by platform policy` };
  }
  const haystack = `${url}\n${body ?? ''}`;
  for (const [re, why] of DESTRUCTIVE_PATTERNS) {
    if (re.test(haystack)) return { ok: false, reason: `payload refused: ${why}` };
  }
  if (body !== undefined && Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) {
    return { ok: false, reason: 'body exceeds 8 KiB probe limit' };
  }
  return { ok: true };
}

/** Benign marker used for reflection probes (active mode only). */
export const REFLECTION_MARKER = `ovap-marker-${'a1b2c3d4e5'}`;
