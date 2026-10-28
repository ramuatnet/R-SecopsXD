/**
 * Central secret redaction. Everything that is persisted (evidence headers,
 * body excerpts, process output, logs) passes through here.
 */
const HEADER_REDACT = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
  'x-api-key', 'x-auth-token', 'x-session-token', 'x-csrf-token', 'x-amz-security-token',
]);

const VALUE_PATTERNS: Array<[RegExp, string]> = [
  [/Bearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, 'Bearer [REDACTED]'],
  [/basic\s+[A-Za-z0-9+/=]{8,}/gi, 'Basic [REDACTED]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED-AWS-KEY]'],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, '[REDACTED-GITHUB-TOKEN]'],
  [/\bsk-[A-Za-z0-9_-]{16,}\b/g, '[REDACTED-API-KEY]'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, '[REDACTED-SLACK-TOKEN]'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED-PRIVATE-KEY]'],
  // JWTs: three base64url segments with a plausible signature length
  [/\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b/g, '[REDACTED-JWT]'],
  // long secret-looking literals after an assignment to a secret-ish name
  [/(password|passwd|secret|token|apikey|api_key|private_key)(["'\s:=]+)([A-Za-z0-9+/=_-]{12,})/gi,
    '$1$2[REDACTED]'],
];

export function redactValue(nameOrBody: string, value?: string): string {
  if (value === undefined) return redactText(nameOrBody);
  if (HEADER_REDACT.has(nameOrBody.toLowerCase())) {
    return `${value.slice(0, value.indexOf('=') + 1)}[REDACTED]`;
  }
  return redactText(value);
}

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k] = redactValue(k, v);
  return out;
}

export function redactText(text: string, maxLen = 2048): string {
  let t = text;
  for (const [re, replacement] of VALUE_PATTERNS) {
    t = t.replace(re, replacement as string);
  }
  if (t.length > maxLen) t = `${t.slice(0, maxLen)}…[truncated ${text.length - maxLen} chars]`;
  return t;
}
