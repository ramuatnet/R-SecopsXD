/**
 * ScopedHttpClient — the ONLY network egress path for built-in engines.
 *
 * Every request: payload-guarded, scope-checked (including each redirect
 * hop), rate-limited, concurrency-bounded, timeout-bounded, and captured as
 * redacted evidence. Statistics feed the scan record.
 */
import { ScopeGuard, ScopeError } from '../safety/guard.ts';
import { RateLimiter, abortError } from '../safety/rateLimiter.ts';
import { Semaphore } from '../safety/concurrency.ts';
import { validateOutbound } from '../safety/payloadGuard.ts';
import { redactHeaders, redactText } from '../core/redact.ts';
import type { HttpEvidence } from '../core/types.ts';
import { log } from '../logging.ts';

export const MAX_RESPONSE_BYTES = 256 * 1024;

export interface HttpClientOptions {
  timeoutMs: number;
  maxRedirectHops: number;
}

export interface RequestStats {
  sent: number;
  blocked: number;
}

export interface HttpResponse {
  ok: true;
  status: number;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
  finalUrl: string;
  elapsedMs: number;
  evidence: HttpEvidence;
}

export type HttpResult = HttpResponse | { ok: false; blocked: string; url: string };

export interface RequestOptions {
  headers?: Record<string, string>;
  body?: string;
  contentType?: string;
}

export class ScopedHttpClient {
  private readonly guard: ScopeGuard;
  private readonly limiter: RateLimiter;
  private readonly semaphore: Semaphore;
  private readonly opts: HttpClientOptions;
  private readonly stats: RequestStats;
  private readonly signal: AbortSignal | undefined;

  constructor(
    guard: ScopeGuard,
    limiter: RateLimiter,
    semaphore: Semaphore,
    opts: HttpClientOptions,
    stats: RequestStats,
    signal?: AbortSignal,
  ) {
    this.guard = guard;
    this.limiter = limiter;
    this.semaphore = semaphore;
    this.opts = opts;
    this.stats = stats;
    this.signal = signal;
  }

  async request(method: string, rawUrl: string, reqOpts: RequestOptions = {}): Promise<HttpResult> {
    const verdict = validateOutbound(method, rawUrl, reqOpts.body);
    if (!verdict.ok) {
      this.stats.blocked++;
      return { ok: false, blocked: verdict.reason, url: rawUrl };
    }
    try {
      this.guard.checkUrl(rawUrl);
    } catch (e) {
      this.stats.blocked++;
      return { ok: false, blocked: e instanceof Error ? e.message : String(e), url: rawUrl };
    }

    const release = await this.semaphore.acquire(this.signal).catch(() => null);
    if (!release) return { ok: false, blocked: 'aborted', url: rawUrl };
    try {
      return await this.doRequest(method.toUpperCase(), rawUrl, reqOpts, 0, []);
    } finally {
      release();
    }
  }

  async get(url: string, headers?: Record<string, string>): Promise<HttpResult> {
    return this.request('GET', url, headers ? { headers } : {});
  }

  async postForm(url: string, form: Record<string, string>): Promise<HttpResult> {
    const body = new URLSearchParams(form).toString();
    return this.request('POST', url, { body, contentType: 'application/x-www-form-urlencoded' });
  }

  private async doRequest(
    method: string,
    url: string,
    reqOpts: RequestOptions,
    hop: number,
    carriedCookies: string[],
  ): Promise<HttpResult> {
    const started = Date.now();
    await this.limiter.acquire(this.guard.origin.host + ':' + this.guard.origin.port, this.signal).catch(() => {
      throw abortError();
    });
    this.stats.sent++;

    const headers: Record<string, string> = {
      'user-agent': 'OWASP-Assessment-Platform/0.1 (authorized scan)',
      accept: '*/*',
      ...reqOpts.headers,
    };
    if (reqOpts.body !== undefined && reqOpts.contentType) headers['content-type'] = reqOpts.contentType;

    const timeout = AbortSignal.timeout(this.opts.timeoutMs);
    const signal = this.signal ? AbortSignal.any([timeout, this.signal]) : timeout;

    let res: Response;
    try {
      const init: RequestInit = {
        method,
        headers,
        redirect: 'manual', // every hop is validated explicitly
        signal,
      };
      if (reqOpts.body !== undefined) init.body = reqOpts.body;
      res = await fetch(url, init);
    } catch (e) {
      if (e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError')) {
        const kind = e.name === 'TimeoutError' ? 'request timeout' : 'aborted';
        return {
          ok: false,
          blocked: kind,
          url,
        };
      }
      return { ok: false, blocked: `connection error: ${e instanceof Error ? e.message : String(e)}`, url };
    }

    // Redirect handling: validate every hop against scope.
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (location) {
        try {
          const next = this.guard.checkRedirect(url, location, hop);
          // Carry Set-Cookie issued on intermediate redirect responses (e.g. login
          // flows that set the session cookie on the 302 itself) — browser-equivalent
          // behavior for the duration of this redirect chain only: injected into the
          // next hop's Cookie header, never persisted anywhere.
          const carried = [...carriedCookies];
          const sc = res.headers.get('set-cookie');
          if (sc) carried.push(sc);
          const nextOpts: RequestOptions = { ...reqOpts };
          const cookiePairs = carried
            .map((c) => /([A-Za-z0-9_.!-]+)=([^;,]*)/.exec(c))
            .filter((m): m is RegExpExecArray => m !== null)
            .map((m) => `${m[1]}=${m[2]}`);
          if (cookiePairs.length > 0 && nextOpts.headers?.cookie === undefined) {
            nextOpts.headers = { ...nextOpts.headers, cookie: cookiePairs.join('; ') };
          }
          log.debug('following redirect', { from: url, to: next.toString() });
          return await this.doRequest(method, next.toString(), nextOpts, hop + 1, carried);
        } catch (e) {
          this.stats.blocked++;
          const msg = e instanceof ScopeError || e instanceof Error ? e.message : String(e);
          return { ok: false, blocked: `redirect blocked: ${msg}`, url };
        }
      }
    }

    const respHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => { respHeaders[k] = v; });
    if (carriedCookies.length > 0) {
      const own = respHeaders['set-cookie'];
      respHeaders['set-cookie'] = [...carriedCookies, ...(own ? [own] : [])].join('\n');
    }

    const { text, truncated } = await readBodyCapped(res, MAX_RESPONSE_BYTES, this.opts.timeoutMs);
    const elapsedMs = Date.now() - started;

    const evidence: HttpEvidence = {
      kind: 'http',
      request: { method, url, headers: redactHeaders(headers) },
      response: {
        status: res.status,
        headers: redactHeaders(respHeaders),
        bodyExcerpt: redactText(text.slice(0, 2048)),
      },
      observation: `${method} ${url} → ${res.status} (${elapsedMs}ms)`,
    };

    return {
      ok: true,
      status: res.status,
      headers: respHeaders,
      body: text,
      truncated,
      finalUrl: url,
      elapsedMs,
      evidence,
    };
  }
}

async function readBodyCapped(
  res: Response,
  cap: number,
  timeoutMs: number,
): Promise<{ text: string; truncated: boolean }> {
  if (!res.body) return { text: '', truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  const deadline = Date.now() + timeoutMs;
  try {
    for (;;) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) { truncated = true; break; }
      const { done, value } = await Promise.race([
        reader.read(),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('body read timeout')), remaining),
        ),
      ]).catch(() => ({ done: true, value: undefined as Uint8Array | undefined }));
      if (done) break;
      if (value) {
        chunks.push(value);
        total += value.byteLength;
        if (total >= cap) { truncated = true; break; }
      }
    }
  } catch {
    truncated = true;
  } finally {
    reader.cancel().catch(() => { /* best effort */ });
  }
  const buf = Buffer.concat(chunks.map((c) => Buffer.from(c)));
  return { text: buf.toString('utf8'), truncated };
}
