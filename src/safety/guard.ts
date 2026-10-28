/**
 * Scope guard — the authoritative decision on whether a URL may be requested.
 *
 * Rules (see docs/THREAT-MODEL.md):
 *  1. Only http/https.
 *  2. Host+port must exactly match the approved target origin.
 *  3. No embedded credentials (user:pass@host).
 *  4. Public-internet hosts are refused unless the operator opted in
 *     (config.allowPublicTargets) — loopback/private/link-local targets are
 *     always allowed.
 *  5. Redirects are validated hop-by-hop (same rules) with a hop cap.
 */
export interface ParsedOrigin {
  scheme: string;
  host: string; // lowercase hostname (no port)
  port: number;
}

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScopeError';
  }
}

export function parseOrigin(origin: string): ParsedOrigin {
  let u: URL;
  try {
    u = new URL(origin);
  } catch {
    throw new ScopeError(`invalid origin: ${origin}`);
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new ScopeError(`origin must be http(s), got ${u.protocol}`);
  }
  if (u.username || u.password) {
    throw new ScopeError('origin must not embed credentials');
  }
  return {
    scheme: u.protocol.replace(':', ''),
    host: u.hostname.toLowerCase(),
    port: u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80,
  };
}

const PRIVATE_V4 = [
  /^127\./, // loopback
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./, // link-local
  /^0\./,
];

export function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1' || h === '[::1]') return true;
  if (h.endsWith('.internal') || h.endsWith('.local') || h.endsWith('.lan') || h.endsWith('.home')) {
    return true;
  }
  return PRIVATE_V4.some((re) => re.test(h));
}

export interface GuardOptions {
  allowPublicTargets: boolean;
  maxRedirectHops: number;
}

export class ScopeGuard {
  readonly origin: ParsedOrigin;
  private readonly opts: GuardOptions;

  constructor(origin: string, opts: GuardOptions) {
    this.origin = parseOrigin(origin);
    this.opts = opts;
    if (!opts.allowPublicTargets && !isPrivateHost(this.origin.host)) {
      throw new ScopeError(
        `refusing public-internet target ${this.origin.host}: set OWASP_ALLOW_PUBLIC_TARGETS=1 ` +
        'and ensure you have written authorization before registering public targets',
      );
    }
  }

  /** Validate an absolute URL against the approved scope. Throws ScopeError. */
  checkUrl(rawUrl: string): URL {
    let u: URL;
    try {
      u = new URL(rawUrl);
    } catch {
      throw new ScopeError(`invalid URL: ${rawUrl}`);
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      throw new ScopeError(`blocked non-http(s) scheme: ${u.protocol}`);
    }
    if (u.username || u.password) {
      throw new ScopeError('blocked URL with embedded credentials');
    }
    const port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
    const host = u.hostname.toLowerCase();
    if (host !== this.origin.host || port !== this.origin.port) {
      throw new ScopeError(
        `out-of-scope request blocked: ${host}:${port} is not ${this.origin.host}:${this.origin.port}`,
      );
    }
    return u;
  }

  /** Validate a redirect Location header relative to the URL that produced it. */
  checkRedirect(fromUrl: string, location: string, hop: number): URL {
    if (hop >= this.opts.maxRedirectHops) {
      throw new ScopeError(`too many redirects (>${this.opts.maxRedirectHops})`);
    }
    const resolved = new URL(location, fromUrl);
    return this.checkUrl(resolved.toString());
  }

  /** True when a hostname is in scope for this target (used by crawlers). */
  inScope(url: string): boolean {
    try {
      this.checkUrl(url);
      return true;
    } catch {
      return false;
    }
  }
}
