/**
 * Bearer-token authentication. Every route except /api/health and static UI
 * assets requires it.
 *
 * CSRF posture: the token must be supplied via the Authorization header,
 * which cross-origin pages cannot cause a browser to send. No cookies are
 * used, so no CSRF token is needed (see docs/THREAT-MODEL.md).
 */
import { ApiError, type Handler, type RequestContext } from './router.ts';

export function extractBearerToken(req: Request): string {
  const header = req.headers.get('authorization') ?? '';
  const m = /^Bearer\s+(.+)$/i.exec(header);
  return m?.[1]?.trim() ?? '';
}

/** Wrap a handler so it only runs with a valid bearer token. */
export function withAuth(verify: (token: string) => boolean, handler: Handler): Handler {
  return async (ctx: RequestContext) => {
    const token = extractBearerToken(ctx.req);
    if (token === '' || !verify(token)) {
      throw new ApiError(401, 'unauthorized', 'missing or invalid bearer token');
    }
    ctx.state.authenticated = true;
    return handler(ctx);
  };
}
