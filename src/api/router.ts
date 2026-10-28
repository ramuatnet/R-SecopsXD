/** Minimal typed HTTP router (no dependencies). */
export type Handler = (ctx: RequestContext) => Promise<Response> | Response;

export interface RequestContext {
  req: Request;
  params: Record<string, string>;
  url: URL;
  /** Parsed JSON body for POST/PUT; undefined otherwise. Throws ApiError on invalid JSON. */
  body<T = unknown>(): Promise<T>;
  /** Extra context attached by middleware (e.g. auth info). */
  state: Record<string, unknown>;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

interface Route {
  method: string;
  pattern: RegExp;
  paramNames: string[];
  handler: Handler;
}

function compilePattern(path: string): { pattern: RegExp; paramNames: string[] } {
  const paramNames: string[] = [];
  const regexSrc = path
    .split('/')
    .map((seg) => {
      if (seg.startsWith(':')) {
        paramNames.push(seg.slice(1));
        return '([^/]+)';
      }
      return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return { pattern: new RegExp(`^${regexSrc}/?$`), paramNames };
}

export class Router {
  private readonly routes: Route[] = [];

  add(method: string, path: string, handler: Handler): this {
    const { pattern, paramNames } = compilePattern(path);
    this.routes.push({ method: method.toUpperCase(), pattern, paramNames, handler });
    return this;
  }

  get(path: string, handler: Handler): this { return this.add('GET', path, handler); }
  post(path: string, handler: Handler): this { return this.add('POST', path, handler); }
  delete(path: string, handler: Handler): this { return this.add('DELETE', path, handler); }

  /** Returns handler+params for a request, or undefined when no route matches. */
  match(method: string, pathname: string): { handler: Handler; params: Record<string, string> } | undefined {
    for (const r of this.routes) {
      if (r.method !== method.toUpperCase()) continue;
      const m = r.pattern.exec(pathname);
      if (!m) continue;
      const params: Record<string, string> = {};
      r.paramNames.forEach((name, i) => { params[name] = decodeURIComponent(m[i + 1] ?? ''); });
      return { handler: r.handler, params };
    }
    return undefined;
  }

  /** True when any route matches the path regardless of method (for 405s). */
  pathExists(pathname: string): boolean {
    return this.routes.some((r) => r.pattern.test(pathname));
  }
}

export function jsonResponse(data: unknown, status = 200, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
}

export function errorResponse(e: unknown): Response {
  if (e instanceof ApiError) {
    return jsonResponse({ error: e.code, message: e.message }, e.status);
  }
  const message = e instanceof Error ? e.message : String(e);
  return jsonResponse({ error: 'internal', message }, 500);
}

/** Read and parse a JSON body with a size cap. */
export async function readJsonBody(req: Request, maxBytes = 1_000_000): Promise<unknown> {
  const text = await req.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    throw new ApiError(413, 'body_too_large', `body exceeds ${maxBytes} bytes`);
  }
  if (text.trim() === '') return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(400, 'invalid_json', 'request body is not valid JSON');
  }
}
