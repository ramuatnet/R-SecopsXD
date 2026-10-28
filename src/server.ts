/**
 * Composition root: config, database, token bootstrap, engine registry,
 * orchestrator, routes and static UI serving.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, extname, normalize } from 'node:path';
import { loadConfig, type Config } from './config.ts';
import { Database, generateToken } from './db/database.ts';
import { EngineRegistry } from './engines/registry.ts';
import { Orchestrator } from './scan/orchestrator.ts';
import { Router, errorResponse, jsonResponse, ApiError, type Handler, type RequestContext } from './api/router.ts';
import { withAuth } from './api/auth.ts';
import * as h from './api/handlers.ts';
import { log, setLogLevel } from './logging.ts';
import { PROFILES } from './core/profiles.ts';

const VERSION = '0.1.0';
const UI_DIR = join(import.meta.dirname, 'ui');

export interface Platform {
  config: Config;
  db: Database;
  registry: EngineRegistry;
  orchestrator: Orchestrator;
  token: string;
  router: Router;
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function staticFile(relPath: string): Response | undefined {
  const safe = normalize(relPath).replace(/^(\.\.[/\\])+/, '');
  const full = join(UI_DIR, safe);
  if (!full.startsWith(UI_DIR) || !existsSync(full)) return undefined;
  const body = readFileSync(full);
  return new Response(new Uint8Array(body), {
    headers: {
      'content-type': MIME[extname(full)] ?? 'application/octet-stream',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

export function buildPlatform(config = loadConfig()): Platform {
  setLogLevel(config.logLevel);
  const db = new Database(config.dataDir);
  const registry = new EngineRegistry(config);
  const orchestrator = new Orchestrator(db, config, registry);

  // Auth token: env override > persisted file > generated (persisted to file).
  const tokenFile = join(config.dataDir, 'auth-token.txt');
  let token = config.token;
  if (!token && existsSync(tokenFile)) {
    token = readFileSync(tokenFile, 'utf8').trim();
  }
  if (!token) {
    token = generateToken();
  }
  writeFileSync(tokenFile, token, { flag: 'w' });
  db.setAuthToken(token);

  const app: h.App = { config, db, orchestrator, registry, version: VERSION };
  const authed = (handler: Handler): Handler => withAuth(db.verifyToken.bind(db), handler);

  const router = new Router();
  router.get('/api/health', h.health(app));
  router.get('/api/owasp', authed(h.listOwasp(app)));
  router.get('/api/targets', authed(h.listTargets(app)));
  router.post('/api/targets', authed(h.createTarget(app)));
  router.get('/api/targets/:id', authed(h.targetSummary(app)));
  router.get('/api/targets/:id/diff', authed(h.targetDiff(app)));
  router.get('/api/targets/:id/model', authed(h.targetModel(app)));
  router.post('/api/targets/:id/approve', authed(h.approveTarget(app)));
  router.post('/api/targets/:id/credentials', authed(h.setCredentials(app)));
  router.delete('/api/targets/:id/credentials', authed(h.deleteCredentials(app)));
  router.delete('/api/targets/:id', authed(h.deleteTarget(app)));
  router.get('/api/profiles', authed(h.listProfiles(app)));
  router.get('/api/engines', authed(h.listEngines(app)));
  router.post('/api/scans', authed(h.startScan(app)));
  router.get('/api/scans', authed(h.listScans(app)));
  router.get('/api/scans/:id', authed(h.getScan(app)));
  router.post('/api/scans/:id/cancel', authed(h.cancelScan(app)));
  router.get('/api/scans/:id/findings', authed(h.listFindings(app)));
  router.post('/api/scans/:scanId/findings/:findingId/status', authed(h.triageFinding(app)));
  router.get('/api/scans/:id/report', authed(h.getReport(app)));
  router.get('/api/audit', authed(h.listAudit(app)));

  return { config, db, registry, orchestrator, token, router };
}

/** The full request pipeline (API + static UI), exposed for tests and the HTTP adapter. */
export function createRequestHandler(platform: Platform): (req: Request) => Promise<Response> {
  const { db, router } = platform;
  return async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    try {
      if (url.pathname.startsWith('/api/')) {
        const match = router.match(req.method, url.pathname);
        if (!match) {
          if (router.pathExists(url.pathname)) return jsonResponse({ error: 'method_not_allowed' }, 405);
          return jsonResponse({ error: 'not_found', message: 'no such API route' }, 404);
        }
        const ctx: RequestContext = {
          req,
          params: match.params,
          url,
          body: async <T,>() => (await import('./api/router.ts')).readJsonBody(req) as Promise<T>,
          state: {},
        };
        return await match.handler(ctx);
      }
      // Static UI (no auth — the UI itself holds the token in memory only)
      if (req.method === 'GET') {
        const file = url.pathname === '/' ? 'index.html' : url.pathname.replace(/^\/ui\//, '');
        const res = staticFile(file);
        if (res) return res;
      }
      return jsonResponse({ error: 'not_found' }, 404);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        db.audit({ actor: 'anonymous', action: 'auth.failed', details: { path: url.pathname } });
      }
      const status = e instanceof ApiError ? e.status : 500;
      if (status >= 500) {
        log.error('request failed', { path: url.pathname, error: e instanceof Error ? e.stack : String(e) });
      }
      return errorResponse(e);
    }
  };
}

export function startServer(platform: Platform): { shutdown: () => void } {
  const { config, db, router, token } = platform;
  const handler = createRequestHandler(platform);

  if (!['127.0.0.1', 'localhost', '::1'].includes(config.host)) {
    if (!process.env.OWASP_TOKEN) {
      throw new Error(
        `refusing to bind non-loopback host ${config.host} without an explicitly configured token: ` +
        'set OWASP_TOKEN before binding to a network interface',
      );
    }
    log.warn('binding non-loopback host — ensure network-level access control', { host: config.host });
  }

  const shutdown = (): void => {
    db.close();
  };

  void (async () => {
    const { createServer } = await import('node:http');
    const srv = createServer((req, res) => {
      void (async () => {
        const headers = new Headers();
        for (const [k, v] of Object.entries(req.headers)) {
          if (typeof v === 'string') headers.set(k, v);
          else if (Array.isArray(v)) headers.set(k, v.join(', '));
        }
        const hasBody = !['GET', 'HEAD'].includes(req.method ?? '');
        const init: RequestInit = { method: req.method ?? 'GET', headers };
        if (hasBody) {
          init.body = await readBody(req);
          (init as { duplex?: string }).duplex = 'half';
        }
        const request = new Request(`http://${req.headers.host ?? 'localhost'}${req.url}`, init);
        const response = await handler(request);
        res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
        if (response.body) {
          const reader = response.body.getReader();
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            res.write(Buffer.from(value));
          }
        }
        res.end();
      })().catch((e) => {
        log.error('handler crashed', { error: e instanceof Error ? e.stack : String(e) });
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal' }));
      });
    });
    srv.listen(config.port, config.host, () => {
      log.info('platform listening', { host: config.host, port: config.port, version: VERSION });
      log.info(`auth token written to ${join(config.dataDir, 'auth-token.txt')} (also printed below once)`);
      process.stdout.write(`AUTH TOKEN: ${token}\n`);
      log.info(`profiles: ${PROFILES.map((p) => p.id).join(', ')}`);
    });
    const onClose = (): void => {
      srv.close();
      shutdown();
      process.exit(0);
    };
    process.on('SIGINT', onClose);
    process.on('SIGTERM', onClose);
  })();

  return { shutdown };
}

async function readBody(req: import('node:http').IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > 1_000_000) throw new ApiError(413, 'body_too_large', 'request body exceeds 1MB');
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

export function main(): void {
  const config = loadConfig();
  const platform = buildPlatform(config);
  startServer(platform);
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop() ?? '@@')) {
  main();
}
