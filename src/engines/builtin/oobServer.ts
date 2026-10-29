/**
 * OOB callback server (v2 Phase X, T-X1) — enables blind SSRF/XXE/injection
 * detection via unique per-attempt callback tokens.
 *
 * The server listens on a configurable port and records every incoming
 * request. Injection payloads embed callback URLs like:
 *   http://<callback-host>:<port>/<token>
 * If the target makes an outbound request to our listener, the token
 * confirms the injection was processed server-side.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { log } from '../../logging.ts';

export interface OOBHit {
  token: string;
  timestamp: string;
  sourceIp: string;
  path: string;
  method: string;
  headers: Record<string, string>;
}

export class OOBServer {
  private server: import('node:http').Server | undefined;
  private readonly hits = new Map<string, OOBHit[]>();
  private readonly tokens = new Set<string>();
  private _port = 0;
  private _host = '127.0.0.1';

  get port(): number { return this._port; }
  get host(): string { return this._host; }
  get url(): string { return `http://${this._host}:${this._port}`; }

  /** Start the OOB listener. Returns the base URL for callback injection. */
  start(host = '127.0.0.1', port = 0): Promise<string> {
    return new Promise((resolve) => {
      this._host = host;
      this.server = createServer((req, res) => this.handleRequest(req, res));
      this.server.listen(port, host, () => {
        this._port = (this.server!.address() as { port: number }).port;
        log.info('OOB callback server started', { url: this.url });
        resolve(this.url);
      });
    });
  }

  /** Generate a unique callback token + URL for an injection attempt. */
  generateCallback(prefix = 'oob'): string {
    const token = `${prefix}-${randomUUID().slice(0, 12)}`;
    this.tokens.add(token);
    return `${this.url}/${token}`;
  }

  /** Check if a specific token has been hit. */
  hasHit(token: string): boolean {
    return this.hits.has(token);
  }

  /** Get all hits for a token. */
  getHits(token: string): OOBHit[] {
    return this.hits.get(token) ?? [];
  }

  /** Get all recorded hits. */
  allHits(): Array<OOBHit & { token: string }> {
    return [...this.hits.entries()].flatMap(([token, hits]) =>
      hits.map((h) => ({ ...h, token })));
  }

  stop(): void {
    if (this.server) {
      this.server.close();
      this.server = undefined;
    }
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const urlPath = req.url ?? '/';
    const token = urlPath.split('/')[1]?.split('?')[0] ?? 'unknown';
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      headers[k] = Array.isArray(v) ? v.join(', ') : (v ?? '');
    }

    const hit: OOBHit = {
      token,
      timestamp: new Date().toISOString(),
      sourceIp: req.socket.remoteAddress ?? 'unknown',
      path: req.url ?? '/',
      method: req.method ?? 'GET',
      headers,
    };

    const existing = this.hits.get(token) ?? [];
    existing.push(hit);
    this.hits.set(token, existing);

    log.info('OOB callback received', { token, sourceIp: hit.sourceIp, path: hit.path });

    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('OK');
  }
}
