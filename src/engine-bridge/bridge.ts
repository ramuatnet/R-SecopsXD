/**
 * TS EngineBridge (v2 Phase 0, T0.4) — spawns and supervises the Python
 * rsec-engine data plane, speaks the engine/proto/v1.md NDJSON JSON-RPC.
 *
 * Responsibilities: spawn/supervise, frame by newline, correlate responses by
 * id, per-call timeout, restart-on-crash (respawn on next call). Safety
 * policy travels IN the request envelope — the bridge never weakens it.
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { log } from '../logging.ts';

export interface BridgeRequestParams {
  /** ping/shutdown may omit scope; engine methods require it. */
  scope?: { origins: string[]; allow_public: boolean; max_redirect_hops?: number } | undefined;
  scan_id: string;
  action_id: string;
  budget?: { max_requests?: number; max_ms?: number };
  safety?: { rate_per_sec?: number; burst?: number; max_concurrency?: number };
  args?: Record<string, unknown>;
}

export interface BridgeResponse {
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  final_url?: string;
  elapsed_ms?: number;
  truncated?: boolean;
  redirect_chain?: string[];
  pong?: boolean;
  engine?: string;
  version?: string;
  tech?: string[];
  ok?: boolean;
}

export class BridgeError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export class EngineBridge {
  private proc: ChildProcessWithoutNullStreams | undefined;
  private readonly pending = new Map<string, { resolve: (v: BridgeResponse) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private readonly buffer: string[] = [];
  private readonly scriptPath: string;
  private readonly pythonPath: string;
  private crashCount = 0;

  constructor(opts: { scriptPath?: string; pythonPath?: string } = {}) {
    this.scriptPath = opts.scriptPath ?? join(process.cwd(), 'engine', 'rsec_engine.py');
    this.pythonPath = opts.pythonPath ?? 'python';
  }

  get running(): boolean {
    return this.proc !== undefined && this.proc.exitCode === null;
  }

  get crashes(): number {
    return this.crashCount;
  }

  /** Spawn the engine if not running. Throws when the interpreter is unavailable. */
  start(): void {
    if (this.running) return;
    if (!existsSync(this.scriptPath)) {
      throw new BridgeError('engine_missing', `engine script not found: ${this.scriptPath}`);
    }
    const child = spawn(this.pythonPath, ['-u', this.scriptPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    this.proc = child as ChildProcessWithoutNullStreams;

    let stdoutBuf = '';
    this.proc.stdout.on('data', (chunk: Buffer) => {
      stdoutBuf += chunk.toString('utf8');
      let idx: number;
      while ((idx = stdoutBuf.indexOf('\n')) >= 0) {
        const line = stdoutBuf.slice(0, idx).trim();
        stdoutBuf = stdoutBuf.slice(idx + 1);
        if (line === '') continue;
        this.route(line);
      }
    });
    this.proc.stderr.on('data', (chunk: Buffer) => {
      log.debug('[rsec-engine stderr]', { line: chunk.toString('utf8').slice(0, 200) });
    });
    this.proc.on('exit', (code) => {
      this.proc = undefined;
      this.crashCount++;
      for (const [, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(new BridgeError('engine_died', `engine exited (code ${code ?? 'signal'}) before responding`));
      }
      this.pending.clear();
      log.warn('rsec-engine exited', { code: code ?? 'signal', crashes: this.crashCount });
    });
  }

  private route(line: string): void {
    try {
      const msg = JSON.parse(line) as { id?: string; result?: BridgeResponse; error?: { code: string; message: string } };
      const id = msg.id ?? '';
      const p = this.pending.get(id);
      if (!p) return;
      this.pending.delete(id);
      clearTimeout(p.timer);
      if (msg.error) p.reject(new BridgeError(msg.error.code, msg.error.message));
      else p.resolve(msg.result ?? {});
    } catch {
      log.warn('rsec-engine: unparseable frame dropped');
    }
  }

  /** One JSON-RPC call. Respawn-on-crash: restarts the engine if it died. */
  async call<T = BridgeResponse>(method: string, params: BridgeRequestParams, timeoutMs = 30_000): Promise<T> {
    if (!this.running) this.start();
    const id = randomUUID();
    const frame = JSON.stringify({ id, method, params }) + '\n';

    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new BridgeError('timeout', `engine call ${method} exceeded ${timeoutMs}ms`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => resolve(v as T),
        reject,
        timer,
      });
      try {
        this.proc!.stdin.write(frame);
      } catch (e) {
        this.pending.delete(id);
        clearTimeout(timer);
        reject(new BridgeError('engine_died', `write failed: ${e instanceof Error ? e.message : String(e)}`));
      }
    });
  }

  /** Convenience: ping with respawn. */
  async ping(timeoutMs = 10_000): Promise<{ pong: boolean; engine: string; version: string }> {
    return this.call('ping', { scan_id: 'bridge', action_id: 'ping' }, timeoutMs);
  }

  stop(): void {
    if (this.proc && this.proc.exitCode === null) {
      try {
        this.proc.stdin.write(JSON.stringify({ id: 'shutdown', method: 'shutdown', params: {} }) + '\n');
      } catch { /* already gone */ }
      setTimeout(() => {
        try { this.proc?.kill(); } catch { /* gone */ }
      }, 500);
    }
    this.proc = undefined;
  }
}
