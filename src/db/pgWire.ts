/**
 * Minimal Postgres wire-protocol client (C1/T10.1-lite PoC) — stdlib only
 * (node:net), implementing protocol 3.0 simple query. This keeps the
 * zero-runtime-dependency ADR while proving the Postgres graph deployment is
 * writable from the platform itself.
 *
 * HONEST LIMIT: authentication supports TRUST only — the PoC container runs a
 * dedicated `pocuser` with a trust pg_hba line. Production use needs SCRAM-
 * SHA-256 (implementable with node:crypto) or the `pg` driver (an explicit
 * ADR exception). Unknown auth requests fail closed with a clear error.
 */
import { connect, type Socket } from 'node:net';

export interface PgRow { [column: string]: string | null; }
export interface PgResult { command: string; rowCount: number; columns: string[]; rows: PgRow[]; }

type Pending = {
  resolve: (r: PgResult) => void;
  reject: (e: Error) => void;
  columns: string[];
  rows: PgRow[];
  currentRow: (string | null)[];
  command: string;
};

export class PgWireClient {
  private sock: Socket | undefined;
  private buffer = Buffer.alloc(0);
  private pending: Pending | undefined;
  private readyResolve: (() => void) | undefined;
  private readyReject: ((e: Error) => void) | undefined;

  static async connect(host: string, port: number, user: string, database: string, connectTimeoutMs = 8000): Promise<PgWireClient> {
    const client = new PgWireClient();
    await client.doConnect(host, port, user, database, connectTimeoutMs);
    return client;
  }

  private doConnect(host: string, port: number, user: string, database: string, timeoutMs: number): Promise<void> {
    return new Promise((resolve, reject) => {
      this.readyResolve = resolve;
      this.readyReject = reject;
      const sock: Socket = connect({ host, port });
      this.sock = sock;
      const timer = setTimeout(() => reject(new Error(`postgres connect timeout (${timeoutMs}ms)`)), timeoutMs);
      void timer.unref?.();
      sock.on('error', (e) => {
        clearTimeout(timer);
        this.readyReject?.(new Error(`postgres connect failed: ${e.message}`));
        this.readyReject = undefined;
      });
      sock.on('connect', () => {
        // StartupMessage: len(int32) + protocol 3.0 (196608) + "user\0<user>\0database\0<db>\0\0"
        const params = `user\0${user}\0database\0${database}\0\0`;
        const body = Buffer.alloc(4 + 4 + params.length);
        body.writeInt32BE(4 + 4 + params.length, 0);
        body.writeInt32BE(196608, 4);
        body.write(params, 8);
        sock.write(body);
      });
      sock.on('data', (chunk: Buffer) => {
        clearTimeout(timer);
        this.buffer = Buffer.concat([this.buffer, chunk]);
        this.consume();
      });
      sock.on('close', () => {
        this.pending?.reject(new Error('connection closed'));
      });
    });
  }

  private consume(): void {
    for (;;) {
      if (this.buffer.length < 5) return;
      const type = String.fromCharCode(this.buffer[0]!);
      const len = this.buffer.readInt32BE(1);
      if (this.buffer.length < 1 + len) return;
      const body = this.buffer.subarray(5, 1 + len);
      this.buffer = this.buffer.subarray(1 + len);
      this.handleMessage(type, body);
    }
  }

  private handleMessage(type: string, body: Buffer): void {
    switch (type) {
      case 'R': { // Authentication
        const code = body.readInt32BE(0);
        if (code !== 0) {
          const what = code === 3 ? 'cleartext password' : code === 10 ? 'SCRAM-SHA-256' : `code ${code}`;
          this.readyReject?.(new Error(`postgres requested ${what} auth — this PoC client supports TRUST only (see header)`));
          this.readyReject = undefined;
        }
        break;
      }
      case 'S': // ParameterStatus — ignore
      case 'K': // BackendKeyData — ignore
        break;
      case 'Z': { // ReadyForQuery — terminates the connect handshake AND each query exchange
        if (this.pending !== undefined) {
          const p = this.pending;
          this.pending = undefined;
          p.resolve({ command: p.command, rowCount: p.rows.length, columns: p.columns, rows: p.rows });
        }
        this.readyResolve?.();
        this.readyResolve = undefined;
        this.readyReject = undefined;
        break;
      }
      case 'E': { // ErrorResponse
        const msg = parseErrorFields(body);
        const err = new Error(`postgres error: ${msg}`);
        if (this.readyReject !== undefined) { this.readyReject(err); this.readyReject = undefined; }
        else this.pending?.reject(err);
        this.pending = undefined;
        break;
      }
      case 'T': { // RowDescription
        if (this.pending === undefined) break;
        const n = body.readInt16BE(0);
        let off = 2;
        this.pending.columns = [];
        for (let i = 0; i < n; i++) {
          const end = body.indexOf(0, off);
          this.pending.columns.push(body.subarray(off, end).toString('utf8'));
          off = end! + 1 + 18; // name + fixed OID/len/mod/table bytes
        }
        break;
      }
      case 'D': { // DataRow
        if (this.pending === undefined) break;
        const n = body.readInt16BE(0);
        let off = 2;
        const row: PgRow = {};
        for (let i = 0; i < n; i++) {
          const cellLen = body.readInt32BE(off);
          off += 4;
          const col = this.pending.columns[i] ?? `col${i}`;
          if (cellLen === -1) row[col] = null;
          else { row[col] = body.subarray(off, off + cellLen).toString('utf8'); off += cellLen; }
        }
        this.pending.rows.push(row);
        break;
      }
      case 'C': { // CommandComplete
        if (this.pending === undefined) break;
        this.pending.command = body.subarray(0, body.indexOf(0)).toString('utf8').split(' ')[0] ?? '';
        break;
      }
      default:
        break; // CopyIn/Notice etc. — not used by the PoC
    }
  }

  async query(sql: string): Promise<PgResult> {
    if (this.sock === undefined) throw new Error('not connected');
    const p: Pending = { resolve: () => {}, reject: () => {}, columns: [], rows: [], currentRow: [], command: '' };
    return new Promise<PgResult>((resolve, reject) => {
      this.pending = { ...p, resolve, reject };
      const body = Buffer.from(sql, 'utf8');
      const msg = Buffer.alloc(1 + 4 + body.length + 1);
      msg.write('Q', 0);
      msg.writeInt32BE(4 + body.length + 1, 1);
      body.copy(msg, 5);
      this.sock!.write(msg);
    }).then((r) => {
      this.pending = undefined;
      return r;
    }, (e) => {
      this.pending = undefined;
      throw e;
    });
  }

  close(): void {
    this.sock?.end();
    this.sock = undefined;
  }
}

function parseErrorFields(body: Buffer): string {
  // ErrorResponse fields: (byte code, cstring value) terminated by 0x00
  let off = 0;
  let severity = '';
  let message = '';
  while (off < body.length) {
    const code = String.fromCharCode(body[off]!);
    if (body[off] === 0) break;
    const end = body.indexOf(0, off + 1);
    const value = body.subarray(off + 1, end).toString('utf8');
    if (code === 'S') severity = value;
    if (code === 'M') message = value;
    off = end! + 1;
  }
  return `${severity}: ${message}`.trim();
}
