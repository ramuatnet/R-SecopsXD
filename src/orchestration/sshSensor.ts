/**
 * Credentialed SSH sensor (newtask.md E4) — read-only host inventory over
 * SSH using the platform's external-tool pattern (the OS ssh binary via
 * runProcess; shell:false, argument array, timeout + abort controlled).
 *
 * Commands are a FIXED read-only allowlist — no operator-supplied command
 * strings are ever executed. Results merge into the asset graph on the host
 * node (by asset UID) with provenance 'credentialed' (3.3: credentialed value
 * wins over the uncredentialed guess, which is retained as history).
 *
 * When the ssh binary or the target is unreachable, the sensor reports
 * honestly (notExecutedReason) — never fabricates inventory.
 */
import { runProcess, resolveBinary } from '../engines/adapters/common.ts';
import { assetUid } from '../graph/uid.ts';
import type { GraphStore } from '../graph/graph.ts';
import { log } from '../logging.ts';

export interface SshTarget {
  host: string;
  port: number;
  user: string;
  /** Path to the PEM/OpenSSH private key (credential vault responsibility in production). */
  keyPath: string;
}

/** Fixed read-only allowlist — the sensor never executes anything else. */
export const INVENTORY_COMMANDS: Array<{ id: string; cmd: string }> = [
  { id: 'kernel', cmd: 'uname -sr' },
  { id: 'os-release', cmd: 'cat /etc/os-release 2>/dev/null | head -4' },
  { id: 'listening-ports', cmd: '(ss -tln 2>/dev/null || netstat -tln 2>/dev/null) | tail -n +2' },
  { id: 'packages', cmd: '(dpkg -l 2>/dev/null | tail -n +6 | awk \'{print $2"="$3}\'; apk info -v 2>/dev/null; rpm -qa 2>/dev/null) | head -100' },
  { id: 'uptime', cmd: 'uptime -p 2>/dev/null || uptime' },
];

export interface SshInventory {
  host: string;
  kernel?: string | undefined;
  osRelease?: string | undefined;
  listeningPorts: number[];
  packages: string[];
  uptime?: string | undefined;
  commandsRun: string[];
  commandsFailed: string[];
}

function parsePorts(ssOutput: string): number[] {
  const ports = new Set<number>();
  for (const line of ssOutput.split('\n')) {
    const m = /[:.](\d+)\s/.exec(line) ?? /[:.](\d+)$/.exec(line.trim());
    if (m !== null) {
      const p = Number(m[1]);
      if (p > 0 && p < 65536) ports.add(p);
    }
  }
  return [...ports].sort((a, b) => a - b);
}

export class CredentialedSshSensor {
  readonly available: boolean;

  constructor() {
    this.available = resolveBinary('ssh') !== undefined;
  }

  private async runCommand(target: SshTarget, command: string, signal?: AbortSignal): Promise<string> {
    const res = await runProcess('ssh', [
      '-i', target.keyPath,
      '-p', String(target.port),
      '-o', 'StrictHostKeyChecking=no',
      '-o', 'UserKnownHostsFile=/dev/null',
      '-o', 'ConnectTimeout=10',
      '-o', 'BatchMode=yes',
      `${target.user}@${target.host}`,
      command,
    ], { timeoutMs: 30_000, ...(signal !== undefined ? { signal } : {}) });
    if (res.exitCode !== 0) throw new Error(`ssh exit ${res.exitCode}: ${res.stderr.slice(0, 200)}`);
    return res.stdout;
  }

  /** Read-only inventory of one host. Never executes anything outside the allowlist. */
  async inventory(target: SshTarget, signal?: AbortSignal): Promise<SshInventory> {
    if (!this.available) throw new Error('ssh binary not found on PATH');
    const inv: SshInventory = { host: target.host, listeningPorts: [], packages: [], commandsRun: [], commandsFailed: [] };
    for (const c of INVENTORY_COMMANDS) {
      try {
        const out = (await this.runCommand(target, c.cmd, signal)).trim();
        inv.commandsRun.push(c.id);
        if (c.id === 'kernel') inv.kernel = out.split('\n')[0];
        else if (c.id === 'os-release') inv.osRelease = out.split('\n')[0]?.replace(/^NAME="?|"?$/g, '');
        else if (c.id === 'listening-ports') inv.listeningPorts = parsePorts(out).slice(0, 50);
        else if (c.id === 'packages') inv.packages = out.split('\n').filter((l) => l.includes('=') || /[\w+-]-[\d.]/.test(l)).slice(0, 100);
        else if (c.id === 'uptime') inv.uptime = out.split('\n')[0];
      } catch (e) {
        inv.commandsFailed.push(c.id);
        log.warn('ssh inventory command failed', { host: target.host, command: c.id, error: e instanceof Error ? e.message : String(e) });
      }
    }
    return inv;
  }

  /** Merge inventory into the graph: credentialed attributes win (3.3). */
  mergeIntoGraph(inv: SshInventory, store: GraphStore, at = new Date().toISOString()): string {
    const hostUid = store.upsertNode({
      type: 'host', identity: inv.host, display: inv.host,
      attributes: {
        kernel: inv.kernel ?? null, os: inv.osRelease ?? null, uptime: inv.uptime ?? null,
        credentialed: true, packagesSeen: inv.packages.length,
      },
      provenance: ['credentialed-ssh'],
    });
    for (const p of inv.listeningPorts) {
      store.upsertEdge({
        edgeType: 'exposes',
        src: { type: 'host', identity: inv.host, display: inv.host },
        dst: { type: 'port', identity: `${inv.host}:${p}`, display: `${inv.host}:${p}`, attributes: { credentialed: true } },
        provenance: ['credentialed-ssh'],
      }, at);
    }
    void assetUid; // uid consistency guaranteed by the store
    return hostUid;
  }
}
