/**
 * Subprocess plumbing for scanner adapters. No shell is ever involved
 * (spawn with argument array, shell: false), output is capped, and every
 * child is timeout- and abort-controlled.
 */
import { spawn } from 'node:child_process';
import { accessSync, constants } from 'node:fs';
import { join, delimiter } from 'node:path';
import { log } from '../../logging.ts';

export interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
  command: string;
  durationMs: number;
}

export class BinaryNotFoundError extends Error {
  readonly binary: string;
  constructor(binary: string) {
    super(`binary not found: ${binary}`);
    this.binary = binary;
  }
}

const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

/**
 * Resolve a binary name to an absolute path, probing Windows PATHEXT
 * extensions (.exe/.cmd/.bat) since spawn() without a shell cannot exec
 * .cmd shims directly.
 */
export function resolveBinary(name: string): string | undefined {
  const exts = process.platform === 'win32' ? ['', '.exe', '.cmd', '.bat'] : [''];
  const dirs = (process.env.PATH ?? '').split(delimiter).filter(Boolean);
  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = join(dir, name + ext);
      try {
        accessSync(candidate, constants.X_OK);
        return candidate;
      } catch { /* keep probing */ }
    }
  }
  return undefined;
}

export async function runProcess(
  command: string,
  args: string[],
  opts: { timeoutMs: number; cwd?: string; signal?: AbortSignal },
): Promise<RunResult> {
  const resolved = resolveBinary(command);
  if (!resolved) throw new BinaryNotFoundError(command);

  return new Promise<RunResult>((resolve, reject) => {
    const started = Date.now();
    const child = spawn(resolved, args, {
      cwd: opts.cwd,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let settled = false;

    const kill = (): void => {
      timedOut = true;
      try {
        if (process.platform === 'win32') {
          // taskkill the tree; child.kill alone does not kill .cmd wrappers
          spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true });
        } else {
          child.kill('SIGKILL');
        }
      } catch { /* already exited */ }
    };

    const timer = setTimeout(kill, opts.timeoutMs);
    const onAbort = (): void => {
      kill();
    };
    opts.signal?.addEventListener('abort', onAbort, { once: true });

    const finish = (exitCode: number | null, err?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
      if (err !== undefined) {
        reject(err);
        return;
      }
      resolve({
        stdout, stderr, exitCode, timedOut,
        command: `${command} ${args.join(' ')}`,
        durationMs: Date.now() - started,
      });
    };

    child.stdout!.on('data', (chunk: Buffer) => {
      if (stdoutBytes < MAX_OUTPUT_BYTES) {
        stdoutBytes += chunk.length;
        stdout += chunk.toString('utf8');
      }
    });
    child.stderr!.on('data', (chunk: Buffer) => {
      if (stderrBytes < MAX_OUTPUT_BYTES) {
        stderrBytes += chunk.length;
        stderr += chunk.toString('utf8');
      }
    });
    child.on('error', (err) => {
      log.warn('process error', { command, error: err.message });
      finish(null, err);
    });
    child.on('close', (code) => finish(code));
  });
}

/** Run `<binary> --version` and return the first output line. */
export async function detectVersion(
  binary: string,
  args: string[] = ['--version'],
  timeoutMs = 15_000,
): Promise<string | undefined> {
  const res = await runProcess(binary, args, { timeoutMs });
  const line = (res.stdout || res.stderr).split('\n')[0]?.trim();
  return line === '' ? undefined : line;
}
