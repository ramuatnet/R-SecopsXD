/**
 * Structured JSON-lines logger. Everything the platform logs goes through
 * here; secret-bearing values must be redacted by callers (evidence already
 * is before it reaches a log call).
 */
import { redactText } from './core/redact.ts';

type Level = 'debug' | 'info' | 'warn' | 'error';
const LEVELS: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

let minLevel: number = LEVELS.info;

export function setLogLevel(level: Level): void {
  minLevel = LEVELS[level] ?? LEVELS.info;
}

function write(level: Level, msg: string, fields?: Record<string, unknown>): void {
  if (LEVELS[level] < minLevel) return;
  const entry: Record<string, unknown> = {
    ts: new Date().toISOString(),
    level,
    msg,
  };
  for (const [k, v] of Object.entries(fields ?? {})) {
    entry[k] = typeof v === 'string' ? redactText(v, 512) : v;
  }
  process.stdout.write(`${JSON.stringify(entry)}\n`);
}

export const log = {
  debug: (msg: string, fields?: Record<string, unknown>) => write('debug', msg, fields),
  info: (msg: string, fields?: Record<string, unknown>) => write('info', msg, fields),
  warn: (msg: string, fields?: Record<string, unknown>) => write('warn', msg, fields),
  error: (msg: string, fields?: Record<string, unknown>) => write('error', msg, fields),
};
