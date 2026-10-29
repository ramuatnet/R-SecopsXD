/**
 * Platform configuration. All values have safe defaults; environment overrides
 * use the OWASP_* prefix. Hostname binding defaults to loopback.
 */
export interface Config {
  host: string;
  port: number;
  dataDir: string;
  /** Auth token; when unset a random one is generated on first boot. */
  token?: string | undefined;
  allowPublicTargets: boolean;
  rateLimitPerSecond: number;
  rateBurst: number;
  maxConcurrency: number;
  maxConcurrentScans: number;
  requestTimeoutMs: number;
  engineTimeoutMs: number;
  scanTimeoutMs: number;
  maxCrawlPages: number;
  /** Set when OWASP_MAX_CRAWL_PAGES was provided explicitly — overrides profile caps. */
  maxCrawlPagesExplicit: boolean;
  /** T-W4: autonomous loop settings. */
  loopEnabled: boolean;
  loopMaxIterations: number;
  loopMaxRequests: number;
  loopMaxMs: number;
  loopSeed: number;
  loopSubscanFanout: number;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

function num(name: string, def: number): number {
  const v = process.env[name];
  if (v === undefined || v === '') return def;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : def;
}

function bool(name: string, def: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === '') return def;
  return /^(1|true|yes)$/i.test(v);
}

export function loadConfig(): Config {
  const level = process.env.OWASP_LOG_LEVEL;
  return {
    host: process.env.OWASP_HOST ?? '127.0.0.1',
    port: num('OWASP_PORT', 7788),
    dataDir: process.env.OWASP_DATA_DIR ?? 'data',
    token: process.env.OWASP_TOKEN || undefined,
    allowPublicTargets: bool('OWASP_ALLOW_PUBLIC_TARGETS', false),
    rateLimitPerSecond: num('OWASP_RATE_RPS', 5),
    rateBurst: num('OWASP_RATE_BURST', 10),
    maxConcurrency: num('OWASP_MAX_CONCURRENCY', 8),
    maxConcurrentScans: num('OWASP_MAX_CONCURRENT_SCANS', 2),
    requestTimeoutMs: num('OWASP_REQUEST_TIMEOUT_MS', 15_000),
    engineTimeoutMs: num('OWASP_ENGINE_TIMEOUT_MS', 600_000),
    scanTimeoutMs: num('OWASP_SCAN_TIMEOUT_MS', 1_800_000),
    maxCrawlPages: num('OWASP_MAX_CRAWL_PAGES', 30),
    maxCrawlPagesExplicit: bool('OWASP_MAX_CRAWL_PAGES_EXPLICIT', false),
    logLevel: (['debug', 'info', 'warn', 'error'].includes(level ?? '')
      ? level
      : 'info') as Config['logLevel'],
    loopEnabled: bool('OWASP_LOOP_ENABLED', false),
    loopMaxIterations: num('OWASP_LOOP_MAX_ITERATIONS', 40),
    loopMaxRequests: num('OWASP_LOOP_MAX_REQUESTS', 800),
    loopMaxMs: num('OWASP_LOOP_MAX_MS', 600_000),
    loopSeed: num('OWASP_LOOP_SEED', 0),
    loopSubscanFanout: num('OWASP_LOOP_SUBSCAN_FANOUT', 3),
  };
}
