/**
 * Engine interface. Built-in engines and external scanner adapters implement
 * the same contract; the orchestrator, UI and coverage reporting treat them
 * uniformly.
 */
import type {
  CategoryCapability, EngineAvailability, EngineInfo, Evidence, OwaspCategory, RawFinding,
  ScanMode, Target,
} from '../core/types.ts';
import type { ScopedHttpClient, RequestStats } from '../scan/httpClient.ts';
import type { ScopeGuard } from '../safety/guard.ts';

export type { CategoryCapability, EngineAvailability, EngineInfo };

export interface CrawlPage {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
  forms: Array<{ action: string; method: string; fields: string[]; hasPasswordField: boolean }>;
  links: string[];
}

export interface CrawlCorpus {
  pages: CrawlPage[];
  robots: { disallow: string[]; fetched: boolean };
  /** API endpoints extracted from served JavaScript bundles (endpoint-discovery). */
  discoveredEndpoints?: string[] | undefined;
}

export interface CredentialProfile {
  username: string;
  password: string;
  role?: string | undefined;
  /** 'form' (default): POST form-encoded to a discovered/credential-provided form action.
   *  'json': POST JSON {username,password} to loginUrl; session = cookie or bearer token from response. */
  loginType?: string | undefined;
  loginUrl?: string | undefined;
  usernameField?: string | undefined;
  passwordField?: string | undefined;
  /** For json login: the JSON path to the token in the response (e.g. 'token', 'access_token'). */
  tokenField?: string | undefined;
}

export interface ScanContext {
  scanId: string;
  target: Target;
  mode: ScanMode;
  /** Primary test account (B1). */
  credentials?: CredentialProfile | undefined;
  /** Second test identity with a different role — enables the cross-role matrix. */
  credentialsSecondary?: CredentialProfile | undefined;
  client: ScopedHttpClient;
  guard: ScopeGuard;
  stats: RequestStats;
  signal: AbortSignal;
  /** Directory for raw engine output (provenance), e.g. data/scan-<id>/<engine>/ */
  workDir: string;
  /** Shared between engines: crawler-lite fills this, passive observers read it. */
  crawl?: CrawlCorpus | undefined;
  /** A2: verified/probable findings from earlier stages — seeds for variant-hunter. */
  seedFindings?: import('../core/types.ts').Finding[] | undefined;
  log: (msg: string, fields?: Record<string, unknown>) => void;
}

export interface Engine {
  info: EngineInfo;
  availability(): Promise<EngineAvailability>;
  /**
   * Execute the engine. Returns raw findings to be normalized by the
   * orchestrator. Engines must honor ctx.signal (cancel/timeout) and may
   * throw on fatal errors (recorded as engine failure).
   */
  run(ctx: ScanContext): Promise<EngineRunResult>;
}

export interface EngineRunResult {
  findings: RawFinding[];
  version?: string | undefined;
  detail?: string | undefined;
  /** Set when the engine could not execute its checks at all (e.g. no credentials). */
  notExecutedReason?: string | undefined;
  /** HON-01 (edgetask.md): a dependency failed — dependants are NOT_EXECUTED_DEGRADED, never clean. */
  degraded?: boolean | undefined;
}

/** Convenience builder for capability maps. */
export function cap(note: string, strength: 'strong' | 'heuristic' = 'strong'): CategoryCapability {
  return { note, strength };
}

export type { Evidence, OwaspCategory };
