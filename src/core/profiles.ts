/**
 * Scan profiles: named presets that select engines per scan mode and target
 * kind. Profiles are declarative and safe to expose via the API/UI.
 */
import type { ScanMode, TargetKind } from './types.ts';

export interface Profile {
  id: string;
  name: string;
  description: string;
  targetKinds: TargetKind[];
  maxCrawlPages: number;
  /** Engines run in passive mode (and always in active mode). */
  passiveEngines: string[];
  /** Engines run ONLY in active mode (requires explicit scan.mode=active). */
  activeEngines: string[];
}

export const PROFILES: Profile[] = [
  {
    id: 'quick-passive',
    name: 'Quick passive assessment',
    description: 'Crawls up to 10 pages with plain GETs and observes HTTP security posture. Sends no active probes. Suitable for continuous monitoring and first look.',
    targetKinds: ['webapp'],
    maxCrawlPages: 50,
    passiveEngines: ['builtin.crawler-lite', 'builtin.http-observation', 'builtin.tls-analysis', 'builtin.openapi-policy', 'builtin.endpoint-discovery'],
    activeEngines: [],
  },
  {
    id: 'standard-passive',
    name: 'Standard passive assessment',
    description: 'Crawls up to 30 pages and observes HTTP security posture incl. TLS and API-spec policy signals. No active probes.',
    targetKinds: ['webapp'],
    maxCrawlPages: 200,
    passiveEngines: ['builtin.crawler-lite', 'builtin.http-observation', 'builtin.tls-analysis', 'builtin.openapi-policy', 'builtin.endpoint-discovery'],
    activeEngines: [],
  },
  {
    id: 'standard-active',
    name: 'Standard active assessment',
    description: 'Passive crawl (incl. TLS + API-spec policy) + bounded active probes: sensitive-path checks, input-reflection markers, authentication probes (enumeration + rate limiting), open-redirect and authenticated checks when a credential profile is configured. Also resolves the target hostname (DNS) and port-scans the resolved IPs (service fingerprinting, version→CVE matching, OS hints) — context-based infrastructure recon, no separate CIDR target needed. Must be explicitly enabled on an approved target.',
    targetKinds: ['webapp'],
    maxCrawlPages: 200,
    passiveEngines: ['builtin.crawler-lite', 'builtin.http-observation', 'builtin.tls-analysis', 'builtin.openapi-policy', 'builtin.endpoint-discovery'],
    activeEngines: ['builtin.path-probe', 'builtin.reflection-probe', 'builtin.auth-probe', 'builtin.redirect-probe', 'builtin.authenticated-probe', 'builtin.graphql-probe', 'builtin.blind-ssrf-probe', 'builtin.variant-hunter', 'builtin.host-infra'],
  },
  {
    id: 'external-dast',
    name: 'External DAST (ZAP + Nuclei)',
    description: 'Standard active assessment plus OWASP ZAP quick scan and Nuclei template scanning (DoS/fuzz/bruteforce templates excluded). Includes context-based infrastructure recon (DNS resolution → port scan of the resolved IPs). Requires installed tools; unavailable engines are recorded and skipped.',
    targetKinds: ['webapp'],
    maxCrawlPages: 200,
    passiveEngines: ['builtin.crawler-lite', 'builtin.http-observation', 'builtin.tls-analysis', 'builtin.openapi-policy', 'builtin.endpoint-discovery'],
    activeEngines: ['builtin.path-probe', 'builtin.reflection-probe', 'builtin.auth-probe', 'builtin.redirect-probe', 'builtin.authenticated-probe', 'builtin.graphql-probe', 'builtin.blind-ssrf-probe', 'builtin.host-infra', 'adapter.zap', 'adapter.nuclei'],
  },
  {
    id: 'internal-scan',
    name: 'Internal Network Scan',
    description: 'CIDR block scan: host discovery, TCP port scan, service fingerprinting, version→CVE matching. Requires an explicitly registered CIDR target.',
    targetKinds: ['cidr'],
    maxCrawlPages: 0,
    passiveEngines: [],
    activeEngines: ['builtin.internal-scan'],
  },
  {
    id: 'source-review',
    name: 'Source + dependency review',
    description: 'Reviews a source tree: built-in pattern scan, dependency inventory, plus Semgrep/Trivy/Grype when installed.',
    targetKinds: ['source'],
    maxCrawlPages: 0,
    passiveEngines: ['builtin.source-scan', 'builtin.dep-manifest', 'adapter.semgrep', 'adapter.trivy', 'adapter.grype'],
    activeEngines: [],
  },
];

export function getProfile(id: string): Profile | undefined {
  return PROFILES.find((p) => p.id === id);
}

/** Engines that will run for a profile+mode combination (active engines are reported skipped in passive mode). */
export function enginePlan(profile: Profile, mode: ScanMode): Array<{ id: string; willRun: boolean }> {
  const plan: Array<{ id: string; willRun: boolean }> = [];
  for (const id of profile.passiveEngines) plan.push({ id, willRun: true });
  for (const id of profile.activeEngines) plan.push({ id, willRun: mode === 'active' });
  return plan;
}
