/**
 * Engine registry: instantiates engines for a profile, caches availability
 * probes (binaries can be slow to answer --version).
 */
import type { Config } from '../config.ts';
import type { EngineAvailability, Engine as EngineIface } from './types.ts';
import { CrawlerLiteEngine } from './builtin/crawlerLite.ts';
import { HttpObservationEngine } from './builtin/httpObservation.ts';
import { PathProbeEngine } from './builtin/pathProbe.ts';
import { ReflectionProbeEngine } from './builtin/reflectionProbe.ts';
import { AuthProbeEngine } from './builtin/authProbe.ts';
import { SourceScanEngine } from './builtin/sourceScan.ts';
import { DepManifestEngine } from './builtin/depManifest.ts';
import { TlsAnalysisEngine } from './builtin/tlsAnalysis.ts';
import { OpenApiPolicyEngine } from './builtin/openapiPolicy.ts';
import { AuthenticatedProbeEngine } from './builtin/authenticatedProbe.ts';
import { RedirectProbeEngine } from './builtin/redirectProbe.ts';
import { GraphqlProbeEngine } from './builtin/graphqlProbe.ts';
import { EndpointDiscoveryEngine } from './builtin/endpointDiscovery.ts';
import { VariantHunter } from './builtin/variantHunter.ts';
import { BlindSsrfProbeEngine } from './builtin/blindSsrfProbe.ts';
import { InternalScanEngine } from './builtin/internalScanEngine.ts';
import { HostInfraEngine } from './builtin/hostInfra.ts';
import { probeHostHeaderInjection } from './builtin/rawProbes.ts';
import { SemgrepAdapter } from './adapters/semgrep.ts';
import { TrivyAdapter } from './adapters/trivy.ts';
import { GrypeAdapter } from './adapters/grype.ts';
import { NucleiAdapter } from './adapters/nuclei.ts';
import { ZapAdapter } from './adapters/zap.ts';

export type { EngineIface as Engine };

export class EngineRegistry {
  private readonly config: Config;
  private readonly availabilityCache = new Map<string, { at: number; value: EngineAvailability }>();
  private static readonly CACHE_TTL_MS = 300_000;

  constructor(config: Config) {
    this.config = config;
  }

  /** Instantiate an engine by id. Returns undefined for unknown ids. */
  create(id: string, maxCrawlPages: number): EngineIface | undefined {
    switch (id) {
      case 'builtin.crawler-lite': return new CrawlerLiteEngine(maxCrawlPages);
      case 'builtin.http-observation': return new HttpObservationEngine();
      case 'builtin.path-probe': return new PathProbeEngine();
      case 'builtin.reflection-probe': return new ReflectionProbeEngine();
      case 'builtin.auth-probe': return new AuthProbeEngine();
      case 'builtin.source-scan': return new SourceScanEngine();
      case 'builtin.dep-manifest': return new DepManifestEngine();
      case 'builtin.tls-analysis': return new TlsAnalysisEngine();
      case 'builtin.openapi-policy': return new OpenApiPolicyEngine();
      case 'builtin.authenticated-probe': return new AuthenticatedProbeEngine();
      case 'builtin.redirect-probe': return new RedirectProbeEngine();
      case 'builtin.graphql-probe': return new GraphqlProbeEngine();
      case 'builtin.endpoint-discovery': return new EndpointDiscoveryEngine();
      case 'builtin.variant-hunter': return new VariantHunter();
      case 'builtin.blind-ssrf-probe': return new BlindSsrfProbeEngine();
      case 'builtin.internal-scan': return new InternalScanEngine();
      case 'builtin.host-infra': return new HostInfraEngine();
      case 'adapter.semgrep': return new SemgrepAdapter();
      case 'adapter.trivy': return new TrivyAdapter();
      case 'adapter.grype': return new GrypeAdapter();
      case 'adapter.nuclei': return new NucleiAdapter();
      case 'adapter.zap': return new ZapAdapter();
      default: return undefined;
    }
  }

  allEngineIds(): string[] {
    return [
      'builtin.crawler-lite', 'builtin.http-observation', 'builtin.path-probe',
      'builtin.reflection-probe', 'builtin.auth-probe', 'builtin.source-scan',
      'builtin.dep-manifest', 'builtin.tls-analysis', 'builtin.openapi-policy', 'builtin.authenticated-probe', 'builtin.redirect-probe', 'builtin.graphql-probe', 'builtin.endpoint-discovery', 'builtin.variant-hunter', 'builtin.blind-ssrf-probe', 'builtin.internal-scan', 'builtin.host-infra', 'adapter.semgrep', 'adapter.trivy', 'adapter.grype',
      'adapter.nuclei', 'adapter.zap',
    ];
  }

  async availability(id: string): Promise<EngineAvailability> {
    const cached = this.availabilityCache.get(id);
    if (cached && Date.now() - cached.at < EngineRegistry.CACHE_TTL_MS) return cached.value;
    const engine = this.create(id, this.config.maxCrawlPages);
    const value = engine
      ? await engine.availability()
      : { available: false, reason: 'unknown engine' };
    this.availabilityCache.set(id, { at: Date.now(), value });
    return value;
  }
}
