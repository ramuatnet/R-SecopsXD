/**
 * Built-in OpenAPI policy analysis engine (A06) — passive heuristic review of
 * machine-readable API specifications exposed by the target.
 *
 * Probes a small set of conventional spec locations (≤6 plain GETs). When a
 * spec is found it reports: the spec's public exposure itself, and operations
 * declared without authentication requirements. These are design-policy
 * SIGNALS (heuristic, probable) — not proof that enforcement is missing.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.openapi-policy',
  name: 'OpenAPI Design-Policy Review',
  kind: 'builtin',
  capabilities: {
    A06: cap('exposed API specification review: operations declared without security requirements (spec-level, not enforcement proof)'),
    A02: cap('publicly exposed API documentation artifacts'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['webapp'],
};

const SPEC_PATHS = ['/openapi.json', '/openapi.yaml', '/swagger.json', '/api-docs', '/v3/api-docs', '/api/openapi.json'];

interface ApiSpec {
  openapi?: string;
  swagger?: string;
  paths?: Record<string, Record<string, { security?: unknown[]; tags?: string[]; summary?: string }>>;
  security?: unknown[];
  components?: { securitySchemes?: unknown };
}

function isSpec(body: string): ApiSpec | undefined {
  const trimmed = body.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('openapi:') && !trimmed.startsWith('swagger:')) return undefined;
  try {
    const parsed = JSON.parse(trimmed) as ApiSpec;
    if (parsed.openapi || parsed.swagger) return parsed;
  } catch { /* YAML or not a spec */ }
  // minimal YAML shape sniffing without a YAML parser: keys at document start
  if (trimmed.startsWith('openapi:') || trimmed.startsWith('swagger:')) {
    return { openapi: 'yaml (structure not parsed)' };
  }
  return undefined;
}

export class OpenApiPolicyEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const origin = ctx.target.origin;
    let spec: ApiSpec | undefined;
    let specUrl = '';
    let specEvidence = '';
    let probes = 0;

    for (const path of SPEC_PATHS) {
      if (ctx.signal.aborted || spec) break;
      if (probes >= 6) break;
      probes++;
      const res = await ctx.client.get(new URL(path, origin + '/').toString());
      if (!res.ok || res.status !== 200) continue;
      const parsed = isSpec(res.body);
      if (parsed) {
        spec = parsed;
        specUrl = path;
        specEvidence = res.body.slice(0, 600);
      }
    }

    if (!spec) {
      return { findings: [], version: 'builtin', detail: `no machine-readable API specification at ${probes} conventional paths` };
    }

    const findings: RawFinding[] = [];
    const versionLabel = spec.openapi ?? spec.swagger ?? 'unknown';

    // 1. The design document itself is exposed (information disclosure, aids reconnaissance)
    findings.push({
      rawId: 'openapi-spec-exposed',
      title: `API specification publicly exposed at ${specUrl}`,
      category: 'A02',
      cwe: 1233,
      severity: 'low',
      confidence: 'high',
      status: 'confirmed',
      asset: ctx.target.origin,
      locator: specUrl,
      evidence: [{
        kind: 'http',
        request: { method: 'GET', url: new URL(specUrl, origin + '/').toString(), headers: {} },
        response: { status: 200, headers: { 'content-type': 'application/json' }, bodyExcerpt: specEvidence },
        observation: `API spec (version label: ${versionLabel}) is retrievable without authentication`,
      }],
      explanation:
        'The machine-readable API specification is publicly retrievable. This hands attackers a complete, ' +
        'accurate map of endpoints, parameters and data models — eliminating the reconnaissance work a ' +
        'well-configured deployment would force.',
      remediation:
        'Serve API documentation only to authenticated internal consumers (API gateway, auth-gated docs) ' +
        'unless the surface is intentionally public, and ensure the published spec matches deployed reality.',
      references: [W('01-Information_Gathering/README')],
    });

    // 2. Operations declared without security requirements (design-policy signal)
    if (spec.paths) {
      const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'];
      const globalSecurity = Array.isArray(spec.security) ? spec.security : [];
      const hasSchemes = Boolean(spec.components?.securitySchemes);
      const unsecured: string[] = [];
      let total = 0;
      for (const [path, ops] of Object.entries(spec.paths)) {
        for (const method of HTTP_METHODS) {
          const op = ops[method];
          if (!op) continue;
          total++;
          const opSecurity = Array.isArray(op.security) ? op.security : undefined;
          const explicitPublic = opSecurity !== undefined && opSecurity.length === 0;
          const covered = explicitPublic ? false
            : opSecurity !== undefined ? opSecurity.length > 0
            : globalSecurity.length > 0;
          if (!covered) unsecured.push(`${method.toUpperCase()} ${path}`);
        }
      }
      if (unsecured.length > 0 && total > 0) {
        findings.push({
          rawId: 'openapi-unauthenticated-operations',
          title: `${unsecured.length} of ${total} API operations declared without authentication requirement`,
          category: 'A06',
          cwe: 285,
          severity: 'medium',
          confidence: 'medium',
          status: 'probable',
          asset: ctx.target.origin,
          locator: specUrl,
          evidence: [{
            kind: 'http',
            request: { method: 'GET', url: new URL(specUrl, origin + '/').toString(), headers: {} },
            response: { status: 200, headers: {}, bodyExcerpt: unsecured.slice(0, 12).join(', ') },
            observation:
              `Spec declares ${hasSchemes ? 'securitySchemes' : 'no securitySchemes'} and ` +
              `${globalSecurity.length > 0 ? 'a global security requirement' : 'no global security requirement'}; ` +
              `${unsecured.length} operations are declared (explicitly or implicitly) unauthenticated`,
          }],
          explanation:
            'The API specification declares operations without any security requirement and (where the spec ' +
            'has securitySchemes) without applying one. This is a design-policy signal: the spec SAYS these ' +
            'operations are unauthenticated. Whether middleware enforces auth anyway cannot be concluded from ' +
            'the spec — hence probable, not confirmed.',
          remediation:
            'Apply a global security requirement in the spec, mark intentionally-public operations explicitly ' +
            'with security: [], and verify deployed middleware matches the declaration.',
          references: [W('03-Identity_Management_Testing/README')],
        });
      }
    }

    ctx.log('openapi policy review finished', { specUrl, findings: findings.length });
    return { findings, version: 'builtin', detail: `spec found at ${specUrl}; ${findings.length} policy signal(s)` };
  }
}

function W(path: string): string {
  return `https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/${path}`;
}
