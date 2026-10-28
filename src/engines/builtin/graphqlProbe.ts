/**
 * Built-in GraphQL probe engine (ACTIVE) — bounded API-surface checks:
 *  - introspection enabled on conventional GraphQL endpoints (API misconfig,
 *    hands attackers the full schema)
 *  - GraphiQL / playground exposure
 *
 * Safety: ≤4 endpoints, one small introspection query each, no nested depth,
 * no data mutation. The introspection query is read-only metadata.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, RawFinding } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.graphql-probe',
  name: 'GraphQL Probe',
  kind: 'builtin',
  capabilities: {
    A01: cap('GraphQL introspection exposure and playground discovery (bounded, read-only)'),
  },
  modes: ['active'],
  targetKinds: ['webapp'],
};

const ENDPOINTS = ['/graphql', '/api/graphql', '/graphiql', '/graphql/console'];
const INTROSPECTION = JSON.stringify({
  query: '{ __schema { queryType { name } mutationType { name } } }',
});

export class GraphqlProbeEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const findings: RawFinding[] = [];
    let probes = 0;
    let graphqlFound = false;

    for (const endpoint of ENDPOINTS) {
      if (ctx.signal.aborted || probes >= 4) break;
      probes++;
      const url = new URL(endpoint, ctx.target.origin + '/').toString();

      const res = await ctx.client.request('POST', url, {
        body: INTROSPECTION,
        contentType: 'application/json',
      });
      if (res.ok && res.status === 200 && res.body.includes('__schema')) {
        graphqlFound = true;
        findings.push({
          rawId: 'graphql-introspection-enabled',
          title: `GraphQL introspection enabled at ${endpoint}`,
          category: 'A01',
          cwe: 200,
          severity: 'medium',
          confidence: 'high',
          status: 'confirmed',
          asset: ctx.target.origin,
          locator: endpoint,
          evidence: [{
            kind: 'http',
            request: { method: 'POST', url, headers: { 'content-type': 'application/json' } },
            response: { status: res.status, headers: { 'content-type': res.headers['content-type'] ?? '' }, bodyExcerpt: res.body.slice(0, 200) },
            observation: 'Introspection query returned __schema metadata — the full API schema is retrievable',
          }],
          explanation:
            'GraphQL introspection is enabled and reachable without authentication, so the complete API ' +
            'schema (every type, field and relation) can be downloaded — the reconnaissance work an API ' +
            'should force is eliminated (CWE-200 information exposure).',
          remediation:
            'Disable introspection in production (most servers support an explicit flag), or restrict it to ' +
            'authenticated internal consumers.',
          references: ['https://owasp.org/www-project-api-security/'],
        });
      } else if (res.ok && res.status === 200 && /graphiql|apollo server middleware/i.test(res.body)) {
        graphqlFound = true;
        findings.push({
          rawId: 'graphql-playground-exposed',
          title: `GraphQL playground/editor exposed at ${endpoint}`,
          category: 'A02',
          cwe: 1233,
          severity: 'low',
          confidence: 'medium',
          status: 'confirmed',
          asset: ctx.target.origin,
          locator: endpoint,
          evidence: [{
            kind: 'http',
            request: { method: 'POST', url, headers: { 'content-type': 'application/json' } },
            response: { status: res.status, headers: {}, bodyExcerpt: res.body.slice(0, 200) },
            observation: 'GraphQL editor/playground HTML served without authentication',
          }],
          explanation:
            'An interactive GraphQL editor is exposed unauthenticated. Combined with introspection it hands ' +
            'over both the schema and a ready-made query console (CWE-1233 family).',
          remediation: 'Disable the playground in production or gate it behind authentication.',
          references: ['https://owasp.org/www-project-api-security/'],
        });
      }
    }

    return { findings, version: 'builtin', detail: graphqlFound ? 'GraphQL surface found' : `no GraphQL surface at ${probes} conventional endpoints` };
  }
}
