/**
 * Fingerprint → payload planner (newtask.md E3, section 3.3).
 *
 * Closes V8: service/OS nodes feed payload selection. A fingerprinted service
 * maps to capability tags, and each capability maps to a payload family
 * (engine probes + in-house template families). Unknown stays unknown — an
 * unfingerprinted service gets the generic family only.
 */

export interface ServiceFingerprintInput {
  ip: string;
  port: number;
  product?: string | undefined;
  version?: string | undefined;
  service: string;
}

export type CapabilityTag =
  | 'tomcat' | 'jboss' | 'weblogic' | 'glassfish' | 'jenkins' | 'grafana' | 'kibana'
  | 'php' | 'aspnet' | 'python' | 'node' | 'graphql' | 'openapi' | 'elasticsearch'
  | 'docker' | 'kubernetes' | 'database' | 'smb' | 'rdp' | 'vnc' | 'generic';

export interface PayloadFamily {
  capability: CapabilityTag;
  /** Engines that consume this family. */
  engines: string[];
  /** In-house nuclei template families (template id prefixes). */
  templateFamilies: string[];
  /** Extra probe paths (merged into path-probe). */
  probePaths: string[];
  rationale: string;
}

const FAMILIES: Record<CapabilityTag, PayloadFamily> = {
  tomcat: { capability: 'tomcat', engines: ['builtin.path-probe', 'adapter.nuclei'], templateFamilies: ['rsec-tomcat', 'rsec-jboss'], probePaths: ['/manager/html', '/manager/status', '/host-manager/', '/examples/', '/docs/'], rationale: 'Tomcat fingerprint → JSP/manager console checks' },
  jboss: { capability: 'jboss', engines: ['builtin.path-probe', 'adapter.nuclei'], templateFamilies: ['rsec-jboss'], probePaths: ['/jmx-console/', '/web-console/'], rationale: 'JBoss fingerprint → JMX console checks' },
  weblogic: { capability: 'weblogic', engines: ['builtin.path-probe', 'adapter.nuclei'], templateFamilies: ['rsec-weblogic'], probePaths: ['/console/', '/uddiexplorer/'], rationale: 'WebLogic fingerprint → admin console + IIOP surface' },
  glassfish: { capability: 'glassfish', engines: ['builtin.path-probe', 'adapter.nuclei'], templateFamilies: ['rsec-glassfish'], probePaths: ['/common/index.jsf'], rationale: 'GlassFish fingerprint → admin GUI checks' },
  jenkins: { capability: 'jenkins', engines: ['adapter.nuclei'], templateFamilies: ['rsec-jenkins'], probePaths: ['/script', '/asynchPeople/'], rationale: 'Jenkins fingerprint → unauth script/console checks' },
  grafana: { capability: 'grafana', engines: ['adapter.nuclei'], templateFamilies: ['rsec-grafana'], probePaths: ['/api/health'], rationale: 'Grafana fingerprint → API/plugins exposure' },
  kibana: { capability: 'kibana', engines: ['adapter.nuclei'], templateFamilies: ['rsec-kibana'], probePaths: ['/app/kibana'], rationale: 'Kibana fingerprint → data-surface exposure' },
  php: { capability: 'php', engines: ['builtin.path-probe', 'adapter.nuclei'], templateFamilies: ['rsec-php'], probePaths: ['/info.php', '/phpinfo.php', '/adminer.php', '/phpmyadmin/'], rationale: 'PHP fingerprint → .php traversal/phpinfo set' },
  aspnet: { capability: 'aspnet', engines: ['builtin.path-probe', 'adapter.nuclei'], templateFamilies: ['rsec-aspnet', 'rsec-elmah'], probePaths: ['/elmah.axd', '/trace.axd', '/web.config.bak'], rationale: 'ASP.NET fingerprint → elmah/trace/config checks' },
  python: { capability: 'python', engines: ['builtin.path-probe'], templateFamilies: [], probePaths: ['/admin/', '/flask-debug'], rationale: 'Python fingerprint → debug console checks' },
  node: { capability: 'node', engines: ['builtin.path-probe'], templateFamilies: [], probePaths: ['/_next/static/', '/__webpack_hmr'], rationale: 'Node fingerprint → bundle/source-map surface' },
  graphql: { capability: 'graphql', engines: ['builtin.graphql-probe', 'adapter.nuclei'], templateFamilies: ['rsec-graphql'], probePaths: ['/graphql', '/graphiql'], rationale: 'GraphQL present → introspection/playground set' },
  openapi: { capability: 'openapi', engines: ['builtin.openapi-policy', 'adapter.nuclei'], templateFamilies: ['rsec-openapi'], probePaths: ['/openapi.json', '/swagger-ui/'], rationale: 'OpenAPI present → spec-policy checks' },
  elasticsearch: { capability: 'elasticsearch', engines: ['adapter.nuclei'], templateFamilies: ['rsec-elasticsearch'], probePaths: ['/_cat/indices'], rationale: 'Elasticsearch fingerprint → unauth API checks' },
  docker: { capability: 'docker', engines: ['adapter.nuclei'], templateFamilies: [], probePaths: ['/version', '/containers/json'], rationale: 'Docker API fingerprint → unauth API is critical' },
  kubernetes: { capability: 'kubernetes', engines: ['adapter.nuclei'], templateFamilies: [], probePaths: ['/version', '/api/v1/pods'], rationale: 'K8s API fingerprint → unauth API checks' },
  database: { capability: 'database', engines: [], templateFamilies: [], probePaths: [], rationale: 'Database port at the edge — no HTTP probes; alert + gate' },
  smb: { capability: 'smb', engines: [], templateFamilies: [], probePaths: [], rationale: 'SMB at the edge — protocol-level checks out of scope for HTTP tooling; alert' },
  rdp: { capability: 'rdp', engines: [], templateFamilies: [], probePaths: [], rationale: 'RDP at the edge — alert; NLA/patch level needs credentialed sensor' },
  vnc: { capability: 'vnc', engines: [], templateFamilies: [], probePaths: [], rationale: 'VNC at the edge — alert' },
  generic: { capability: 'generic', engines: ['builtin.path-probe', 'adapter.nuclei'], templateFamilies: ['rsec-git', 'rsec-env', 'rsec-backup'], probePaths: [], rationale: 'Unfingerprinted service → generic exposure pack only' },
};

export function capabilitiesFor(f: ServiceFingerprintInput): CapabilityTag[] {
  const caps = new Set<CapabilityTag>();
  const hay = `${f.service} ${f.product ?? ''}`.toLowerCase();
  if (/tomcat|coyote/.test(hay)) caps.add('tomcat');
  if (/jboss|wildfly/.test(hay)) caps.add('jboss');
  if (/weblogic/.test(hay)) caps.add('weblogic');
  if (/glassfish/.test(hay)) caps.add('glassfish');
  if (/jenkins/.test(hay)) caps.add('jenkins');
  if (/grafana/.test(hay)) caps.add('grafana');
  if (/kibana/.test(hay)) caps.add('kibana');
  if (/php/.test(hay)) caps.add('php');
  if (/asp\.net|iis/.test(hay)) caps.add('aspnet');
  if (/django|flask|python|gunicorn|uwsgi/.test(hay)) caps.add('python');
  if (/node|express|next\.js/.test(hay)) caps.add('node');
  if (/elasticsearch/.test(hay) || f.port === 9200) caps.add('elasticsearch');
  if (/docker/.test(hay) || f.port === 2375 || f.port === 2376) caps.add('docker');
  if (/kubernetes|kube/.test(hay) || f.port === 6443) caps.add('kubernetes');
  if (f.port === 3306 || f.port === 5432 || f.port === 6379 || f.port === 27017 || f.port === 11211 || f.port === 5984) caps.add('database');
  if (f.port === 445 || f.port === 139) caps.add('smb');
  if (f.port === 3389) caps.add('rdp');
  if (f.port === 5900) caps.add('vnc');
  if (caps.size === 0) caps.add('generic');
  return [...caps];
}

export function planFor(f: ServiceFingerprintInput): PayloadFamily[] {
  return capabilitiesFor(f).map((c) => FAMILIES[c]);
}

/** Non-HTTP families are alert-only: no probes get sent against databases/SMB/RDP/VNC. */
export function isProbeable(family: PayloadFamily): boolean {
  return family.engines.length > 0 || family.probePaths.length > 0;
}
