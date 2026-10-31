"""Generate the in-house nuclei template pack (N1/N4) + index.json (N5) — no clone.

Templates are minimal, curated, and each carries a `# source:` citation (N9).
Every template only touches the approved origin (N8 egress rule).
"""
import io
import json
import os

WSTG_CONF = 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration/README'
WSTG_INFO = 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/README'
WSTG_API = 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Data_Validation/README'
APISEC = 'https://owasp.org/www-project-api-security/'
CORS_WSTG = 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side/Testing_for_CORS'

# (id, dir, name, severity, cwe, tags, source, paths, method, body, headers, word_matchers, condition, statuses, status_part_needed, requires)
# word_matchers: list of (part, words, condition)
T = []

def tmpl(id_, dir_, name, sev, cwe, tags, source, paths, words, statuses, method='GET', body=None, headers=None, requires=None, condition='and'):
    T.append(dict(id=id_, dir=dir_, name=name, sev=sev, cwe=cwe, tags=tags, source=source,
                  paths=paths, method=method, body=body, headers=headers, words=words,
                  statuses=statuses, requires=requires or [], condition=condition))

# ---------- A01 / exposure ----------
tmpl('rsec-git-config-exposure', 'A01-sensitive-exposure', 'Exposed .git/config', 'high', 538, 'exposure,git,rsec', 'WSTG-CONF; CWE-538',
     ['/.git/config'], [('body', ['[core]', 'repositoryformatversion'], 'and')], [200])
tmpl('rsec-git-head-exposure', 'A01-sensitive-exposure', 'Exposed .git/HEAD', 'medium', 538, 'exposure,git,rsec', 'WSTG-CONF; CWE-538',
     ['/.git/HEAD'], [('body', ['ref: refs/'], 'or')], [200])
tmpl('rsec-env-file-exposure', 'A01-sensitive-exposure', 'Exposed .env file', 'high', 200, 'exposure,dotenv,rsec', 'WSTG-CONF; CWE-200',
     ['/.env'], [('body', ['=', 'KEY'], 'and'), ('body', ['DB_', 'SECRET', 'PASSWORD', 'API_KEY', 'TOKEN'], 'or')], [200])
tmpl('rsec-env-backup-exposure', 'A01-sensitive-exposure', 'Exposed .env backup variants', 'high', 538, 'exposure,dotenv,backup,rsec', 'WSTG-CONF; CWE-538',
     ['/.env.bak', '/.env.old', '/.env~', '/.env.save'], [('body', ['=', 'KEY'], 'and')], [200])
tmpl('rsec-aws-credentials-exposure', 'A01-sensitive-exposure', 'Exposed AWS credentials file', 'critical', 522, 'exposure,aws,rsec', 'WSTG-CONF; CWE-522',
     ['/.aws/credentials'], [('body', ['aws_access_key_id'], 'and')], [200])
tmpl('rsec-gcp-key-exposure', 'A01-sensitive-exposure', 'Exposed GCP service account key', 'critical', 522, 'exposure,gcp,rsec', 'WSTG-CONF; CWE-522',
     ['/service-account.json', '/gcp-credentials.json'], [('body', ['"private_key"', 'service_account'], 'and')], [200])
tmpl('rsec-database-dump-exposure', 'A01-sensitive-exposure', 'Exposed database dump', 'high', 538, 'exposure,database,backup,rsec', 'WSTG-CONF; CWE-538',
     ['/dump.sql', '/database.sql', '/db.sql', '/backup.sql'], [('body', ['CREATE TABLE', 'INSERT INTO'], 'or')], [200])
tmpl('rsec-backup-archive-exposure', 'A01-sensitive-exposure', 'Exposed backup archives', 'high', 538, 'exposure,backup,rsec', 'WSTG-CONF; CWE-538',
     ['/backup.zip', '/backup.tar.gz', '/site.tar.gz', '/www.zip', '/web.bak'], [('body', ['PK\x03\x04', '\\x1f\\x8b'], 'or')], [200])
tmpl('rsec-svn-entries-exposure', 'A01-sensitive-exposure', 'Exposed SVN metadata', 'medium', 538, 'exposure,svn,rsec', 'WSTG-CONF; CWE-538',
     ['/.svn/entries', '/.svn/wc.db'], [('body', ['svn', 'SQLite format 3'], 'or')], [200])
tmpl('rsec-idea-workspace-exposure', 'A01-sensitive-exposure', 'Exposed IDE workspace', 'medium', 538, 'exposure,ide,rsec', 'WSTG-CONF; CWE-538',
     ['/.idea/workspace.xml'], [('body', ['<project version', 'component'], 'and')], [200])
tmpl('rsec-ds-store-exposure', 'A01-sensitive-exposure', 'Exposed .DS_Store', 'low', 538, 'exposure,macos,rsec', 'WSTG-CONF; CWE-538',
     ['/.DS_Store'], [('body', ['Bud1'], 'or')], [200])
tmpl('rsec-htaccess-exposure', 'A01-sensitive-exposure', 'Exposed .htaccess', 'medium', 538, 'exposure,apache,rsec', 'WSTG-CONF; CWE-538',
     ['/.htaccess'], [('body', ['RewriteRule', 'Options', 'AuthType'], 'or')], [200])
tmpl('rsec-elmah-exposure', 'A01-sensitive-exposure', 'Exposed ELMAH error log', 'high', 538, 'exposure,aspnet,logs,rsec', 'WSTG-CONF; CWE-538',
     ['/elmah.axd'], [('body', ['ELMAH', 'Error Log'], 'and')], [200])
tmpl('rsec-source-map-exposure', 'A01-sensitive-exposure', 'Exposed JavaScript source maps', 'medium', 540, 'exposure,sourcemap,rsec', 'WSTG-INFO; CWE-540',
     ['/main.js.map', '/app.js.map', '/bundle.js.map', '/static/js/main.js.map'], [('body', ['"sources"', '"mappings"'], 'and')], [200])
tmpl('rsec-composer-json-exposure', 'A01-sensitive-exposure', 'Exposed composer.json (dependency disclosure)', 'info', 200, 'exposure,php,dependencies,rsec', 'WSTG-INFO; CWE-200',
     ['/composer.json'], [('body', ['"require"', '"name"'], 'and')], [200])
tmpl('rsec-package-json-exposure', 'A01-sensitive-exposure', 'Exposed package.json', 'info', 200, 'exposure,node,dependencies,rsec', 'WSTG-INFO; CWE-200',
     ['/package.json'], [('body', ['"dependencies"', '"name"'], 'and')], [200])

# ---------- A02 / admin consoles & services ----------
tmpl('rsec-tomcat-manager-unauth', 'A02-admin-consoles', 'Tomcat Manager reachable without auth', 'high', 650, 'tomcat,manager,rsec', 'WSTG-CONF; CWE-650',
     ['/manager/html'], [('body', ['Tomcat Web Application Manager'], 'and')], [200])
tmpl('rsec-tomcat-manager-present', 'A02-admin-consoles', 'Tomcat Manager present (auth required)', 'info', 650, 'tomcat,manager,rsec', 'WSTG-CONF; CWE-650',
     ['/manager/html'], [('header', ['401', 'Tomcat'], 'and')], [401])
tmpl('rsec-tomcat-default-page', 'A02-admin-consoles', 'Tomcat default page (uncustomized deployment)', 'info', 1188, 'tomcat,default,rsec', 'WSTG-INFO; CWE-1188',
     ['/'], [('body', ['Apache Tomcat/'], 'and')], [200])
tmpl('rsec-jboss-jmx-console', 'A02-admin-consoles', 'JBoss JMX console exposed', 'high', 650, 'jboss,jmx,rsec', 'WSTG-CONF; CWE-650',
     ['/jmx-console/'], [('body', ['JBoss JMX Management Console', 'jboss.admin'], 'or')], [200])
tmpl('rsec-spring-actuator', 'A02-admin-consoles', 'Spring Boot Actuator exposed', 'medium', 200, 'spring,actuator,rsec', 'WSTG-CONF; CWE-200',
     ['/actuator', '/actuator/health'], [('body', ['"_links"', '"self"'], 'and')], [200])
tmpl('rsec-spring-actuator-env', 'A02-admin-consoles', 'Spring Boot Actuator env endpoint exposed', 'high', 200, 'spring,actuator,rsec', 'WSTG-CONF; CWE-200',
     ['/actuator/env'], [('body', ['"propertySources"', 'property'], 'and')], [200])
tmpl('rsec-spring-actuator-heapdump', 'A02-admin-consoles', 'Spring Boot Actuator heapdump exposed', 'high', 200, 'spring,actuator,rsec', 'WSTG-CONF; CWE-200',
     ['/actuator/heapdump'], [('header', ['application/vnd.springframework'], 'and')], [200])
tmpl('rsec-spring-gateway-routes', 'A02-admin-consoles', 'Spring Cloud Gateway routes exposed', 'high', 200, 'spring,gateway,rsec', 'WSTG-CONF; CWE-200',
     ['/actuator/gateway/routes'], [('body', ['route_id', 'predicate'], 'or')], [200])
tmpl('rsec-jenkins-presence', 'A02-admin-consoles', 'Jenkins CI exposed', 'medium', 650, 'jenkins,ci,rsec', 'WSTG-CONF; CWE-650',
     ['/login', '/'], [('header', ['X-Jenkins'], 'or')], [200])
tmpl('rsec-grafana-presence', 'A02-admin-consoles', 'Grafana login exposed', 'info', 650, 'grafana,dashboard,rsec', 'WSTG-CONF; CWE-650',
     ['/login', '/'], [('body', ['Grafana'], 'and')], [200])
tmpl('rsec-kibana-exposed', 'A02-admin-consoles', 'Kibana exposed', 'medium', 650, 'kibana,elastic,rsec', 'WSTG-CONF; CWE-650',
     ['/app/kibana', '/login'], [('body', ['kibana', 'elastic'], 'or')], [200])
tmpl('rsec-phpmyadmin-exposed', 'A02-admin-consoles', 'phpMyAdmin exposed', 'medium', 650, 'phpmyadmin,db,rsec', 'WSTG-CONF; CWE-650',
     ['/phpmyadmin/', '/pma/'], [('body', ['phpMyAdmin'], 'and')], [200])
tmpl('rsec-adminer-exposed', 'A02-admin-consoles', 'Adminer DB manager exposed', 'high', 650, 'adminer,db,rsec', 'WSTG-CONF; CWE-650',
     ['/adminer.php', '/adminer/'], [('body', ['Adminer'], 'and')], [200])
tmpl('rsec-apache-server-status', 'A02-admin-consoles', 'Apache server-status exposed', 'medium', 200, 'apache,mod_status,rsec', 'WSTG-CONF; CWE-200',
     ['/server-status'], [('body', ['Apache Server Status'], 'and')], [200])
tmpl('rsec-prometheus-metrics', 'A02-admin-consoles', 'Prometheus metrics endpoint exposed', 'medium', 200, 'metrics,prometheus,rsec', 'WSTG-CONF; CWE-200',
     ['/metrics'], [('body', ['# HELP', '# TYPE'], 'and')], [200])
tmpl('rsec-nginx-autoindex', 'A02-admin-consoles', 'Directory listing enabled', 'low', 548, 'listing,nginx,rsec', 'WSTG-CONF; CWE-548',
     ['/assets/', '/files/', '/backup/'], [('body', ['Index of /', 'Directory listing for'], 'or')], [200], condition='and')

# ---------- A01 / API surface ----------
tmpl('rsec-graphql-introspection', 'A01-api-surface', 'GraphQL introspection enabled', 'high', 200, 'graphql,introspection,rsec', 'OWASP API Security; CWE-200',
     ['/graphql', '/api/graphql', '/graphiql'],
     [('body', ['__schema', 'types'], 'and')], [200], method='POST',
     body='{"query":"{ __schema { types { name } } }"}', headers={'Content-Type': 'application/json'},
     requires=['graphql'])
tmpl('rsec-graphql-playground', 'A01-api-surface', 'GraphiQL IDE exposed', 'medium', 200, 'graphql,playground,rsec', 'OWASP API Security; CWE-200',
     ['/graphiql', '/playground'], [('body', ['GraphiQL', 'graphiql'], 'or')], [200], requires=['graphql'])
tmpl('rsec-openapi-spec-exposed', 'A01-api-surface', 'OpenAPI/Swagger specification exposed', 'info', 200, 'openapi,swagger,rsec', 'OWASP API Security; CWE-200',
     ['/openapi.json', '/swagger.json', '/v2/swagger.json', '/v3/api-docs'], [('body', ['"openapi"', '"swagger"'], 'or')], [200])

# ---------- A10 / verbose errors ----------
tmpl('rsec-java-stacktrace', 'A10-verbose-errors', 'Java stack trace disclosed on error', 'medium', 209, 'errors,java,rsec', 'WSTG-CONF; CWE-209',
     ['/rsec-nonexistent-probe'], [('body', ['at java.', 'at org.', 'java.lang.Exception'], 'or')], [500])
tmpl('rsec-aspnet-stacktrace', 'A10-verbose-errors', 'ASP.NET error details disclosed', 'medium', 209, 'errors,aspnet,rsec', 'WSTG-CONF; CWE-209',
     ['/rsec-nonexistent-probe'], [('body', ['Server Error in', 'Stack Trace'], 'and')], [500])
tmpl('rsec-php-error-disclosure', 'A10-verbose-errors', 'PHP error disclosure', 'medium', 209, 'errors,php,rsec', 'WSTG-CONF; CWE-209',
     ['/rsec-nonexistent-probe'], [('body', ['Fatal error', 'Warning:'], 'or')], [500])

# ---------- A02 / CORS ----------
tmpl('rsec-cors-reflect-credentials', 'A02-cors', 'CORS reflects arbitrary origin with credentials', 'high', 942, 'cors,rsec', 'WSTG-CLNT; Testing for CORS',
     ['/'], [('header', ['access-control-allow-origin: https://evil.example'], 'and'),
             ('header', ['access-control-allow-credentials: true'], 'and')], [200], headers={'Origin': 'https://evil.example'})
tmpl('rsec-cors-reflect-any-origin', 'A02-cors', 'CORS reflects arbitrary origin', 'medium', 942, 'cors,rsec', 'WSTG-CLNT; Testing for CORS',
     ['/'], [('header', ['access-control-allow-origin: https://evil.example'], 'and')], [200], headers={'Origin': 'https://evil.example'})

# ---------- A07 / default pages ----------
tmpl('rsec-default-credential-page', 'A07-default-credentials', 'Generic admin login page exposed (default branding)', 'info', 1188, 'admin,default,rsec', 'WSTG-AUTHN; CWE-1188',
     ['/admin', '/administrator', '/wp-login.php'], [('body', ['<input', 'type="password"'], 'and')], [200], condition='and')

assert len(T) == 41, f'expected 41 templates, got {len(T)}'

# ---------- YAML rendering ----------
def render(t):
    lines = [f'id: {t["id"]}', 'info:']
    lines += [f'  name: {t["name"]}', '  author: r-secopsxd', f'  severity: {t["sev"]}',
              f'  description: {t["name"]} - curated in-house check derived from the cited source.',
              '  reference:']
    if t['source'].startswith('WSTG-CONF'):
        lines.append(f'    - {WSTG_CONF}')
    elif t['source'].startswith('WSTG-INFO'):
        lines.append(f'    - {WSTG_INFO}')
    elif t['source'].startswith('WSTG-CLNT'):
        lines.append(f'    - {CORS_WSTG}')
    elif t['source'].startswith('OWASP API'):
        lines.append(f'    - {APISEC}')
    else:
        lines.append(f'    - {WSTG_API}')
    lines += ['  classification:', f'    cwe-id: CWE-{t["cwe"]}', f'  tags: {t["tags"]}',
              f'# source: {t["source"]}', '', 'http:']
    lines.append(f'  - method: {t["method"]}')
    lines.append('    path:')
    for pth in t['paths']:
        lines.append(f'      - "{{{{BaseURL}}}}{pth}"')
    if t['headers']:
        lines.append('    headers:')
        for k, v in t['headers'].items():
            lines.append(f'      {k}: {v}')
    if t['body']:
        lines.append(f'    body: {json.dumps(t["body"])}')
    if t['statuses']:
        lines.append('    matchers-condition: and')
        lines.append('    matchers:')
        for part, ws, cond in t['words']:
            lines.append('      - type: word')
            lines.append(f'        part: {part}')
            lines.append('        words:')
            for w in ws:
                lines.append(f'          - "{w}"')
            lines.append(f'        condition: {cond}')
        lines.append('      - type: status')
        lines.append('        part: status')
        lines.append('        status:')
        for st in t['statuses']:
            lines.append(f'          - {st}')
    return '\n'.join(lines) + '\n'

root = 'templates'
count = 0
index = []
for t in T:
    d = os.path.join(root, t['dir'])
    os.makedirs(d, exist_ok=True)
    fp = os.path.join(d, f"{t['id']}.yaml")
    io.open(fp, 'w', encoding='utf8', newline='\n').write(render(t))
    entry = {'file': f"{t['dir']}/{t['id']}.yaml", 'id': t['id'], 'severity': t['sev']}
    if t['requires']:
        entry['requires'] = t['requires']
    index.append(entry)
    count += 1

io.open(os.path.join(root, 'index.json'), 'w', encoding='utf8', newline='\n').write(
    json.dumps({'schema': 'rsec-template-index/1', 'templates': index}, indent=2) + '\n')

print(f'generated {count} templates + index.json')
