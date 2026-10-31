/**
 * Template pack linter (newtask.md N3 + N7 + N9).
 *
 * npm run lint:templates
 *
 * Checks every template YAML under templates/: required keys, unique ids,
 * "# source:" review-gate citation, matcher type+part, max 3 requests per
 * template, and the DSL allowlist (no "code:" protocol, no javascript
 * expressions, payload lists capped at 40 items). Exit code 1 on any
 * violation — CI gate.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

export interface Violation { file: string; rule: string; detail: string; }

const ALLOWED_SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
const KNOWN_CAPABILITIES = new Set(['graphql', 'openapi']);

export function lintTemplates(dir: string, violations: Violation[] = []): Violation[] {
  const seenIds = new Map<string, string>();
  const files = listYamls(dir);
  if (files.length === 0) violations.push({ file: dir, rule: 'nonempty', detail: 'no templates found' });

  for (const file of files) {
    const rel = file.slice(dir.length + 1);
    const text = readFileSync(file, 'utf8');

    const id = /^id:\s*(\S+)/m.exec(text)?.[1];
    if (id === undefined) violations.push({ file: rel, rule: 'required-id', detail: 'missing id' });
    else {
      if (!id.startsWith('rsec-')) violations.push({ file: rel, rule: 'id-prefix', detail: `id "${id}" must start with rsec-` });
      const owner = seenIds.get(id);
      if (owner !== undefined) violations.push({ file: rel, rule: 'unique-id', detail: `duplicate id "${id}" (also in ${owner})` });
      else seenIds.set(id, rel);
    }

    if (!/^#\s*source:/im.test(text)) {
      violations.push({ file: rel, rule: 'source-citation', detail: 'missing "# source:" citation (review gate N9)' });
    }

    const sev = /^\s{2}severity:\s*(\S+)\s*$/m.exec(text)?.[1];
    if (sev === undefined || !ALLOWED_SEVERITIES.has(sev)) {
      violations.push({ file: rel, rule: 'required-severity', detail: `info.severity missing or invalid: "${sev ?? ''}"` });
    }

    if (!/\btags:\s*.*\brsec\b/.test(text)) {
      violations.push({ file: rel, rule: 'required-tag', detail: 'info.tags must include "rsec"' });
    }

    // every matcher must declare type AND part (N3)
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (/^\s*-\s*type:\s*\S+/.test(lines[i] ?? '')) {
        const block = lines.slice(i + 1, i + 9).join('\n');
        if (!/^\s+part:\s*\S+/m.test(block)) {
          violations.push({ file: rel, rule: 'matcher-part', detail: `matcher at line ${i + 1} lacks "part:"` });
        }
      }
    }

    const requestCount = lines.filter((l) => /^\s*-\s*method:\s*\S+/.test(l)).length;
    if (requestCount === 0) violations.push({ file: rel, rule: 'requests', detail: 'no http request block' });
    if (requestCount > 3) violations.push({ file: rel, rule: 'max-requests', detail: `${requestCount} request blocks (max 3)` });

    // N7 DSL allowlist
    if (/^\s*code:\s*$/m.test(text) || /^\s*code:\s*\S/m.test(text)) {
      violations.push({ file: rel, rule: 'dsl-allowlist', detail: '"code:" protocol block is banned (N7)' });
    }
    if (/javascript:/i.test(text)) {
      violations.push({ file: rel, rule: 'dsl-allowlist', detail: 'javascript expressions are banned (N7)' });
    }
    if (/^payloads:/m.test(text)) {
      const start = lines.findIndex((l) => /^payloads:/m.test(l));
      let count = 0;
      for (let i = start + 1; i < lines.length && !/^\S/.test(lines[i] ?? ' '); i++) {
        if (/^\s*-\s/.test(lines[i] ?? '')) count++;
      }
      if (count > 40) violations.push({ file: rel, rule: 'payload-cap', detail: `${count} payload items (max 40)` });
    }
  }

  // index.json consistency (paths normalized to forward slashes)
  try {
    const index = JSON.parse(readFileSync(join(dir, 'index.json'), 'utf8')) as { templates: Array<{ file: string; requires?: string[] }> };
    const indexed = new Set(index.templates.map((t) => t.file.replace(/\\/g, '/')));
    for (const file of files) {
      const rel = file.slice(dir.length + 1).replace(/\\/g, '/');
      if (!indexed.has(rel)) violations.push({ file: rel, rule: 'index-entry', detail: 'template missing from index.json' });
    }
    for (const t of index.templates) {
      for (const r of t.requires ?? []) {
        if (!KNOWN_CAPABILITIES.has(r)) violations.push({ file: t.file, rule: 'capability-unknown', detail: `requires unknown capability "${r}"` });
      }
    }
  } catch (e) {
    violations.push({ file: 'index.json', rule: 'index-parse', detail: e instanceof Error ? e.message : String(e) });
  }
  return violations;
}

function listYamls(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...listYamls(p));
    else if (name.endsWith('.yaml')) out.push(p);
  }
  return out;
}

const isMain = process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop() ?? '?');
if (isMain) {
  const dir = join(import.meta.dirname, '..', 'templates');
  const violations = lintTemplates(dir);
  if (violations.length > 0) {
    for (const v of violations) console.error(`VIOLATION [${v.rule}] ${v.file}: ${v.detail}`);
    console.error(`lint:templates — ${violations.length} violation(s)`);
    process.exit(1);
  }
  console.log(`lint:templates — OK (${listYamls(dir).length} templates)`);
}
