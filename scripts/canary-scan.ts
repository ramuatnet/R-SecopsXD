/**
 * Canary scan (newtask.md N10).
 *
 * npm run canary
 *
 * Layer 1 (always): parser canary — canned nuclei JSONL must map to the
 * expected finding fields; a regression in the mapping fails loudly.
 * Layer 2 (when installed): binary integrity status; if the pinned binary is
 * present AND the vuln-app fixture is up on 127.0.0.1:8899, the in-house pack
 * is executed against it and match counts reported. Missing binary or fixture
 * = honest skip, never a fake pass.
 */
import { NucleiAdapter, checkBinaryIntegrity } from '../src/engines/adapters/nuclei.ts';

const CANNED_JSONL = [
  JSON.stringify({
    'template-id': 'rsec-git-config-exposure',
    info: {
      name: 'Exposed .git/config',
      severity: 'high',
      description: 'The Git repository configuration file is publicly readable.',
      reference: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration/README'],
      classification: { 'cwe-id': ['CWE-538'] },
    },
    host: 'http://127.0.0.1:8899',
    'matched-at': 'http://127.0.0.1:8899/.git/config',
    type: 'http',
  }),
  'not-json noise line',
].join('\n');

async function parserCanary(): Promise<boolean> {
  const findings = NucleiAdapter.parseEvents(CANNED_JSONL, 'http://127.0.0.1:8899', 'canary');
  if (findings.length !== 1) {
    console.error(`canary FAIL: expected 1 finding, got ${findings.length}`);
    return false;
  }
  const f = findings[0]!;
  const checks: Array<[string, boolean]> = [
    ['rawId', f.rawId === 'rsec-git-config-exposure'],
    ['severity', f.severity === 'high'],
    ['cwe', f.cwe === 538],
    ['locator', f.locator === '/.git/config'],
    ['reference', f.references?.length === 1],
  ];
  for (const [name, ok] of checks) {
    if (!ok) { console.error(`canary FAIL: ${name} mismatch`); return false; }
  }
  console.log('parser canary: OK (1 finding mapped with id/severity/cwe/locator/reference)');
  return true;
}

async function main(): Promise<void> {
  const ok = await parserCanary();
  if (!ok) process.exit(1);

  const integrity = await checkBinaryIntegrity();
  if (!integrity.available) {
    console.log(`binary integrity: ${integrity.reason} — execution canary skipped honestly (N10)`);
    return;
  }
  console.log(`binary integrity: OK (${integrity.version})`);

  // Execution canary — only when the fixture is actually up.
  try {
    const res = await fetch('http://127.0.0.1:8899/', { signal: AbortSignal.timeout(2000) });
    void res;
  } catch {
    console.log('fixture 127.0.0.1:8899 not running — execution canary skipped honestly (N10)');
    return;
  }
  const { runProcess } = await import('../src/engines/adapters/common.ts');
  const { buildNucleiArgs, loadTemplateIndex, gateTemplates, inferCapabilities } = await import('../src/engines/adapters/nuclei.ts');
  const index = await loadTemplateIndex();
  const caps = inferCapabilities(undefined);
  const eligible = gateTemplates(index.templates, caps);
  const args = buildNucleiArgs('http://127.0.0.1:8899', 'active', eligible.map((e) => e.file));
  const proc = await runProcess('nuclei', args, { timeoutMs: 120_000 });
  const matches = proc.stdout.split('\n').filter((l) => l.startsWith('{')).length;
  console.log(`execution canary: nuclei exit=${proc.exitCode}, ${matches} match(es) on fixture from ${eligible.length} template(s)`);
}

await main();
