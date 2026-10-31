/**
 * Live nuclei execution tests (B2/N6/N10) — run the pinned binary against
 * fixtures. Skips honestly when the binary is not installed.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { checkBinaryIntegrity, NucleiAdapter, loadTemplateIndex, gateTemplates, inferCapabilities, buildNucleiArgs } from '../../src/engines/adapters/nuclei.ts';
import { runProcess } from '../../src/engines/adapters/common.ts';

const integrity = await checkBinaryIntegrity();
const available = integrity.available;

test('nuclei binary integrity: pinned version + sha256 verified (N6)', { skip: !available && 'nuclei binary not installed' }, async () => {
  assert.ok(available);
  assert.match(integrity.version ?? '', /v?3\.11\.1/, 'pinned version recorded');
});

test('pack executes end-to-end and detects planted exposures (B2 closed loop)', { skip: !available && 'nuclei binary not installed' }, async () => {
  const server = createServer((req, res) => {
    if (req.url === '/.git/config') { res.writeHead(200); res.end('[core]\n  repositoryformatversion = 0\n  bare = false'); return; }
    if (req.url === '/.env') { res.writeHead(200); res.end('DB_PASSWORD=supersecret\nAPI_KEY=abc123'); return; }
    res.writeHead(404); res.end('nope');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const index = await loadTemplateIndex();
    const eligible = gateTemplates(index.templates, inferCapabilities(undefined));
    const args = buildNucleiArgs(`http://127.0.0.1:${port}`, 'active', eligible.map((e) => e.file));
    const proc = await runProcess('nuclei', args, { timeoutMs: 120_000 });
    assert.equal(proc.exitCode, 0, `nuclei exits clean, stderr: ${proc.stderr.slice(0, 200)}`);
    const findings = NucleiAdapter.parseEvents(proc.stdout, `http://127.0.0.1:${port}`, 'test');
    const ids = new Set(findings.map((f) => f.rawId));
    assert.ok(ids.has('rsec-git-config-exposure'), 'planted .git/config detected');
    assert.ok(ids.has('rsec-env-file-exposure'), 'planted .env detected');
    const git = findings.find((f) => f.rawId === 'rsec-git-config-exposure')!;
    assert.equal(git.severity, 'high');
    assert.equal(git.cwe, 538, 'cwe-id parsed from lowercase nuclei classification');
    assert.equal(git.locator, '/.git/config');
  } finally {
    server.close();
  }
});

test('clean fixture yields zero pack matches (precision control)', { skip: !available && 'nuclei binary not installed' }, async () => {
  const server = createServer((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><body>clean app</body></html>'); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const index = await loadTemplateIndex();
    const eligible = gateTemplates(index.templates, inferCapabilities(undefined));
    const args = buildNucleiArgs(`http://127.0.0.1:${port}`, 'active', eligible.map((e) => e.file));
    const proc = await runProcess('nuclei', args, { timeoutMs: 120_000 });
    const findings = NucleiAdapter.parseEvents(proc.stdout, `http://127.0.0.1:${port}`, 'test');
    assert.equal(findings.length, 0, 'no false positives on a clean fixture');
  } finally {
    server.close();
  }
});
