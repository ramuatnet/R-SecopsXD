/**
 * End-to-end demo against the local vulnerable fixture (loopback only).
 * Usage: npm run demo
 */
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { buildPlatform } from '../src/server.ts';

const ROOT = join(import.meta.dirname, '..');
const PORT = 8899;

async function waitFor(url: string, timeoutMs: number): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`fixture at ${url} did not start`);
}

async function main(): Promise<void> {
  console.log('Starting vulnerable fixture app (loopback only)…');
  const fixture = spawn(process.execPath, [join(ROOT, 'fixtures', 'vuln-app', 'server.cjs')], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: 'ignore',
  });
  const platform = buildPlatform();
  try {
    await waitFor(`http://127.0.0.1:${PORT}/`, 15_000);

    const target = platform.db.createTarget({ name: 'Demo VulnApp', origin: `http://127.0.0.1:${PORT}`, kind: 'webapp', approved: false });
    platform.db.approveTarget(target.id, 'demo');
    console.log(`Target registered and approved: ${target.id}`);

    const scan = await platform.orchestrator.startScan(target.id, 'standard-active', 'active');
    console.log(`Scan ${scan.id.slice(0, 8)} started (standard-active)…`);
    const start = Date.now();
    let final;
    for (;;) {
      final = platform.db.getScan(scan.id);
      if (final && !['queued', 'running'].includes(final.status)) break;
      if (Date.now() - start > 120_000) throw new Error('demo scan timeout');
      await new Promise((r) => setTimeout(r, 300));
    }
    if (!final || final.status !== 'completed') throw new Error(`scan ${final?.status}: ${final?.error ?? ''}`);

    console.log('\n=== Findings ===');
    for (const f of platform.db.getFindings(scan.id)) {
      console.log(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.category} ${f.status.padEnd(13)} ${f.title}  → ${f.locator}`);
    }
    console.log('\n=== Coverage (honest limits) ===');
    for (const c of final.coverage) {
      console.log(`  ${c.category}  ${c.verdict.padEnd(11)} ${c.engines.join(', ') || 'manual'}`);
    }
    console.log(`\nOpen the UI for reports: npm start → http://127.0.0.1:7788`);
    console.log(`JSON export: node src/cli/cli.ts scan report ${scan.id} --format json`);
  } finally {
    fixture.kill();
    platform.db.close();
  }
}

main().then(() => process.exit(0), (e) => {
  console.error(`demo failed: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
