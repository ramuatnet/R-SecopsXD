/**
 * Generates sample reports (JSON/HTML/PDF) from a completed scan into
 * docs/samples/. Usage: node scripts/generate-samples.ts <scanId-prefix|latest> [dataDir]
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Database } from '../src/db/database.ts';
import { renderReport } from '../src/reports/registry.ts';

const ROOT = join(import.meta.dirname, '..');
const dataDir = process.argv[3] ?? join(ROOT, 'data-demo');
const prefix = process.argv[2] ?? 'latest';

const db = new Database(dataDir);
const scans = db.listScans(50);
const scan = prefix === 'latest'
  ? scans[0]
  : scans.find((s) => s.id.startsWith(prefix));
if (!scan) {
  console.error('no completed scan found');
  process.exit(1);
}
if (scan.status !== 'completed') {
  console.error(`scan ${scan.id} is ${scan.status}, not completed`);
  process.exit(1);
}

const findings = db.getFindings(scan.id);
const outDir = join(ROOT, 'docs', 'samples');
mkdirSync(outDir, { recursive: true });

const base = `assessment-${scan.targetName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${scan.id.slice(0, 8)}`;
for (const fmt of ['json', 'html', 'pdf']) {
  const out = renderReport(scan, findings, fmt);
  const file = join(outDir, `${base}.${fmt}`);
  writeFileSync(file, out as never);
  console.log(`wrote ${file} (${fmt === 'pdf' ? `${(out as Uint8Array).byteLength} bytes` : `${(out as string).length} chars`})`);
}
db.close();
