/**
 * Template pack digest (hardtask.md J2/J3) — sha256 over index.json plus every
 * template file, sorted. `templates/pack-version.json` pins {version, digest};
 * lint:templates fails on mismatch, so any template change requires a version
 * bump in the same commit.
 *
 * Usage: node scripts/packDigest.ts   (prints digest; --check validates pin)
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

export function packDigest(dir = join(import.meta.dirname, '..', 'templates')): string {
  const h = createHash('sha256');
  h.update(readFileSync(join(dir, 'index.json')));
  const files: string[] = [];
  const walk = (d: string): void => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else if (n.endsWith('.yaml')) files.push(p);
    }
  };
  walk(dir);
  for (const f of files.sort()) h.update(readFileSync(f));
  return h.digest('hex');
}

const isMain = process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop() ?? '?');
if (isMain) {
  const dir = join(import.meta.dirname, '..', 'templates');
  const digest = packDigest(dir);
  if (process.argv.includes('--check')) {
    const pin = JSON.parse(readFileSync(join(dir, 'pack-version.json'), 'utf8')) as { version: number; digest: string };
    if (pin.digest !== digest) {
      console.error(`pack digest MISMATCH: pinned ${pin.digest} (v${pin.version}), actual ${digest}`);
      console.error('Template changes require a pack version bump commit (J3).');
      process.exit(1);
    }
    console.log(`pack digest OK: v${pin.version} ${digest}`);
  } else {
    console.log(digest);
  }
}
