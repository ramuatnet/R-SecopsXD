/**
 * Headless CLI for the assessment platform: register/approve targets, run
 * scans, wait, export reports — without the web UI. Uses the platform core
 * directly (same code paths as the API).
 *
 * Examples:
 *   node src/cli/cli.ts target register --name "Local app" --kind webapp --origin http://127.0.0.1:3000
 *   node src/cli/cli.ts target approve <id>
 *   node src/cli/cli.ts scan start --target <id> --profile standard-active --mode active --wait
 *   node src/cli/cli.ts scan report <scanId> --format pdf --out report.pdf
 *   node src/cli/cli.ts findings <scanId> --severity high
 *   node src/cli/cli.ts engines
 */
import { writeFileSync } from 'node:fs';
import { buildPlatform } from '../server.ts';
import type { Scan } from '../core/types.ts';
import type { Database } from '../db/database.ts';

function parseArgs(argv: string[]): { _: string[]; flags: Record<string, string> } {
  const _: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = 'true';
      }
    } else {
      _.push(a);
    }
  }
  return { _, flags };
}

async function waitForScan(dbScan: (id: string) => Scan | undefined, id: string, timeoutMs: number): Promise<Scan> {
  const start = Date.now();
  for (;;) {
    const scan = dbScan(id);
    if (scan && !['queued', 'running'].includes(scan.status)) return scan;
    if (Date.now() - start > timeoutMs) throw new Error(`scan ${id} timeout after ${timeoutMs}ms`);
    await new Promise((r) => setTimeout(r, 300));
  }
}

function resolveScan(db: Database, idOrPrefix: string): Scan {
  const exact = db.getScan(idOrPrefix);
  if (exact) return exact;
  const matches = db.listScans(200).filter((s) => s.id.startsWith(idOrPrefix));
  if (matches.length === 1) return matches[0]!;
  throw new Error(matches.length === 0 ? `no scan matching ${idOrPrefix}` : `ambiguous scan prefix ${idOrPrefix}`);
}

async function main(): Promise<number> {
  const { _, flags } = parseArgs(process.argv.slice(2));
  const [cmd, sub] = _;
  const platform = buildPlatform();
  const { db, orchestrator, registry } = platform;
  const KNOWN_SUBS = ['register', 'approve', 'list', 'start', 'status', 'report'];
  const key = `${cmd ?? ''}${cmd && sub && KNOWN_SUBS.includes(sub) ? ` ${sub}` : ''}`.trim();
  try {
    switch (key) {
      case 'target register': {
        const kind = flags.kind === 'source' ? 'source' : 'webapp';
        if (kind === 'webapp' && !flags.origin) throw new Error('--origin required for webapp targets');
        if (kind === 'source' && !flags.sourcePath) throw new Error('--sourcePath required for source targets');
        const t = db.createTarget({
          name: flags.name ?? 'unnamed', origin: flags.origin ?? '', kind,
          sourcePath: flags.sourcePath, approved: false,
        });
        db.audit({ actor: 'cli', action: 'target.registered', details: { targetId: t.id } });
        console.log(JSON.stringify(t, null, 2));
        console.error(`\nNext: node src/cli/cli.ts target approve ${t.id}`);
        return 0;
      }
      case 'target approve': {
        const t = db.approveTarget(_[2]!, 'cli');
        if (!t) throw new Error('target not found');
        db.audit({ actor: 'cli', action: 'target.approved', details: { targetId: t.id } });
        console.log(`approved: ${t.name} (${t.origin || t.sourcePath})`);
        return 0;
      }
      case 'target credentials': {
        const target = db.getTarget(_[2]!);
        if (!target) throw new Error('target not found');
        if (!flags.username || !flags.password) throw new Error('--username and --password required');
        db.setCredentials(target.id, {
          username: flags.username, password: flags.password,
          loginUrl: flags.loginUrl, usernameField: flags.usernameField, passwordField: flags.passwordField,
        });
        console.log(`credentials stored (encrypted) for ${target.name} — active scans with --mode active will authenticate as ${flags.username}`);
        return 0;
      }
      case 'target list': {
        console.log(JSON.stringify(db.listTargets(), null, 2));
        return 0;
      }
      case 'scan start': {
        const target = flags.target ? db.getTarget(flags.target) : db.listTargets().find((t) => t.approved);
        if (!target) throw new Error('target not found (use --target <id>)');
        if (!target.approved) throw new Error(`target ${target.name} is not approved`);
        const mode = flags.mode === 'active' ? 'active' : 'passive';
        const scan = await orchestrator.startScan(target.id, flags.profile ?? 'standard-active', mode);
        console.error(`scan ${scan.id} started (${scan.profile}, ${mode})`);
        const final = flags.wait !== undefined ? await waitForScan((id) => db.getScan(id), scan.id, 1_800_000) : undefined;
        if (final) {
          console.log(JSON.stringify({ scan: final, findings: db.getFindings(final.id).length }, null, 2));
        } else {
          console.log(scan.id);
          console.error('use --wait to block until completion');
        }
        return 0;
      }
      case 'scan status': {
        const scan = resolveScan(db, _[2]!);
        console.log(JSON.stringify(scan, null, 2));
        return 0;
      }
      case 'scan report': {
        const scan = resolveScan(db, _[2]!);
        const fmt = flags.format ?? 'json';
        const out = flags.out ?? `assessment-${scan.id.slice(0, 8)}.${fmt}`;
        const { renderReport } = await import('../reports/registry.ts');
        const report = renderReport(scan, db.getFindings(scan.id), fmt);
        writeFileSync(out, report as never);
        console.log(`wrote ${out}`);
        return 0;
      }
      case 'findings': {
        const scanId = _[1] === 'findings' ? _[2] : _[1];
        if (!scanId) throw new Error('scan id required');
        const scan = resolveScan(db, scanId);
        let findings = db.getFindings(scan.id);
        if (flags.severity) findings = findings.filter((f) => f.severity === flags.severity);
        if (flags.category) findings = findings.filter((f) => f.category === flags.category);
        for (const f of findings) {
          console.log(`${f.severity.toUpperCase().padEnd(8)} ${f.category} ${f.status.padEnd(13)} ${f.title}  [${f.locator}] (${f.id})`);
        }
        console.error(`\n${findings.length} findings`);
        return 0;
      }
      case 'diff': {
        const target = db.listTargets().find((t) => t.id === _[1] || t.name === _[1]);
        if (!target) throw new Error('target not found (pass target id or name)');
        const completed = db.listScans(200).filter((sc) => sc.targetId === target.id && sc.status === 'completed');
        if (completed.length < 2) throw new Error('need at least two completed scans');
        const to = flags.to ? resolveScan(db, flags.to) : completed[0]!;
        const from = flags.from ? resolveScan(db, flags.from) : completed[1]!;
        const { diffScanFindings } = await import('../scan/diff.ts');
        const d = diffScanFindings(db.getFindings(from.id), db.getFindings(to.id), from.id, to.id);
        for (const f of d.added) console.log(`NEW       ${f.severity.padEnd(8)} ${f.category} ${f.title}`);
        for (const f of d.removed) console.log(`FIXED     ${f.severity.padEnd(8)} ${f.category} ${f.title}`);
        console.error(`
${d.added.length} new, ${d.removed.length} fixed, ${d.unchanged.length} persistent`);
        return 0;
      }
      case 'engines': {
        for (const id of registry.allEngineIds()) {
          const a = await registry.availability(id);
          console.log(`${a.available ? 'available  ' : 'UNAVAILABLE'} ${id.padEnd(28)} ${a.version ?? a.reason ?? ''}`);
        }
        return 0;
      }
      default:
        console.error(`unknown command: ${_.join(' ')}
usage:
  target register --name N --kind webapp|source [--origin URL] [--sourcePath PATH]
  target approve <id> | target list
  scan start --target <id> --profile <id> [--mode passive|active] [--wait]
  scan status <id> | scan report <id> --format json|html|pdf [--out FILE]
  findings <scanId> [--severity S] [--category A0x]
  engines`);
        return 2;
    }
  } finally {
    db.close();
  }
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`error: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  },
);
