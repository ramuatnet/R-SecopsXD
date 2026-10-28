/**
 * Built-in source review engine — heuristic pattern scanning of source trees.
 *
 * These are REGEX HEURISTICS, not dataflow analysis: expect false negatives
 * (obfuscated/aliased sinks) and occasional false positives (test fixtures,
 * docs). Every finding is labelled confidence=low|medium and
 * status=probable, with file/line evidence for human verification. For real
 * SAST use the Semgrep adapter.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import type { Engine, EngineAvailability, EngineRunResult, ScanContext } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo, FileEvidence, RawFinding } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.source-scan',
  name: 'Source Pattern Review',
  kind: 'builtin',
  capabilities: {
    A04: cap('weak hash / crypto primitives, disabled certificate validation (pattern-level)'),
    A05: cap('SQL string concatenation, eval usage (pattern-level, no dataflow)'),
    A07: cap('hardcoded credentials (pattern-level)'),
  },
  modes: ['passive', 'active'],
  targetKinds: ['source'],
};

interface SourceRule {
  id: string;
  title: string;
  category: 'A02' | 'A03' | 'A04' | 'A05' | 'A07' | 'A08' | 'A09';
  cwe: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: 'low' | 'medium';
  pattern: RegExp;
  exclude?: RegExp;
  explanation: string;
  remediation: string;
  references: string[];
}

const RULES: SourceRule[] = [
  {
    id: 'hardcoded-credential',
    title: 'Hardcoded credential in source',
    category: 'A07', cwe: 798, severity: 'high', confidence: 'medium',
    pattern: /(?:^|[^a-z0-9])(api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*["'][^"'\s]{8,}["']/i,
    exclude: /process\.env|getenv|placeholder|example|xxx+|dummy|\$\{|\bchangeme\b|test|spec|fixtures?|mock/i,
    explanation: 'A credential appears to be hardcoded in source code. Anyone with repository access, and anyone who obtains a build artifact or leaked source, recovers the secret.',
    remediation: 'Move the secret to a secret manager or environment configuration; rotate the exposed credential; add secret scanning to CI.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
  },
  {
    id: 'weak-hash-md5-sha1',
    title: 'Weak hash algorithm (MD5/SHA-1) used',
    category: 'A04', cwe: 327, severity: 'medium', confidence: 'medium',
    pattern: /createHash\(\s*["'](md5|sha1)["']\s*\)/i,
    explanation: 'MD5/SHA-1 are broken for security purposes. If used for password storage or signatures, collisions/preimages are practical. (Note: non-security checksums are a false positive of this rule.)',
    remediation: 'Use SHA-256 or better for integrity; for password storage use Argon2id/bcrypt/scrypt.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
  },
  {
    id: 'sql-concatenation',
    title: 'SQL query built by string concatenation',
    category: 'A05', cwe: 89, severity: 'high', confidence: 'medium',
    pattern: /["'](SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)[^"';]*["']\s*\+\s*\w/i,
    exclude: /fixtures?|test|spec|mock/i,
    explanation: 'A SQL statement appears to be assembled with string concatenation of a variable, the classic SQL injection pattern. Without dataflow analysis the platform cannot confirm the concatenated value is attacker-controlled.',
    remediation: 'Use parameterized queries / prepared statements; never interpolate input into SQL text.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  {
    id: 'tls-verification-disabled',
    title: 'TLS certificate verification disabled',
    category: 'A04', cwe: 295, severity: 'high', confidence: 'medium',
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|InsecureSkipVerify\s*:\s*true/,
    exclude: /fixtures?|test|spec|mock/i,
    explanation: 'Certificate verification is disabled for an TLS connection, enabling machine-in-the-middle attacks against that channel.',
    remediation: 'Enable certificate verification; if needed for self-signed internal services, pin the specific CA instead of disabling verification.',
    references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README'],
  },
  {
    id: 'secrets-in-logs',
    title: 'Sensitive data written to logs',
    category: 'A09', cwe: 532, severity: 'high', confidence: 'medium',
    pattern: /(console|logger|log)\s*\.\s*(log|info|warn|error|debug)\s*\([^)]*\b(password|passwd|secret|token|apikey|api[_-]?key|authorization)\b/i,
    exclude: /fixtures?|test|spec|mock/i,
    explanation: 'A log statement appears to include credential-bearing values. Logs are broadly readable (ops, support, log aggregators, breaches) — CWE-532 insertion of sensitive information into log files.',
    remediation: 'Never log credentials or tokens; log identifiers instead, and redact at the logging framework level.',
    references: ['https://owasp.org/Top10/2025/en/A09_2025-Security_Logging_and_Alerting_Failures/'],
  },
  {
    id: 'log-injection',
    title: 'Potential log injection from request data',
    category: 'A09', cwe: 117, severity: 'low', confidence: 'low',
    pattern: /(logger|log|console)\s*\.\s*(info|warn|error|log|debug)\s*\(\s*[`"][^`"\$]*(\$\{[^}]*req(uest)?\.(query|body|params|headers))/i,
    exclude: /fixtures?|test|spec|mock/i,
    explanation: 'Request-controlled data appears to be interpolated directly into a log line, enabling log forging / injection (CWE-117). Low confidence without dataflow analysis.',
    remediation: 'Sanitize or encode untrusted input before logging; prefer structured logging with field separation.',
    references: ['https://owasp.org/www-community/attacks/Log_Injection'],
  },
  {
    id: 'eval-usage',
    title: 'eval() usage on potentially untrusted input',
    category: 'A05', cwe: 94, severity: 'medium', confidence: 'low',
    pattern: /(^|[^.\w])eval\s*\(/,
    exclude: /fixtures?|test|spec|mock/i,
    explanation: 'eval() executes a string as code. If any part of the string derives from untrusted input this is code injection. The platform cannot determine taint without dataflow analysis, hence low confidence.',
    remediation: 'Remove eval(); use JSON.parse or explicit parsing; if dynamic execution is unavoidable, sandbox and strictly allow-list inputs.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html'],
  },
];

const SOURCE_EXT = /\.(ts|js|mjs|cjs|tsx|jsx|py|rb|php|java|go|cs|json|yml|yaml|xml|config|env|ini|sh|ps1)$/i;
const SKIP_DIRS = new Set(['node_modules', '.git', 'data', 'dist', 'build', 'coverage', '.venv', 'vendor']);
const MAX_FILE_BYTES = 512 * 1024;
const MAX_FILES = 2000;

export class SourceScanEngine implements Engine {
  info = INFO;

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const root = ctx.target.sourcePath;
    if (!root) return { findings: [], detail: 'no sourcePath on target' };
    const findings: RawFinding[] = [];
    let files = 0;

    const walk = (dir: string): void => {
      if (files >= MAX_FILES || ctx.signal.aborted) return;
      let entries: string[];
      try {
        entries = readdirSync(dir);
      } catch {
        return;
      }
      for (const entry of entries) {
        if (files >= MAX_FILES) return;
        if (SKIP_DIRS.has(entry)) continue;
        const full = join(dir, entry);
        let st;
        try {
          st = statSync(full);
        } catch {
          continue;
        }
        if (st.isDirectory()) {
          walk(full);
          continue;
        }
        if (!SOURCE_EXT.test(entry) || st.size > MAX_FILE_BYTES) continue;
        files++;
        let text: string;
        try {
          text = readFileSync(full, 'utf8');
        } catch {
          continue;
        }
        findings.push(...this.scanFile(ctx, root, full, text));
      }
    };

    walk(root);
    ctx.log('source scan finished', { files, findings: findings.length });
    return { findings, version: 'builtin', detail: `${files} files reviewed` };
  }

  private scanFile(ctx: ScanContext, root: string, filePath: string, text: string): RawFinding[] {
    const findings: RawFinding[] = [];
    const rel = relative(root, filePath).split(sep).join('/');
    const lines = text.split('\n');
    for (const rule of RULES) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        if (!rule.pattern.test(line)) continue;
        if (rule.exclude && rule.exclude.test(line)) continue;
        const evidence: FileEvidence = {
          kind: 'file',
          path: rel,
          lineStart: i + 1,
          lineEnd: i + 1,
          excerpt: line.trim().slice(0, 300),
          observation: `Line ${i + 1} matches pattern for ${rule.id}`,
        };
        findings.push({
          rawId: rule.id,
          title: rule.title,
          category: rule.category,
          cwe: rule.cwe,
          severity: rule.severity,
          confidence: rule.confidence,
          status: 'probable',
          asset: ctx.target.sourcePath ?? ctx.target.name,
          locator: `${rel}:${i + 1}`,
          evidence: [evidence],
          explanation: rule.explanation,
          remediation: rule.remediation,
          references: rule.references,
        });
      }
    }
    return findings;
  }
}
