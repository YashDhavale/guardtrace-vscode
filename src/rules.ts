export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface RuleMatch {
  ruleId: string;
  title: string;
  severity: Severity;
  owasp: string;
  line: number;
  startCol: number;
  endCol: number;
  message: string;
  suggestion: string;
  fix?: (lineText: string) => string | null;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  owasp: string;
  languages: string[]; // file extensions this applies to, '*' = all
  test: (lineText: string, lineNo: number, fullText: string) => Omit<RuleMatch, 'ruleId' | 'title' | 'severity' | 'owasp' | 'line'>[] ;
}

const SECRET_KEY_RE = /(api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*["']([a-zA-Z0-9_\-\/+=]{8,})["']/i;
const ENV_VAR_RE = /(process\.env|os\.environ|getenv)/i;

export const RULES: Rule[] = [
  {
    id: 'sql-injection',
    title: 'SQL Injection',
    severity: 'HIGH',
    owasp: 'A03: Injection',
    languages: ['*'],
    test: (line) => {
      const results: any[] = [];
      // string concatenation building a SQL query
      const patterns = [
        /(SELECT|INSERT|UPDATE|DELETE)\b[^"'`]*["'`]\s*\+\s*\w+/i,
        /["'`]\s*\+\s*\w+.*\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b/i,
        /f["']\s*(SELECT|INSERT|UPDATE|DELETE)[^"']*\{[^}]+\}/i, // python f-strings
        /`\s*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]+\}/i // JS template literals
      ];
      if (patterns.some((p) => p.test(line)) && !/execute\(\s*["'`][^"'`]*["'`]\s*,/.test(line)) {
        const idx = line.search(/(SELECT|INSERT|UPDATE|DELETE)/i);
        results.push({
          startCol: Math.max(idx, 0),
          endCol: line.length,
          message: 'User-controlled input appears to be concatenated directly into a SQL query.',
          suggestion: 'Use a parameterized query, e.g. cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        });
      }
      return results;
    }
  },
  {
    id: 'command-injection',
    title: 'Command Injection',
    severity: 'HIGH',
    owasp: 'A03: Injection',
    languages: ['*'],
    test: (line) => {
      const results: any[] = [];
      const patterns = [
        /\bos\.system\s*\([^)]*\+/,
        /\bsubprocess\.(call|run|Popen)\s*\([^)]*\+/,
        /\bexec\s*\(\s*["'`]?[^)]*\+/,
        /\bchild_process\.(exec|execSync)\s*\([^)]*\+/,
        /\beval\s*\(/
      ];
      if (patterns.some((p) => p.test(line))) {
        results.push({
          startCol: 0,
          endCol: line.length,
          message: 'Untrusted input may be passed to a shell/exec call, allowing arbitrary command execution.',
          suggestion: 'Avoid shell=True/string concatenation; use subprocess with an argument list, or an allow-list of commands.'
        });
      }
      return results;
    }
  },
  {
    id: 'hardcoded-secret',
    title: 'Hardcoded Secret',
    severity: 'MEDIUM',
    owasp: 'A02: Cryptographic Failures',
    languages: ['*'],
    test: (line) => {
      const results: any[] = [];
      const m = SECRET_KEY_RE.exec(line);
      if (m && !ENV_VAR_RE.test(line) && !/example|placeholder|xxx|changeme|dummy|<.*>/i.test(m[2])) {
        results.push({
          startCol: m.index,
          endCol: m.index + m[0].length,
          message: `Possible hardcoded credential in variable "${m[1]}".`,
          suggestion: 'Move the secret to an environment variable or a secrets manager (e.g. process.env.API_KEY).'
        });
      }
      return results;
    }
  },
  {
    id: 'weak-crypto',
    title: 'Weak Cryptography',
    severity: 'MEDIUM',
    owasp: 'A02: Cryptographic Failures',
    languages: ['*'],
    test: (line) => {
      const results: any[] = [];
      const patterns = [/\bmd5\s*\(/i, /\bsha1\s*\(/i, /createHash\(\s*["']md5["']\s*\)/i, /createHash\(\s*["']sha1["']\s*\)/i, /\bDES\b/, /\bRC4\b/];
      if (patterns.some((p) => p.test(line))) {
        results.push({
          startCol: 0,
          endCol: line.length,
          message: 'Weak or broken cryptographic algorithm used for security-sensitive data.',
          suggestion: 'Use SHA-256 (or better, bcrypt/Argon2 for passwords) instead of MD5/SHA1/DES/RC4.'
        });
      }
      return results;
    }
  },
  {
    id: 'insecure-http',
    title: 'Insecure HTTP Endpoint',
    severity: 'LOW',
    owasp: 'A02: Cryptographic Failures',
    languages: ['*'],
    test: (line) => {
      const results: any[] = [];
      const m = /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"']+["']/i.exec(line);
      if (m) {
        results.push({
          startCol: m.index,
          endCol: m.index + m[0].length,
          message: 'Plaintext HTTP endpoint; traffic can be intercepted or tampered with.',
          suggestion: 'Use https:// for any endpoint that is not strictly local.'
        });
      }
      return results;
    }
  },
  {
    id: 'insecure-deserialization',
    title: 'Insecure Deserialization',
    severity: 'HIGH',
    owasp: 'A08: Software and Data Integrity Failures',
    languages: ['*'],
    test: (line) => {
      const results: any[] = [];
      const patterns = [/\bpickle\.loads?\s*\(/, /\byaml\.load\s*\(\s*[^,)]*\)(?!.*Loader\s*=\s*yaml\.SafeLoader)/, /\bnew\s+Function\s*\(/, /\beval\s*\(\s*.*JSON/i];
      if (patterns.some((p) => p.test(line))) {
        results.push({
          startCol: 0,
          endCol: line.length,
          message: 'Deserializing untrusted data can lead to remote code execution.',
          suggestion: 'Use safe deserializers (e.g. json.loads, yaml.safe_load) and never unpickle untrusted input.'
        });
      }
      return results;
    }
  },
  {
    id: 'path-traversal',
    title: 'Path Traversal',
    severity: 'LOW',
    owasp: 'A01: Broken Access Control',
    languages: ['*'],
    test: (line) => {
      const results: any[] = [];
      const patterns = [/open\s*\(\s*[^,)]*(req\.|request\.|params\.|user_input|input\()/i, /fs\.readFile\w*\s*\(\s*[^,)]*(req\.|request\.|params\.)/i];
      if (patterns.some((p) => p.test(line))) {
        results.push({
          startCol: 0,
          endCol: line.length,
          message: 'User-controlled input used directly in a file path.',
          suggestion: 'Validate/normalize the path and restrict it to an allowed base directory before use.'
        });
      }
      return results;
    }
  },
  {
    id: 'weak-randomness',
    title: 'Weak Randomness',
    severity: 'LOW',
    owasp: 'A02: Cryptographic Failures',
    languages: ['*'],
    test: (line) => {
      const results: any[] = [];
      if (/\bMath\.random\s*\(\s*\)/.test(line) && /(token|secret|password|session|key|otp|nonce)/i.test(line)) {
        results.push({
          startCol: 0,
          endCol: line.length,
          message: 'Math.random() is not cryptographically secure; unsuitable for tokens/secrets.',
          suggestion: 'Use crypto.randomBytes() (Node) or the secrets module (Python) for security-sensitive randomness.'
        });
      }
      if (/\brandom\.random\s*\(\s*\)/.test(line) && /(token|secret|password|session|key|otp|nonce)/i.test(line)) {
        results.push({
          startCol: 0,
          endCol: line.length,
          message: "Python's random module is not cryptographically secure.",
          suggestion: 'Use the secrets module, e.g. secrets.token_hex(32).'
        });
      }
      return results;
    }
  }
];

export function scanText(text: string, enabledRuleIds: string[]): RuleMatch[] {
  const lines = text.split(/\r?\n/);
  const findings: RuleMatch[] = [];
  const activeRules = RULES.filter((r) => enabledRuleIds.includes(r.id));

  lines.forEach((lineText, idx) => {
    // skip obvious comment lines to reduce false positives
    const trimmed = lineText.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
      return;
    }
    for (const rule of activeRules) {
      const matches = rule.test(lineText, idx, text);
      for (const m of matches) {
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          owasp: rule.owasp,
          line: idx,
          ...m
        });
      }
    }
  });

  return findings;
}
