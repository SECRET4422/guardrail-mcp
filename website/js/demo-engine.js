/**
 * Browser-side GuardRail demo engine.
 * Not a full port of the Python scanners — a high-fidelity client simulation
 * using the same rule IDs / severities so the live demo feels real and never "hangs".
 */
(function (global) {
  const RULES = [
    {
      id: "GR-SEC-001",
      name: "Exposed AWS Access Key ID",
      severity: "CRITICAL",
      re: /\b(AKIA[0-9A-Z]{16})\b/g,
      remediation: "Rotate the key in IAM and load credentials from a secret store.",
    },
    {
      id: "GR-SEC-002",
      name: "Hardcoded Credential Assignment",
      severity: "HIGH",
      re: /\b(api[_-]?key|password|secret|token|passwd)\b\s*[:=]\s*['"][^'"]{8,}['"]/gi,
      remediation: "Move secrets to environment variables or a vault.",
    },
    {
      id: "GR-SEC-002b",
      name: "Provider API Token Prefix",
      severity: "CRITICAL",
      re: /\b(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
      remediation: "Revoke the token at the provider and rotate integrations.",
    },
    {
      id: "GR-SEC-003",
      name: "Dynamic Code Execution (eval/exec)",
      severity: "CRITICAL",
      re: /(?<![\w.])(eval|exec)\s*\(/g,
      remediation: "Remove eval/exec; use safe parsers or allow-listed operations.",
    },
    {
      id: "GR-SEC-004",
      name: "SQL String Interpolation in execute()",
      severity: "HIGH",
      re: /\.execute\s*\(\s*f?['"][^'"]*\{[^}]+\}/g,
      remediation: "Use bound parameters instead of f-strings in SQL.",
    },
    {
      id: "GR-SEC-005",
      name: "Shell Invocation with shell=True",
      severity: "HIGH",
      re: /subprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True/g,
      remediation: "Use shell=False with an argument list.",
    },
    {
      id: "GR-SEC-005b",
      name: "os.system / os.popen Usage",
      severity: "HIGH",
      re: /\b(os\.system|os\.popen)\s*\(/g,
      remediation: "Replace with subprocess.run([...], shell=False).",
    },
    {
      id: "GR-SEC-006",
      name: "Insecure YAML Load",
      severity: "HIGH",
      re: /\byaml\.load\s*\(/g,
      remediation: "Use yaml.safe_load().",
    },
    {
      id: "GR-SEC-009",
      name: "Pickle Deserialization",
      severity: "HIGH",
      re: /\bpickle\.(loads?|Unpickler)\s*\(/g,
      remediation: "Prefer JSON for untrusted data.",
    },
    {
      id: "GR-SEC-010",
      name: "Hardcoded Private Key Block",
      severity: "CRITICAL",
      re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
      remediation: "Remove the key, rotate it, store in a secrets manager.",
    },
    {
      id: "GR-JS-001",
      name: "JS eval / Function",
      severity: "CRITICAL",
      re: /\b(?:eval|new\s+Function)\s*\(/g,
      remediation: "Avoid dynamic code generation from strings.",
    },
    {
      id: "GR-JS-004",
      name: "innerHTML assignment",
      severity: "HIGH",
      re: /\.innerHTML\s*=/g,
      remediation: "Use textContent or sanitize HTML.",
    },
    {
      id: "GR-C-001",
      name: "Dangerous C string API",
      severity: "HIGH",
      re: /\b(gets|strcpy|strcat|sprintf)\s*\(/g,
      remediation: "Use bounded string APIs.",
    },
    {
      id: "GR-C-002",
      name: "system() call",
      severity: "CRITICAL",
      re: /\bsystem\s*\(/g,
      remediation: "Avoid shelling out with untrusted input.",
    },
    {
      id: "GR-GO-002",
      name: "Go SQL via fmt.Sprintf",
      severity: "CRITICAL",
      re: /(?:Query|Exec)\s*\(\s*fmt\.Sprintf/g,
      remediation: "Use parameterized queries.",
    },
    {
      id: "GR-TAINT-003",
      name: "Likely Tainted SQL Flow",
      severity: "CRITICAL",
      test: (src) =>
        /\b(request\.|input\s*\(|argv)/.test(src) &&
        /\.execute\s*\(/.test(src) &&
        (src.includes("f\"") || src.includes("f'") || src.includes(".format") || src.includes("%")),
      remediation: "Bind parameters; do not interpolate request data into SQL.",
    },
    {
      id: "GR-TAINT-001",
      name: "Likely Tainted Code Execution",
      severity: "CRITICAL",
      test: (src) =>
        /\b(request\.|input\s*\()/.test(src) && /\beval\s*\(/.test(src),
      remediation: "Never eval untrusted input.",
    },
  ];

  const WEIGHT = { CRITICAL: 40, HIGH: 25, MEDIUM: 10, LOW: 4, INFO: 1 };

  function lineOf(src, index) {
    return src.slice(0, index).split("\n").length;
  }

  function lineText(src, line) {
    return src.split("\n")[line - 1] || "";
  }

  function redact(text) {
    if (!text) return text;
    return text
      .replace(/(['"])([^'"\n]{8,})\1/g, (_, q, v) => {
        if (v.length <= 8) return q + "*".repeat(v.length) + q;
        return q + v.slice(0, 2) + "*".repeat(Math.min(10, v.length - 4)) + v.slice(-2) + q;
      })
      .replace(/\b(AKIA[0-9A-Z]{16})\b/g, (m) => m.slice(0, 4) + "********" + m.slice(-2))
      .replace(/\b(ghp_|sk-|sk-proj-)[A-Za-z0-9_-]{8,}/g, (m) => m.slice(0, 4) + "********");
  }

  function scan(source) {
    const src = String(source || "");
    const issues = [];
    const seen = new Set();

    for (const rule of RULES) {
      if (typeof rule.test === "function") {
        if (rule.test(src)) {
          const idx = src.search(/execute|eval/);
          const line = idx >= 0 ? lineOf(src, Math.max(0, idx)) : 1;
          const key = rule.id + ":" + line;
          if (!seen.has(key)) {
            seen.add(key);
            issues.push({
              rule_id: rule.id,
              vulnerability_name: rule.name,
              severity: rule.severity,
              line,
              excerpt_redacted: redact(lineText(src, line).trim().slice(0, 120)),
              remediation: rule.remediation,
            });
          }
        }
        continue;
      }
      if (!rule.re) continue;
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(src)) !== null) {
        const line = lineOf(src, m.index);
        const key = rule.id + ":" + line + ":" + m[0].slice(0, 12);
        if (seen.has(key)) continue;
        seen.add(key);
        issues.push({
          rule_id: rule.id,
          vulnerability_name: rule.name,
          severity: rule.severity,
          line,
          excerpt_redacted: redact(lineText(src, line).trim().slice(0, 120)),
          remediation: rule.remediation,
        });
        if (issues.length >= 40) break;
      }
    }

    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    issues.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || a.line - b.line);

    let score = 0;
    for (const i of issues) score += WEIGHT[i.severity] || 10;
    score = Math.min(999, score);

    let secScore = 100;
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const i of issues) {
      counts[i.severity] = (counts[i.severity] || 0) + 1;
      secScore -= { CRITICAL: 25, HIGH: 12, MEDIUM: 5, LOW: 2 }[i.severity] || 5;
    }
    secScore = Math.max(0, Math.min(100, secScore));
    const grade =
      secScore >= 90 ? "A" : secScore >= 75 ? "B" : secScore >= 60 ? "C" : secScore >= 40 ? "D" : "F";

    return {
      status: "OK",
      engines: ["demo-regex", "demo-taint-heuristics"],
      issue_count: issues.length,
      issues,
      risk_score: score,
      risk_level: score >= 100 ? "CRITICAL" : score >= 50 ? "HIGH" : score >= 20 ? "MEDIUM" : score > 0 ? "LOW" : "NONE",
      security_verdict: score >= 40 ? "REJECTED" : "APPROVED",
      policy_decision: score >= 40 ? "DENY" : "ALLOW",
      security_score: { score: secScore, grade, severity_counts: counts },
      notes: [
        "Browser demo engine — mirrors GuardRail rule IDs for UX.",
        "For production truth, use the Python MCP/CLI hybrid_scan.",
      ],
    };
  }

  const SAMPLES = {
    python_bad: `import os, subprocess, pickle

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
password = "SuperSecretPassw0rd!"
api_key = "sk-proj-thisIsAFakeOpenAIStyleToken123456"

def search_users(db, name: str):
    # SQL injection pattern
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'")

def run_user_cmd(cmd: str):
    subprocess.run(cmd, shell=True)
    os.system(cmd)

def load_state(blob: bytes):
    return pickle.loads(blob)

def dynamic(expr: str):
    return eval(expr)
`,
    python_taint: `def handler(request, db):
    user = request.args.get("q")
    q = f"SELECT * FROM items WHERE q = '{user}'"
    db.execute(q)
    expr = request.form.get("expr")
    return eval(expr)
`,
    python_clean: `def add(a: int, b: int) -> int:
    """Safe helper."""
    return a + b

def greet(name: str) -> str:
    return f"hello {name}"
`,
    javascript_bad: `const { exec } = require('child_process');

function run(userDir) {
  eval(userDir);
  exec(\`ls \${userDir}\`);
  element.innerHTML = userDir;
}
`,
    go_bad: `package main
import "fmt"
func badQuery(db *sql.DB, id string) {
  db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))
}
`,
    c_bad: `#include <string.h>
#include <stdlib.h>
void bad(char *src) {
  char buf[16];
  strcpy(buf, src);
  system(src);
}
`,
  };

  global.GuardRailDemo = { scan, SAMPLES, RULES };
})(typeof window !== "undefined" ? window : globalThis);
