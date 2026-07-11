"""
Deterministic 'AI-style' fix drafts from findings.

Produces unified-diff-like suggestions and natural-language patches
without calling an external model (offline, reproducible).
Agents can apply or further refine these drafts.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# rule_id prefix / exact → fix template
_FIX_TEMPLATES: Dict[str, Dict[str, str]] = {
    "GR-SEC-003": {
        "title": "Remove dynamic eval/exec",
        "guidance": "Replace eval/exec with a safe parser or explicit allow-listed operations.",
        "example_before": "result = eval(user_input)",
        "example_after": "result = ast.literal_eval(user_input)  # literals only\n# or: result = ALLOWED[user_input]()",
    },
    "GR-AST-003": {
        "title": "Remove dynamic eval/exec (including aliases)",
        "guidance": "Delete aliases to eval/exec and use explicit safe APIs.",
        "example_before": "runner = eval\nrunner(payload)",
        "example_after": "# removed alias\n# parse structured input instead\ndata = json.loads(payload)",
    },
    "GR-AST-004": {
        "title": "Parameterize SQL query",
        "guidance": "Never interpolate untrusted values into SQL; use bound parameters.",
        "example_before": "db.execute(f\"SELECT * FROM t WHERE id = '{user_id}'\")",
        "example_after": "db.execute(\"SELECT * FROM t WHERE id = ?\", (user_id,))",
    },
    "GR-AST-004b": {
        "title": "Parameterize interpolated SQL",
        "guidance": "Move SQL to a constant with placeholders; pass values separately.",
        "example_before": "cur.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)",
        "example_after": "cur.execute(\"SELECT * FROM t WHERE n = %s\", (name,))",
    },
    "GR-SEC-004": {
        "title": "Use bound parameters in execute()",
        "guidance": "Replace f-strings/concat inside execute with placeholders.",
        "example_before": "cur.execute(f\"SELECT * FROM u WHERE name='{name}'\")",
        "example_after": "cur.execute(\"SELECT * FROM u WHERE name=?\", (name,))",
    },
    "GR-AST-005": {
        "title": "Disable shell and use argv list",
        "guidance": "Prefer shell=False with a fixed executable and argument vector.",
        "example_before": "subprocess.run(cmd, shell=True)",
        "example_after": "subprocess.run([\"/usr/bin/echo\", arg], shell=False, check=True)",
    },
    "GR-SEC-005": {
        "title": "Avoid shell=True",
        "guidance": "Pass a list of arguments; never build a shell string from user input.",
        "example_before": "subprocess.run(f\"ls {path}\", shell=True)",
        "example_after": "subprocess.run([\"ls\", path], shell=False, check=True)",
    },
    "GR-SEC-005b": {
        "title": "Replace os.system",
        "guidance": "Use subprocess.run with an argument list.",
        "example_before": "os.system(\"rm -rf \" + path)",
        "example_after": "subprocess.run([\"rm\", \"-rf\", \"--\", path], check=True)",
    },
    "GR-AST-006": {
        "title": "Use yaml.safe_load",
        "guidance": "Never yaml.load untrusted data without SafeLoader.",
        "example_before": "cfg = yaml.load(open('c.yaml'))",
        "example_after": "cfg = yaml.safe_load(open('c.yaml'))",
    },
    "GR-SEC-006": {
        "title": "Use yaml.safe_load",
        "guidance": "Switch to safe_load or explicit SafeLoader.",
        "example_before": "yaml.load(stream)",
        "example_after": "yaml.safe_load(stream)",
    },
    "GR-AST-009": {
        "title": "Avoid pickle for untrusted data",
        "guidance": "Prefer JSON or a signed format; never pickle.loads untrusted bytes.",
        "example_before": "obj = pickle.loads(blob)",
        "example_after": "obj = json.loads(blob.decode())",
    },
    "GR-SEC-009": {
        "title": "Replace pickle.loads",
        "guidance": "Use JSON/msgpack for interchange; restrict pickle to trusted local cache only.",
        "example_before": "pickle.loads(data)",
        "example_after": "json.loads(data)",
    },
    "GR-SEC-001": {
        "title": "Remove AWS access key from source",
        "guidance": "Rotate the key in IAM and load credentials from the environment or a secrets manager.",
        "example_before": 'AWS_ACCESS_KEY_ID = "AKIA..."',
        "example_after": 'AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]',
    },
    "GR-SEC-001b": {
        "title": "Remove AWS secret from source",
        "guidance": "Revoke the secret and inject via Secrets Manager / env at runtime.",
        "example_before": 'aws_secret_access_key = "wJal..."',
        "example_after": 'aws_secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]',
    },
    "GR-SEC-002": {
        "title": "Externalize credentials",
        "guidance": "Move secrets to environment variables or a vault; keep placeholders in git.",
        "example_before": 'password = "SuperSecret123"',
        "example_after": 'password = os.environ["DB_PASSWORD"]',
    },
    "GR-SEC-002b": {
        "title": "Revoke and externalize API token",
        "guidance": "Revoke the leaked token at the provider; load replacements from secrets.",
        "example_before": 'api_key = "sk-..."',
        "example_after": 'api_key = os.environ["API_KEY"]',
    },
    "GR-SEC-011": {
        "title": "Remove Slack webhook from source",
        "guidance": "Rotate the webhook in Slack admin and store the URL in a secret store.",
        "example_before": 'HOOK = "https://example.invalid/slack-webhook/..."',
        "example_after": 'HOOK = os.environ["SLACK_WEBHOOK_URL"]',
    },
    "GR-JS-001": {
        "title": "Remove JS eval",
        "guidance": "Use JSON.parse or a schema-validated parser.",
        "example_before": "eval(userInput)",
        "example_after": "JSON.parse(userInput)",
    },
    "GR-JS-002": {
        "title": "Use execFile with argv",
        "guidance": "Avoid shell string interpolation in child_process.",
        "example_before": "exec(`ls ${dir}`)",
        "example_after": "execFile('ls', [dir], {shell: false})",
    },
    "GR-JS-004": {
        "title": "Avoid raw innerHTML",
        "guidance": "Use textContent or sanitize HTML before assignment.",
        "example_before": "el.innerHTML = userHtml",
        "example_after": "el.textContent = userHtml\n// or: el.innerHTML = DOMPurify.sanitize(userHtml)",
    },
    "GR-GO-002": {
        "title": "Parameterize Go SQL",
        "guidance": "Use placeholders instead of fmt.Sprintf for queries.",
        "example_before": 'db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))',
        "example_after": 'db.Query("SELECT * FROM t WHERE id=$1", id)',
    },
    "GR-JAVA-002": {
        "title": "Use PreparedStatement",
        "guidance": "Bind parameters instead of concatenating SQL.",
        "example_before": 'stmt.executeQuery("SELECT * FROM t WHERE id=" + id)',
        "example_after": 'ps = conn.prepareStatement("SELECT * FROM t WHERE id=?"); ps.setString(1, id);',
    },
    "GR-C-001": {
        "title": "Replace unsafe C string API",
        "guidance": "Use bounded string functions.",
        "example_before": "strcpy(dst, src);",
        "example_after": "snprintf(dst, sizeof(dst), \"%s\", src);",
    },
    "GR-C-002": {
        "title": "Replace system()",
        "guidance": "Use execve with an argv array.",
        "example_before": 'system(cmd);',
        "example_after": 'execlp("echo", "echo", arg, (char*)NULL);',
    },
    "GR-INFRA-002": {
        "title": "Restrict security group CIDR",
        "guidance": "Replace 0.0.0.0/0 with least-privilege source ranges.",
        "example_before": 'cidr_blocks = ["0.0.0.0/0"]',
        "example_after": 'cidr_blocks = ["10.0.0.0/8"]  # or office/VPN CIDR',
    },
    "GR-INFRA-003": {
        "title": "Disable privileged container mode",
        "guidance": "Remove privileged: true; add only required capabilities.",
        "example_before": "privileged: true",
        "example_after": "privileged: false\n# capabilities: { add: [\"NET_BIND_SERVICE\"] }",
    },
    "GR-INFRA-001": {
        "title": "Run container as non-root",
        "guidance": "Create a user and set USER to non-root.",
        "example_before": "USER root",
        "example_after": "RUN useradd -u 10001 app\nUSER app",
    },
}


def _lookup_template(rule_id: str) -> Optional[Dict[str, str]]:
    if rule_id in _FIX_TEMPLATES:
        return _FIX_TEMPLATES[rule_id]
    # prefix match longest key
    best = None
    for k, v in _FIX_TEMPLATES.items():
        if rule_id.startswith(k) and (best is None or len(k) > len(best)):
            best = k
    return _FIX_TEMPLATES[best] if best else None


def generate_fix_draft(finding: Dict[str, Any], *, path: Optional[str] = None) -> Dict[str, Any]:
    """
    Build a structured fix draft for one finding dict
    (keys: rule_id, line, excerpt_redacted, remediation, ...).
    """
    rule_id = finding.get("rule_id") or finding.get("id") or ""
    tmpl = _lookup_template(rule_id)
    line = finding.get("line") or 1
    excerpt = finding.get("excerpt_redacted") or finding.get("excerpt") or ""
    rem = finding.get("remediation") or ""

    if tmpl:
        title = tmpl["title"]
        guidance = tmpl["guidance"]
        before = tmpl["example_before"]
        after = tmpl["example_after"]
    else:
        title = f"Address {rule_id}"
        guidance = rem or finding.get("description") or "Review and remediate this finding."
        before = excerpt or "# original code"
        after = f"# TODO: remediate {rule_id}\n{rem}".strip()

    loc = f"{path or 'file'}:{line}"
    unified = (
        f"--- a/{path or 'file'}\n"
        f"+++ b/{path or 'file'}\n"
        f"@@ line {line} @@\n"
        f"- {before.splitlines()[0] if before else excerpt}\n"
        f"+ {after.splitlines()[0] if after else '# fixed'}\n"
    )

    return {
        "rule_id": rule_id,
        "path": path,
        "line": line,
        "title": title,
        "guidance": guidance,
        "confidence": "high" if tmpl else "medium",
        "example_before": before,
        "example_after": after,
        "unified_diff_sketch": unified,
        "agent_prompt": (
            f"Fix the security issue {rule_id} at {loc}.\n"
            f"Guidance: {guidance}\n"
            f"Current excerpt: {excerpt}\n"
            f"Preferred pattern:\n{after}\n"
            "Keep behavior equivalent where possible; add tests if behavior changes."
        ),
    }


def generate_fixes_for_issues(
    issues: List[Dict[str, Any]],
    *,
    path: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    out = []
    for issue in issues[:limit]:
        out.append(generate_fix_draft(issue, path=path or issue.get("path")))
    return out
