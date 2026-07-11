"""Heuristic vulnerability signatures (demo-grade static patterns)."""

from __future__ import annotations

from .models import Severity, VulnerabilityRule

# Patterns are intentionally conservative where false positives are costly
# (e.g. shell invocations) and stricter for credential shapes.
VULNERABILITY_RULES: list[VulnerabilityRule] = [
    VulnerabilityRule(
        id="GR-SEC-001",
        name="Exposed AWS Access Key ID",
        pattern=r"\b(AKIA[0-9A-Z]{16})\b",
        severity=Severity.CRITICAL,
        description=(
            "An Amazon Web Services access key ID (AKIA…) appears in plaintext. "
            "Often paired with a secret key nearby."
        ),
        remediation=(
            "Rotate the key in IAM immediately, remove it from source control history "
            "if committed, and load credentials from a secrets manager or runtime env."
        ),
    ),
    VulnerabilityRule(
        id="GR-SEC-001b",
        name="Likely AWS Secret Access Key Assignment",
        # Assignment-style only to cut random 40-char base64 FPs
        pattern=(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*"
            r"[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        severity=Severity.CRITICAL,
        description="A value shaped like an AWS secret access key is assigned in source.",
        remediation=(
            "Revoke the secret in IAM, purge from VCS, and migrate to Secrets Manager / SSM."
        ),
    ),
    VulnerabilityRule(
        id="GR-SEC-002",
        name="Hardcoded Credential Assignment",
        pattern=(
            r"(?i)\b(api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|"
            r"client[_-]?secret|jwt[_-]?secret|password|passwd|db_password|"
            r"private[_-]?key|secret[_-]?key)\b\s*[:=]\s*['\"]([^'\"\n]{8,})['\"]"
        ),
        severity=Severity.HIGH,
        description="A credential-like identifier is assigned a long string literal.",
        remediation=(
            "Move secrets to environment variables or a secret store; "
            "use placeholders in examples and inject at runtime."
        ),
    ),
    VulnerabilityRule(
        id="GR-SEC-002b",
        name="Common Provider API Token Prefix",
        pattern=(
            r"\b("
            r"ghp_[A-Za-z0-9]{20,}"
            r"|github_pat_[A-Za-z0-9_]{20,}"
            r"|sk-[A-Za-z0-9]{20,}"
            r"|sk-proj-[A-Za-z0-9_-]{20,}"
            r"|xox[baprs]-[A-Za-z0-9-]{10,}"
            r"|AIza[0-9A-Za-z\-_]{35}"
            r")\b"
        ),
        severity=Severity.CRITICAL,
        description="A token matching a well-known provider prefix was found in plaintext.",
        remediation="Revoke the token at the provider console and rotate any dependent integrations.",
    ),
    VulnerabilityRule(
        id="GR-SEC-003",
        name="Dynamic Code Execution (eval/exec)",
        pattern=r"(?<![\w.])(eval|exec)\s*\(",
        severity=Severity.CRITICAL,
        description=(
            "Direct use of eval/exec enables arbitrary code execution if input is attacker-controlled."
        ),
        remediation=(
            "Remove eval/exec. Prefer parsers, AST-safe alternatives, or strict allow-listed operations."
        ),
    ),
    VulnerabilityRule(
        id="GR-SEC-004",
        name="SQL String Interpolation in execute()",
        pattern=(
            r"\.execute\s*\(\s*(?:"
            r"f['\"][^'\"]*\{[^}]+\}[^'\"]*['\"]"  # f-string
            r"|['\"][^'\"]*%[^'\"]*['\"]\s*%"  # % formatting adjacent
            r"|['\"][^'\"]*['\"]\s*\.format\s*\("  # .format(
            r"|['\"][^'\"]*['\"]\s*\+"  # concat starting execute(".." +
            r")"
        ),
        severity=Severity.HIGH,
        description=(
            "SQL (or query) text appears to be built via interpolation/concatenation "
            "directly inside execute() — classic injection vector."
        ),
        remediation=(
            "Use bound parameters (placeholders) or a trusted ORM query builder; "
            "never concatenate untrusted input into SQL."
        ),
    ),
    VulnerabilityRule(
        id="GR-SEC-004b",
        name="SQL Built via f-string / format (nearby execute risk)",
        pattern=(
            r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+[^;\n]{0,120}"
            r"(?:\{[^}]+\}|%\s*\(|%\s*[sdf]|'\s*\+|\"\s*\+)"
        ),
        severity=Severity.MEDIUM,
        description=(
            "SQL keyword statement appears mixed with interpolation markers. "
            "Risk depends on whether the result is executed with user input."
        ),
        remediation="Build queries with bound parameters; avoid string-building SQL from user data.",
    ),
    VulnerabilityRule(
        id="GR-SEC-005",
        name="Shell Invocation with shell=True",
        pattern=r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^)]*\bshell\s*=\s*True\b",
        severity=Severity.HIGH,
        description=(
            "subprocess called with shell=True. Untrusted input in the command string "
            "can lead to shell injection."
        ),
        remediation=(
            "Prefer shell=False with an argument list. If a shell is required, "
            "strictly sanitize/allow-list inputs and avoid user-controlled fragments."
        ),
        flags=("multiline_span",),
    ),
    VulnerabilityRule(
        id="GR-SEC-005b",
        name="os.system / os.popen Usage",
        pattern=r"\b(os\.system|os\.popen)\s*\(",
        severity=Severity.HIGH,
        description="Legacy os.system/os.popen always go through a shell-like interface.",
        remediation="Replace with subprocess.run([...], shell=False) and explicit argument vectors.",
    ),
    VulnerabilityRule(
        id="GR-SEC-006",
        name="Insecure YAML Load",
        pattern=r"\byaml\.load\s*\((?![^)]*Loader\s*=)",
        severity=Severity.HIGH,
        description=(
            "yaml.load without an explicit SafeLoader can deserialize untrusted data unsafely."
        ),
        remediation="Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
    ),
    VulnerabilityRule(
        id="GR-SEC-007",
        name="TLS Verification Disabled",
        pattern=(
            r"(?i)(?:verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*0|"
            r"rejectUnauthorized\s*:\s*false)"
        ),
        severity=Severity.MEDIUM,
        description="TLS certificate verification appears disabled — MITM risk.",
        remediation="Enable certificate verification in production; use a proper CA bundle.",
    ),
    VulnerabilityRule(
        id="GR-SEC-008",
        name="Binding HTTP Server to All Interfaces",
        pattern=r"""['"]0\.0\.0\.0['"]""",
        severity=Severity.LOW,
        description=(
            "Service binds to 0.0.0.0 (all interfaces). May be intentional in containers; "
            "risky on developer laptops without firewall rules."
        ),
        remediation="Bind to 127.0.0.1 for local tools; expose only via reverse proxy when needed.",
    ),
    VulnerabilityRule(
        id="GR-SEC-009",
        name="Pickle Deserialization",
        pattern=r"\bpickle\.(loads?|Unpickler)\s*\(",
        severity=Severity.HIGH,
        description="pickle can execute arbitrary code during load of untrusted data.",
        remediation="Prefer JSON or other non-executable formats for untrusted inputs.",
    ),
    VulnerabilityRule(
        id="GR-SEC-010",
        name="Hardcoded Private Key Block",
        pattern=r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        description="A PEM private key block is embedded in the scanned text.",
        remediation="Remove the key from the file, rotate it, and store it in a secrets manager or HSM.",
    ),
    VulnerabilityRule(
        id="GR-SEC-011",
        name="Slack Incoming Webhook URL",
        pattern=(
            r"https://hooks\.slack\.com/services/"
            r"T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
        ),
        severity=Severity.CRITICAL,
        description="A Slack incoming webhook URL is embedded in plaintext (full channel write access).",
        remediation="Revoke the webhook in Slack, store the URL in a secret manager, and rotate integrations.",
    ),
    VulnerabilityRule(
        id="GR-SEC-012",
        name="Discord Webhook URL",
        pattern=r"https://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
        severity=Severity.HIGH,
        description="A Discord webhook URL appears in plaintext.",
        remediation="Regenerate the webhook in Discord and load it from environment/secrets at runtime.",
    ),
]


def get_rules() -> list[VulnerabilityRule]:
    return list(VULNERABILITY_RULES)
