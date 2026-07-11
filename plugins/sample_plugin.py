"""Sample GuardRail plugin — demonstrates register() + RULES + hooks."""

PLUGIN_NAME = "sample-org-plugin"
PLUGIN_VERSION = "1.0.0"

RULES = [
    {
        "id": "ORG-PLUGIN-NO-MD5",
        "name": "Disallow MD5",
        "languages": ["python"],
        "severity": "MEDIUM",
        "type": "regex",
        "pattern": r"\bhashlib\.md5\s*\(|\bmd5\s*\(",
        "message": "MD5 is not suitable for security-sensitive hashing.",
        "remediation": "Use hashlib.sha256 or a password KDF (bcrypt/argon2).",
    }
]


def register(registry):
    # Could add hooks dynamically
    registry.add_rules(RULES)


def post_scan(source, language, findings, context):
    # Example: tag all findings with plugin note
    for f in findings:
        if isinstance(f, dict):
            notes = f.setdefault("plugin_notes", [])
            if "sample-org-plugin" not in notes:
                notes.append("sample-org-plugin")
    return findings
