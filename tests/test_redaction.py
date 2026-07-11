from __future__ import annotations

import unittest

from guardrail.redaction import redact_excerpt, redact_match, sanitize_for_log


class RedactionTests(unittest.TestCase):
    def test_redact_match_edges(self):
        s = "ABCDEFGHIJKLMNOP"
        r = redact_match(s)
        self.assertTrue(r.startswith("AB"))
        self.assertTrue(r.endswith("OP"))
        self.assertIn("*", r)

    def test_excerpt(self):
        line = 'api_key = "sk-abcdefghijklmnopqrstuv"'
        # match the value span roughly
        start = line.index("sk-")
        end = len(line) - 1  # before closing quote? include token
        end = line.rindex('"')
        start = line.index('"') + 1
        ex = redact_excerpt(line, start, end)
        self.assertNotIn("sk-abcdefghijklmnopqrstuv", ex)
        self.assertIn("api_key", ex)

    def test_sanitize_log(self):
        msg = "got token ghp_abcdefghijklmnopqrstuvwxyz0123456789 ok"
        out = sanitize_for_log(msg)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz0123456789", out)


if __name__ == "__main__":
    unittest.main()
