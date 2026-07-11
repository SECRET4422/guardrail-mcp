from __future__ import annotations

import unittest

from guardrail.infra_security import deep_analyze_infra, scan_infra_security

DOCKER = """
FROM ubuntu
USER root
COPY . /app
"""

TF = """
resource "aws_security_group_rule" "all" {
  cidr_blocks = ["0.0.0.0/0"]
  instance_type = "m5.xlarge"
}

resource "aws_instance" "gpu" {
  instance_type = "p4d.24xlarge"
}

container:
  privileged: true
"""


class InfraSecurityTests(unittest.TestCase):
    def test_docker_root(self):
        hits = scan_infra_security(DOCKER)
        ids = {h.anomaly_id for h in hits}
        self.assertIn("PRIVILEGED_DOCKER_USER", ids)

    def test_combined_reject_on_budget(self):
        res = deep_analyze_infra(TF, "aws", budget_limit_usd=500)
        self.assertTrue(res["budget_limit_exceeded"])
        self.assertEqual(res["security_verdict"], "REJECTED")
        self.assertGreaterEqual(res["security_issue_count"], 2)

    def test_clean_budget(self):
        res = deep_analyze_infra('instance_type = "t3.medium"\n', "aws", budget_limit_usd=500)
        self.assertFalse(res["budget_limit_exceeded"])
        self.assertEqual(res["security_verdict"], "APPROVED")


if __name__ == "__main__":
    unittest.main()
