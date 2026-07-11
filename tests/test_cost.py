"""Unit tests for cloud cost estimation."""

from __future__ import annotations

import unittest

from guardrail.cost import run_core_cost_audit

TF = '''
resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "t3.medium"
  count         = 3
}

resource "aws_db_instance" "db" {
  instance_class = "db.m5.large"
}
'''

GCP = '''
resource "google_compute_instance" "gpu" {
  machine_type = "a2-highgpu-1g"
}
'''


class CostAuditTests(unittest.TestCase):
    def test_aws_totals(self):
        res = run_core_cost_audit(TF, "aws")
        self.assertEqual(res["status"], "OK")
        self.assertGreater(res["estimated_monthly_usd"], 0)
        resources = {i["resource"] for i in res["line_items"]}
        self.assertIn("t3.medium", resources)
        self.assertIn("db.m5.large", resources)
        # count = 3 nearby t3.medium
        t3 = next(i for i in res["line_items"] if i["resource"] == "t3.medium")
        self.assertEqual(t3["quantity"], 3)

    def test_gcp(self):
        res = run_core_cost_audit(GCP, "gcp")
        self.assertEqual(res["status"], "OK")
        self.assertAlmostEqual(res["estimated_monthly_usd"], 2684.50, places=1)

    def test_bad_provider(self):
        res = run_core_cost_audit("t3.micro", "azure")
        self.assertEqual(res["status"], "ERROR")

    def test_empty(self):
        res = run_core_cost_audit("locals { x = 1 }", "aws")
        self.assertEqual(res["status"], "OK")
        self.assertEqual(res["estimated_monthly_usd"], 0)


if __name__ == "__main__":
    unittest.main()
