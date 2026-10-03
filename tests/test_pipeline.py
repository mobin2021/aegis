"""
Unit and integration tests for Aegis multi-agent pipeline.
"""

import unittest
from pathlib import Path
from aegis.config import AegisConfig
from aegis.manager import AegisManager
from aegis.workers.decompile_worker import DecompileWorker
from aegis.workers.fuzz_worker import FuzzWorker


class TestAegisPipeline(unittest.TestCase):

    def setUp(self):
        self.config = AegisConfig(
            target_path="benchmarks/stack_overflow.c",
            output_dir="aegis_output_test",
            poc_output_path="aegis_output_test/poc.py",
            report_output_path="aegis_output_test/audit_report.json",
            verbose=False,
        )

    def test_decompile_worker_identifies_strcpy(self):
        worker = DecompileWorker(self.config)
        res = worker.execute({"target_path": "benchmarks/stack_overflow.c"})
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["has_high_severity"])
        symbols = [c["symbol"] for c in res["unsafe_calls"]]
        self.assertIn("strcpy", symbols)

    def test_fuzz_worker_identifies_crash(self):
        worker = FuzzWorker(self.config)
        res = worker.execute({
            "target_path": "benchmarks/stack_overflow.c",
            "unsafe_calls": [{"symbol": "strcpy"}],
        })
        self.assertEqual(res["status"], "success")
        self.assertGreater(res["crashes_count"], 0)
        self.assertEqual(res["primary_crash"]["offset"], 72)

    def test_end_to_end_assessment(self):
        manager = AegisManager(self.config)
        report = manager.assess_target("benchmarks/stack_overflow.c")
        self.assertIn("findings", report)
        self.assertEqual(report["findings"]["crash_offset"], 72)
        self.assertTrue(Path("aegis_output_test/poc.py").exists())
        self.assertTrue(Path("aegis_output_test/audit_report.json").exists())


if __name__ == "__main__":
    unittest.main()
