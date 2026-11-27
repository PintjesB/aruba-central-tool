import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.local_benchmark import benchmark


class LocalBenchmarkTests(unittest.TestCase):
    def test_fixed_aggregate_output_without_private_values(self):
        bundle = {"schema": 1, "kind": "configuration_audit", "captured_at": "test",
                  "tenant_name": "private-tenant-label", "results": {}}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-private-filename.json"
            path = Path(directory) / name
            original = json.dumps(bundle)
            path.write_text(original)
            result = benchmark(directory, name, repeat=2)
            self.assertEqual(path.read_text(), original)
            self.assertEqual(result["central_api_requests"], 0)
            self.assertEqual(result["repeat"], 2)
            self.assertEqual(result["counts"]["devices"], 0)
            self.assertIn("engineering_cache_hit", result["stages"])
            self.assertIn("device_overrides", result["stages"])
            for stage in result["stages"].values():
                self.assertEqual(len(stage["samples"]), 2)
                self.assertGreaterEqual(stage["median_wall_seconds"], 0)
                self.assertGreaterEqual(stage["median_cpu_seconds"], 0)
            self.assertNotIn("private-tenant-label", json.dumps(result))
            self.assertNotIn(name, json.dumps(result))
            with self.assertRaises(ValueError):
                benchmark(directory, name, repeat=0)
            with self.assertRaises(ValueError):
                benchmark(directory, "missing.json", repeat=1)

    def test_ui_benchmark_exports_only_aggregate_measurements(self):
        from test_consolidation import fixture
        bundle = fixture()
        bundle["tenant_name"] = "private-tenant-marker"
        bundle["results"]["ACCESS_SWITCH"]["scopes"][2]["name"] = "private-device-marker"
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-private-name.json"
            path = Path(directory) / name
            original = json.dumps(bundle)
            path.write_text(original)
            result = benchmark(directory, name, repeat=2, ui=True)
            self.assertEqual(path.read_text(), original)
            self.assertEqual(result["central_api_requests"], 0)
            for stage in ("optimization_worklist", "configuration_health", "configuration_search",
                          "configuration_search_grouped", "render_assessment", "render_health",
                          "render_customer_report", "render_device_review", "render_keyed_evidence",
                          "render_assessment_repeat", "consolidation_workspace_lookup", "consolidation_cache_hit"):
                self.assertEqual(len(result["stages"][stage]["samples"]), 2)
            self.assertGreater(result["counts"]["render_assessment_bytes"], 0)
            self.assertGreater(result["counts"]["search_observations"], 0)
            for private in ("private-tenant-marker", "private-device-marker", name):
                self.assertNotIn(private, json.dumps(result))
