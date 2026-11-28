import json
import shutil
import tempfile
import unittest
from pathlib import Path

from aruba_central.browser_benchmark import browser_benchmark
from test_consolidation import fixture

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


@unittest.skipUnless(sync_playwright, "Browser test dependency unavailable")
class BrowserBenchmarkTests(unittest.TestCase):
    def test_local_browser_measurements_do_not_export_tenant_data(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-private-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            result = browser_benchmark(directory, name, repeat=1,
                executable=shutil.which("google-chrome") or shutil.which("chromium"))
            self.assertEqual(result["central_api_requests"], 0)
            self.assertIn("advisor_inspector", result["stages"])
            self.assertIn("coverage", result["stages"])
            self.assertIn("dashboard", result["stages"])
            self.assertIn("assignments", result["stages"])
            for stage in ("field_search", "field_search_alternate", "field_search_multi_term", "grouped_search"):
                self.assertIn(stage, result["stages"])
                self.assertGreater(result["stages"][stage]["first_navigation_seconds"], 0)
                self.assertIsNone(result["stages"][stage]["warm_median_navigation_seconds"])
            self.assertEqual(result["search_index"]["status"], "indexed")
            self.assertGreater(result["search_index"]["leaves"], 0)
            self.assertGreater(result["stages"]["advisor"]["samples"][0]["dom_nodes"], 0)
            self.assertGreater(result["stages"]["coverage"]["samples"][0]["html_bytes"], 0)
            exported = json.dumps(result)
            self.assertNotIn(name, exported)
            self.assertNotIn("Switch A", exported)
            self.assertNotIn("127.0.0.1", exported)
