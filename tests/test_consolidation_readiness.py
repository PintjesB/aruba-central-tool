import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from test_consolidation import fixture

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


class ConsolidationReadinessTests(unittest.TestCase):
    def html(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            return Workspace(directory).advisor({"snapshot": name})

    def test_readiness_labels(self):
        html = self.html()
        for value in ("selectable", "destination", "blocked", "review"):
            self.assertIn('data-readiness="' + value + '"', html)
        self.assertIn("Evidence blocks preview", html)
        self.assertIn("Most local copies first", html)

    @unittest.skipUnless(sync_playwright, "Browser test dependency unavailable")
    def test_preview_filter_keeps_hidden_selection_visible(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                tab = browser.new_page()
                tab.set_content(self.html())
                tab.locator("#readiness").select_option("preview")
                self.assertEqual(tab.locator('#advisor-table tr[data-readiness="blocked"]:visible').count(), 0)
                row = tab.locator('#advisor-table tr[data-readiness="selectable"]:visible').first
                row.locator(".choose").check()
                tab.locator("#readiness").select_option("blocked")
                self.assertEqual(tab.locator("#hidden-selected").inner_text(), "1 selected outside current filters")
                self.assertEqual(tab.locator("#selected").inner_text(), "1 selected")
                tab.locator("#clear-selection").click()
                self.assertEqual(tab.locator("#hidden-selected").inner_text(), "")
                tab.locator("#clear").click()
                tab.locator("#advisor-sort").select_option("copies")
                visible = tab.locator("#advisor-table tr[data-source-count]:visible")
                counts = [int(row.get_attribute("data-source-count")) for row in visible.all()]
                self.assertEqual(counts, sorted(counts, reverse=True))
            finally:
                browser.close()
