import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from test_consolidation import fixture


class CustomerAssessmentTests(unittest.TestCase):
    def test_report_contains_aggregate_counts_not_raw_device_names(self):
        bundle = fixture()
        bundle["results"]["ACCESS_SWITCH"]["scopes"][2]["name"] = "private-device-marker"
        bundle["collection_checkpoint"] = {"mixed_capture_times": True}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            html = workspace.assessment({"snapshot": name, "mode": "customer-report"})
            self.assertIn("Network configuration assessment", html)
            self.assertIn("Evidence gaps and validation", html)
            self.assertIn("Print / save PDF", html)
            self.assertIn("Evidence limitation", html)
            self.assertIn("@media print", html)
            self.assertNotIn("private-device-marker", html)
            self.assertIn("Open customer assessment report", workspace.assessment({"snapshot": name}))


    def test_browser_print_layout_hides_workspace_controls(self):
        import shutil
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Browser test dependency unavailable")
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            html = Workspace(directory).assessment({"snapshot": name, "mode": "customer-report"})
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"), args=["--no-sandbox"])
                try:
                    tab = browser.new_page(viewport={"width": 794, "height": 1123}, color_scheme="dark")
                    tab.set_content(html)
                    tab.evaluate("document.documentElement.dataset.theme = 'dark'")
                    tab.evaluate("document.documentElement.classList.add('mobile-nav')")
                    tab.emulate_media(media="print")
                    for selector in (".sidebar", ".topbar", ".report-actions"):
                        self.assertEqual(tab.locator(selector).evaluate("(el) => getComputedStyle(el).display"), "none")
                    self.assertEqual(tab.evaluate("getComputedStyle(document.documentElement).colorScheme"), "light")
                    self.assertEqual(tab.evaluate("getComputedStyle(document.querySelector('.app-body'), '::before').display"), "none")
                    self.assertTrue(tab.locator("main h1").is_visible())
                    self.assertTrue(tab.evaluate("document.documentElement.scrollWidth <= window.innerWidth"))
                    pdf = tab.pdf(format="A4", prefer_css_page_size=True)
                    self.assertTrue(pdf.startswith(b"%PDF"))
                    self.assertGreater(len(pdf), 1000)
                finally:
                    browser.close()
