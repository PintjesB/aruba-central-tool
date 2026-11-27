import unittest
from aruba_central.workspace_views import ADVISOR_JS


class PreviewDecisionTests(unittest.TestCase):
    def test_preview_renders_readable_blockers_and_transition_from_observed_data(self):
        # These labels are rendered with textContent, never HTML from captures.
        for label in ("Resolve export blockers", "Review export available",
                      "Captured configuration", "Proposed configuration source",
                      "Not a simulated or verified outcome", "Observed recipient pairs"):
            self.assertIn(label, ADVISOR_JS)
        self.assertIn("review.missing_destinations.length", ADVISOR_JS)
        self.assertIn("review.collisions.length", ADVISOR_JS)
        self.assertIn("review.dependency_order.blocked.length", ADVISOR_JS)


    def test_browser_preview_shows_destination_blocker_and_source_transition(self):
        import json
        import shutil
        import tempfile
        from pathlib import Path
        from aruba_central.config_app import Workspace
        from test_consolidation import fixture
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Browser test dependency unavailable")
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            html = Workspace(directory).advisor({"snapshot": name, "finding": "promote_local"})
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"), args=["--no-sandbox"])
                try:
                    tab = browser.new_page()
                    errors = []
                    tab.on("pageerror", lambda exc: errors.append(str(exc)))
                    tab.set_content(html)
                    row = tab.locator('#advisor-table tr[data-action="promote_local"]:visible').first
                    row.locator(".choose").check()
                    tab.locator("#open-preview").click()
                    self.assertTrue(tab.locator("#plan-dialog").is_visible())
                    self.assertIn("Resolve export blockers", tab.locator(".preview-decision").inner_text())
                    self.assertTrue(tab.locator("#export-plan").is_disabled())
                    self.assertIn("Captured configuration", tab.locator(".preview-transition").inner_text())
                    tab.locator("#close-preview").click()
                    row.locator(".destination").select_option("library")
                    tab.locator("#open-preview").click()
                    self.assertIn("Review export available", tab.locator(".preview-decision").inner_text())
                    self.assertIn("Library / exact source scopes", tab.locator(".preview-transition").inner_text())
                    self.assertTrue(tab.locator("#export-plan").is_enabled())
                    with tab.expect_download() as pending:
                        tab.locator("#export-plan").click()
                    exported = json.loads(Path(pending.value.path()).read_text(encoding="utf-8"))
                    from aruba_central.review_manifest import validate_selection
                    validated = validate_selection(Workspace(directory), exported["selection_manifest"])
                    self.assertTrue(validated["review_export_gates_passed"])
                    self.assertFalse(validated["safe_to_apply"])
                    self.assertEqual(validated["observed_recipient_pairs"], len(exported["bulk_review"]["known_recipients"]))
                    self.assertEqual(validated["uncertain_recipient_pairs"], len(exported["bulk_review"]["unknown_recipients"]))
                    self.assertEqual(errors, [])
                finally:
                    browser.close()
