import unittest
from aruba_central.workspace_views import ADVISOR_JS


class PreviewDecisionTests(unittest.TestCase):
    def test_preview_renders_readable_blockers_and_transition_from_observed_data(self):
        # These labels are rendered with textContent, never HTML from captures.
        for label in ("Resolve export blockers", "Review export available",
                      "Captured configuration", "Proposed configuration source",
                      "Not a simulated or verified outcome", "Observed recipient pairs",
                      "Destination impact requires review", "Exact observed recipient set"):
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
                    options = row.locator(".destination option").all_text_contents()
                    self.assertTrue(any("not confirmed matching" in option for option in options))
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


    def test_browser_bulk_overlap_counts_all_pairs_and_matches_server_gate(self):
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
        # Exercise the actual browser function with synthetic proposals rather
        # than modifying the production UI or exporting a live plan.
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            html = Workspace(directory).advisor({"snapshot": name, "finding": "promote_local"})
            marker = "function selection(){"
            self.assertIn(marker, html)
            html = html.replace(marker, "window.testBulkReview=bulkReview;\n" + marker, 1)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"), args=["--no-sandbox"])
                try:
                    tab = browser.new_page()
                    tab.set_content(html)
                    result = tab.evaluate("""() => {
                        const chosen=['a','b','c'].map((id,i)=>({id,persona:'ACCESS_SWITCH',module:'layer2-vlan',
                            identity:'20',action:'reuse_library',sources:[{scope:String(i+1)}],
                            recipient_evidence:{known:[{scope:'3',name:'Switch A'}],unknown:[]},
                            dependency_review:{dependencies:[]},fallbacks:[]}));
                        return window.testBulkReview(chosen).collisions;
                    }""")
                    self.assertEqual(len(result), 3)
                    self.assertTrue(all("observed device recipient" in row["reason"] for row in result))
                    self.assertEqual({(row["first"], row["second"]) for row in result}, {("a","b"),("a","c"),("b","c")})
                    result = tab.evaluate("""() => {
                        const chosen=['a','b'].map((id,i)=>({id,persona:'ACCESS_SWITCH',module:'dns',
                            identity:'dns-'+id,action:'reuse_library',sources:[{scope:String(i+1)}],
                            recipient_evidence:{known:[{scope:'3',name:'Switch A'}],unknown:[]},
                            dependency_review:{dependencies:[]},fallbacks:[]}));
                        const atomic=window.testBulkReview(chosen).collisions;
                        chosen.forEach(f=>f.module='layer2-vlan');
                        return {atomic, additive:window.testBulkReview(chosen).collisions};
                    }""")
                    self.assertEqual(len(result["atomic"]), 1)
                    self.assertIn("atomic module", result["atomic"][0]["reason"])
                    self.assertEqual(result["additive"], [])
                finally:
                    browser.close()


    def test_browser_reuse_export_records_exact_assignment_destination(self):
        import json
        import shutil
        import tempfile
        from pathlib import Path
        from aruba_central.config_app import Workspace
        from aruba_central.review_manifest import reconstruct_selection
        from test_consolidation import fixture
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Browser test dependency unavailable")
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory)/name).write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            html = workspace.advisor({"snapshot":name,"finding":"reuse_library"})
            with sync_playwright() as playwright:
                browser=playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"),args=["--no-sandbox"])
                try:
                    tab=browser.new_page()
                    tab.set_content(html)
                    row=tab.locator('#advisor-table tr[data-action="reuse_library"]:visible').first
                    row.locator(".choose").check()
                    tab.locator("#open-preview").click()
                    self.assertIn("Review export available",tab.locator(".preview-decision").inner_text())
                    with tab.expect_download() as pending:
                        tab.locator("#export-plan").click()
                    export=json.loads(Path(pending.value.path()).read_text())
                    self.assertIsNone(export["selection_manifest"]["selections"][0]["destination"])
                    plan=reconstruct_selection(workspace,export["selection_manifest"])
                    self.assertEqual(export["recommendations"][0]["selected_destination"],
                                     plan["recommendations"][0]["selected_destination"])
                    self.assertTrue(plan["recommendations"][0]["selected_destination"]["reuse_existing"])
                finally:
                    browser.close()
