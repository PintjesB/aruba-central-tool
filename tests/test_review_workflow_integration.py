"""Exercise local engineering review through the real loopback application."""
import json
import shutil
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

from aruba_central.config_app import Workspace, handler_for
from aruba_central.review_dispositions import read_disposition
from test_consolidation import fixture

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


@unittest.skipUnless(sync_playwright, "Browser test dependency unavailable")
class ReviewWorkflowIntegrationTests(unittest.TestCase):
    def test_bulk_selection_confirmation_and_persisted_review(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            original = json.dumps(fixture())
            path.write_text(original)
            workspace = Workspace(directory)
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(workspace))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{server.server_port}"
            root = origin + "/" + workspace.token + "/"
            try:
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"), args=["--no-sandbox"])
                    try:
                        tab = browser.new_page(viewport={"width": 1440, "height": 900})
                        errors = []
                        tab.on("pageerror", lambda error: errors.append(str(error)))
                        response = tab.goto(root + "assessment?" + urlencode({"snapshot": name}))
                        self.assertEqual(response.status, 200)
                        choices = tab.locator("#bulk-review-table [data-bulk-key]:visible")
                        self.assertGreaterEqual(choices.count(), 2)
                        keys = [choices.nth(i).get_attribute("data-bulk-key") for i in range(2)]
                        choices.nth(0).check()
                        choices.nth(1).check()
                        self.assertIn("2 selected", tab.locator("#bulk-selection").inner_text())
                        submit = tab.locator("#bulk-review-submit")
                        self.assertTrue(submit.is_disabled())
                        search = tab.locator("#bulk-review-table [data-table-search]")
                        search.fill("no-such-synthetic-finding")
                        self.assertIn("2 outside visible page", tab.locator("#bulk-selection").inner_text())
                        search.fill("")
                        form = tab.locator("#bulk-review-form")
                        form.locator("[name=state]").select_option("deferred")
                        form.locator("[name=replace_notes]").select_option("yes")
                        form.locator("[name=note]").fill("Review in next maintenance window")
                        form.locator("[name=confirmed]").check()
                        self.assertTrue(submit.is_enabled())
                        with tab.expect_navigation():
                            submit.click()
                        self.assertEqual([read_disposition(directory, key)["state"] for key in keys], ["deferred", "deferred"])
                        self.assertTrue(all(read_disposition(directory, key)["note"] == "Review in next maintenance window" for key in keys))
                        tab.goto(root + "assessment?" + urlencode({"snapshot": name, "state": "deferred"}))
                        self.assertEqual(tab.locator("#bulk-review-table [data-bulk-key]:visible").count(), 2)
                        self.assertEqual(errors, [])
                        self.assertEqual(path.read_text(), original)
                        form_data = {"snapshot": name, "keys": json.dumps(keys), "state": "open", "note": "",
                                     "replace_notes": "no", "confirmed": "yes", "csrf": workspace.csrf}
                        headers = {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}
                        self.assertEqual(tab.request.post(root + "bulk-review-disposition", data=urlencode({**form_data, "csrf": "wrong"}), headers=headers).status, 403)
                        self.assertEqual(tab.request.post(root + "bulk-review-disposition", data=urlencode(form_data), headers={**headers, "Origin": "https://example.invalid"}).status, 403)
                        self.assertEqual(tab.request.post(root + "bulk-review-disposition", data=urlencode({**form_data, "keys": json.dumps([keys[0], "0" * 64])}), headers=headers).status, 400)
                        self.assertTrue(all(read_disposition(directory, key)["state"] == "deferred" for key in keys))
                    finally:
                        browser.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
