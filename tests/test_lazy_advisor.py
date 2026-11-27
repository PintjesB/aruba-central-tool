import json
import shutil
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

from aruba_central.config_app import Workspace, handler_for
from test_consolidation import fixture

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


@unittest.skipUnless(sync_playwright, "Browser test dependency unavailable")
class LazyAdvisorTests(unittest.TestCase):
    def test_remote_evidence_keeps_selection_and_rejects_replaced_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(workspace))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            root = f"http://127.0.0.1:{server.server_port}/{workspace.token}/"
            try:
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"), args=["--no-sandbox"])
                    try:
                        tab = browser.new_page()
                        errors = []
                        tab.on("pageerror", lambda exc: errors.append(str(exc)))
                        response = tab.goto(root + "advisor?" + urlencode({"snapshot": name, "finding": "promote_local"}))
                        self.assertEqual(response.status, 200)
                        row = tab.locator('#advisor-table tr[data-action="promote_local"]:visible').first
                        row.locator(".choose").check()
                        button = row.locator("[data-inspect-url]")
                        endpoint = button.get_attribute("data-inspect-url")
                        self.assertNotIn("Configuration comparison</h3>", response.text())
                        button.click()
                        tab.locator("#workspace-inspector-body h3", has_text="Configuration comparison").wait_for()
                        self.assertIn("Observed dependencies", tab.locator("#workspace-inspector-body").inner_text())
                        tab.locator("#workspace-close").click()
                        self.assertTrue(row.locator(".choose").is_checked())
                        path.write_text(path.read_text() + " ")
                        self.assertEqual(tab.request.get(f"http://127.0.0.1:{server.server_port}" + endpoint).status, 400)
                        button.click()
                        tab.locator("#workspace-inspector-body [role=alert]").wait_for()
                        self.assertEqual(errors, [])
                    finally:
                        browser.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
