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
class LazyEngineeringTests(unittest.TestCase):
    def test_duplicate_review_loads_only_requested_group(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            bundle = fixture()
            bundle["library"]["modules"]["sw-port-profiles"] = {
                "status": "list_parsed",
                "profiles": {k: {"profile-name": k, "enable": True}
                             for k in ("a", "b")}}
            path.write_text(json.dumps(bundle))
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
                        response = tab.goto(root + "advanced?" + urlencode({"snapshot": name, "workflow": "duplicates"}))
                        self.assertEqual(response.status, 200)
                        self.assertNotIn("data-migration-plans=", response.text())
                        button = tab.locator("[data-inspect-url]").first
                        endpoint = button.get_attribute("data-inspect-url")
                        button.click()
                        choice = tab.locator("#workspace-inspector-body [data-keep]")
                        choice.wait_for()
                        choice.select_option("a")
                        tab.locator("#workspace-inspector-body h4", has_text="Exact observed migration worklist").wait_for()
                        self.assertIn("Retain a.", tab.locator("#workspace-inspector-body").inner_text())
                        tab.locator("#workspace-close").click()
                        path.write_text(path.read_text() + " ")
                        self.assertEqual(tab.request.get(f"http://127.0.0.1:{server.server_port}" + endpoint).status, 400)
                        self.assertEqual(errors, [])
                    finally:
                        browser.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
