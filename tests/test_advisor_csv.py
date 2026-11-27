import csv
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
class AdvisorCsvTests(unittest.TestCase):
    def test_csv_uses_current_filters_and_literal_cells(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            bundle = fixture()
            bundle["results"]["ACCESS_SWITCH"]["scopes"][2]["name"] = "=Switch A"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(workspace))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            root = f"http://127.0.0.1:{server.server_port}/{workspace.token}/"
            try:
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"), args=["--no-sandbox"])
                    try:
                        tab = browser.new_page(accept_downloads=True)
                        errors = []
                        tab.on("pageerror", lambda exc: errors.append(str(exc)))
                        response = tab.goto(root + "advisor?" + urlencode({"snapshot": name, "finding": "promote_local"}))
                        self.assertEqual(response.status, 200)
                        row = tab.locator('#advisor-table tr[data-action="promote_local"]:visible').first
                        row.locator(".choose").check()
                        row.locator(".destination").select_option("library")
                        with tab.expect_download() as download:
                            tab.locator("#advisor-export-csv").click()
                        with open(download.value.path(), encoding="utf-8-sig", newline="") as handle:
                            records = list(csv.DictReader(handle))
                        self.assertTrue(records)
                        self.assertTrue(all(r["Recommendation"] == "promote_local" for r in records))
                        selected = next(r for r in records if r["Selected for preview"] == "Yes")
                        self.assertIn("Library", selected["Suggested next step"])
                        self.assertTrue(selected["Source scopes"].startswith("'="))
                        tab.locator("#search").fill("no-result-test")
                        self.assertTrue(tab.locator("#advisor-export-csv").is_disabled())
                        self.assertEqual(errors, [])
                    finally:
                        browser.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
