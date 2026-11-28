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
            data = fixture()
            data.update(region="https://de1.example",inventory=[{"inventory":{"serial":"A"}}])
            for scope in data["results"]["ACCESS_SWITCH"]["scopes"]:
                if scope["kind"] == "device":
                    scope["metadata"] = {"serial":scope["id"]}
            data["library"]["assignments"]["rows"] = [{"profile-type": "layer2-vlan", "profile-instance": "30",
                "scope-id": "3", "device-function": "ACCESS_SWITCH"}]
            (Path(directory) / name).write_text(json.dumps(data))
            from copy import deepcopy
            previous = "config-audit-private-previous.json"
            prior = deepcopy(data)
            prior["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][2]["effective_view"]["profiles"]["20"]["name"] = "Private prior value"
            (Path(directory)/previous).write_text(json.dumps(prior))
            result = browser_benchmark(directory, name, repeat=1, previous=previous,
                executable=shutil.which("google-chrome") or shutil.which("chromium"))
            self.assertEqual(result["central_api_requests"], 0)
            self.assertIn("advisor_inspector", result["stages"])
            self.assertIn("coverage", result["stages"])
            self.assertIn("dashboard", result["stages"])
            self.assertIn("assignments", result["stages"])
            self.assertIn("assignments_inspector", result["stages"])
            self.assertIn("history_drift",result["stages"])
            self.assertIn("history_drift_inspector",result["stages"])
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
            self.assertNotIn(previous,exported)
            self.assertNotIn("Private prior value",exported)
            self.assertNotIn("Switch A", exported)
            self.assertNotIn("127.0.0.1", exported)


    def test_assignment_inspector_nested_comparison_and_no_script_evidence(self):
        from threading import Thread
        from http.server import ThreadingHTTPServer
        from aruba_central.config_app import Workspace, handler_for
        from urllib.parse import urlencode
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            data = fixture()
            data["library"]["assignments"]["rows"] = [{"profile-type":"layer2-vlan","profile-instance":"30",
                "scope-id":"3","device-function":"ACCESS_SWITCH"}]
            (Path(directory)/name).write_text(json.dumps(data))
            workspace=Workspace(directory)
            server=ThreadingHTTPServer(("127.0.0.1",0),handler_for(workspace))
            thread=Thread(target=server.serve_forever,daemon=True)
            thread.start()
            try:
                with sync_playwright() as playwright:
                    browser=playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"))
                    try:
                        tab=browser.new_page()
                        errors=[]
                        tab.on("pageerror",lambda exc:errors.append(str(exc)))
                        url=f"http://127.0.0.1:{server.server_port}/{workspace.token}/assignments?"+urlencode({"snapshot":name})
                        tab.goto(url)
                        tab.locator("[data-inspect-url]:visible").first.click()
                        body=tab.locator("#workspace-inspector-body")
                        body.get_by_role("button",name="Compare").first.wait_for()
                        body.get_by_role("button",name="Compare").first.click()
                        self.assertIn("Captured configuration bodies are identical",body.inner_text())
                        back=tab.locator("#workspace-inspector-back")
                        self.assertTrue(back.is_visible())
                        back.click()
                        self.assertIn("Library definition captured",body.inner_text())
                        self.assertTrue(body.get_by_role("button",name="Compare").first.is_visible())
                        self.assertFalse(back.is_visible())
                        self.assertTrue(body.get_by_role("button",name="Compare").first.evaluate("(el)=>document.activeElement===el"))
                        body.get_by_role("button",name="Compare").first.click()
                        tab.locator("#workspace-close").click()
                        self.assertFalse(back.is_visible())
                        self.assertEqual(errors,[])
                        plain=browser.new_context(java_script_enabled=False)
                        page=plain.new_page()
                        page.goto(url)
                        page.locator("noscript a").first.click()
                        self.assertIn("Assignment evidence",page.title())
                        self.assertIn("Library definition captured",page.locator("body").inner_text())
                        plain.close()
                    finally:
                        browser.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
