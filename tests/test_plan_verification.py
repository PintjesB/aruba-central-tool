import json
import tempfile
import unittest
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.review_dispositions import snapshot_binding
from aruba_central.plan_verification import verify_plan
from test_consolidation import fixture


class PlanVerificationTests(unittest.TestCase):
    def test_verify_real_review_choices_against_newer_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            before_name, after_name = "config-audit-before.json", "config-audit-after.json"
            def capture(time):
                data = fixture()
                data["captured_at"] = time
                data["region"] = "https://de1.example"
                data["inventory"] = [{"inventory": {"serial": "A"}}]
                for scope in data["results"]["ACCESS_SWITCH"]["scopes"]:
                    if scope["kind"] == "device":
                        scope["metadata"] = {"serial": scope["id"]}
                return data
            prior = capture("2026-01-01T00:00:00+00:00")
            current = capture("2026-01-02T00:00:00+00:00")
            for name, data in ((before_name,prior),(after_name,current)):
                (Path(directory)/name).write_text(json.dumps(data))
            workspace=Workspace(directory)
            before=workspace.reviewed_snapshot(before_name)
            proposals=workspace.consolidation_snapshot(before)
            promote=next(f for f in proposals if f["action"]=="promote_local")
            reuse=next(f for f in proposals if f["action"]=="reuse_library")
            manifest={"schema":1,"kind":"consolidation_selection","snapshot":before_name,
                      "snapshot_binding":snapshot_binding(workspace,before_name,before),
                      "selections":[{"id":promote["id"],"destination":"library"},{"id":reuse["id"],"destination":None}]}
            with self.assertRaises(ValueError):
                verify_plan(workspace,manifest,after_name)
            report=verify_plan(workspace,manifest,after_name,confirmed=True)
            self.assertEqual(report["proposal_counts"],{"promote_local":1,"reuse_library":1})
            self.assertEqual(len(report["reports"]),2)
            self.assertFalse(report["safe_to_apply"])
            self.assertFalse(report["complete"])
            manifest["selections"].reverse()
            self.assertEqual(report,verify_plan(workspace,manifest,after_name,confirmed=True))
            with self.assertRaises(ValueError):
                verify_plan(workspace,manifest,before_name,confirmed=True)
            path=Path(directory)/before_name
            path.write_text(path.read_text()+" ")
            with self.assertRaises(ValueError):
                verify_plan(workspace,manifest,after_name,confirmed=True)


    def test_browser_import_sends_only_manifest_and_renders_results(self):
        import shutil
        from http.server import ThreadingHTTPServer
        from threading import Thread
        from urllib.parse import urlencode
        from aruba_central.config_app import handler_for
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Browser test dependency unavailable")
        with tempfile.TemporaryDirectory() as directory:
            before_name,after_name="config-audit-before.json","config-audit-after.json"
            for name,time in ((before_name,"2026-01-01T00:00:00+00:00"),(after_name,"2026-01-02T00:00:00+00:00")):
                data=fixture()
                data.update(captured_at=time,region="https://de1.example",inventory=[{"inventory":{"serial":"A"}}])
                (Path(directory)/name).write_text(json.dumps(data))
            workspace=Workspace(directory)
            before=workspace.reviewed_snapshot(before_name)
            proposal=next(f for f in workspace.consolidation_snapshot(before) if f["action"]=="promote_local")
            manifest={"schema":1,"kind":"consolidation_selection","snapshot":before_name,
                      "snapshot_binding":snapshot_binding(workspace,before_name,before),
                      "selections":[{"id":proposal["id"],"destination":"library"}]}
            server=ThreadingHTTPServer(("127.0.0.1",0),handler_for(workspace))
            thread=Thread(target=server.serve_forever,daemon=True)
            thread.start()
            try:
                with sync_playwright() as playwright:
                    browser=playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"),args=["--no-sandbox"])
                    try:
                        tab=browser.new_page()
                        url=f"http://127.0.0.1:{server.server_port}/{workspace.token}/remediation?"+urlencode({"snapshot":after_name})
                        tab.goto(url)
                        form=tab.locator("#verify-exported-plan")
                        form.locator("input[type=file]").set_input_files({"name":"preview.json","mimeType":"application/json","buffer":json.dumps({"selection_manifest":manifest,"recommendations":["untrusted-private-marker"]}).encode()})
                        form.locator("input[name=confirmed]").check()
                        with tab.expect_request(lambda request:request.method=="POST" and request.url.endswith("/verify-plan")) as sent:
                            form.get_by_role("button",name="Verify entire plan").click()
                        self.assertNotIn("untrusted-private-marker",sent.value.post_data)
                        tab.get_by_role("heading",name="Plan verification results").wait_for()
                        self.assertIn("Reopen individual verification",tab.locator("body").inner_text())
                        self.assertNotIn("untrusted-private-marker",tab.locator("body").inner_text())
                    finally:
                        browser.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
