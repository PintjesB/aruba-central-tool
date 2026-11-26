import http.client
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from config_app import Workspace, audit_files, compare_devices, handler_for, read_audit


class WorkspaceTests(unittest.TestCase):
    def fixture(self):
        def view(v):
            return {"status": "list_parsed", "profiles": {"10": {"vlan": 10, "name": v}}}
        return {"schema": 1, "kind": "configuration_audit", "results": {
            "ACCESS_SWITCH": {"scopes": [{"id": "a", "kind": "device", "name": "A"},
                                        {"id": "b", "kind": "device", "name": "B"}],
                              "modules": {"layer2-vlan": {"scope_results": [
                                  {"scope": "a", "effective_view": view("A")},
                                  {"scope": "b", "effective_view": view("B")}]},
                                  "ethernet-interfaces": {"scope_results": []}}}}}

    def test_comparison_preserves_unknown_and_excludes_infrastructure_by_default(self):
        data = self.fixture()
        result = compare_devices(data, "ACCESS_SWITCH", "a", "b")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["status"], "different")
        self.assertEqual(result[0]["differences"][0]["identity"], "10")
        self.assertEqual(compare_devices(data, "ACCESS_SWITCH", "a", "b", "ethernet-interfaces")[0]["status"],
                         "unqualified")
        with self.assertRaises(ValueError):
            compare_devices(data, "ACCESS_SWITCH", "a", "a")

    def test_snapshot_selection_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "config-audit-one.json").write_text(json.dumps(self.fixture()), encoding="utf-8")
            (path / "other.json").write_text("{}", encoding="utf-8")
            self.assertEqual([p.name for p in audit_files(path)], ["config-audit-one.json"])
            self.assertEqual(read_audit(path, "config-audit-one.json")["schema"], 1)
            with self.assertRaises(ValueError):
                read_audit(path, "../config-audit-one.json")

    def test_loopback_access_and_refresh_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(directory)
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(workspace))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            root = "/" + workspace.token + "/"
            def request(method, path, headers=None):
                with_connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                try:
                    with_connection.request(method, path, headers=headers or {})
                    response = with_connection.getresponse()
                    result = response.status, response.getheader("Cache-Control"), response.read()
                    return result
                finally:
                    with_connection.close()
            try:
                self.assertEqual(request("GET", "/")[0], 404)
                self.assertEqual(request("GET", root, {"Host": "example.com"})[0], 404)
                status, cache, body = request("GET", root)
                self.assertEqual((status, cache), (200, "no-store"))
                self.assertIn(b"Saved snapshots", body)
                self.assertEqual(request("POST", root + "refresh", {"Origin": "https://example.com"})[0], 403)
                self.assertEqual(request("POST", root + "refresh", {
                    "Origin": f"http://127.0.0.1:{server.server_port}"})[0], 409)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_coverage_distinguishes_partial_and_unqualified(self):
        from config_app import module_coverage
        bundle = {"results": {"ACCESS_SWITCH": {"modules": {
            "a": {"scope_results": [{"review": {"qualified": True}}]},
            "b": {"scope_results": [{"review": {"qualified": True}}, {"review": {"qualified": False}}]},
            "c": {"scope_results": [{"review": {"qualified": False}}]}}}}}
        rows = {r["module"]: r for r in module_coverage(bundle)}
        self.assertEqual(rows["a"]["status"], "qualified")
        self.assertEqual(rows["b"]["status"], "partial")
        self.assertEqual(rows["c"]["status"], "unqualified")

    def test_one_shot_credentials_are_not_saved_or_retained(self):
        from unittest.mock import patch
        from config_app import credential_refresh
        from central_tool import EU_REGIONS
        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(directory)
            with patch("central_tool.detect_region"), patch("central_tool.configuration_audit", return_value=self.fixture()):
                refresh = credential_refresh("test-client-id", "test-secret", EU_REGIONS[0])
                client = refresh.__closure__[0].cell_contents
                self.assertTrue(workspace.start_refresh(refresh))
                deadline = time.monotonic() + 3
                while workspace.state == "running" and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual(workspace.state, "complete")
                self.assertIsNone(workspace.refresh)
                self.assertIsNone(client.client_id)
                self.assertIsNone(client.client_secret)
                self.assertIsNone(client.token)
                self.assertFalse(workspace.start_refresh())
                files = audit_files(Path(directory))
                self.assertEqual(len(files), 1)
                self.assertNotIn("test-secret", files[0].read_text())
                self.assertNotIn("test-client-id", workspace.home())
            with self.assertRaises(ValueError):
                credential_refresh("id", "secret", "https://example.com")

    def test_refresh_single_flight_and_saved_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            release = threading.Event()
            def refresh():
                release.wait(2)
                return self.fixture()
            workspace = Workspace(directory, refresh)
            self.assertTrue(workspace.start_refresh())
            self.assertFalse(workspace.start_refresh())
            release.set()
            deadline = time.monotonic() + 3
            while workspace.state == "running" and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(workspace.state, "complete")
            self.assertEqual(len(audit_files(Path(directory))), 1)


if __name__ == "__main__":
    unittest.main()
