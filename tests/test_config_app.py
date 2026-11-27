import http.client
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch

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

    def test_device_comparison_distinguishes_individual_details_and_sampled_evidence(self):
        bundle = self.fixture()
        scopes = bundle["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"]
        scopes[1]["effective_view"]["profiles"]["10"]["name"] = "A"
        def detail(enabled):
            return {"status": "identity_observed", "profile": {"vlan": 10, "name": "A", "enable": enabled}}
        def scope(evidence):
            return {"layer2-vlan": {"10": {"effective": evidence}}}
        profiles = {"a": scope(detail(True)), "b": scope(detail(False))}
        bundle["keyed_profile_details"] = {"profiles": {"ACCESS_SWITCH": profiles}}
        result = compare_devices(bundle, "ACCESS_SWITCH", "a", "b")[0]
        self.assertEqual(result["status"], "different")
        row = result["differences"][0]
        self.assertEqual(row["status"], "individual_detail_difference")
        self.assertEqual(row["fields"], [])
        self.assertEqual(row["individual"]["fields"][0]["path"], ["enable"])
        profiles["b"] = scope({"status": "collection_only_sampled"})
        result = compare_devices(bundle, "ACCESS_SWITCH", "a", "b")[0]
        self.assertEqual(result["status"], "unqualified")
        row = result["differences"][0]
        self.assertEqual(row["status"], "individual_comparison_unavailable")
        self.assertIsNone(row["individual"]["right"])
        self.assertIsNone(row["individual"]["fields"])
        profiles["b"] = scope(detail(True))
        self.assertEqual(compare_devices(bundle, "ACCESS_SWITCH", "a", "b")[0]["status"], "exact_match")

    def test_supplemental_browser_lists_and_compares_observed_profiles(self):
        data = self.fixture()
        def captured(*rows):
            return {"status": "response_received", "raw": {"portals": list(rows)}}
        local = {"portal-id": "portal-a", "description": "Local"}
        effective = {"portal-id": "portal-a", "description": "Effective"}
        data["unadapted_profiles"] = {"portals": {"status": "supplemental_raw",
            "library": captured(local), "source_views": [{"persona": "ACCESS_SWITCH",
                "scope": "a", "observed_instances": [], "committed": captured(local),
                "effective": captured(effective, {"portal-id": "portal-b", "enable": False})}]}}
        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(directory)
            name = "config-audit-supplemental.json"
            (Path(directory) / name).write_text(json.dumps(data), encoding="utf-8")
            query = {"snapshot": name, "module": "portals", "persona": "ACCESS_SWITCH", "scope": "a"}
            with patch("central_tool.refresh_configuration_review", side_effect=lambda data: data) as review:
                html = workspace.unadapted(query)
                self.assertIn("Observed profiles", html)
                self.assertIn("Different observed settings", html)
                self.assertIn("One view observed; other unverified", html)
                html = workspace.unadapted({**query, "profile": "portal-a"})
                self.assertIn("Local", html)
                self.assertIn("Effective", html)
                self.assertIn("Back to observed profiles", html)
                self.assertEqual(review.call_count, 1)
                with self.assertRaises(ValueError):
                    workspace.unadapted({**query, "profile": "unknown"})
                html = workspace.unadapted({"snapshot": name, "module": "portals"})
                self.assertIn("Observed profiles", html)
                self.assertIn("portal-a", html)

    def test_reviewed_snapshot_cache_is_bounded_and_invalidated_by_file_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(directory)
            one = Path(directory) / "config-audit-one.json"
            two = Path(directory) / "config-audit-two.json"
            one.write_text(json.dumps(self.fixture()), encoding="utf-8")
            two.write_text(json.dumps(self.fixture()), encoding="utf-8")
            with patch("central_tool.refresh_configuration_review", side_effect=lambda data: data) as review:
                first = workspace.reviewed_snapshot(one.name)
                self.assertIs(first, workspace.reviewed_snapshot(one.name))
                self.assertEqual(review.call_count, 1)
                changed = self.fixture()
                changed["extra"] = "changed snapshot"
                one.write_text(json.dumps(changed), encoding="utf-8")
                self.assertEqual(workspace.reviewed_snapshot(one.name)["extra"], "changed snapshot")
                self.assertEqual(review.call_count, 2)
                workspace.reviewed_snapshot(two.name)
                workspace.reviewed_snapshot(one.name)
                self.assertEqual(review.call_count, 4)
                one.unlink()
                with self.assertRaises(ValueError):
                    workspace.reviewed_snapshot(one.name)
                with self.assertRaises(ValueError):
                    workspace.reviewed_snapshot("../outside.json")
                self.assertEqual(review.call_count, 4)

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
            def request(method, path, headers=None, body=None):
                with_connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                try:
                    with_connection.request(method, path, body=body, headers=headers or {})
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
                self.assertIn(b"async function poll()", body)
                self.assertEqual(request("GET", root + "status", {"Host": "example.com"})[0], 404)
                initial = json.loads(request("GET", root + "status")[2])
                self.assertEqual(initial["state"], "idle")
                self.assertEqual(request("POST", root + "refresh", {"Origin": "https://example.com"})[0], 403)
                same = {"Origin": f"http://127.0.0.1:{server.server_port}",
                        "Content-Type": "application/x-www-form-urlencoded"}
                self.assertIn(workspace.csrf.encode(), body)
                self.assertEqual(request("POST", root + "refresh", same,
                                         urlencode({"csrf": workspace.csrf}))[0], 409)
                self.assertEqual(request("POST", root + "refresh", same,
                                         urlencode({"csrf": "wrong"}))[0], 403)
                opaque = {**same, "Origin": "null", "Sec-Fetch-Site": "same-origin"}
                form = urlencode({"csrf": workspace.csrf, "client_id": "example-id",
                                  "client_secret": "example-secret", "region": "", "depth": "deep"})
                with patch("config_app.credential_refresh", return_value=lambda progress=None: self.fixture()) as factory:
                    self.assertEqual(request("POST", root + "credentials",
                                             {**opaque, "Sec-Fetch-Site": "cross-site"}, form)[0], 403)
                    self.assertEqual(request("POST", root + "credentials",
                                             {**opaque, "Origin": "https://example.com"}, form)[0], 403)
                    self.assertEqual(request("POST", root + "credentials",
                                             {**opaque, "Sec-Fetch-Site": "none"}, form)[0], 403)
                    self.assertEqual(request("POST", root + "credentials", opaque, form)[0], 303)
                    factory.assert_called_once_with("example-id", "example-secret", "", deep_catalog=True)
                    deadline = time.monotonic() + 3
                    while workspace.state == "running" and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertEqual(workspace.state, "complete")
                    finished = json.loads(request("GET", root + "status")[2])
                    self.assertEqual(finished["state"], "complete")
                    self.assertTrue(finished["snapshot"].endswith(".json"))
                    self.assertNotIn("example-secret", json.dumps(finished))
                    self.assertIn(b"Audit complete", request("GET", root)[2])
                    self.assertIn(b"Open new configuration snapshot", request("GET", root)[2])
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
                from inspect import getclosurevars
                client = getclosurevars(refresh).nonlocals['client']
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

    def test_library_comparison_joins_exact_identities_and_qualified_local_bodies(self):
        from config_app import library_profile_comparison
        data = self.fixture()
        data["library"] = {"modules": {"layer2-vlan": {"status": "list_parsed", "profiles": {
            "10": {"vlan": 10, "name": "A", "@": {"source": "shared"}},
            "20": {"vlan": 20, "name": "Other"}}}},
            "assignments": {"rows": [
                {"profile-type": "layer2-vlan", "profile-instance": 10, "scope-id": "a"},
                {"profile-type": "roles", "profile-instance": "10", "scope-id": "a"}]}}
        scopes = data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"]
        scopes[0]["review"] = {"qualified": True, "profiles": [
            {"identity": "10", "local": {"vlan": 10, "name": "A"}}]}
        scopes[1]["review"] = {"qualified": True, "profiles": [
            {"identity": "10", "local": {"vlan": 10, "name": "B"}}]}
        result = library_profile_comparison(data, "layer2-vlan")
        self.assertEqual(len(result["10"]["assignments"]), 1)
        self.assertEqual({v["classification"] for v in result["10"]["local_variants"]},
                         {"exact_match", "different_body"})
        self.assertFalse(result["20"]["assignment_completeness_verified"])
        self.assertEqual(result["20"]["assignments"], [])
        scopes[1]["review"]["qualified"] = False
        self.assertEqual(len(library_profile_comparison(data, "layer2-vlan")["10"]["local_variants"]), 1)

    def test_customer_boundary_rejects_unrelated_inventory(self):
        from config_app import verify_workspace_identity, WorkspaceIdentityError
        def capture(serial, region="region", global_id="1"):
            return {"schema": 1, "kind": "configuration_audit", "region": region,
                    "inventory": [{"inventory": {"serial": serial}}],
                    "results": {"ACCESS_SWITCH": {"scopes": [{"kind": "global", "id": global_id}]}}}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            verify_workspace_identity(directory, capture("A"))
            (directory / "config-audit-first.json").write_text(json.dumps(capture("A")))
            verify_workspace_identity(directory, capture("A"))
            for other in (capture("B"), capture("A", "other-region"), capture("A", global_id="2")):
                with self.assertRaises(WorkspaceIdentityError):
                    verify_workspace_identity(directory, other)
            workspace = Workspace(directory)
            self.assertTrue(workspace.start_refresh(lambda progress=None: capture("B")))
            deadline = time.monotonic() + 3
            while workspace.state == "running" and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(workspace.status()["state"], "failed")
            self.assertIn("separate customer directory", workspace.status()["message"])
            self.assertEqual(len(audit_files(directory)), 1)

    def test_refresh_failure_is_sanitized(self):
        from central_tool import APIError
        def fail(progress=None):
            raise APIError("OAuth", 403)
        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(directory, fail)
            self.assertTrue(workspace.start_refresh())
            deadline = time.monotonic() + 3
            while workspace.state == "running" and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(workspace.status()["state"], "failed")
            self.assertIn("OAuth returned HTTP 403", workspace.status()["message"])
            self.assertIsNone(workspace.status()["snapshot"])
            self.assertEqual(audit_files(Path(directory)), [])

    def test_phase_timing_uses_current_phase_not_total_elapsed(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(directory)
            workspace.state = "running"
            workspace.started = 100
            with patch("config_app.time.monotonic", return_value=160):
                workspace.update_progress("Discovery", 0, 0, "Inventory")
            with patch("config_app.time.monotonic", return_value=200):
                workspace.update_progress("Profile details", 0, 100, "Details")
            with patch("config_app.time.monotonic", return_value=220):
                workspace.update_progress("Profile details", 40, 100, "Details")
                state = workspace.status()
            self.assertEqual(state["elapsed"], 120)
            self.assertEqual(state["phase_elapsed"], 20)
            self.assertEqual(state["phase_items_per_second"], 2)
            self.assertEqual(state["phase_eta_seconds"], 30)
            self.assertEqual(state["phase_history"], [
                {"phase": "Discovery", "done": 0, "total": 0, "seconds": 40}])
            with patch("config_app.time.monotonic", return_value=230):
                workspace.update_progress("Profile detail expansion", 0, 20, "Expansion")
                self.assertIsNone(workspace.status()["phase_eta_seconds"])
                self.assertEqual(workspace.status()["phase_elapsed"], 0)

    def test_refresh_single_flight_and_saved_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            release = threading.Event()
            def refresh(progress=None):
                progress("Configuration scopes", 2, 5, "ACCESS_SWITCH / layer2-vlan")
                release.wait(2)
                return self.fixture()
            workspace = Workspace(directory, refresh)
            self.assertTrue(workspace.start_refresh())
            self.assertFalse(workspace.start_refresh())
            deadline = time.monotonic() + 1
            while workspace.status()["done"] != 2 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(workspace.status()["done"], 2)
            self.assertEqual(workspace.status()["total"], 5)
            self.assertEqual(workspace.status()["state"], "running")
            release.set()
            deadline = time.monotonic() + 3
            while workspace.state == "running" and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(workspace.state, "complete")
            self.assertEqual(len(audit_files(Path(directory))), 1)


if __name__ == "__main__":
    unittest.main()
