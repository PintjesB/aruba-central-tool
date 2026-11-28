import json
import unittest
from aruba_central.nac_service_probe import nac_service_probe, ENDPOINTS


class NACServiceProbeTests(unittest.TestCase):
    def test_reads_only_safe_observed_identities_and_exports_counts(self):
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append((path, params))
                if path.endswith("/cnac-dpp-reg"):
                    return {"items": [{"id": "private-dpp", "uri": "private-uri"}], "count": 1}
                if path.endswith("/cnac-job"):
                    return {"items": [{"id": "private-job", "errorMessage": "private-error"}], "count": 1, "total": 1}
                if path.endswith("/private-dpp"):
                    return {"id": "private-dpp", "uri": "private-uri"}
                if path.endswith("/private-job/status"):
                    return {"id": "private-job", "status": "private-status"}
                raise AssertionError("Unexpected path")
        client = Client()
        report = nac_service_probe(client)
        self.assertEqual(len(client.calls), 4)
        self.assertEqual(report["operations"][1]["outcomes"], {"identity_observed": 1})
        self.assertEqual(report["operations"][3]["outcomes"], {"identity_observed": 1})
        self.assertEqual(report["endpoint_policy"]["cnac-certificate"], "requires_user_principal_name")
        self.assertNotIn("private", json.dumps(report))
        self.assertFalse(report["complete"])

    def test_no_detail_read_for_unsafe_or_duplicate_identities(self):
        class Client:
            def get(self, path, **params):
                self.assert_list(path)
                return {"items": [{"id": "../unsafe"}, {"id": "../unsafe"}]}
            def assert_list(self, path):
                if not path.endswith(("/cnac-dpp-reg", "/cnac-job")):
                    raise AssertionError("Detail read attempted")
        report = nac_service_probe(Client())
        self.assertEqual(report["operations"][0]["status"], "identity_or_page_unqualified")
        self.assertEqual(report["operations"][1]["attempted"], 0)
        self.assertEqual(report["operations"][3]["attempted"], 0)


    def test_empty_lists_distinguish_page_count_from_reported_total(self):
        from aruba_central.nac_service_probe import capture_service_inventory
        class Client:
            def get(self, path, **params):
                if path.endswith("/cnac-dpp-reg"):
                    return {"items": [], "count": 0}
                if path.endswith("/cnac-job"):
                    return {"items": [], "count": 0, "total": 0}
                raise AssertionError("No identifiers observed")
        report = capture_service_inventory(Client())
        self.assertFalse(report["operations"][0]["count_confirmed"])
        self.assertTrue(report["operations"][2]["count_confirmed"])
        self.assertFalse(report["complete"])
        self.assertFalse(report["safe_to_apply"])

    def test_count_confirmation_rejects_inconsistent_or_partial_pages(self):
        from aruba_central.nac_service_probe import service_count_confirmed
        row = {"status": "list_observed", "total": 1, "rows": 1, "count": 1,
               "identity_count": 1, "next_cursor_present": False}
        self.assertTrue(service_count_confirmed(row))
        for change in ({"total": 2}, {"count": 2}, {"next_cursor_present": True},
                       {"identity_count": 0}, {"status": "schema_unqualified"}):
            self.assertFalse(service_count_confirmed({**row, **change}))


    def test_malformed_metadata_does_not_qualify_empty_inventory(self):
        from aruba_central.nac_service_probe import capture_service_inventory
        for bad in ({"next": ["unexpected"]}, {"count": False}, {"total": -1}):
            class Client:
                def get(self, path, **params):
                    return {"items": [], "count": 0, "total": 0, **bad}
            report = capture_service_inventory(Client())
            for row in report["operations"][::2]:
                self.assertEqual(row["status"], "pagination_unqualified")
                self.assertFalse(row["count_confirmed"])


    def test_saved_service_inventory_ui_and_anonymous_coverage(self):
        import tempfile
        from pathlib import Path
        from test_consolidation import fixture
        from aruba_central.config_app import Workspace
        from aruba_central.coverage_diagnostics import diagnostics
        from aruba_central.nac_service_probe import capture_service_inventory
        class Client:
            def get(self, path, **params):
                return {"items": [], "count": 0, **({"total": 0} if path.endswith("/cnac-job") else {})}
        bundle = fixture()
        bundle["nac_service_inventory"] = capture_service_inventory(Client())
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).nac({"snapshot": name})
            self.assertIn("Additional NAC service inventory", html)
            self.assertIn("cnac-dpp-reg", html)
            self.assertIn("cnac-job", html)
            self.assertIn("No observed identity queried", html)
        report = diagnostics(bundle)["nac"]
        self.assertFalse(report["cnac-dpp-reg"]["count_confirmed"])
        self.assertTrue(report["cnac-job"]["count_confirmed"])
