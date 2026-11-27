import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from aruba_central.device_review import device_review
from test_consolidation import fixture


class DeviceReviewTests(unittest.TestCase):
    def test_device_hub_preserves_membership_and_module_evidence(self):
        bundle = fixture()
        bundle["results"]["ACCESS_SWITCH"]["scopes"][2]["metadata"] = {"siteId": 2}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            reviewed = workspace.reviewed_snapshot(name)
            report = device_review(reviewed, "ACCESS_SWITCH", "3")
            self.assertEqual(report["membership"]["site"]["id"], "2")
            self.assertFalse(report["safe_to_apply"])
            self.assertTrue(report["modules"])
            html = workspace.scopes({"snapshot": name, "mode": "device", "persona": "ACCESS_SWITCH", "device": "3"})
            self.assertIn("Device review actions", html)
            self.assertIn("Configuration by module", html)
            self.assertIn("device=3", html)
            self.assertIn("scope=2", html)
            self.assertIn("Review device", workspace.scopes({"snapshot": name}))
            with self.assertRaises(ValueError):
                device_review(reviewed, "ACCESS_SWITCH", "2")


    def test_supplemental_device_evidence_keeps_exact_scope_and_selector(self):
        from aruba_central.configuration_search import search_configuration, grouped_search
        bundle = fixture()
        bundle["unadapted_profiles"] = {"example-module": {"source_views": [
            {"scope": "3", "persona": "UNFILTERED_SCOPE", "effective": {"status": "response_received", "raw": {"value": "device-specific"}}},
            {"scope": "4", "persona": "UNFILTERED_SCOPE", "effective": {"status": "response_received", "raw": {"value": "other-device"}}},
            {"scope": "3", "persona": "CAMPUS_AP", "effective": {"status": "response_received", "raw": {"value": "other-function"}}}
        ]}}
        report = device_review(bundle, "ACCESS_SWITCH", "3")
        self.assertEqual(len(report["supplemental"]), 1)
        self.assertEqual(report["supplemental"][0]["selector"], "UNFILTERED_SCOPE")
        result = search_configuration(bundle, "value", persona="UNFILTERED_SCOPE", module="example-module", scope="3")
        self.assertEqual([r["value"] for r in result["matches"]], ["device-specific"])
        groups = grouped_search(bundle, "value", persona="UNFILTERED_SCOPE", module="example-module", scope="3")
        self.assertEqual(groups["total"], 1)
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            html = workspace.scopes({"snapshot": name, "mode": "device", "persona": "ACCESS_SWITCH", "device": "3"})
            self.assertIn("Supplemental configuration evidence", html)
            self.assertIn("Search captured settings", html)
            self.assertIn("Inspect complete response", html)
            self.assertIn("unadapted?", html)
            html = workspace.report({"snapshot": name, "mode": "search", "persona": "UNFILTERED_SCOPE", "module": "example-module", "scope": "3", "q": "value"})
            self.assertIn("device-specific", html)
            self.assertNotIn("other-device", html)
            self.assertIn('name="scope" value="3"', html)


    def test_individual_evidence_summary_keeps_request_selectors_separate(self):
        bundle = fixture()
        def observation(status):
            return {"roles": {"role": {"effective": {"status": status}}}}
        bundle["keyed_profile_details"] = {"profiles": {
            "ACCESS_SWITCH": {"3": observation("collection_only_sampled"), "4": observation("schema_unresolved")},
            "ALL_DEVICE_FUNCTIONS": {"3": observation("schema_unresolved")}}}
        result = device_review(bundle, "ACCESS_SWITCH", "3")
        self.assertEqual({r["selector"]: r["counts"] for r in result["keyed"]},
                         {"ACCESS_SWITCH": {"sampled": 1}, "ALL_DEVICE_FUNCTIONS": {"unqualified": 1}})
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).scopes({"snapshot": name, "mode": "device", "persona": "ACCESS_SWITCH", "device": "3"})
            self.assertIn("Individual profile evidence", html)
            self.assertIn("Review discrepancies", html)
            self.assertIn("mode=keyed", html)
            self.assertIn("scope=3", html)


    def test_unqualified_module_has_visible_diagnostic_action(self):
        bundle = fixture()
        entry = bundle["results"]["ACCESS_SWITCH"]
        row = next(v for v in entry["modules"]["layer2-vlan"]["scope_results"] if v["scope"] == "3")
        row["effective_view"] = {"status": "request_rejected", "http_error": 400, "profiles": {}}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).scopes({"snapshot": name, "mode": "device", "persona": "ACCESS_SWITCH", "device": "3"})
            self.assertIn("structured modules need evidence review", html)
            self.assertIn("API request rejected", html)
            self.assertIn("Review incomplete evidence", html)
            self.assertIn("Evidence gap", html)
            self.assertIn("module=layer2-vlan&amp;view=diagnostics", html)
            self.assertIn("Not assessed", html)
