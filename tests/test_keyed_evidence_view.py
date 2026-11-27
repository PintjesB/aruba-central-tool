import json
import tempfile
import unittest
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.central_tool import field_differences
from aruba_central.keyed_evidence_view import keyed_observations
from test_consolidation import fixture


class KeyedEvidenceViewTests(unittest.TestCase):
    def test_order_is_not_equivalence_and_unqualified_remains_visible(self):
        bundle = fixture()
        a, b = {"servers": ["first", "second"]}, {"servers": ["second", "first"]}
        bundle["keyed_profile_details"] = {"profiles": {"Library": {"": {
            "server-groups": {"example-group": {"library": {"status": "identity_observed", "differences": field_differences(a, b), "profile": b}}},
            "roles": {"example-role": {"library": {"status": "schema_unresolved", "raw": {"unexpected": True}}},
                      "sampled-role": {"library": {"status": "collection_only_sampled"}}}
        }}}}
        self.assertEqual({r["category"] for r in keyed_observations(bundle)}, {"order_only", "unqualified", "sampled"})
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            html = workspace.assessment({"snapshot": name, "mode": "keyed"})
            self.assertIn("example-group", html)
            self.assertIn("example-role", html)
            self.assertIn("List order differs", html)
            self.assertNotIn("sampled-role", html)
            self.assertIn("No qualified exact comparison available", html)
            html = workspace.assessment({"snapshot": name, "mode": "keyed", "category": "sampled"})
            self.assertIn("sampled-role", html)
            self.assertNotIn("example-group", html)


    def test_exact_scope_and_function_filters_apply_to_rows_and_metrics(self):
        bundle = fixture()
        def evidence(identity):
            return {"roles": {identity: {"effective": {"status": "schema_unresolved", "raw": {"name": identity}}}}}
        bundle["keyed_profile_details"] = {"profiles": {
            "ACCESS_SWITCH": {"3": evidence("selected-example"), "4": evidence("other-device-example")},
            "ALL_DEVICE_FUNCTIONS": {"3": evidence("other-selector-example")}}}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            html = workspace.assessment({"snapshot": name, "mode": "keyed",
                                         "persona": "ACCESS_SWITCH", "scope": "3"})
            self.assertIn("selected-example", html)
            self.assertNotIn("other-device-example", html)
            self.assertNotIn("other-selector-example", html)
            self.assertIn("1 matching observations", html)
            self.assertIn('name="scope" value="3"', html)
