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
            self.assertNotIn("No qualified exact comparison available", html)
            from aruba_central.review_dispositions import snapshot_binding
            binding = snapshot_binding(workspace, name, workspace.reviewed_snapshot(name))
            q = {"snapshot": name, "mode": "keyed", "persona": "Library", "scope": "",
                 "module": "roles", "identity": "example-role", "view": "library",
                 "detail": "1", "binding": binding}
            detail = workspace.assessment(q)
            self.assertIn("No qualified exact comparison available", detail)
            self.assertIn("unexpected", detail)
            self.assertNotIn("unexpected", html)
            with self.assertRaises(ValueError):
                workspace.assessment({**q, "identity": "unknown"})
            with self.assertRaises(ValueError):
                workspace.assessment({**q, "binding": "stale"})
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


    def test_explains_case_collision_and_server_count_without_qualifying(self):
        from aruba_central.keyed_evidence_view import individual_detail
        bundle = fixture()
        bundle["library"]["modules"]["roles"] = {"status": "list_parsed", "profiles": {
            "Example": {"name": "Example"}, "example": {"name": "example"}}}
        role = {"status": "schema_unresolved", "raw": {"name": "example"}}
        html = individual_detail(role, context=(bundle, "Library", "", "roles", "Example", "library"))
        self.assertIn("Multiple distinct case-equivalent names", html)
        self.assertIn("No qualified exact comparison available", html)
        read = {"status": "identity_observed", "profile": {"servers": ["one", "two"]},
                "differences": field_differences({"servers": ["one", "two"], "example-count": 2},
                                                  {"servers": ["one", "two"]})}
        html = individual_detail(read, context=(bundle, "Library", "", "server-groups", "test", "library"))
        self.assertIn("equals the length of the observed individual server list", html)
        self.assertIn("does not establish a derived field", html)
        self.assertIn("Exact comparison", html)


    def test_full_evidence_search_before_paging_and_saved_filters(self):
        from aruba_central.filter_presets import selection
        bundle = fixture()
        bundle["keyed_profile_details"] = {"profiles": {"Library": {"": {"roles": {
            f"profile-{i:03}": {"library": {"status": "schema_unresolved", "raw": {"name": str(i)}}}
            for i in range(250)}}}}}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            base = {"snapshot": name, "mode": "keyed", "persona": "Library"}
            initial = workspace.assessment(base)
            self.assertNotIn("profile-249", initial)
            self.assertIn("250 matching observations", initial)
            html = workspace.assessment({**base, "q": "PROFILE-249 library"})
            self.assertIn("profile-249", html)
            self.assertIn("1 matching observations", html)
            self.assertNotIn("profile-248", html)
            batch = workspace.assessment({**base, "q": "profile-", "offset": "200"})
            self.assertIn("profile-249", batch)
            self.assertIn("q=profile-", batch)
            self.assertIn("250 matching observations", batch)
            empty = workspace.assessment({**base, "q": "nonexistent", "offset": "200"})
            self.assertIn("Return to first batch", empty)
            with self.assertRaises(ValueError):
                workspace.assessment({**base, "q": "x" * 201})
            self.assertEqual(selection("assessment", {"mode": "keyed", "q": "profile-249"}),
                             {"mode": "keyed", "q": "profile-249"})
