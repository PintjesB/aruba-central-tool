import json
import tempfile
import unittest
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.consolidation import profile_recommendations
from aruba_central.review_dispositions import snapshot_binding
from aruba_central.review_manifest import validate_selection
from test_consolidation import fixture


class PromotionDestinationEvidenceTests(unittest.TestCase):
    def test_exact_scope_and_library_conflicts_exclude_only_affected_choices(self):
        data = fixture()
        entry = data["results"]["ACCESS_SWITCH"]
        for scope in entry["scopes"]:
            if scope["id"] in ("3", "4"):
                scope["metadata"] = {"siteId": "2"}
        module = entry["modules"]["layer2-vlan"]
        global_row = module["scope_results"][0]
        global_row["effective_view"]["count_confirmed"] = True
        data["library"]["modules"]["layer2-vlan"]["count_confirmed"] = True
        def finding(bundle):
            return next(f for f in profile_recommendations(bundle) if f["action"] == "promote_local" and f["identity"] == "20")
        prior = finding(data)
        self.assertTrue({"1", "2"} <= {p["scope"] for p in prior["placement_options"]})
        direct = {"status": "identity_observed", "profile": {"vlan": 20, "name": "Contradiction"}}
        data["keyed_profile_details"] = {"profiles": {
            "ACCESS_SWITCH": {"1": {"layer2-vlan": {"20": {"effective": direct}}}},
            "Library": {"": {"layer2-vlan": {"20": {"library": direct}}}}}}
        after = finding(data)
        self.assertEqual({d["destination"] for d in after["blocked_destinations"]}, {"1", "library"})
        self.assertTrue(after["preview_selectable"])
        self.assertEqual({p["scope"] for p in after["placement_options"]}, {"2"})
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(data))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            f = next(f for f in workspace.consolidation_snapshot(bundle)
                     if f["action"] == "promote_local" and f["identity"] == "20")
            binding = snapshot_binding(workspace, name, bundle)
            manifest = {"schema": 1, "kind": "consolidation_selection", "snapshot": name,
                        "snapshot_binding": binding, "selections": [{"id": f["id"], "destination": "2"}]}
            self.assertTrue(validate_selection(workspace, manifest)["review_export_gates_passed"])
            for blocked in ("1", "library"):
                manifest["selections"][0]["destination"] = blocked
                with self.assertRaises(ValueError):
                    validate_selection(workspace, manifest)
            html = workspace.advisor({"snapshot": name, "group": f["id"], "detail": "1", "binding": binding})
            self.assertIn("Blocked destination: Library", html)
            self.assertIn("Blocked destination: Global", html)
        module["scope_results"][1]["effective_view"]["count_confirmed"] = True
        data["keyed_profile_details"]["profiles"]["ACCESS_SWITCH"]["2"] = {"layer2-vlan": {"20": {"effective": direct}}}
        self.assertFalse(finding(data)["preview_selectable"])
