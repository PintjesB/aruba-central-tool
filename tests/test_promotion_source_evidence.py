import json
import tempfile
import unittest
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.consolidation import profile_recommendations
from aruba_central.review_dispositions import snapshot_binding
from aruba_central.review_manifest import validate_selection
from test_consolidation import fixture


class PromotionSourceEvidenceTests(unittest.TestCase):
    def test_source_contradiction_blocks_only_exact_promotion(self):
        data = fixture()
        def find(bundle, action, identity):
            return next(f for f in profile_recommendations(bundle)
                        if f["persona"] == "ACCESS_SWITCH" and f["module"] == "layer2-vlan"
                        and f["action"] == action and f["identity"] == identity)
        before = find(data, "promote_local", "20")
        reuse = find(data, "reuse_library", "30")
        self.assertTrue(before["preview_selectable"])
        data["keyed_profile_details"] = {"profiles": {"ACCESS_SWITCH": {"3": {"layer2-vlan": {
            "20": {"local": {"status": "identity_observed", "profile": {"vlan": 20, "name": "Conflicting"}}}}}}}}
        blocked = find(data, "promote_local", "20")
        self.assertFalse(blocked["preview_selectable"])
        self.assertEqual(blocked["individual_conflicts"][0]["view"], "local")
        self.assertEqual(find(data, "reuse_library", "30"), reuse)
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(data))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            finding = next(f for f in workspace.consolidation_snapshot(bundle)
                           if f["action"] == "promote_local" and f["module"] == "layer2-vlan" and f["identity"] == "20")
            binding = snapshot_binding(workspace, name, bundle)
            manifest = {"schema": 1, "kind": "consolidation_selection", "snapshot": name,
                        "snapshot_binding": binding, "selections": [{"id": finding["id"], "destination": "library"}]}
            with self.assertRaises(ValueError):
                validate_selection(workspace, manifest)
            detail = workspace.advisor({"snapshot": name, "group": finding["id"], "detail": "1", "binding": binding})
            self.assertIn("Conflicting individual evidence", detail)
            self.assertIn("Conflicting", detail)
        data["keyed_profile_details"]["profiles"]["ACCESS_SWITCH"]["3"]["layer2-vlan"]["20"]["local"]["status"] = "collection_only_sampled"
        self.assertEqual(find(data, "promote_local", "20"), before)

    def test_retained_library_contradiction_blocks_reuse(self):
        data = fixture()
        data["keyed_profile_details"] = {"profiles": {"Library": {"": {"layer2-vlan": {
            "30": {"library": {"status": "identity_observed", "profile": {"vlan": 30, "name": "Different"}}}}}}}}
        finding = next(f for f in profile_recommendations(data) if f["action"] == "reuse_library" and f["identity"] == "30")
        self.assertFalse(finding["preview_selectable"])
        self.assertEqual(finding["individual_conflicts"][0]["persona"], "Library")
        self.assertEqual(finding["individual_conflicts"][0]["view"], "library")
