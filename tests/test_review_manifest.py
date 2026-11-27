import json
import tempfile
import unittest
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.review_dispositions import snapshot_binding
from aruba_central.review_manifest import validate_selection
from test_consolidation import fixture


class SelectionManifestTests(unittest.TestCase):
    def test_exact_capture_and_destination_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            findings = workspace.consolidation_snapshot(bundle)
            promote = next(f for f in findings if f["action"] == "promote_local")
            blocked = next(f for f in findings if f["action"] == "remove_override")
            manifest = {"schema": 1, "kind": "consolidation_selection", "snapshot": name,
                        "snapshot_binding": snapshot_binding(workspace, name, bundle),
                        "selections": [{"id": promote["id"], "destination": None}]}
            result = validate_selection(workspace, manifest)
            self.assertEqual(result["missing_destinations"], 1)
            self.assertFalse(result["review_export_gates_passed"])
            manifest["selections"][0]["destination"] = "library"
            result = validate_selection(workspace, manifest)
            self.assertTrue(result["review_export_gates_passed"])
            self.assertFalse(result["safe_to_apply"])
            self.assertEqual(result["observed_recipient_pairs"], 2)
            manifest["selections"][0]["destination"] = "invalid"
            with self.assertRaises(ValueError):
                validate_selection(workspace, manifest)
            manifest["selections"] = [{"id": blocked["id"], "destination": None}]
            with self.assertRaises(ValueError):
                validate_selection(workspace, manifest)
            manifest["selections"] = [{"id": promote["id"], "destination": "library"}]
            manifest["selections"] *= 2
            with self.assertRaises(ValueError):
                validate_selection(workspace, manifest)
            manifest["selections"] = manifest["selections"][:1]
            path.write_text(path.read_text() + " ")
            with self.assertRaises(ValueError):
                validate_selection(workspace, manifest)


    def test_overlap_and_dependency_order_are_rederived_not_trusted(self):
        from unittest.mock import patch
        from copy import deepcopy
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            first = deepcopy(next(f for f in workspace.consolidation_snapshot(bundle) if f["action"] == "promote_local"))
            second = deepcopy(first)
            second["id"] = "synthetic-overlap"
            manifest = {"schema": 1, "kind": "consolidation_selection", "snapshot": name,
                        "snapshot_binding": snapshot_binding(workspace, name, bundle),
                        "selections": [{"id": first["id"], "destination": "library"},
                                       {"id": second["id"], "destination": "library"}]}
            with patch.object(workspace, "consolidation_snapshot", return_value=[first, second]):
                report = validate_selection(workspace, manifest)
                self.assertGreater(report["overlapping_proposal_conflicts"], 0)
                self.assertFalse(report["review_export_gates_passed"])
            second["identity"] = "21"
            refs = []
            for source, target in ((first, second), (second, first)):
                refs.append({"persona": source["persona"], "scope": "3", "device": "Synthetic",
                             "source_module": source["module"], "source": source["identity"],
                             "target_module": target["module"], "target": target["identity"],
                             "source_view": "effective", "source_scope_kind": "device", "status": "observed"})
            with patch.object(workspace, "consolidation_snapshot", return_value=[first, second]), patch.object(workspace, "advanced_snapshot", return_value={"references": refs}):
                report = validate_selection(workspace, manifest)
                self.assertEqual(report["overlapping_proposal_conflicts"], 0)
                self.assertEqual(report["dependency_order_blocked"], 2)
                self.assertFalse(report["review_export_gates_passed"])
