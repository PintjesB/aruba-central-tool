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


    def test_different_scopes_with_same_observed_profile_recipient_block_combination(self):
        from unittest.mock import patch
        from copy import deepcopy
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            first = deepcopy(next(f for f in workspace.consolidation_snapshot(bundle) if f["action"] == "promote_local"))
            second = deepcopy(first)
            first["action"] = second["action"] = "reuse_library"
            first["sources"] = [{"scope": "1", "kind": "global", "name": "Global"}]
            second["sources"] = [{"scope": "3", "kind": "device", "name": "Switch A"}]
            first["fallbacks"] = second["fallbacks"] = []
            second["id"] = "synthetic-second"
            manifest = {"schema": 1, "kind": "consolidation_selection", "snapshot": name,
                        "snapshot_binding": snapshot_binding(workspace, name, bundle),
                        "selections": [{"id": f["id"], "destination": None} for f in (first, second)]}
            with patch.object(workspace, "consolidation_snapshot", return_value=[first, second]):
                report = validate_selection(workspace, manifest)
                self.assertEqual(report["conflicts_by_reason"], {"recipient_overlap": 1})
                self.assertFalse(report["review_export_gates_passed"])
                manifest["selections"].reverse()
                self.assertEqual(validate_selection(workspace, manifest), report)
                second["identity"] = "different-profile"
                self.assertTrue(validate_selection(workspace, manifest)["review_export_gates_passed"])


    def test_reconstructed_plan_uses_only_original_selection_and_exact_snapshot(self):
        from aruba_central.review_manifest import reconstruct_selection
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            findings = workspace.consolidation_snapshot(bundle)
            promote = next(f for f in findings if f["action"] == "promote_local")
            reuse = next(f for f in findings if f["action"] == "reuse_library")
            manifest = {"schema": 1, "kind": "consolidation_selection", "snapshot": name,
                        "snapshot_binding": snapshot_binding(workspace, name, bundle),
                        "selections": [{"id": promote["id"], "destination": "library"},
                                       {"id": reuse["id"], "destination": None}]}
            plan = reconstruct_selection(workspace, manifest)
            self.assertEqual(plan["kind"], "reconstructed_consolidation_review")
            self.assertFalse(plan["safe_to_apply"])
            self.assertEqual(plan["validation"], validate_selection(workspace, manifest))
            self.assertEqual(plan["cleanup_review_order"], list(reversed(plan["review_order"])))
            reconstructed = next(f for f in plan["recommendations"] if f["id"] == promote["id"])
            self.assertEqual(reconstructed["local"], promote["local"])
            self.assertEqual(reconstructed["selected_destination"]["kind"], "library")
            self.assertEqual(reconstructed["selected_destination"]["assignment_scopes"], [r["scope"] for r in promote["sources"]])
            manifest["selections"].reverse()
            self.assertEqual(reconstruct_selection(workspace, manifest), plan)
            manifest["selections"][1]["destination"] = None
            with self.assertRaises(ValueError):
                reconstruct_selection(workspace, manifest)
            path.write_text(path.read_text() + " ")
            with self.assertRaises(ValueError):
                reconstruct_selection(workspace, manifest)

    def test_cli_reconstruction_ignores_untrusted_preview_bodies(self):
        from unittest.mock import patch
        from contextlib import redirect_stdout, redirect_stderr
        from io import StringIO
        from aruba_central.review_manifest import main
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            promote = next(f for f in workspace.consolidation_snapshot(bundle) if f["action"] == "promote_local")
            manifest = {"schema": 1, "kind": "consolidation_selection", "snapshot": name,
                        "snapshot_binding": snapshot_binding(workspace, name, bundle),
                        "selections": [{"id": promote["id"], "destination": "library"}]}
            preview = Path(directory) / "preview.json"
            preview.write_text(json.dumps({"selection_manifest": manifest,
                "recommendations": [{"local": "untrusted-marker", "safe_to_apply": True}],
                "bulk_review": {"known_recipients": "untrusted-marker"}}))
            output = Path(directory) / "rebuilt.json"
            args = ["review_manifest", "--directory", directory, "--preview", str(preview),
                    "--reconstruct-output", str(output)]
            with patch("sys.argv", args), redirect_stdout(StringIO()):
                self.assertEqual(main(), 0)
            self.assertNotIn("untrusted-marker", output.read_text())
            self.assertFalse(json.loads(output.read_text())["safe_to_apply"])
            with patch("sys.argv", args), redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                main()


    def test_atomic_module_different_names_share_scope_and_recipient_gate(self):
        from unittest.mock import patch
        from copy import deepcopy
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            first = deepcopy(next(f for f in workspace.consolidation_snapshot(bundle) if f["action"] == "promote_local"))
            second = deepcopy(first)
            for proposal, identity, scope, kind in ((first, "dns-first", "1", "global"), (second, "dns-second", "3", "device")):
                proposal.update(action="reuse_library", module="dns", identity=identity,
                                sources=[{"scope": scope, "kind": kind, "name": scope}], fallbacks=[])
            second["id"] = "atomic-second"
            manifest = {"schema": 1, "kind": "consolidation_selection", "snapshot": name,
                        "snapshot_binding": snapshot_binding(workspace, name, bundle),
                        "selections": [{"id": f["id"], "destination": None} for f in (first, second)]}
            with patch.object(workspace, "consolidation_snapshot", return_value=[first, second]):
                result = validate_selection(workspace, manifest)
                self.assertEqual(result["conflicts_by_reason"], {"recipient_overlap": 1})
                self.assertFalse(result["review_export_gates_passed"])
                manifest["selections"].reverse()
                self.assertEqual(validate_selection(workspace, manifest), result)
                first["sources"] = second["sources"]
                self.assertEqual(validate_selection(workspace, manifest)["conflicts_by_reason"],
                                 {"recipient_overlap": 1, "scope_overlap": 1})
                second["sources"] = [{"scope": "4", "kind": "device", "name": "Other"}]
                self.assertTrue(validate_selection(workspace, manifest)["review_export_gates_passed"])
