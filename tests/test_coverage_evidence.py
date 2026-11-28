import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from aruba_central.review_dispositions import snapshot_binding
from aruba_central.coverage_evidence import evidence_record
from test_consolidation import fixture


class CoverageEvidenceTests(unittest.TestCase):
    def test_raw_hierarchy_response_loaded_only_for_exact_capture(self):
        bundle = fixture()
        bundle["scope_hierarchy_evidence"] = {"records": [
            {"scope": "3", "kind": "device", "status": "response_received", "raw": {"payload": "marker-a" * 1000}},
            {"scope": "4", "kind": "device", "status": "response_received", "raw": {"payload": "marker-b" * 1000}}]}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            reviewed = workspace.reviewed_snapshot(name)
            overview = workspace.coverage({"snapshot": name})
            self.assertIn("evidence_kind=hierarchy", overview)
            self.assertNotIn("marker-a", overview)
            self.assertNotIn("marker-b", overview)
            query = {"snapshot": name, "evidence_kind": "hierarchy", "evidence_index": "1",
                     "binding": snapshot_binding(workspace, name, reviewed)}
            detail = workspace.coverage(query)
            self.assertIn("marker-b", detail)
            self.assertNotIn("marker-a", detail)
            self.assertIn("#coverage-hierarchy", detail)
            with self.assertRaises(ValueError):
                workspace.coverage({**query, "evidence_index": "2"})
            path.write_text(path.read_text() + " ")
            with self.assertRaises(ValueError):
                workspace.coverage(query)

    def test_exact_assignment_ordinal(self):
        bundle = {"keyed_assignment_details": {"records": [{"raw": "first"}, {"raw": "second"}]}}
        self.assertEqual(evidence_record(bundle, "assignment", 1), {"raw": "second"})
        with self.assertRaises(ValueError):
            evidence_record(bundle, "assignment", -1)
