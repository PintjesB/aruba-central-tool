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


    def test_coverage_paging_searches_all_rows_and_preserves_ordinals(self):
        from aruba_central.coverage_navigation import coverage_batch
        records = [(i, f"row-{i}") for i in range(250)]
        args = ("/local/", "capture.json")
        batch, controls = coverage_batch(*args, {}, "hierarchy", records, lambda row: row[1])
        self.assertEqual(batch, records[:100])
        self.assertIn("Next batch", controls)
        query = {"coverage_table": "hierarchy", "coverage_offset": "100", "gap_reason": "unverified"}
        batch, controls = coverage_batch(*args, query, "hierarchy", records, lambda row: row[1])
        self.assertEqual(batch, records[100:200])
        self.assertIn("gap_reason=unverified", controls)
        batch, controls = coverage_batch(*args, {**query, "coverage_offset": "0", "coverage_q": "row-249"},
                                         "hierarchy", records, lambda row: row[1])
        self.assertEqual(batch, [(249, "row-249")])
        self.assertIn("1 matching rows", controls)
        self.assertEqual(coverage_batch(*args, query, "operations", records, lambda row: row[1])[0], records[:100])
        with self.assertRaises(ValueError):
            coverage_batch(*args, {**query, "coverage_offset": "-1"}, "hierarchy", records, lambda row: row[1])


    def test_library_and_supplemental_batches_keep_full_search_and_exact_links(self):
        bundle = fixture()
        bundle["unadapted_profiles"] = {
            f"example-module-{i:03}": {"source_views": [], "library": {"status": "response_received"}}
            for i in range(125)}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            def section(html, key):
                return html.split('id="coverage-' + key + '"', 1)[1].split("</section>", 1)[0]
            initial = workspace.coverage({"snapshot": name})
            for key in ("library", "supplemental"):
                overview = section(initial, key)
                self.assertIn("Next batch", overview)
                self.assertNotIn("module=example-module-124", overview)
                result = section(workspace.coverage({"snapshot": name, "coverage_table": key,
                    "coverage_q": "example-module-124"}), key)
                self.assertIn("module=example-module-124", result)
                self.assertIn("1 matching rows", result)
                self.assertNotIn("module=example-module-000", result)
