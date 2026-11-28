import json
import tempfile
import unittest
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.coverage_navigation import gap_summary
from aruba_central.workspace_views import collection_gap_rows
from test_consolidation import fixture


class CoverageNavigationTests(unittest.TestCase):
    def test_coverage_links_and_exact_reason_filter(self):
        bundle = fixture()
        row = bundle["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][2]
        row["effective_view"] = {"status": "request_rejected", "http_error": 400, "profiles": {}}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            gaps = collection_gap_rows(workspace.reviewed_snapshot(name))
            self.assertTrue(any(g["reason"] == "HTTP 400" for g in gaps))
            html = workspace.coverage({"snapshot": name})
            self.assertIn('aria-label="Coverage sections"', html)
            for target in ("coverage-gaps", "coverage-health", "coverage-keyed", "coverage-library", "coverage-operations"):
                self.assertIn(f'href="#{target}"', html)
                self.assertIn(f'id="{target}"', html)
            filtered = workspace.coverage({"snapshot": name, "gap_reason": "HTTP 400"})
            self.assertIn('gap_reason=HTTP+400#coverage-gaps', filtered)
            self.assertIn("1 matching module/context/reason groups", filtered)
            with self.assertRaises(ValueError):
                workspace.coverage({"snapshot": name, "gap_reason": "unknown"})

    def test_reason_counts_sum_observations_not_groups(self):
        html = gap_summary("/test/", "config-audit-example.json",
            [{"reason": "HTTP 400", "observations": 2}, {"reason": "HTTP 400", "observations": 5}], "HTTP 400")
        self.assertIn('<strong>7</strong><span>HTTP 400</span>', html)
        self.assertIn('aria-current="true"', html)

    def test_overview_previews_and_full_table_search(self):
        from aruba_central.coverage_navigation import coverage_batch
        records=[f"row-{i:03}" for i in range(125)]
        args=("/test/","config-audit-example.json")
        rows,html=coverage_batch(*args,{},"operations",records,str)
        self.assertEqual(rows,records[:15])
        self.assertIn("Open full table",html)
        self.assertIn("coverage_offset=0",html)
        rows,html=coverage_batch(*args,{"coverage_table":"operations"},"operations",records,str)
        self.assertEqual(rows,records[:100])
        self.assertIn("coverage_offset=100",html)
        rows,html=coverage_batch(*args,{"coverage_table":"operations","coverage_offset":"100"},"operations",records,str)
        self.assertEqual(rows,records[100:])
        self.assertIn("Previous batch",html)
        rows,html=coverage_batch(*args,{"coverage_table":"operations","coverage_q":"row-124"},"operations",records,str)
        self.assertEqual(rows,["row-124"])
        self.assertIn("of 1 matching rows (125 total)",html)
