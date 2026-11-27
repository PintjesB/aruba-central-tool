import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.comparison_matrix import comparison_matrix
from aruba_central.config_app import Workspace
from test_consolidation import fixture


class ComparisonMatrixTests(unittest.TestCase):
    def test_missing_fields_and_unqualified_reads_not_equal_to_explicit_values(self):
        bundle = fixture()
        entry = bundle["results"]["ACCESS_SWITCH"]
        data = entry["modules"]["layer2-vlan"]["scope_results"]
        data[0]["effective_view"]["profiles"]["10"]["enable"] = False
        data[1]["effective_view"]["profiles"]["10"]["enable"] = None
        data[3]["effective_view"]["profiles"].pop("10")
        data[3]["effective_view"]["count_confirmed"] = True
        matrix = comparison_matrix(bundle, "ACCESS_SWITCH", "layer2-vlan", "10", ["1", "2", "3", "4", "5"])
        rows = {row["field"]: row for row in matrix["rows"]}
        self.assertEqual([c["state"] for c in rows["enable"]["cells"]],
                         ["observed", "observed", "not_returned", "confirmed_absent", "unqualified"])
        self.assertIs(rows["enable"]["cells"][0]["value"], False)
        self.assertIsNone(rows["enable"]["cells"][1]["value"])
        self.assertEqual(rows["enable"]["state"], "different")
        self.assertFalse(matrix["safe_to_apply"])
        with self.assertRaises(ValueError):
            comparison_matrix(bundle, "ACCESS_SWITCH", "layer2-vlan", "10", ["1", "1"])
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            html = workspace.comparison({"snapshot": name, "mode": "matrix", "persona": "ACCESS_SWITCH",
                                         "module": "layer2-vlan", "identity": "10", "scope1": "1", "scope2": "2"})
            self.assertIn("Multi-scope comparison", html)
            self.assertIn('name="identity"', html)
            self.assertIn("Observed values differ", html)
            self.assertIn("Global / Global", html)
            self.assertIn("Site / Site", html)
