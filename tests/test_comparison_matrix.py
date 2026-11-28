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

    def test_profile_suggestions_and_difference_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            query = {"snapshot": name, "mode": "matrix", "persona": "ACCESS_SWITCH",
                     "module": "layer2-vlan", "scope1": "1", "scope2": "2"}
            html = workspace.comparison(query)
            self.assertIn('list="matrix-identities"', html)
            self.assertIn('<option value="10"></option>', html)
            html = workspace.comparison({**query, "identity": "10", "fields": "differences"})
            self.assertIn("Show all fields", html)
            self.assertIn("Comparison summary", html)
            self.assertNotIn(">Observed values match<", html)
            self.assertIn("Profile evidence", html)


    def test_nested_comparison_preserves_list_order_and_type_conflicts(self):
        bundle = fixture()
        data = bundle["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"]
        first = data[0]["effective_view"]["profiles"]["10"]
        second = data[1]["effective_view"]["profiles"]["10"]
        first.update({"settings": {"flag": False, "a/b": 1, "only-first": True},
                      "ordered": ["a", "b"], "shape": {"a": 1}})
        second.update({"settings": {"flag": 0, "a/b": 1}, "ordered": ["b", "a"], "shape": None})
        result = comparison_matrix(bundle, "ACCESS_SWITCH", "layer2-vlan", "10", ["1", "2"], depth="nested")
        rows = {r["field"]: r for r in result["rows"]}
        self.assertEqual(rows["/settings/flag"]["state"], "different")
        self.assertEqual(rows["/settings/a~1b"]["state"], "matching")
        self.assertEqual(rows["/settings/only-first"]["cells"][1]["state"], "not_returned")
        self.assertEqual(rows["/ordered"]["state"], "different")
        self.assertEqual(rows["/shape"]["state"], "different")
        self.assertNotIn("/shape/a", rows)
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).comparison({"snapshot": name, "mode": "matrix", "persona": "ACCESS_SWITCH",
                "module": "layer2-vlan", "identity": "10", "scope1": "1", "scope2": "2", "depth": "nested"})
            self.assertIn("Show top-level settings", html)
            self.assertIn("JSON Pointer", html)


    def test_http_five_scope_nested_differences_link(self):
        from http.server import ThreadingHTTPServer
        from threading import Thread
        from urllib.parse import urlencode
        from urllib.request import urlopen
        from urllib.error import HTTPError
        from aruba_central.config_app import handler_for
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(workspace))
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            root = f"http://127.0.0.1:{server.server_port}/{workspace.token}/compare?"
            params = {"snapshot": name, "mode": "matrix", "persona": "ACCESS_SWITCH",
                      "module": "layer2-vlan", "identity": "10", "view": "effective",
                      "depth": "nested", "fields": "differences",
                      **{f"scope{i}": str(i) for i in range(1, 6)}}
            self.assertEqual(len(params), 13)
            try:
                with urlopen(root + urlencode(params), timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    html = response.read().decode()
                self.assertIn("Show all fields", html)
                self.assertIn("Show top-level settings", html)
                with self.assertRaises(HTTPError) as ctx:
                    urlopen(root + urlencode({**params, **{f"extra{i}": "1" for i in range(4)}}), timeout=5)
                self.assertEqual(ctx.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
