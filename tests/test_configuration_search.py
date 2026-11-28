import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.configuration_search import search_configuration, grouped_search
from aruba_central.config_app import Workspace
from test_consolidation import fixture


class ConfigurationSearchTests(unittest.TestCase):
    def test_search_distinguishes_sources_and_caps_results(self):
        bundle = fixture()
        bundle["unadapted_profiles"] = {"example-module": {"source_views": [{
            "persona": "ACCESS_SWITCH", "scope": "3", "committed": {"status": "response_received", "raw": {"nested": {"value": "needle-private"}}},
            "effective": {}}], "library": {}}}
        bundle["keyed_profile_details"] = {"profiles": {"ACCESS_SWITCH": {"3": {"layer2-vlan": {"10": {
            "local": {"status": "identity_observed", "profile": {"name": "needle-private"}},
            "effective": {"status": "collection_only_sampled", "profile": {"name": "needle-private"}}}}}}}}
        result = search_configuration(bundle, "needle-private", limit=1)
        self.assertEqual(result["total"], 2)
        self.assertTrue(result["truncated"])
        rows = search_configuration(bundle, "needle-private")["matches"]
        self.assertEqual({r["source"] for r in rows}, {"supplemental", "individual"})
        raw = search_configuration(bundle, "nested needle-private", module="example-module")["matches"]
        self.assertEqual(raw[0]["path"], ["nested", "value"])
        self.assertEqual(raw[0]["scope"], "3")
        self.assertEqual(search_configuration(bundle, "needle-private", persona="Library")["total"], 0)
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).report({"snapshot": name, "mode": "search", "q": "needle-private"})
            self.assertIn("2 matching fields", html)
            self.assertIn("Inspect source", html)
            self.assertIn("nested.value", html)

    def test_exact_evidence_link_does_not_substitute_another_profile(self):
        bundle = fixture()
        rows = search_configuration(bundle, "10", module="layer2-vlan")["matches"]
        row = next(r for r in rows if r["identity"] == "10")
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            reviewed = workspace.reviewed_snapshot(name)
            row = next(r for r in search_configuration(reviewed, "10", module="layer2-vlan")["matches"] if r["identity"] == "10")
            query = {"snapshot": name, "mode": "evidence", "persona": row["persona"],
                     "module": row["module"], "scope": row["scope"], "evidence": row["evidence_id"]}
            html = workspace.report(query)
            self.assertIn("Captured configuration evidence", html)
            self.assertIn("Complete captured value", html)
            with self.assertRaises(ValueError):
                workspace.report({**query, "evidence": "0" * 64})
            with self.assertRaises(ValueError):
                workspace.report({**query, "scope": "nonexistent"})

    def test_search_batches_are_complete_and_disjoint(self):
        bundle = fixture()
        all_rows = search_configuration(bundle, "10", module="layer2-vlan", limit=1000)
        total = all_rows["total"]
        self.assertGreater(total, 2)
        expected = all_rows["matches"]
        observed = []
        for offset in range(0, total, 2):
            batch = search_configuration(bundle, "10", module="layer2-vlan", limit=2, offset=offset)
            self.assertEqual(batch["total"], total)
            self.assertEqual(batch["truncated"], offset + len(batch["matches"]) < total)
            observed.extend(batch["matches"])
        self.assertEqual(observed, expected)
        with self.assertRaises(ValueError):
            search_configuration(bundle, "10", offset=-1)
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).report({"snapshot": name, "mode": "search", "q": "10", "offset": "300"})
            self.assertIn("Previous result batch", html)
            self.assertIn("loaded batch only", html)

    def test_grouped_search_preserves_types_and_evidence_sources(self):
        bundle = fixture()
        entry = bundle["results"]["ACCESS_SWITCH"]
        for scope in entry["modules"]["layer2-vlan"]["scope_results"]:
            if scope["scope"] in ("3", "4"):
                scope["effective_view"] = {"status": "list_parsed", "profiles": {"10": {"test-needle": False}}}
        entry["modules"]["layer2-vlan"]["scope_results"][0]["effective_view"]["profiles"]["10"]["test-needle"] = 0
        groups = grouped_search(bundle, "test-needle", module="layer2-vlan")
        false_group = next(g for g in groups["groups"] if g["selector"][-1] is False)
        self.assertEqual(false_group["devices"], 2)
        self.assertEqual(false_group["observations"], 2)
        self.assertTrue(any(type(g["selector"][-1]) is int for g in groups["groups"]))
        rows = search_configuration(bundle, "test-needle", module="layer2-vlan", group=false_group["id"])
        self.assertEqual(rows["total"], 2)
        self.assertTrue(all(r["value"] is False for r in rows["matches"]))
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            html = Workspace(directory).report({"snapshot": name, "mode": "search", "q": "test-needle", "presentation": "grouped"})
            self.assertIn("distinct field/value groups", html)
            self.assertIn("Inspect matching observations", html)


    def test_source_filters_preserve_observations_and_skip_other_modules(self):
        from aruba_central.configuration_search import configuration_sources
        bundle = fixture()
        bundle["unadapted_profiles"] = {"raw-example": {"source_views": [{
            "persona": "ACCESS_SWITCH", "scope": "3", "committed": {"status": "response_received", "raw": {"value": "example"}}}],
            "library": {"status": "response_received", "raw": {"value": "library"}}}}
        all_sources = list(configuration_sources(bundle))
        for persona, module, scope in (("ACCESS_SWITCH", "layer2-vlan", "3"), ("Library", "", ""), ("", "raw-example", None)):
            expected = [r for r in all_sources if (not persona or r["persona"] == persona)
                        and (not module or r["module"] == module) and (scope is None or r["scope"] == scope)]
            self.assertEqual(list(configuration_sources(bundle, persona=persona, module=module, scope=scope)), expected)
        class Unvisited:
            def __iter__(self):
                raise AssertionError("Unselected module was traversed")
        bundle["results"]["ACCESS_SWITCH"]["modules"]["unselected"] = {"scope_results": Unvisited()}
        matches = search_configuration(bundle, "10", persona="ACCESS_SWITCH", module="layer2-vlan")
        self.assertGreater(matches["total"], 0)


    def test_search_filter_and_exact_links_for_additional_captured_sources(self):
        bundle = fixture()
        bundle["nac_configuration"] = {"authz-policies": {"status": "list_parsed",
            "profiles": {"p": {"name": "unique-needle"}}}}
        bundle["unadapted_profiles"] = {"raw-example": {"source_views": [{
            "persona": "UNFILTERED_SCOPE", "scope": "3",
            "effective": {"status": "partial_response", "pagination_status": "request_failed",
                          "raw": {}, "raw_pages": [{"items": [{"name": "unique-needle"}]}]}}]}}
        bundle["keyed_profile_details"] = {"profiles": {"ALL_DEVICE_FUNCTIONS": {"3": {
            "keyed-example": {"r": {"effective": {"status": "schema_unresolved",
                "raw": {"name": "unique-needle"}}}}}}}}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            reviewed = workspace.reviewed_snapshot(name)
            for persona, module, source in (("NAC", "authz-policies", "structured"),
                                             ("UNFILTERED_SCOPE", "raw-example", "supplemental_page"),
                                             ("ALL_DEVICE_FUNCTIONS", "keyed-example", "individual_raw")):
                rows = search_configuration(reviewed, "unique-needle", persona=persona, module=module)["matches"]
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row["source"], source)
                html = workspace.report({"snapshot": name, "mode": "search", "q": "unique-needle",
                                         "persona": persona, "module": module})
                self.assertIn("1 matching fields", html)
                evidence = workspace.report({"snapshot": name, "mode": "evidence", "persona": persona,
                                             "module": module, "scope": row["scope"], "evidence": row["evidence_id"]})
                self.assertIn("unique-needle", evidence)


    def test_optimized_matching_matches_reference_search_and_skips_unneeded_encoding(self):
        from unittest.mock import patch
        from aruba_central.configuration_search import configuration_sources, leaves, matching_fields, group_id
        from aruba_central.central_tool import canonical
        bundle = fixture()
        bundle["nac_configuration"] = {"authz-policies": {"status": "list_parsed",
            "profiles": {"p": {"name": "Straße", "nested": {"flag": False, "null": None}, "items": [0, "a b"]}}}}
        for query in ("NAC", "NAC nested false", "strasse", "items 0", "name a", "flag null", "not-found", "a b"):
            expected = []
            for record in configuration_sources(bundle):
                context = " ".join(str(record[k]) for k in ("persona", "module", "name", "scope", "identity", "view")).casefold()
                for path, value in leaves(record["body"]):
                    haystack = context + " " + ".".join(map(str, path)).casefold() + " " + canonical(value).casefold()
                    if all(term in haystack for term in query.casefold().split()):
                        expected.append((record, path, value))
            actual = [(record, path, value) for record, matches in matching_fields(bundle, query)
                      for path, value in matches]
            self.assertEqual(actual, expected)
        with patch("aruba_central.configuration_search.canonical", side_effect=AssertionError("Unneeded serialization")):
            rows = [(path, value) for _, matches in matching_fields(bundle, "NAC", persona="NAC")
                    for path, value in matches]
            self.assertGreater(len(rows), 0)
        groups = grouped_search(bundle, "NAC")
        self.assertTrue(all(row["id"] == group_id(row["selector"]) for row in groups["groups"]))


    def test_repeated_leaf_cache_keeps_exact_types_and_reduces_serialization(self):
        from unittest.mock import patch
        from aruba_central.configuration_search import matching_fields, group_id
        from aruba_central.central_tool import canonical
        bundle = {"results": {}, "nac_configuration": {
            "authz-policies": {"status": "list_parsed", "profiles": {
                str(i): {"flag": False, "number": 0, "float": -0.0 if i % 2 else 0.0,
                         "value": "repeat-value", "empty": None}
                for i in range(100)}}}}
        with patch("aruba_central.configuration_search.canonical", wraps=canonical) as encode:
            values = [value for _, matches in matching_fields(bundle, "repeat-value") for _, value in matches]
            self.assertEqual(values, ["repeat-value"] * 100)
            # Floats deliberately bypass caching. Repeated scalar encodings do not.
            self.assertLessEqual(encode.call_count, 104)
        groups = grouped_search(bundle, "NAC")["groups"]
        self.assertEqual(sum(row["observations"] for row in groups), 500)
        self.assertEqual(len(groups), 6)
        self.assertTrue(all(row["id"] == group_id(row["selector"]) for row in groups))
        self.assertEqual({canonical(row["selector"][-1]) for row in groups},
                         {"false", "0", "0.0", "-0.0", '"repeat-value"', "null"})


    def test_grouped_paths_distinguish_object_keys_from_array_indices(self):
        from aruba_central.configuration_search import display_path
        bundle = {"results": {}, "nac_configuration": {
            "authz-policies": {"status": "list_parsed", "profiles": {
                "object": {"items": {"0": "needle"}},
                "array": {"items": ["needle"]}}}}}
        groups = grouped_search(bundle, "needle")["groups"]
        self.assertEqual(len(groups), 2)
        paths = {tuple(row["selector"][-2]) for row in groups}
        self.assertEqual(paths, {("items", "0"), ("items", 0)})
        self.assertEqual({display_path(path) for path in paths}, {'items["0"]', "items[0]"})
        self.assertEqual(display_path(("a.b", "x")), '["a.b"].x')
        for group in groups:
            result = search_configuration(bundle, "needle", group=group["id"])
            self.assertEqual(result["total"], 1)
            self.assertEqual(result["matches"][0]["path"], group["selector"][-2])


    def test_index_preserves_exact_search_results_and_bounds(self):
        from aruba_central.configuration_search import build_search_index
        bundle = fixture()
        bundle["nac_configuration"] = {"example": {"status": "list_parsed", "profiles": {
            "object": {"items": {"0": "Straße"}, "flag": False, "float": -0.0},
            "array": {"items": ["Straße"], "flag": 0, "float": 0.0, "empty": []}}}}
        index = build_search_index(bundle)
        self.assertIsNotNone(index)
        self.assertIsNone(build_search_index(bundle, max_leaves=1))
        self.assertIsNone(build_search_index(bundle, max_chars=1))
        self.assertIsNone(build_search_index(bundle, max_sources=1))
        for query in ("strasse", "NAC flag false", "items 0", "0.0", "10", "not-found"):
            for filters in ({}, {"persona": "NAC", "scope": ""}, {"module": "layer2-vlan"}):
                self.assertEqual(search_configuration(bundle, query, index=index, **filters),
                                 search_configuration(bundle, query, **filters))
                self.assertEqual(grouped_search(bundle, query, index=index, **filters),
                                 grouped_search(bundle, query, **filters))
                self.assertEqual(search_configuration(bundle, query, offset=1, limit=1, index=index, **filters),
                                 search_configuration(bundle, query, offset=1, limit=1, **filters))

    def test_workspace_index_reuse_and_replacement(self):
        bundle = fixture()
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            first = workspace.reviewed_snapshot(name)
            index = workspace.configuration_search_index(first)
            self.assertIsNotNone(index)
            self.assertIs(workspace.configuration_search_index(first), index)
            bundle["nac_configuration"] = {"example": {"status": "list_parsed",
                "profiles": {"new": {"name": "new-value"}}}}
            path.write_text(json.dumps(bundle))
            second = workspace.reviewed_snapshot(name)
            self.assertIsNone(workspace.configuration_search_index(first))
            replacement = workspace.configuration_search_index(second)
            self.assertIsNot(replacement, index)
            self.assertEqual(search_configuration(second, "new-value", index=replacement)["total"], 1)


    def test_index_deduplicates_exact_ordered_bodies_without_losing_observations(self):
        from aruba_central.configuration_search import build_search_index
        bundle = {"results": {}, "nac_configuration": {"example": {"status": "list_parsed",
            "profiles": {str(i): {"name": "needle", "flag": False} for i in range(100)}}}}
        bundle["nac_configuration"]["example"]["profiles"]["reordered"] = {"flag": False, "name": "needle"}
        bundle["nac_configuration"]["example"]["profiles"]["different"] = {"name": "needle", "flag": 0}
        diagnostics = {}
        index = build_search_index(bundle, max_leaves=6, diagnostics=diagnostics)
        self.assertIsNotNone(index)
        self.assertEqual(diagnostics["unique_bodies"], 3)
        self.assertEqual(diagnostics["unique_leaves"], 6)
        self.assertEqual(diagnostics["observed_leaves"], 204)
        self.assertEqual(search_configuration(bundle, "NAC", index=index), search_configuration(bundle, "NAC"))
        self.assertEqual(grouped_search(bundle, "NAC", index=index), grouped_search(bundle, "NAC"))
        self.assertIs(index[0][2], index[1][2])
        self.assertIsNot(index[0][2], index[-2][2])
        rejected = {}
        self.assertIsNone(build_search_index(bundle, max_leaves=5, diagnostics=rejected))
        self.assertEqual(rejected["reason"], "leaf_limit")


    def test_workspace_search_page_cache_fallback_filter_eviction_and_replacement(self):
        from unittest.mock import patch
        bundle = fixture()
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            first = workspace.reviewed_snapshot(name)
            with patch("aruba_central.configuration_search.build_search_index", return_value=None):
                with patch("aruba_central.configuration_search.search_configuration",
                           wraps=search_configuration) as search:
                    original = workspace.configuration_search_page(first, "vlan")
                    self.assertEqual(original, search_configuration(first, "vlan"))
                    self.assertIs(workspace.configuration_search_page(first, "vlan"), original)
                    self.assertEqual(search.call_count, 1)
                    workspace.configuration_search_page(first, "vlan", offset=1)
                    workspace.configuration_search_page(first, "vlan", persona="NAC")
                    self.assertEqual(search.call_count, 3)
                    for i in range(8):
                        workspace.configuration_search_page(first, "unique-query-" + str(i))
                    self.assertEqual(len(workspace._configuration_search_pages), 8)
                    workspace.configuration_search_page(first, "vlan")
                    self.assertEqual(search.call_count, 12)
            grouped = workspace.configuration_search_page(first, "vlan", grouped=True)
            self.assertEqual(grouped, grouped_search(first, "vlan"))
            self.assertIs(workspace.configuration_search_page(first, "vlan", grouped=True), grouped)
            bundle["nac_configuration"] = {"example": {"status": "list_parsed",
                "profiles": {"new": {"name": "new-value"}}}}
            path.write_text(json.dumps(bundle))
            second = workspace.reviewed_snapshot(name)
            self.assertEqual(workspace._configuration_search_pages, {})
            workspace.configuration_search_page(first, "vlan")
            self.assertEqual(workspace._configuration_search_pages, {})
            self.assertEqual(workspace.configuration_search_page(second, "new-value")["total"], 1)
