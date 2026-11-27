import json
import unittest
from aruba_central.coverage_diagnostics import diagnostics


class DiagnosticsTests(unittest.TestCase):
    def test_compare_coverage_matches_exact_selectors_without_exporting_values(self):
        from copy import deepcopy
        from aruba_central.coverage_diagnostics import compare_coverage
        old = {"schema": 1, "kind": "configuration_audit", "region": "PRIVATE-REGION",
               "collection_strategy": "deep",
               "results": {"ACCESS_SWITCH": {"modules": {"dns": {"scope_results": [
                   {"scope": "PRIVATE-1", "local_view": {"status": "list_parsed", "count_confirmed": True},
                    "effective_view": {"status": "list_parsed", "count_confirmed": True}},
                   {"scope": "PRIVATE-2", "local_view": {"status": "list_parsed"},
                    "effective_view": {"status": "list_parsed"}}
               ]}}}},
               "keyed_profile_details": {"profiles": {"ACCESS_SWITCH": {"PRIVATE-1": {
                   "dns": {"PRIVATE-NAME": {"effective": {"status": "identity_observed"}}}
               }}}}}
        new = deepcopy(old)
        scopes = new["results"]["ACCESS_SWITCH"]["modules"]["dns"]["scope_results"]
        scopes[0]["effective_view"] = {"status": "read_failed"}
        scopes[1]["scope"] = "PRIVATE-3"
        new["keyed_profile_details"]["profiles"]["ACCESS_SWITCH"]["PRIVATE-1"]["dns"]["PRIVATE-NAME"]["effective"] = {
            "status": "collection_only_sampled"}
        report = compare_coverage(old, new)
        structured = report["selectors"]["structured"]
        self.assertEqual(structured["matched"], 2)
        self.assertEqual(structured["previous_only"], 2)
        self.assertEqual(structured["current_only"], 2)
        self.assertEqual(structured["previous_positive_now_missing"], 2)
        self.assertEqual(structured["previous_positive_now_unqualified"], 1)
        self.assertEqual(structured["previous_count_confirmed_now_unqualified"], 1)
        self.assertEqual(report["selectors"]["keyed"]["direct_to_sampled"], 1)
        self.assertTrue(report["same_region"])
        self.assertFalse(report["complete"])
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_supplemental_exact_reuse_is_counted_separately(self):
        bundle = {"schema": 1, "kind": "configuration_audit", "unadapted_profiles": {
            "dns": {"library": {"reused_exact_collection": True},
                    "source_views": [{"committed": {"reused_exact_collection": True},
                                      "effective": {"raw": {"PRIVATE": True}}}]}}}
        report = diagnostics(bundle)
        self.assertEqual(report["collection_performance"]["supplemental_exact_reuse"],
                         [{"module": "dns", "scope_views": 1, "library_view": True}])
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_supplemental_footprint_counts_scope_kind_and_selector_without_leaking_values(self):
        bundle = {"schema": 1, "kind": "configuration_audit",
                  "results": {"ACCESS_SWITCH": {"scopes": [{"id": "PRIVATE-A", "kind": "device"},
                                                         {"id": "PRIVATE-B", "kind": "group"}]}},
                  "unadapted_profiles": {"dns": {"source_views": [
                      {"scope": "PRIVATE-A", "persona": "ALL_DEVICE_FUNCTIONS",
                       "committed": {"status": "empty_response", "raw": {}},
                       "effective": {"status": "response_received", "raw": {"dns": [{"name": "PRIVATE-PROFILE"}]},
                                     "reused_exact_collection": True}},
                      {"scope": "PRIVATE-B", "persona": "ACCESS_SWITCH",
                       "committed": {"status": "request_rejected", "http_error": 400},
                       "effective": {"status": "response_received", "raw": {"dns": [], "metadata": {"total": 0}},
                                     "collection_count_verified": True}},
                      {"scope": "PRIVATE-C", "persona": "PRIVATE-FUNCTION",
                       "committed": {"status": "partial_response", "raw": {"dns": [{"name": "PRIVATE-PROFILE"}]},
                                     "pagination_status": "request_failed", "raw_pages": [{}]},
                       "effective": {"status": "response_received", "raw": {"metadata": {"count": 0}}}}
                  ]}}}
        rows = diagnostics(bundle)["supplemental_survey_footprint"]
        by_kind = {r["scope_kind"]: r for r in rows}
        self.assertEqual(by_kind["device"]["empty_object"], 1)
        self.assertEqual(by_kind["device"]["positive_uncounted"], 1)
        self.assertEqual(by_kind["device"]["reused_views"], 1)
        self.assertEqual(by_kind["device"]["selector"], "unfiltered")
        self.assertEqual(by_kind["group"]["http_400"], 1)
        self.assertEqual(by_kind["group"]["counted_empty"], 1)
        self.assertEqual(by_kind["unknown"]["pagination_failures"], 1)
        self.assertEqual(by_kind["unknown"]["metadata_or_empty_collection"], 1)
        self.assertEqual(sum(r["views"] for r in rows), 6)
        self.assertNotIn("PRIVATE", json.dumps(rows))

    def test_no_customer_values_in_diagnostics(self):
        private = "CUSTOMER-PRIVATE-IDENTITY"
        bundle = {
            "schema": 1, "kind": "configuration_audit", "region": private,
            "inventory": [{"serial": private}],
            "results": {"ACCESS_SWITCH": {"modules": {"layer2-vlan": {"scope_results": [{
                "scope": private, "scope_kind": "device",
                "local_view": {"status": "list_parsed", "count_confirmed": True,
                               "profiles": {private: {"name": private}}},
                "effective_view": {"status": private, "raw": {private: private}},
            }]}}}},
            "api_read_coverage": {"operations": [
                {"path": "/network-config/v1alpha1/layer2-vlan", "attempted": 1, "received": 1,
                 "outcomes": {"response_received": 1, private: 2}},
                {"path": "/" + private, "attempted": 1},
            ]},
            "unadapted_profiles": {private: {"scope_read_outcomes": {private: 1}}},
            "nac_registrations": {"status": "count_confirmed", "rows": [{"id": private}],
                                  "count_confirmed": True},
        }
        result = diagnostics(bundle)
        self.assertNotIn(private, json.dumps(result))
        self.assertEqual(len(result["scoped_views"]), 2)
        self.assertEqual(result["nac"]["mac-registrations"]["records"], 1)
        self.assertEqual(result["nac"]["mac-registrations"]["status"], "count_confirmed")
        self.assertEqual(len(result["attempted_operations"]), 1)
        self.assertFalse(result["complete"])


    def test_keyed_identity_shapes_without_leaking_identity(self):
        bundle = {"schema": 1, "kind": "configuration_audit",
                  "keyed_profile_details": {"profiles": {"ACCESS_SWITCH": {"PRIVATE-SCOPE": {
                      "ethernet-interfaces": {"1/1/24": {"local": {"status": "invalid_selector"},
                                                       "effective": {"status": "invalid_selector"}}},
                      "dns": {"PRIVATE-NAME": {"local": {"status": "schema_unresolved"}}}
                  }}}}, "unadapted_profiles": {"dns": {"scope_read_outcomes": {"empty_response": 2}}}}
        report = diagnostics(bundle)
        self.assertEqual(report["invalid_selector_shapes"],
                         [{"module": "ethernet-interfaces", "shape": "numeric_port", "reads": 2}])
        self.assertEqual(len(report["keyed_read_outcomes"]), 3)
        self.assertEqual(report["raw_scope_outcomes"], [{"module": "dns", "status": "empty_response", "views": 2}])
        self.assertEqual(report["nac"]["mac-registrations"]["status"], "not_collected")
        for value in ("PRIVATE-SCOPE", "PRIVATE-NAME", "1/1/24"):
            self.assertNotIn(value, json.dumps(report))


    def test_operation_gap_inventory_reconciles_catalog(self):
        bundle = {"schema": 1, "kind": "configuration_audit", "api_read_coverage": {
            "operations": [{"path": "/network-config/v1alpha1/layer2-vlan",
                            "attempted": 1, "received": 1}]}}
        report = diagnostics(bundle)
        gaps = report["unattempted_operations"]
        groups = report["operation_groups"].values()
        self.assertEqual(len(gaps) + len(report["attempted_operations"]), report["catalog_operations"])
        self.assertEqual(sum(g["documented"] for g in groups), report["catalog_operations"])
        self.assertEqual(sum(g["not_attempted"] for g in groups), len(gaps))
        self.assertEqual(sum(g["attempted"] for g in groups), 1)
        self.assertTrue(any(row["selector_required"] for row in gaps))
        self.assertNotIn("/network-config/v1alpha1/layer2-vlan", {row["path"] for row in gaps})


    def test_raw_shapes_distinguish_metadata_from_profile_records(self):
        private = "PRIVATE-VALUE"
        bundle = {"schema": 1, "kind": "configuration_audit", "unadapted_profiles": {
            "lldp": {"library": {"raw": {"metadata": {"count": 2}}},
                     "source_views": [{"committed": {"raw": {"private-envelope": [
                         {"name": private}, {"name": "another"}, {"unrecognized": private}]}},
                                       "effective": {"raw": {"private-envelope": []}}}]}}}
        report = diagnostics(bundle)
        shapes = {r["shape"]: r for r in report["raw_profile_shapes"]}
        self.assertEqual(shapes["record_list"]["records"], 3)
        self.assertEqual(shapes["record_list"]["records_with_documented_key"], 2)
        self.assertEqual(shapes["metadata_only"]["records"], 0)
        self.assertEqual(shapes["empty_list"]["records"], 0)
        self.assertNotIn(private, json.dumps(report))
        self.assertNotIn("private-envelope", json.dumps(report))


    def test_specialized_read_outcomes_are_anonymous(self):
        private = "PRIVATE-RESOURCE-IDENTITY"
        bundle = {"schema": 1, "kind": "configuration_audit",
                  "scope_hierarchy_evidence": {"outcomes": {"response_received": 2, private: 1},
                                               "records": [{"scope": private}]},
                  "keyed_assignment_details": {"outcomes": {"identity_observed": 3},
                                               "records": [{"selector": private}]},
                  "nac_portal_assets": {"status": "list_parsed", "count_confirmed": True,
                                        "images": [{"imageID": private}], "details": {private: {}}}}
        report = diagnostics(bundle)
        self.assertEqual(report["specialized_reads"]["hierarchy"]["outcomes"], {"response_received": 2, "other": 1})
        self.assertEqual(report["specialized_reads"]["assignments"]["outcomes"], {"identity_observed": 3})
        self.assertEqual(report["specialized_reads"]["portal-assets"]["images"], 1)
        self.assertTrue(report["specialized_reads"]["portal-assets"]["count_confirmed"])
        self.assertNotIn(private, json.dumps(report))


    def test_pagination_and_keyed_comparison_counts_are_anonymous(self):
        private = "PRIVATE-SCOPE-AND-VALUE"
        bundle = {"schema": 1, "kind": "configuration_audit",
                  "unadapted_profiles": {"dns": {"library": {
                      "pagination_status": "schema_changed",
                      "raw_pages": [{"profiles": [{"name": private}]}, {}]}}},
                  "library": {"assignments": {"scope_reads": {"ACCESS_SWITCH": {
                      private: {"pagination_status": private, "raw_pages": []}}}}},
                  "keyed_profile_details": {"profiles": {"ACCESS_SWITCH": {private: {
                      "dns": {private: {"effective": {"status": "identity_observed",
                                  "differences": [{"kind": "missing_local", "path": private, "value": private}]}}}
                  }}}}}
        report = diagnostics(bundle)
        rows = {row["source"]: row for row in report["pagination_evidence"]}
        self.assertEqual(rows["raw_library"]["reason"], "schema_changed")
        self.assertEqual(rows["raw_library"]["pages"], 2)
        self.assertEqual(rows["raw_library"]["last_page_empty_object"], 1)
        self.assertEqual(rows["scoped"]["reason"], "other")
        comparisons = {row["comparison"]: row["reads"] for row in report["keyed_comparison_counts"]}
        self.assertEqual(comparisons, {"additional_fields_in_detail": 1, "different": 1})
        self.assertNotIn(private, json.dumps(report))


    def test_adaptive_collection_only_is_not_counted_as_an_individual_read(self):
        bundle = {"schema": 1, "kind": "configuration_audit", "collection_strategy": "deep",
                  "keyed_profile_details": {"detail_strategy": "adaptive",
                    "profiles": {"ACCESS_SWITCH": {"PRIVATE-SCOPE": {"dns": {
                        "PRIVATE-PROFILE": {"effective": {"status": "collection_only_sampled"},
                                            "local": {"status": "identity_observed"}}}}}}}}
        report = diagnostics(bundle)
        performance = report["collection_performance"]
        self.assertEqual(performance["individual_reads"], 1)
        self.assertEqual(performance["collection_only"], 1)
        self.assertEqual(performance["detail_strategy"], "adaptive")
        self.assertEqual(len(report["keyed_read_outcomes"]), 1)
        self.assertNotIn("PRIVATE-", json.dumps(report))


    def test_specialized_shapes_exclude_unrecognized_keys_and_customer_values(self):
        private = "PRIVATE-CUSTOMER"
        bundle = {"schema": 1, "kind": "configuration_audit",
                  "keyed_assignment_details": {"records": [
                      {"raw": {"items": [{"scope-id": private, private: private}]}}]},
                  "nac_portal_assets": {"list_read": {"raw": {"items": [{"imageId": private}]}}}}
        result = diagnostics(bundle)["specialized_reads"]
        assignment = result["assignments"]["response_shapes"][0]["shape"]
        self.assertEqual(assignment["record_fields"]["items"], {"scope-id": 1})
        assets = result["portal-assets"]["response_shapes"][0]["shape"]
        self.assertEqual(assets["record_fields"]["items"], {"imageId": 1})
        self.assertNotIn(private, json.dumps(result))


    def test_assignment_rejections_and_legacy_matches_export_without_values(self):
        private = "PRIVATE-IDENTITY"
        selector = {"scope-id": "12", "device-function": "ACCESS_SWITCH",
                    "profile-type": "dns", "profile-instance": private}
        bundle = {"schema": 1, "kind": "configuration_audit",
                  "library": {"assignments": {"rows": [selector, {**selector, "profile-instance": private + "/invalid"}]}},
                  "keyed_assignment_details": {"records": [
                      {"selector": selector, "raw": {"scope-id": 12, "persona": "ACCESS_SWITCH",
                                                     "resource": "dns/" + private}},
                      {"selector": selector, "raw": {"scope-id": 12, "persona": "ACCESS_SWITCH",
                                                     "resource": "dns"}}]},
                  "scope_hierarchy_evidence": {"records": [{"scope": private, "kind": "group",
                     "status": "request_rejected", "http_error": 400}]}}
        result = diagnostics(bundle)["specialized_reads"]
        self.assertEqual(result["assignments"]["selector_rejection_reasons"], {"unqualified_slash_instance": 1})
        self.assertEqual(result["assignments"]["retained_legacy_identity_matches"],
                         {"identity_observed": 1, "scope_only_observed": 1})
        self.assertEqual(result["hierarchy"]["scope_outcomes"], [
            {"kind": "group", "version": "v1", "status": "request_rejected", "http_error": 400, "reads": 1}])
        self.assertNotIn(private, json.dumps(result))


    def test_diagnostics_output_file_is_exclusive_and_does_not_print_json(self):
        import contextlib
        import io
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from aruba_central.coverage_diagnostics import main
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "config-audit-test.json"
            snapshot.write_text(json.dumps({"schema": 1, "kind": "configuration_audit"}), encoding="utf-8")
            output = root / "diagnostics.json"
            args = ["coverage_diagnostics.py", "--directory", tmp, "--output", str(output)]
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()) as stdout:
                main()
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["kind"],
                             "anonymous_collection_diagnostics")
            self.assertNotIn("attempted_operations", stdout.getvalue())
            before = output.read_bytes()
            with patch("sys.argv", args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main()
            self.assertEqual(output.read_bytes(), before)

    def test_http_transport_diagnostics_are_bounded_and_anonymous(self):
        bundle = {"schema": 1, "kind": "configuration_audit",
                  "http_get_transport": {"http_get_attempts": 25, "http_get_retries": 5,
                                         "http_get_429": 1, "http_get_5xx": 4,
                                         "custom_500_retry_sequences_suppressed": 2,
                                         "PRIVATE": "PRIVATE"}}
        report = diagnostics(bundle)["collection_performance"]["http_get_transport"]
        self.assertEqual(report, {"http_get_attempts": 25, "http_get_retries": 5,
                                 "http_get_429": 1, "http_get_5xx": 4,
                                 "custom_500_retry_sequences_suppressed": 2, "http_get_transient_errors": 0})
        del bundle["http_get_transport"]
        self.assertIsNone(diagnostics(bundle)["collection_performance"]["http_get_transport"])
