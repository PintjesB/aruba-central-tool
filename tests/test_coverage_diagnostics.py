import json
import unittest
from coverage_diagnostics import diagnostics


class DiagnosticsTests(unittest.TestCase):
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
                                            "local": {"status": "identity_observed"}}}}}}}
        report = diagnostics(bundle)
        performance = report["collection_performance"]
        self.assertEqual(performance["individual_reads"], 1)
        self.assertEqual(performance["collection_only"], 1)
        self.assertEqual(performance["detail_strategy"], "adaptive")
        self.assertEqual(len(report["keyed_read_outcomes"]), 1)
        self.assertNotIn("PRIVATE-", json.dumps(report))
