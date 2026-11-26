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
