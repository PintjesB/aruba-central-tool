import json
import unittest
from aruba_central.applicability_evidence import applicability_evidence


class ApplicabilityEvidenceTests(unittest.TestCase):
    def test_platform_and_selector_remain_distinct_and_never_qualify_pruning(self):
        bundle = {"results": {
            "ACCESS_SWITCH": {"scopes": [{"id": "private-switch", "kind": "device"}]},
            "CAMPUS_AP": {"scopes": [{"id": "private-ap", "kind": "device"}]}},
            "unadapted_profiles": {"ids": {"source_views": [
                {"scope": "private-switch", "persona": "ALL_DEVICE_FUNCTIONS",
                 "committed": {"status": "response_received", "raw": {}},
                 "effective": {"status": "response_received", "raw": {"ids": [{"name": "private-profile"}]}}},
                {"scope": "private-ap", "persona": "CAMPUS_AP",
                 "effective": {"status": "response_received", "raw": {"metadata": {}},
                               "collection_count_verified": True}}
            ]}}}
        report = applicability_evidence(bundle)
        rows = report["device_scope_observations"]
        switch = next(row for row in rows if row["inventory_platform"] == "non_AP" and row["view"] == "effective")
        self.assertEqual(switch["selector"], "unfiltered")
        self.assertEqual(switch["positive"], 1)
        self.assertFalse(report["deep_scope_suppression_qualified"])
        self.assertNotIn("private", json.dumps(report))
