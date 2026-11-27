import json
import unittest
from pathlib import Path
from aruba_central.central_tool import ALPHA
from aruba_central.coverage_policy import operation_handling, coverage_action, NAC_CAPTURE, NAC_HANDLING
from aruba_central.nac_service_probe import ENDPOINTS


class CoveragePolicyTests(unittest.TestCase):
    def test_all_documented_nac_operations_classified(self):
        import aruba_central.coverage_policy as policy
        catalog = json.loads(Path(policy.__file__).with_name("central_api_catalog.json").read_text(encoding="utf-8"))
        paths = {r["path"] for r in catalog["get_requests"] if r["group"] == "Central NAC Service" and r["method"] == "GET"}
        self.assertEqual(paths, {ALPHA + "/" + name for name in NAC_CAPTURE.keys() | ENDPOINTS.keys()})
        self.assertEqual(set(ENDPOINTS.values()), set(NAC_HANDLING))
        row = {"path": ALPHA + "/cnac-job", "status": "not_attempted"}
        self.assertEqual(coverage_action(row), {"handling": "Bounded diagnostic available", "read_state": "not_attempted"})
        self.assertIn("user principal", operation_handling(ALPHA + "/cnac-certificate"))
        self.assertIn("Excluded", operation_handling(ALPHA + "/cnac-visitor/export"))
        self.assertIn("Path selector required", operation_handling(ALPHA + "/roles/:name"))

    def test_keyed_gap_reasons_do_not_infer_absence(self):
        from aruba_central.coverage_policy import gap_handling, keyed_gap_context
        row = {"path": ALPHA + "/roles/:name", "attempted": 0}
        self.assertIn("not recorded", gap_handling(row, keyed_gap_context({})))
        bundle = {"keyed_profile_details": {"supported_modules": ["roles"], "candidate_reads_by_module": {}}}
        self.assertIn("absence not established", gap_handling(row, keyed_gap_context(bundle)))
        bundle["keyed_profile_details"]["candidate_reads_by_module"]["roles"] = 3
        self.assertIn("3 individual candidates", gap_handling(row, keyed_gap_context(bundle)))
        self.assertNotIn("3 individual candidates", gap_handling({**row, "attempted": 1}, keyed_gap_context(bundle)))
        from aruba_central.filter_presets import selection
        self.assertEqual(selection("assessment", {"mode": "keyed", "module": "roles"}), {"mode": "keyed", "module": "roles"})
