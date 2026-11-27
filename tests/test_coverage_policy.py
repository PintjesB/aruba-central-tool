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
