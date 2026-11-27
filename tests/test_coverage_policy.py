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


    def test_nac_empty_collection_explains_why_keyed_reads_were_not_planned(self):
        from aruba_central.coverage_policy import gap_handling, keyed_gap_context
        row = {"path": ALPHA + "/skins/:skin-id", "attempted": 0}
        empty = {"status": "empty_response", "raw": {}}
        bundle = {"keyed_profile_details": {"supported_modules": ["skins"], "candidate_reads_by_module": {}},
                  "unadapted_profiles": {"skins": {"library": empty,
                      "source_views": [{"committed": empty, "effective": empty}]}}}
        self.assertIn("3 empty collection responses", gap_handling(row, keyed_gap_context(bundle)))
        self.assertIn("absence not established", gap_handling(row, keyed_gap_context(bundle)))
        bundle["unadapted_profiles"]["skins"]["library"] = {"status": "response_received", "raw": {
            "skins": [{"skin-id": "12345678-1234-1234-1234-123456789abc"}]}}
        self.assertIn("1 collection views contain candidate identities", gap_handling(row, keyed_gap_context(bundle)))

    def test_nac_uuid_selectors_are_validated_before_get(self):
        from aruba_central.central_tool import keyed_profile_read
        from unittest.mock import Mock
        for module, key in (("message-providers", "provider-id"), ("skins", "skin-id"), ("overrides", "override-id")):
            client = Mock()
            result = keyed_profile_read(client, module, key, "display-name", {}, None)
            self.assertEqual(result["status"], "invalid_selector")
            client.get.assert_not_called()
            identity = "12345678-1234-1234-1234-123456789abc"
            client.get.return_value = {key: identity}
            result = keyed_profile_read(client, module, key, identity, {}, None)
            client.get.assert_called_once_with(ALPHA + "/" + module + "/" + identity)
            self.assertEqual(result["status"], "identity_observed")
