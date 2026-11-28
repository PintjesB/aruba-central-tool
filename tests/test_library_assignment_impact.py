"""Regression for Library assignment observation changes across functions."""
import unittest
from unittest.mock import patch
from aruba_central.promotion_verification import verify_promotion
from test_configuration_history import snapshot


class LibraryAssignmentImpactTests(unittest.TestCase):
    def test_observed_outside_assignments_are_not_hidden_or_claimed_removed(self):
        before, after = snapshot(), snapshot()
        before["captured_at"] = "2026-01-01T00:00:00+00:00"
        after["captured_at"] = "2026-01-02T00:00:00+00:00"
        candidate = {"id": "test", "action": "reuse_library", "persona": "ACCESS_SWITCH",
                     "module": "layer2-vlan", "identity": "20", "local": {"vlan": 20, "name": "Office"},
                     "sources": [{"scope": "3", "name": "Reference", "kind": "device"}]}
        base = {"profile-type": "layer2-vlan", "profile-instance": "20"}
        before["library"]["assignments"] = {"status": "response_received", "rows": [
            {**base, "device-function": "ACCESS_SWITCH", "scope-id": "4"}]}
        after["library"]["assignments"] = {"status": "response_received", "rows": [
            {**base, "device-function": "ACCESS_SWITCH", "scope-id": "3"},
            {**base, "device-function": "CAMPUS_AP", "scope-id": "99"}]}
        with patch("aruba_central.promotion_verification.promotion_candidates", return_value=[candidate]):
            report = verify_promotion(before, after, "test", "library", confirmed=True)
        self.assertTrue(report["destination_and_assignments_observed"])
        rows = {(r["persona"], r["scope"]): r for r in report["assignment_comparison"]["rows"]}
        self.assertEqual(rows["ACCESS_SWITCH", "3"]["status"], "newly_observed")
        self.assertTrue(rows["ACCESS_SWITCH", "3"]["selected_source_scope"])
        self.assertEqual(rows["ACCESS_SWITCH", "4"]["status"], "no_longer_observed")
        self.assertFalse(rows["CAMPUS_AP", "99"]["selected_source_scope"])
        self.assertEqual(rows["CAMPUS_AP", "99"]["status"], "newly_observed")
        self.assertFalse(report["safe_to_apply"])
