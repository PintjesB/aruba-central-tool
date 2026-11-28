import unittest
from aruba_central.assignment_review import assignment_review
from test_inheritance_review import fixture


class AssignmentDiffOptimizationTests(unittest.TestCase):
    def test_identical_body_skips_recursive_diff_but_typed_difference_is_retained(self):
        from unittest.mock import patch
        from aruba_central.central_tool import field_differences
        entry = fixture(group="Office", global_="Office")
        expected = {"vlan": 20, "name": "Office", "enable": False}
        entry["modules"]["layer2-vlan"]["scope_results"].append({"scope": "5", "effective_view": {
            "status": "list_parsed", "profiles": {"20": {**expected, "@": {"aruba-annotation:object_type": "SHARED"}}}}})
        bundle = {"results": {"ACCESS_SWITCH": entry}, "library": {
            "modules": {"layer2-vlan": {"status": "list_parsed", "profiles": {"20": expected}}},
            "assignments": {"rows": [{"profile-type": "layer2-vlan", "profile-instance": "20",
                                      "device-function": "ACCESS_SWITCH", "scope-id": "5"}]}}}
        with patch("aruba_central.assignment_review.field_differences", wraps=field_differences) as diff:
            row = assignment_review(bundle)["rows"][0]["recipients"][0]
            self.assertEqual(row["status"], "matching_shared")
            self.assertEqual(row["differences"], [])
            diff.assert_not_called()
            entry["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]["profiles"]["20"]["enable"] = 0
            row = assignment_review(bundle)["rows"][0]["recipients"][0]
            self.assertEqual(row["status"], "different_body")
            self.assertEqual(row["differences"][0]["kind"], "type_difference")
            diff.assert_called_once()
