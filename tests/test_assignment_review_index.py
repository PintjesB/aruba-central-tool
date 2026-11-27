import unittest
from unittest.mock import patch

from aruba_central.assignment_review import assignment_review
from aruba_central.consolidation import scope_memberships


class AssignmentReviewIndexTests(unittest.TestCase):
    def test_filtered_review_indexes_only_matching_persona_and_preserves_recipients(self):
        scopes = [{"id": "1", "kind": "global"},
                  {"id": "2", "kind": "site", "metadata": {"id": 20}},
                  {"id": "3", "kind": "device", "metadata": {"siteId": 20}},
                  {"id": "4", "kind": "device"}]
        profile = {"name": "example", "servers": ["192.0.2.1"]}
        actual = {**profile, "@": {"aruba-annotation:object_type": "SHARED"}}
        module = {"scope_results": [{"scope": "3", "effective_view": {
            "status": "list_parsed", "profiles": {"example": actual}}},
            {"scope": "4", "effective_view": {"status": "list_parsed", "profiles": {}}}]}
        def assignment(scope, persona="ACCESS_SWITCH"):
            return {"profile-type": "dns", "profile-instance": "example",
                    "device-function": persona, "scope-id": scope}
        bundle = {"results": {
            "ACCESS_SWITCH": {"scopes": scopes, "modules": {"dns": module}},
            "CORE_SWITCH": {"scopes": [], "modules": {}}},
            "library": {"modules": {"dns": {"status": "list_parsed", "profiles": {"example": profile}}},
                        "assignments": {"status": "response_received", "rows": [
                            assignment("2"), assignment("1"), assignment("2"), assignment("2", "CORE_SWITCH"), {}]}}}
        with patch("aruba_central.assignment_review.scope_memberships", wraps=scope_memberships) as index:
            result = assignment_review(bundle, "dns", "ACCESS_SWITCH", "example")
            self.assertEqual(index.call_count, 1)
        self.assertEqual(len(result["rows"]), 2)
        site = result["rows"][0]
        self.assertEqual(site["known_count"], 1)
        self.assertEqual(site["unknown_count"], 1)
        self.assertEqual([r["status"] for r in site["recipients"]], ["matching_shared", "membership_unverified"])
        self.assertEqual(len(result["overlaps"]), 1)
        self.assertEqual(result["overlaps"][0]["device"], "3")
        self.assertEqual(result["invalid_rows"], [{}])
        self.assertFalse(result["safe_to_apply"])
        full = assignment_review(bundle)
        self.assertEqual(result["rows"], [r for r in full["rows"] if r["persona"] == "ACCESS_SWITCH"])
