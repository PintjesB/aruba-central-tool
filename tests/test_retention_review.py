import unittest
from aruba_central.retention_review import retention_comparison
from aruba_central.advanced_review import preferred_duplicate


def usage(identity, saved, assignments, refs, shared, status="response_received", conflicts=0):
    return {"identity": identity, "definition_reference_count": saved, "assignment_count": assignments,
            "reference_count": refs, "shared_devices": [{}] * shared, "assignment_status": status,
            "different_devices": [], "unknown_devices": [{}], "conflicting_reference_count": conflicts}


class RetentionReviewTests(unittest.TestCase):
    def test_explains_actual_criterion_without_summing_counts(self):
        profiles = {"A": usage("A", 2, 1, 2, 1), "B": usage("B", 1, 9, 10, 20)}
        self.assertEqual(preferred_duplicate(profiles), "A")
        result = retention_comparison(profiles, "A")
        self.assertIn("saved referring objects", result["short_reason"])
        self.assertIn("2 vs 1", result["explanation"])
        self.assertEqual(result["rows"][0]["identity"], "A")

    def test_unknown_and_conflicting_evidence_prevent_suggestion(self):
        profiles = {"A": usage("A", 2, 1, 2, 1), "B": usage("B", 1, 9, 10, 20, status="not_collected")}
        self.assertIsNone(preferred_duplicate(profiles))
        result = retention_comparison(profiles, None)
        self.assertEqual(result["rows"][1]["assignments"], "Unknown")
        self.assertIn("unavailable", result["short_reason"])
        profiles["B"]["assignment_status"] = "response_received"
        profiles["B"]["conflicting_reference_count"] = 1
        self.assertIsNone(preferred_duplicate(profiles))
        self.assertIn("Conflicting", retention_comparison(profiles, None)["short_reason"])
