import unittest
from aruba_central.workspace_views import ADVISOR_JS


class PreviewDecisionTests(unittest.TestCase):
    def test_preview_renders_readable_blockers_and_transition_from_observed_data(self):
        # These labels are rendered with textContent, never HTML from captures.
        for label in ("Resolve export blockers", "Review export available",
                      "Captured configuration", "Proposed configuration source",
                      "Not a simulated or verified outcome", "Observed recipient pairs"):
            self.assertIn(label, ADVISOR_JS)
        self.assertIn("review.missing_destinations.length", ADVISOR_JS)
        self.assertIn("review.collisions.length", ADVISOR_JS)
        self.assertIn("review.dependency_order.blocked.length", ADVISOR_JS)
