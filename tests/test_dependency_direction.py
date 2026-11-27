import unittest
from collections import Counter
from aruba_central.impact_view import direction_panel, reference_path


class DependencyDirectionTests(unittest.TestCase):
    def test_direction_links_keep_context_and_distinguish_counts(self):
        html = direction_panel("/test/", "capture.json", "roles", "Office", "ACCESS_SWITCH", "3",
                               Counter(consumers=4, dependencies=2), "consumers", True)
        self.assertIn("direction=consumers", html)
        self.assertIn("direction=dependencies", html)
        self.assertIn("scope=3", html)
        self.assertIn('aria-current="true"', html)
        self.assertIn("Path limit reached", html)
        self.assertIn("not unique devices", html)

    def test_reference_path_displays_actual_direction(self):
        html = reference_path({"edges": [{"source_module": "roles", "source": "Office",
                     "path": ["policy"], "target_module": "policies", "target": "Restricted"}]})
        self.assertLess(html.index("Roles / Office"), html.index("Policies / Restricted"))
        self.assertIn("references policy", html)
