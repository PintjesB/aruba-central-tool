import unittest
from aruba_central.remediation_presentation import observation_comparison, outcome_table


class RemediationPresentationTests(unittest.TestCase):
    def test_confirmed_absence_not_confused_with_unverified_read(self):
        html = observation_comparison("Saved local definition", {"state": "present", "body": {"name": "Office"}},
                                      {"state": "absence_unverified"})
        self.assertIn("Absence not verified", html)
        self.assertNotIn("Absent (count confirmed)", html)
        self.assertIn("Office", html)

    def test_changed_effective_settings_show_typed_diff(self):
        html = observation_comparison("Effective settings", {"state": "present", "body": {"enable": True}},
                                      {"state": "present", "body": {"enable": False}})
        self.assertIn("Values differ", html)
        self.assertIn("True", html)
        self.assertIn("False", html)

    def test_override_table_has_exact_capture_links(self):
        obs = {"state": "present", "body": {"name": "Office"}}
        row = {"scope": "3", "device": "Switch", "status": "verification_required",
               "before_local": obs, "before_effective": obs, "after_local": {"state": "absent"},
               "after_effective": obs}
        html = outcome_table({"workflow": "override_removal",
                              "candidate": {"module": "roles", "persona": "ACCESS_SWITCH", "identity": "Office"},
                              "rows": [row]}, "/test/", "after.json", "before.json")
        self.assertIn("snapshot=before.json", html)
        self.assertIn("snapshot=after.json", html)
        self.assertIn("scope=3", html)
        self.assertIn("Additional evidence required", html)
        self.assertIn("Inheritance not verified", html)
