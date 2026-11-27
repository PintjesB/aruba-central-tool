import unittest
from aruba_central.library_usage_presentation import visibility_filter, device_visibility, usage_summary


class LibraryUsagePresentationTests(unittest.TestCase):
    def test_visibility_filters_are_profile_counts_and_can_overlap(self):
        device = {"name": "Switch", "persona": "ACCESS_SWITCH", "scope": "3"}
        usage = {"A": {"shared_devices": [device], "unknown_devices": [device]},
                 "B": {"different_devices": [device]}, "C": {"absent_devices": [device]}}
        self.assertEqual(visibility_filter(usage, "all"), {"A", "B", "C"})
        self.assertEqual(visibility_filter(usage, "unknown_devices"), {"A"})
        self.assertEqual(visibility_filter(usage, "different_devices"), {"B"})
        self.assertEqual(visibility_filter(usage, "absent_devices"), {"C"})
        with self.assertRaises(ValueError):
            visibility_filter(usage, "unused")
        html = usage_summary("/test/", "capture.json", "roles", usage, "unknown_devices")
        self.assertIn("Visibility unverified (1)", html)
        self.assertIn("visibility=unknown_devices", html)
        self.assertIn("Categories can overlap", html)

    def test_all_observed_states_link_to_exact_scope(self):
        device = {"name": "Switch", "persona": "ACCESS_SWITCH", "scope": "3"}
        usage = {key: [device] for key in ("shared_devices", "matching_other_devices", "different_devices", "unknown_devices", "absent_devices")}
        html = device_visibility(usage, root="/test/", snapshot="capture.json", module="roles")
        for label in ("Matching shared definition", "Matching settings, source not verified",
                      "Same name, different settings", "Visibility unverified", "Profile absent (count confirmed)"):
            self.assertIn(label, html)
        self.assertIn("scope=3", html)
        self.assertIn("device=3", html)
        self.assertIn("module=roles", html)


    def test_usage_summary_does_not_embed_all_device_rows(self):
        from aruba_central.library_usage_presentation import visibility_detail_link
        usage = {"identity": "Office", "shared_devices": [{"name": "PrivateSwitch"}] * 100}
        html = visibility_detail_link(usage, root="/test/", snapshot="capture.json", module="roles")
        self.assertIn("profile=Office", html)
        self.assertIn("100", html)
        self.assertNotIn("PrivateSwitch", html)


    def test_exact_profile_drilldown_avoids_collection_wide_comparison(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        from aruba_central.config_app import Workspace
        from aruba_central.advanced_review import library_usage
        from test_consolidation import fixture
        bundle = fixture()
        bundle["library"]["modules"]["roles"] = {"status": "list_parsed", "profiles": {"A": {"name": "A"}, "B": {"name": "B"}}}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            reviewed = workspace.reviewed_snapshot(name)
            workspace.advanced_snapshot(reviewed)
            with patch("aruba_central.config_app.library_profile_comparison", side_effect=AssertionError("Unneeded full comparison")), patch("aruba_central.advanced_review.library_usage", wraps=library_usage) as use:
                html = workspace.library({"snapshot": name, "module": "roles", "profile": "A"})
                self.assertIn("A · Device visibility", html)
                self.assertEqual(use.call_count, 1)
                self.assertEqual(use.call_args.args[2], ["A"])
