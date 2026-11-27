import copy
import unittest
from unittest.mock import patch

from aruba_central.remediation_review import verify_override, verify_library_migration, comparable
from test_configuration_history import snapshot


class RemediationTests(unittest.TestCase):
    def captures(self):
        before, after = snapshot(), snapshot()
        before["captured_at"] = "2026-01-01T12:00:00+00:00"
        after["captured_at"] = "2026-01-02T12:00:00+00:00"
        return before, after

    def test_override_requires_newer_capture_and_confirmed_absence(self):
        before, after = self.captures()
        candidate = {"id": "candidate", "persona": "ACCESS_SWITCH", "module": "layer2-vlan",
                     "identity": "20", "sources": [{"scope": "4", "name": "Target", "kind": "device"}]}
        target = after["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]
        target["local_view"] = {"status": "list_parsed", "count_confirmed": True, "profiles": {}}
        target["effective_view"]["profiles"]["20"]["@"] = {"aruba-annotation:inherited": True}
        with patch("aruba_central.remediation_review.override_candidates", return_value=[candidate]):
            result = verify_override(before, after, "candidate", confirmed=True)
            self.assertEqual(result["rows"][0]["status"], "observed_goal_met")
            self.assertFalse(result["safe_to_apply"])
            self.assertEqual(result["rows"][0]["rollback_review"]["saved_body"]["name"], "Office")
            target["local_view"]["count_confirmed"] = False
            self.assertEqual(verify_override(before, after, "candidate", confirmed=True)["rows"][0]["status"], "verification_required")
            target["local_view"]["count_confirmed"] = True
            target["effective_view"]["profiles"]["20"]["name"] = "Different"
            self.assertEqual(verify_override(before, after, "candidate", confirmed=True)["rows"][0]["status"], "effective_configuration_changed")
            with self.assertRaises(ValueError):
                verify_override(after, before, "candidate", confirmed=True)

    def test_duplicate_migration_preserves_observed_remaining_references(self):
        before, after = self.captures()
        persona, module = "ACCESS_SWITCH", "sw-port-profiles"
        def view(profiles):
            return {"status": "list_parsed", "count_confirmed": True, "profiles": profiles}
        keep, old = {"profile-name": "keep", "enable": True}, {"profile-name": "old", "enable": True}
        for bundle, profiles in ((before, {"old": old, "keep": keep}), (after, {"keep": keep})):
            bundle["library"]["modules"][module] = view(profiles)
            bundle["results"][persona]["modules"][module] = {"scope_results": [
                {"scope": "4", "effective_view": view(profiles)}]}
        common = {"assignments": [], "references": [], "different_devices": [], "unknown_devices": []}
        group = {"module": module, "identities": ["keep", "old"], "usage": {
            "keep": dict(common), "old": {**common, "matching_other_devices": [{"persona": persona, "scope": "4", "name": "Target"}]}}}
        after["library"]["assignments"] = {"rows": [{"profile-type": module, "profile-instance": "old"}]}
        with patch("aruba_central.remediation_review.duplicate_candidates", return_value=[group]), patch("aruba_central.remediation_review.advanced_analysis", return_value={"references": [{"target_module": module, "target": "old"}]}):
            report = verify_library_migration(before, after, module, "keep", confirmed=True)
        self.assertEqual(report["rows"][0]["status"], "observed_profiles_match_goal")
        self.assertEqual(len(report["remaining_references"]), 1)
        self.assertEqual(len(report["remaining_assignments"]), 1)
        self.assertEqual(report["rollback_review"]["prior_library"]["old"]["body"], old)
        self.assertFalse(report["complete"])

    def test_page_renders_timestamp_guard_and_candidates(self):
        import json
        import tempfile
        from pathlib import Path
        from aruba_central.config_app import Workspace
        before, after = self.captures()
        with tempfile.TemporaryDirectory() as directory:
            for name, data in (("before", before), ("after", after)):
                (Path(directory) / ("config-audit-" + name + ".json")).write_text(json.dumps(data))
            html = Workspace(directory).remediation({"snapshot": "config-audit-after.json",
                                                     "previous": "config-audit-before.json", "confirmed": "yes"})
            self.assertIn("Prior opportunity", html)
            self.assertIn("Verify observed outcome", html)
