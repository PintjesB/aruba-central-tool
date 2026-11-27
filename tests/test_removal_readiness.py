import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aruba_central.config_app import Workspace
from aruba_central.override_view import device_override_rows
from test_consolidation import fixture


class RemovalReadinessTests(unittest.TestCase):
    def test_explicit_individual_conflict_blocks_removal_review(self):
        bundle = fixture()
        persona = "ACCESS_SWITCH"
        rows, _ = device_override_rows(bundle, persona)
        target = next(row for row in rows if row["review_candidate"])
        scope, module, identity = target["device"], target["module"], target["identity"]
        bundle["keyed_profile_details"] = {"profiles": {persona: {scope: {module: {identity: {
            "local": {"status": "identity_observed", "profile": {"contradictory": True}}
        }}}}}}
        fallback = {"status": "matching_fallback", "source": None, "chain": [], "blockers": []}
        with patch("aruba_central.override_view.nearest_fallback", side_effect=lambda *a, **k: {**fallback, "blockers": []}):
            rows, _ = device_override_rows(bundle, persona)
        row = next(r for r in rows if (r["device"], r["module"], r["identity"]) == (scope, module, identity))
        self.assertEqual(row["fallback"]["status"], "individual_evidence_conflict")
        self.assertEqual(row["removal"], "verification_required")

    def test_page_separates_comparison_and_removal_assessment(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            html = workspace.overrides({"snapshot": name, "readiness": "verification_required"})
            self.assertIn("Removal readiness", html)
            self.assertIn("Observed fallback", html)
            self.assertIn("Global / reference comparison", html)
            with self.assertRaises(ValueError):
                workspace.overrides({"snapshot": name, "readiness": "invalid"})
