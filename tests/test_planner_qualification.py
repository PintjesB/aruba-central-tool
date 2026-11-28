import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aruba_central.planner_qualification import planner_qualification
from test_consolidation import fixture


class PlannerQualificationTests(unittest.TestCase):
    def test_qualifies_advertised_individual_choices_without_private_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-private-name.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            report = planner_qualification(directory, name)
            self.assertGreater(report["candidate_choices"], 0)
            self.assertTrue(report["all_choices_checked"])
            self.assertTrue(report["review_choice_validation_passed"])
            self.assertFalse(report["safe_to_apply"])
            self.assertNotIn("private-name", json.dumps(report))
            self.assertNotIn("Switch A", json.dumps(report))
            self.assertTrue(any(r["action"] == "remove_override" and r["not_selectable"] for r in report["actions"]))
            limited = planner_qualification(directory, name, max_validations=0)
            self.assertFalse(limited["all_choices_checked"])
            self.assertFalse(limited["review_choice_validation_passed"])
            with patch("aruba_central.planner_qualification.validate_selection", side_effect=ValueError("private-error")):
                rejected = planner_qualification(directory, name)
            self.assertEqual(rejected["rejected_choices"], rejected["candidate_choices"])
            self.assertFalse(rejected["review_choice_validation_passed"])
            self.assertNotIn("private-error", json.dumps(rejected))
