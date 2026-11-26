import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from local_standards import (create_standard, evaluate_standard, exception_candidates,
                             approve_exception, active_exceptions, read_record)
from test_configuration_history import snapshot


class LocalStandardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.base = "config-audit-baseline.json"
        self.current = "config-audit-current.json"
        self.write(self.base, snapshot())
        self.write(self.current, snapshot("Changed"))

    def write(self, name, value):
        (self.directory / name).write_text(json.dumps(value), encoding="utf-8")

    def standard(self):
        return create_standard(self.directory, name="Access switching", snapshot=self.current,
                               baseline_name=self.base, persona="ACCESS_SWITCH", reference="3",
                               module="all", target="2", confirmed=True)

    def test_frozen_version_and_exact_expiring_exception(self):
        standard = self.standard()
        self.assertEqual(standard["modules"], ["layer2-vlan"])
        self.assertEqual(read_record(self.directory, "standard", standard["id"]), standard)
        current, result = evaluate_standard(self.directory, standard, self.current, confirmed=True)
        candidates = exception_candidates(current, standard, result)
        self.assertEqual(len(candidates), 1)
        key = next(iter(candidates))
        expiry = date.today() + timedelta(days=7)
        approval = approve_exception(self.directory, standard["id"], self.current, key,
                                     "Intentional local exception", expiry.isoformat(), confirmed=True)
        self.assertEqual(active_exceptions(self.directory, standard["id"], candidates)[key], [approval])
        self.assertEqual(active_exceptions(self.directory, standard["id"], candidates, expiry + timedelta(days=1)), {})
        self.write(self.current, snapshot("Another change"))
        current, result = evaluate_standard(self.directory, standard, self.current, confirmed=True)
        self.assertFalse(active_exceptions(self.directory, standard["id"], exception_candidates(current, standard, result)))
        with self.assertRaises(ValueError):
            approve_exception(self.directory, standard["id"], self.current, key, "stale", expiry.isoformat(), confirmed=True)

    def test_changed_baseline_rejected_and_unknown_evidence_not_approvable(self):
        standard = self.standard()
        current = snapshot("Changed")
        current["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]["count_confirmed"] = False
        self.write(self.current, current)
        current, result = evaluate_standard(self.directory, standard, self.current, confirmed=True)
        self.assertFalse(exception_candidates(current, standard, result))
        self.write(self.base, snapshot("Baseline changed"))
        with self.assertRaisesRegex(ValueError, "Baseline snapshot changed"):
            evaluate_standard(self.directory, standard, self.current, confirmed=True)

    def test_standard_ui(self):
        from config_app import Workspace
        standard = self.standard()
        html = Workspace(self.directory).standards({"snapshot": self.current, "standard": standard["id"], "confirmed": "yes"})
        self.assertIn("Access switching", html)
        self.assertIn("Approve exact deviation", html)
        self.assertIn("Saved standards", html)
