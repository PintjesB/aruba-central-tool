import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from aruba_central.local_standards import (create_standard, evaluate_standard, exception_candidates,
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

    def test_revocation_preserves_history_and_reopens_deviation(self):
        from aruba_central.local_standards import revoke_exception, exception_history
        standard = self.standard()
        current, result = evaluate_standard(self.directory, standard, self.current, confirmed=True)
        candidates = exception_candidates(current, standard, result)
        key = next(iter(candidates))
        expiry = (date.today() + timedelta(days=7)).isoformat()
        approval = approve_exception(self.directory, standard["id"], self.current, key,
                                     "Approved difference", expiry, confirmed=True)
        self.assertEqual(exception_history(self.directory, standard["id"], candidates)[0]["state"], "active")
        self.assertEqual(exception_history(self.directory, standard["id"], {})[0]["state"], "not_observed")
        other = self.standard()
        with self.assertRaises(ValueError):
            revoke_exception(self.directory, other["id"], approval["id"], "Wrong standard")
        revoked = revoke_exception(self.directory, standard["id"], approval["id"], "Policy updated")
        self.assertFalse(active_exceptions(self.directory, standard["id"], candidates))
        history = exception_history(self.directory, standard["id"], candidates)
        self.assertEqual(history[0]["state"], "revoked")
        self.assertEqual(history[0]["revocations"], [revoked])
        self.assertEqual(read_record(self.directory, "exception", approval["id"]), approval)
        from aruba_central.config_app import Workspace
        html = Workspace(self.directory).standards({"snapshot": self.current, "standard": standard["id"], "confirmed": "yes"})
        self.assertIn("Exception history", html)
        self.assertIn("Revoked", html)
        self.assertIn("Policy updated", html)
        self.assertIn("Approve exact deviation", html)

    def test_field_standard_ignores_unselected_changes_and_preserves_approval(self):
        from aruba_central.field_standards import field_key
        base, current = snapshot(), snapshot("Changed")
        for data in (base, current):
            for row in data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"]:
                for key in ("local_view", "effective_view"):
                    row[key]["profiles"]["20"]["enable"] = True
        self.write(self.base, base)
        self.write(self.current, current)
        rule = {"module": "layer2-vlan", "identity": "20", "path": ["name"]}
        standard = create_standard(self.directory, name="VLAN names", snapshot=self.current,
                                   baseline_name=self.base, persona="ACCESS_SWITCH", reference="3",
                                   module="all", target="2", confirmed=True,
                                   field_selection=json.dumps([field_key(rule)]))
        self.assertEqual(standard["field_rules"][0]["path"], ["name"])
        bundle, result = evaluate_standard(self.directory, standard, self.current, confirmed=True)
        candidates = exception_candidates(bundle, standard, result)
        self.assertEqual(len(candidates), 1)
        key = next(iter(candidates))
        expiry = (date.today() + timedelta(days=7)).isoformat()
        approve_exception(self.directory, standard["id"], self.current, key,
                          "Intentional name", expiry, confirmed=True)
        current["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]["profiles"]["20"]["enable"] = False
        self.write(self.current, current)
        bundle, result = evaluate_standard(self.directory, standard, self.current, confirmed=True)
        self.assertEqual(set(exception_candidates(bundle, standard, result)), {key})
        from aruba_central.local_standards import apply_approvals
        candidates = exception_candidates(bundle, standard, result)
        apply_approvals(result, candidates, active_exceptions(self.directory, standard["id"], candidates))
        target = next(r for r in result["findings"] if r["scope"] == "4")
        self.assertEqual(target["status"], "approved_exceptions")

    def test_whole_profile_standard_independent_field_approvals(self):
        from aruba_central.local_standards import apply_approvals
        base, current = snapshot(), snapshot("Changed")
        for data in (base, current):
            for row in data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"]:
                for key in ("local_view", "effective_view"):
                    row[key]["profiles"]["20"]["enable"] = True
        current["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]["profiles"]["20"]["enable"] = False
        self.write(self.base, base)
        self.write(self.current, current)
        standard = self.standard()
        bundle, result = evaluate_standard(self.directory, standard, self.current, confirmed=True)
        candidates = exception_candidates(bundle, standard, result)
        self.assertEqual(len(candidates), 2)
        key = next(k for k, c in candidates.items() if c["field_path"] == ["name"])
        approval = approve_exception(self.directory, standard["id"], self.current, key, "Name only",
                                     (date.today() + timedelta(days=7)).isoformat(), confirmed=True)
        apply_approvals(result, candidates, {key: [approval]})
        target = next(r for r in result["findings"] if r["scope"] == "4")
        self.assertEqual(target["status"], "differences_observed")
        self.assertEqual(target["unapproved_deviation_count"], 1)

    def test_template_freezes_observed_module_set(self):
        standard = create_standard(self.directory, name="Switch access", snapshot=self.current,
                                   baseline_name=self.base, persona="ACCESS_SWITCH", reference="3",
                                   module="template:switching", target="2", confirmed=True)
        self.assertEqual(standard["modules"], ["layer2-vlan"])
        current = snapshot("Changed")
        entry = current["results"]["ACCESS_SWITCH"]
        entry["modules"]["sw-port-profiles"] = {"scope_results": []}
        self.write(self.current, current)
        _, result = evaluate_standard(self.directory, standard, self.current, confirmed=True)
        self.assertEqual(result["modules"], ["layer2-vlan"])
        with self.assertRaises(ValueError):
            create_standard(self.directory, name="No services observed", snapshot=self.current,
                            baseline_name=self.base, persona="ACCESS_SWITCH", reference="3",
                            module="template:services", target="2", confirmed=True)

    def test_standard_ui(self):
        from aruba_central.config_app import Workspace
        standard = self.standard()
        html = Workspace(self.directory).standards({"snapshot": self.current, "standard": standard["id"], "confirmed": "yes"})
        self.assertIn("Access switching", html)
        self.assertIn("Approve exact deviation", html)
        self.assertIn("Saved standards", html)
