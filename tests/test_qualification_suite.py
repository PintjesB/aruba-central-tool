import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aruba_central.qualification_suite import qualification_suite
from test_consolidation import fixture


class QualificationSuiteTests(unittest.TestCase):
    def test_same_capture_is_selected_once_and_only_aggregate_reports_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-private-name.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            with patch("aruba_central.qualification_suite.benchmark", return_value={"count": 1}) as perf, \
                 patch("aruba_central.qualification_suite.browser_benchmark", return_value={"count": 2}) as browser:
                report = qualification_suite(directory, repeat=2, executable="browser")
                perf.assert_called_once_with(directory, name, repeat=2, ui=True)
                browser.assert_called_once_with(directory, name, repeat=2, executable="browser")
            self.assertTrue(report["same_capture_verified"])
            self.assertEqual(report["central_api_requests"], 0)
            self.assertEqual(report["performance"], {"count": 1})
            self.assertEqual(report["browser"], {"count": 2})
            self.assertNotIn("private-name", json.dumps(report))
            self.assertFalse(report["qualification"]["safe_to_apply"])
            self.assertTrue(report["planner"]["review_choice_validation_passed"])
            self.assertFalse(report["planner"]["safe_to_apply"])
            self.assertEqual(report["engineering"]["central_api_requests"],0)
            self.assertFalse(report["engineering"]["safe_to_apply"])
            self.assertIn("conditional_nac_observations",report["engineering"]["counts"]["engineering"])
            for key in ("reference_identity_patterns","named_reference_gaps","named_reference_field_gaps",
                        "reference_absence_patterns","role_vlan_name_evidence","reference_conflict_patterns",
                        "policy_predicate_patterns"):
                self.assertIn(key,report["engineering"])

    def test_changed_capture_aborts_before_remaining_stages(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            def change(*args, **kwargs):
                path.write_text(path.read_text() + " ")
                return {"count": 1}
            with patch("aruba_central.qualification_suite.benchmark", side_effect=change), \
                 patch("aruba_central.qualification_suite.browser_benchmark") as browser:
                with self.assertRaises(ValueError):
                    qualification_suite(directory)
                browser.assert_not_called()


    def test_optional_history_uses_exact_pair_and_exports_only_aggregate_evidence(self):
        from test_configuration_history import snapshot
        with tempfile.TemporaryDirectory() as directory:
            before,after="config-audit-private-before.json","config-audit-private-after.json"
            (Path(directory)/before).write_text(json.dumps(snapshot()))
            (Path(directory)/after).write_text(json.dumps(snapshot("Changed")))
            with patch("aruba_central.qualification_suite.benchmark",return_value={}), \
                 patch("aruba_central.qualification_suite.browser_benchmark",return_value={}) as browser:
                with self.assertRaises(ValueError):
                    qualification_suite(directory,after,previous=before)
                result=qualification_suite(directory,after,previous=before,confirm_history_same_tenant=True,repeat=1,include_browser=True)
                browser.assert_called_once_with(directory,after,repeat=1,executable=None,previous=before)
            self.assertTrue(result["same_capture_pair_verified"])
            self.assertEqual(result["history"]["counts"]["structured_records"],3)
            self.assertIn("warm_comparison",result["history"]["stages"])
            payload=json.dumps(result)
            self.assertNotIn("private-before",payload)
            self.assertNotIn("private-after",payload)
            self.assertNotIn("Changed",payload)
            self.assertNotIn("Office",payload)

    def test_browser_install_error_is_actionable_and_private(self):
        from aruba_central.qualification_suite import QualificationStageError, qualification_stage
        for error, hint in (
            (RuntimeError("BrowserType.launch: Executable doesn't exist at private-path"), "playwright install chromium"),
            (ImportError("private-module"), "optional Playwright dependency"),
            (RuntimeError("private-tenant-token"), "browser benchmark execution"),
        ):
            with self.assertRaises(QualificationStageError) as raised:
                with qualification_stage("browser benchmark"):
                    raise error
            self.assertIn("browser benchmark", str(raised.exception))
            self.assertIn(hint, str(raised.exception))
            self.assertNotIn("private", str(raised.exception))
            self.assertIs(raised.exception.__cause__, error)

    def test_actual_browser_stage_failure_is_not_reported_as_capture_failure(self):
        from aruba_central.qualification_suite import QualificationStageError
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-private-name.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            with patch("aruba_central.qualification_suite.benchmark", return_value={}), \
                 patch("aruba_central.qualification_suite.browser_benchmark", side_effect=RuntimeError("BrowserType.launch: Executable doesn't exist at private-path")):
                with self.assertRaisesRegex(QualificationStageError, "browser benchmark.*playwright install chromium") as raised:
                    qualification_suite(directory, repeat=1, include_browser=True)
            self.assertNotIn("private", str(raised.exception))

    def test_standard_suite_never_starts_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            with patch("aruba_central.qualification_suite.benchmark", return_value={}), \
                 patch("aruba_central.qualification_suite.browser_benchmark", side_effect=ImportError("Playwright absent")) as browser:
                report = qualification_suite(directory, repeat=1)
            browser.assert_not_called()
            self.assertIsNone(report["browser"])
            self.assertEqual(report["browser_qualification"], "not_requested")
            self.assertTrue(report["planner"]["review_choice_validation_passed"])
            self.assertIn("policy_predicate_patterns", report["engineering"])
