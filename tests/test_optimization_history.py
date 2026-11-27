import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.central_tool import refresh_configuration_review
from aruba_central.config_app import Workspace
from aruba_central.optimization_history import compare_workload
from test_configuration_history import snapshot


class OptimizationHistoryTests(unittest.TestCase):
    def test_workload_comparison_flags_coverage_changes_and_identity(self):
        before, after = snapshot(), snapshot("Changed")
        after["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]["count_confirmed"] = False
        result = compare_workload(refresh_configuration_review(before), refresh_configuration_review(after))
        self.assertFalse(result["same_structured_read_states"])
        self.assertTrue(result["same_device_selectors"])
        self.assertFalse(result["verified_removals"])
        with tempfile.TemporaryDirectory() as directory:
            a, b = "config-audit-before.json", "config-audit-after.json"
            (Path(directory) / a).write_text(json.dumps(before))
            (Path(directory) / b).write_text(json.dumps(after))
            html = Workspace(directory).assessment({"snapshot": b, "mode": "history", "previous": a, "confirmed": "yes"})
            self.assertIn("Observed workload change", html)
            self.assertIn("Review exact configuration drift", html)
        after["inventory"] = [{"inventory": {"serial": "Other"}}]
        with self.assertRaises(ValueError):
            compare_workload(refresh_configuration_review(before), refresh_configuration_review(after))

    def test_cached_current_workload_preserves_comparison(self):
        from unittest.mock import patch
        from aruba_central.consolidation import profile_recommendations
        from aruba_central.advanced_review import advanced_analysis
        before = refresh_configuration_review(snapshot())
        after = refresh_configuration_review(snapshot("Changed"))
        expected = compare_workload(before, after)
        findings = profile_recommendations(after)
        engineering = advanced_analysis(after)
        with patch("aruba_central.optimization_history.profile_recommendations", wraps=profile_recommendations) as recommendations, patch("aruba_central.optimization_history.advanced_analysis", wraps=advanced_analysis) as analysis:
            actual = compare_workload(before, after, current_findings=findings, current_engineering=engineering)
            self.assertEqual(actual, expected)
            recommendations.assert_called_once_with(before)
            analysis.assert_called_once_with(before)
