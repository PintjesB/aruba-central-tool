import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aruba_central.config_app import Workspace


class VlanSummaryCacheTests(unittest.TestCase):
    def test_summary_reused_only_for_current_reviewed_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Workspace(directory)
            first = {"results": {}}
            second = {"results": {}}
            workspace._reviewed_snapshot = ("first", first)
            with patch("aruba_central.central_tool.vlan_evidence_summary", side_effect=lambda bundle: {"bundle_id": id(bundle)}) as summary:
                a = workspace.vlan_summary(first)
                self.assertIs(workspace.vlan_summary(first), a)
                self.assertEqual(summary.call_count, 1)
                self.assertNotEqual(workspace.vlan_summary(second), a)
                self.assertIs(workspace.vlan_summary(first), a)
                self.assertEqual(summary.call_count, 2)

    def test_summary_invalidates_when_snapshot_reloaded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config-audit-example.json"
            path.write_text(json.dumps({"schema": 1, "kind": "configuration_audit", "captured_at": "test", "results": {}}))
            workspace = Workspace(directory)
            with patch("aruba_central.config_app.read_audit", side_effect=lambda *args: {"results": {}}), patch("aruba_central.central_tool.refresh_configuration_review", side_effect=lambda bundle: bundle), patch("aruba_central.central_tool.vlan_evidence_summary", side_effect=lambda bundle: {"bundle_id": id(bundle)}) as summary:
                first = workspace.reviewed_snapshot(path.name)
                a = workspace.vlan_summary(first)
                path.write_text(path.read_text() + " ")
                second = workspace.reviewed_snapshot(path.name)
                b = workspace.vlan_summary(second)
                self.assertIsNot(first, second)
                self.assertNotEqual(a, b)
                self.assertEqual(summary.call_count, 2)
