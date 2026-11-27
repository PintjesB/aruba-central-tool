import json
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from aruba_central.filter_presets import save_preset, read_presets, delete_preset, filters_view
from aruba_central.review_dispositions import snapshot_binding
from test_consolidation import fixture


class SavedFilterTests(unittest.TestCase):
    def test_reusable_and_scope_bound_filters(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            path = Path(directory) / name
            path.write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            binding = snapshot_binding(workspace, name, workspace.reviewed_snapshot(name))
            generic = save_preset(workspace, name, "overrides", {"module": "layer2-vlan"}, "VLAN reviews", binding)
            scoped = save_preset(workspace, name, "overrides", {"device": "3"}, "Specific switch", binding)
            self.assertIsNone(generic["binding"])
            self.assertEqual(scoped["binding"], binding)
            self.assertIn("Saved filters", workspace.overrides({"snapshot": name}))
            self.assertEqual(len(read_presets(directory)), 2)
            self.assertEqual(filters_view(workspace, {"snapshot": name}).count(">Open filter</a>"), 2)
            path.write_text(path.read_text() + " ")
            html = filters_view(Workspace(directory), {"snapshot": name})
            self.assertEqual(html.count(">Open filter</a>"), 1)
            self.assertIn("Different or changed snapshot", html)
            with self.assertRaises(ValueError):
                save_preset(workspace, name, "overrides", {"device": "3"}, "Stale", binding)
            with self.assertRaises(ValueError):
                save_preset(workspace, name, "../bad", {}, "Invalid", binding)
            delete_preset(directory, scoped["id"])
            self.assertEqual(len(read_presets(directory)), 1)
