import json
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

from aruba_central.config_app import Workspace
from test_consolidation import fixture


class PlanReader(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("class") == "choose":
            self.rows.append(("disabled" in attrs, json.loads(attrs["data-plan"])))


class AdvisorPayloadTests(unittest.TestCase):
    def test_selectable_rows_keep_gate_inputs_and_full_evidence_is_loaded_at_export(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            workspace = Workspace(directory)
            bundle = workspace.reviewed_snapshot(name)
            findings = {f["id"]: f for f in workspace.consolidation_snapshot(bundle)}
            parser = PlanReader()
            parser.feed(workspace.advisor({"snapshot": name}))
            self.assertTrue(any(blocked for blocked, _ in parser.rows))
            self.assertTrue(any(not blocked for blocked, _ in parser.rows))
            self.assertEqual(set(p["id"] for _, p in parser.rows), set(findings))
            for blocked, plan in parser.rows:
                original = findings[plan["id"]]
                if blocked:
                    self.assertEqual(set(plan), {"id", "identity", "module", "persona", "action", "sources", "observed_counts"})
                    self.assertEqual(plan["sources"], [{"name": s["name"]} for s in original["sources"]])
                    self.assertEqual(plan["observed_counts"], {k: len(v) for k, v in original["observed_devices"].items()})
                else:
                    self.assertNotIn("local", plan)
                    self.assertNotIn("consumers", plan["dependency_review"])
                    from aruba_central.review_dispositions import snapshot_binding
                    from aruba_central.workspace_views import advisor_export_evidence
                    full=advisor_export_evidence(workspace,{"snapshot":name,"group":original["id"],"binding":snapshot_binding(workspace,name,bundle)})
                    self.assertEqual(full["local"],original["local"])
                    self.assertIn("consumers",full["dependency_review"])
                    self.assertEqual(plan["placement_options"], original["placement_options"])
                    self.assertIn("dependency_review", plan)
