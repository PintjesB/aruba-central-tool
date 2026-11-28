import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aruba_central.config_app import Workspace
from aruba_central.review_dispositions import digest, snapshot_binding
from test_consolidation import fixture


class PolicyWorklistTests(unittest.TestCase):
    def test_exact_lazy_policy_evidence_for_all_three_kinds(self):
        with tempfile.TemporaryDirectory() as directory:
            name="config-audit-example.json"
            path=Path(directory)/name
            path.write_text(json.dumps(fixture()))
            w=Workspace(directory)
            bundle=w.reviewed_snapshot(name)
            variant={"persona":"ACCESS_SWITCH","module":"roles","identity":"profile","variants":[
                {"body":{"description":"private-variant-marker"},"devices":[],"differences":[]}],
                "present_count":1,"unknown":[],"absent":[],"status":"explicit_differences"}
            rule={"persona":"ACCESS_SWITCH","module":"policies","identity":"policy","findings":[],
                "locations":[{"name":"private-rule-marker"}],"rules":1,"unsupported_rules":1,
                "status":"rule_schema_unqualified","truncated":False}
            sequence={"persona":"ACCESS_SWITCH","name":"Switch","status":"order_observed",
                "entries":[{}],"references":[{"name":"private-sequence-marker","position":1,
                    "status":"target_unverified"}],"findings":[],"truncated":False}
            records={"variants":[variant],"rules":[rule],"sequences":[sequence]}
            with patch.object(w,"policy_snapshot",side_effect=lambda _,kind:records[kind]):
                variants=w.advanced({"snapshot":name,"workflow":"variants"})
                rules=w.advanced({"snapshot":name,"workflow":"rules"})
                self.assertNotIn("private-variant-marker",variants)
                self.assertNotIn("private-rule-marker",rules)
                self.assertNotIn("private-sequence-marker",rules)
                for kind,workflow,marker in (("variants","variants","private-variant-marker"),
                    ("rules","rules","private-rule-marker"),("sequences","rules","private-sequence-marker")):
                    binding=digest([snapshot_binding(w,name,bundle),kind])
                    query={"snapshot":name,"workflow":workflow,"index":"0","binding":binding}
                    detail=w.advanced({**query,"policy_detail":kind})
                    self.assertIn("data-advisor-evidence",detail)
                    self.assertIn(marker,detail)
                    self.assertIn(marker,w.advanced({**query,"policy_evidence":kind}))
                    with self.assertRaises(ValueError):
                        w.advanced({**query,"index":"1","policy_detail":kind})
                    with self.assertRaises(ValueError):
                        w.advanced({**query,"binding":"wrong","policy_detail":kind})
                path.write_text(path.read_text()+" ")
                with self.assertRaises(ValueError):
                    w.advanced({**query,"policy_detail":"sequences"})
