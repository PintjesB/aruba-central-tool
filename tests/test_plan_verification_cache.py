import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from aruba_central.config_app import Workspace
from aruba_central.review_dispositions import snapshot_binding
from aruba_central.plan_verification import verify_plan
from aruba_central.promotion_verification import verify_promotion
from test_consolidation import fixture


class PlanVerificationCacheTests(unittest.TestCase):
    def test_exact_reconstructed_candidates_reuse_prior_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            names=["config-audit-before.json","config-audit-after.json"]
            for name,time in zip(names,["2026-01-01T00:00:00+00:00","2026-01-02T00:00:00+00:00"]):
                data=fixture()
                data.update(captured_at=time,region="https://de1.example",inventory=[{"inventory":{"serial":"A"}}])
                (Path(directory)/name).write_text(json.dumps(data))
            workspace=Workspace(directory)
            before=workspace.reviewed_snapshot(names[0])
            findings=workspace.consolidation_snapshot(before)
            chosen=[f for f in findings if f["action"] in ("promote_local","reuse_library") and f["preview_selectable"]]
            manifest={"schema":1,"kind":"consolidation_selection","snapshot":names[0],
                      "snapshot_binding":snapshot_binding(workspace,names[0],before),
                      "selections":[{"id":f["id"],"destination":"library" if f["action"]=="promote_local" else None} for f in chosen]}
            after=Workspace(directory).reviewed_snapshot(names[1])
            expected={f["id"]:verify_promotion(before,after,f["id"],"library",confirmed=True) for f in chosen}
            with patch("aruba_central.promotion_verification.profile_recommendations",side_effect=AssertionError("Repeated recommendation analysis")):
                report=verify_plan(workspace,manifest,names[1],confirmed=True)
            self.assertEqual({item["id"]:item["report"] for item in report["reports"]},expected)
            self.assertFalse(report["safe_to_apply"])
