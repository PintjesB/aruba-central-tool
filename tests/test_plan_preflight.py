import json
import tempfile
import unittest
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.review_dispositions import snapshot_binding
from aruba_central.plan_preflight import revalidate_plan
from test_consolidation import fixture


class PlanPreflightTests(unittest.TestCase):
    def test_exact_newer_evidence_and_changed_assignment_or_device(self):
        with tempfile.TemporaryDirectory() as directory:
            before_name,after_name="config-audit-before.json","config-audit-after.json"
            def capture(time):
                data=fixture()
                data.update(captured_at=time,region="https://de1.example",inventory=[{"inventory":{"serial":"A"}}])
                for scope in data["results"]["ACCESS_SWITCH"]["scopes"]:
                    if scope["kind"]=="device":
                        scope["metadata"]={"serial":scope["id"]}
                return data
            before=capture("2026-01-01T00:00:00+00:00")
            after=capture("2026-01-02T00:00:00+00:00")
            for name,data in ((before_name,before),(after_name,after)):
                (Path(directory)/name).write_text(json.dumps(data))
            workspace=Workspace(directory)
            original=workspace.reviewed_snapshot(before_name)
            proposal=next(f for f in workspace.consolidation_snapshot(original) if f["action"]=="promote_local")
            manifest={"schema":1,"kind":"consolidation_selection","snapshot":before_name,
                      "snapshot_binding":snapshot_binding(workspace,before_name,original),
                      "selections":[{"id":proposal["id"],"destination":"library"}]}
            report=revalidate_plan(workspace,manifest,after_name,confirmed=True)
            self.assertTrue(report["observed_review_matches"])
            self.assertFalse(report["safe_to_apply"])
            self.assertFalse(report["complete"])
            after["results"]["ACCESS_SWITCH"]["scopes"][-1]["metadata"]["serial"]="Replaced"
            after["library"]["assignments"]["rows"].append({"profile-type":"layer2-vlan","profile-instance":proposal["identity"],"scope-id":"3","device-function":"ACCESS_SWITCH"})
            (Path(directory)/after_name).write_text(json.dumps(after))
            report=revalidate_plan(workspace,manifest,after_name,confirmed=True)
            self.assertFalse(report["observed_review_matches"])
            self.assertIn("device_identity_unverified",report["rows"][0]["reasons"])
            self.assertIn("library_assignment_evidence_changed",report["rows"][0]["reasons"])
            after["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][2]["local_view"]["profiles"]["20"]["name"]="Changed"
            (Path(directory)/after_name).write_text(json.dumps(after))
            report=revalidate_plan(workspace,manifest,after_name,confirmed=True)
            self.assertIn("proposal_evidence_changed_or_missing",report["rows"][0]["reasons"])
            with self.assertRaises(ValueError):
                revalidate_plan(workspace,manifest,after_name)


    def test_different_outside_body_changes_even_when_recommendation_category_is_unchanged(self):
        from copy import deepcopy
        with tempfile.TemporaryDirectory() as directory:
            names=["config-audit-before.json","config-audit-after.json"]
            before=fixture()
            before.update(captured_at="2026-01-01T00:00:00+00:00",region="https://de1.example",inventory=[{"inventory":{"serial":"A"}}])
            entry=before["results"]["ACCESS_SWITCH"]
            for scope in entry["scopes"]:
                if scope["kind"]=="device":
                    scope["metadata"]={"serial":scope["id"]}
            outside=entry["modules"]["layer2-vlan"]["scope_results"][-1]
            outside["effective_view"]={"status":"list_parsed","count_confirmed":True,
                                      "profiles":{"20":{"vlan":20,"name":"Different A"}}}
            after=deepcopy(before)
            after["captured_at"]="2026-01-02T00:00:00+00:00"
            after["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]["profiles"]["20"]["name"]="Different B"
            for name,data in zip(names,[before,after]):
                (Path(directory)/name).write_text(json.dumps(data))
            w=Workspace(directory)
            bundle=w.reviewed_snapshot(names[0])
            f=next(f for f in w.consolidation_snapshot(bundle) if f["action"]=="promote_local")
            manifest={"schema":1,"kind":"consolidation_selection","snapshot":names[0],
                      "snapshot_binding":snapshot_binding(w,names[0],bundle),"selections":[{"id":f["id"],"destination":"library"}]}
            report=revalidate_plan(w,manifest,names[1],confirmed=True)
            self.assertFalse(report["observed_review_matches"])
            row=report["rows"][0]
            self.assertNotIn("proposal_evidence_changed_or_missing",row["reasons"])
            self.assertIn("exact_profile_evidence_changed",row["reasons"])
            self.assertEqual(len(row["profile_evidence_changes"]),1)
            self.assertEqual(row["profile_evidence_changes"][0]["scope"],"5")
            self.assertFalse(report["safe_to_apply"])


    def test_prerequisite_body_change_is_detected_without_changing_reference_identity(self):
        from copy import deepcopy
        with tempfile.TemporaryDirectory() as directory:
            names=["config-audit-before.json","config-audit-after.json"]
            before=fixture()
            before.update(captured_at="2026-01-01T00:00:00+00:00",region="https://de1.example",inventory=[{"inventory":{"serial":"A"}}])
            entry=before["results"]["ACCESS_SWITCH"]
            for scope in entry["scopes"]:
                if scope["kind"]=="device":
                    scope["metadata"]={"serial":scope["id"]}
            body={"profile-name":"Test","switchport":{"access-vlan":20}}
            entry["modules"]["sw-port-profiles"]={"scope_results":[
                {"scope":sid,"scope_kind":"device","local_view":{"status":"list_parsed","profiles":{"Test":deepcopy(body)}},
                 "effective_view":{"status":"list_parsed","profiles":{"Test":deepcopy(body)}}} for sid in ("3","4")]}
            after=deepcopy(before)
            after["captured_at"]="2026-01-02T00:00:00+00:00"
            after["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][2]["effective_view"]["profiles"]["20"]["name"]="Changed target"
            for name,data in zip(names,[before,after]):
                (Path(directory)/name).write_text(json.dumps(data))
            w=Workspace(directory)
            bundle=w.reviewed_snapshot(names[0])
            f=next(f for f in w.consolidation_snapshot(bundle) if f["module"]=="sw-port-profiles" and f["action"]=="promote_local")
            manifest={"schema":1,"kind":"consolidation_selection","snapshot":names[0],
                      "snapshot_binding":snapshot_binding(w,names[0],bundle),"selections":[{"id":f["id"],"destination":"library"}]}
            report=revalidate_plan(w,manifest,names[1],confirmed=True)
            row=report["rows"][0]
            self.assertIn("prerequisite_profile_evidence_changed",row["reasons"])
            self.assertEqual(row["prerequisite_evidence"]["changes"][0]["identity"],"20")
            self.assertEqual(row["profile_evidence_changes"],[])
            self.assertFalse(report["observed_review_matches"])
