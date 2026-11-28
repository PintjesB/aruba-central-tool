import unittest
import tempfile
import json
from pathlib import Path
from aruba_central.config_app import Workspace
from aruba_central.consolidation import profile_recommendations
from aruba_central.review_dispositions import snapshot_binding
from aruba_central.review_manifest import validate_selection
from test_consolidation import fixture


class DestinationCollisionTests(unittest.TestCase):
    def test_distinct_committed_definition_cannot_be_overwritten_by_consolidation(self):
        data=fixture()
        entry=data["results"]["ACCESS_SWITCH"]
        for scope in entry["scopes"]:
            if scope["id"] in ("3","4"):
                scope["metadata"]={"siteId":"2"}
        module=entry["modules"]["layer2-vlan"]
        module["scope_results"][0]["local_view"]["profiles"]["20"]={"vlan":20,"name":"Existing Global"}
        data["library"]["modules"]["layer2-vlan"]["profiles"]["20"]={"vlan":20,"name":"Existing Library"}
        def finding(bundle):
            return next(f for f in profile_recommendations(bundle) if f["action"]=="promote_local" and f["identity"]=="20")
        f=finding(data)
        self.assertTrue(f["preview_selectable"])
        self.assertEqual({d["destination"] for d in f["blocked_destinations"]},{"1","library"})
        self.assertEqual({d["scope"] for d in f["placement_options"]},{"2"})
        self.assertTrue(all(d["existing_definition_conflicts"] for d in f["blocked_destinations"]))
        with tempfile.TemporaryDirectory() as directory:
            name="config-audit-example.json"
            (Path(directory)/name).write_text(json.dumps(data))
            w=Workspace(directory)
            bundle=w.reviewed_snapshot(name)
            f=next(f for f in w.consolidation_snapshot(bundle) if f["action"]=="promote_local" and f["identity"]=="20")
            binding=snapshot_binding(w,name,bundle)
            manifest={"schema":1,"kind":"consolidation_selection","snapshot":name,"snapshot_binding":binding,
                      "selections":[{"id":f["id"],"destination":"2"}]}
            self.assertTrue(validate_selection(w,manifest)["review_export_gates_passed"])
            for destination in ("1","library"):
                manifest["selections"][0]["destination"]=destination
                with self.assertRaises(ValueError):
                    validate_selection(w,manifest)
            detail=w.advisor({"snapshot":name,"group":f["id"],"binding":binding,"detail":"1"})
            self.assertIn("Existing definition must be retained",detail)
        module["scope_results"][1]["local_view"]["profiles"]["20"]={"vlan":20,"name":"Existing Site"}
        self.assertFalse(finding(data)["preview_selectable"])
