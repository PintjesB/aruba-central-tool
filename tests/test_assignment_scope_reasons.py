import unittest
from aruba_central.assignment_review import assignment_review
from test_consolidation import fixture


class AssignmentScopeReasonTests(unittest.TestCase):
    def test_unresolved_scope_diagnostics_do_not_infer_recipients(self):
        data=fixture()
        data["results"]["CAMPUS_AP"]={"scopes":[{"id":"99","kind":"site","name":"Other site"}],"modules":{}}
        data["library"]["assignments"]["rows"]=[
            {"profile-type":"layer2-vlan","profile-instance":"30","device-function":persona,"scope-id":sid}
            for persona,sid in (("ACCESS_SWITCH","3"),("ACCESS_SWITCH","99"),("ACCESS_SWITCH","100"),("OTHER_FUNCTION","99"))]
        report=assignment_review(data)
        self.assertEqual([r["scope_resolution"] for r in report["rows"]],
                         ["resolved","scope_observed_other_function","scope_not_observed","function_not_collected"])
        for row in report["rows"][1:]:
            self.assertFalse(row["scope_resolved"])
            self.assertEqual(row["recipients"],[])
        self.assertEqual(report["rows"][1]["other_scope_contexts"][0]["persona"],"CAMPUS_AP")
        self.assertFalse(report["safe_to_apply"])
