import unittest
from aruba_central.identity_review import identity_collisions


class IdentityReviewTests(unittest.TestCase):
    def test_exact_names_and_contexts_are_preserved(self):
        def view(*names):
            return {"status":"list_parsed","profiles":{n:{"name":n} for n in names}}
        data={"results":{"ACCESS_SWITCH":{"scopes":[{"id":"1","kind":"device"}],"modules":{"roles":{"scope_results":[
            {"scope":"1","local_view":view("Employee"),"effective_view":view("Employee","employee")}]}}}},
            "library":{"modules":{"roles":view(" EMPLOYEE ","Guest")}}}
        rows=identity_collisions(data)
        self.assertEqual(len(rows),1)
        r=rows[0]
        self.assertEqual(r["identities"],[" EMPLOYEE ","Employee","employee"])
        self.assertEqual(r["same_context_collisions"],1)
        self.assertEqual(r["context_count"],3)
        self.assertEqual(len(r["observations"]),4)
        self.assertFalse(r["safe_to_apply"])
        data["results"]["ACCESS_SWITCH"]["modules"]["roles"]["scope_results"][0]["effective_view"]=view("employee")
        self.assertEqual(identity_collisions(data)[0]["same_context_collisions"],0)
