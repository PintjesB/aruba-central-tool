import unittest
from aruba_central.plan_verification import combined_collateral_review
from aruba_central.remediation_collateral import collateral_review
from test_configuration_history import snapshot


class CombinedCollateralTests(unittest.TestCase):
    def test_combined_exclusions_are_exact_union_not_sum_of_per_proposal_counts(self):
        a,b=snapshot(),snapshot()
        for sid in ("3","4"):
            for bundle,value in ((a,"Old"),(b,"New")):
                row=next(r for r in bundle["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"] if r["scope"]==sid)
                row["effective_view"]["profiles"].update({"20":{"name":value},"21":{"name":value},"22":{"name":value}})
        items=[]
        for sid,identity in (("3","20"),("4","21")):
            items.append({"report":{"candidate":{"persona":"ACCESS_SWITCH","module":"layer2-vlan","identity":identity},
                "rows":[{"scope":sid}],"collateral":collateral_review(a,b,"layer2-vlan",{("ACCESS_SWITCH",sid):{identity}})}})
        combined=combined_collateral_review(a,b,items)[0]
        changed={(r["scope"],r["identity"]) for r in combined["records"] if r["status"]=="changed"}
        self.assertEqual(changed,{("3","21"),("3","22"),("4","20"),("4","22")})
        self.assertEqual(combined["proposal_count"],2)
        self.assertFalse(combined["safe_to_apply"])
        self.assertEqual(combined_collateral_review(a,b,list(reversed(items)))[0],combined)
        self.assertEqual(combined_collateral_review(a,b,items[:1])[0]["records"],items[0]["report"]["collateral"]["records"])
