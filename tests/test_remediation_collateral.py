import unittest
from aruba_central.remediation_collateral import collateral_review
from test_configuration_history import snapshot


class CollateralTests(unittest.TestCase):
    def test_exclusions_are_exact_and_unqualified_counts_remain_visible(self):
        a,b = snapshot(),snapshot("Changed")
        module = "layer2-vlan"
        def view(bundle, scope):
            return next(r["effective_view"] for r in bundle["results"]["ACCESS_SWITCH"]["modules"][module]["scope_results"] if r["scope"] == scope)
        view(a,"4")["profiles"]["21"] = {"vlan":21,"name":"Old"}
        view(b,"4")["profiles"]["21"] = {"vlan":21,"name":"New"}
        view(b,"3")["profiles"]["20"]["name"] = "Unexpected"
        view(b,"3")["count_confirmed"] = False
        result = collateral_review(a,b,module,{("ACCESS_SWITCH","4"):{"20"}})
        rows = {(r["scope"],r["identity"]):r["status"] for r in result["records"]}
        self.assertEqual(rows["4","21"],"changed")
        self.assertEqual(rows["3","20"],"changed")
        self.assertNotIn(("4","20"),rows)
        self.assertEqual(result["counts"]["unverified_view_pairs"],2)
        self.assertFalse(result["safe_to_apply"])
        self.assertFalse(result["complete"])

    def test_other_functions_and_replaced_devices_are_not_excluded(self):
        from copy import deepcopy
        a,b = snapshot(),snapshot()
        for bundle in (a,b):
            bundle["results"]["CAMPUS_AP"] = deepcopy(bundle["results"]["ACCESS_SWITCH"])
        b["results"]["CAMPUS_AP"]["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]["profiles"]["20"]["name"] = "Changed"
        b["results"]["ACCESS_SWITCH"]["scopes"][-1]["metadata"]["serial"] = "Replaced"
        report = collateral_review(a,b,"layer2-vlan",{("ACCESS_SWITCH","4"):{"20"}})
        self.assertTrue(any(r["persona"]=="CAMPUS_AP" and r["identity"]=="20" and r["status"]=="changed" for r in report["records"]))
        self.assertTrue(any(r["persona"]=="ACCESS_SWITCH" and r["scope"]=="5" and r["status"]=="device_identity_unverified" for r in report["records"]))
