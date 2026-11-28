import unittest
from aruba_central.policy_service_review import literal_service,service_evidence
from aruba_central.policy_rule_review import policy_rule_groups


class ServiceReviewTests(unittest.TestCase):
    def test_literal_service_boundaries(self):
        self.assertEqual(literal_service({"protocol":"IP_TCP","ports":[443,80,81,443]}),
                         {"protocol":"tcp","port_ranges":[[80,81],[443,443]]})
        self.assertEqual(literal_service({"protocol":17,"port-range":{"operator":"COMPARISON_RANGE","min":100,"max":110}}),
                         {"protocol":"udp","port_ranges":[[100,110]]})
        self.assertEqual(literal_service({"protocol":6,"port-range":{"operator":"COMPARISON_EQ","min":53}}),
                         {"protocol":"tcp","port_ranges":[[53,53]]})
        for body in ({"protocol":6,"ports":[True]},{"protocol":6,"ports":[65536]},
                     {"protocol":6,"ports":[443],"alg-service":"FTP"},{"protocol":6,"ports":[443],"http-proxy":True},
                     {"protocol":6,"ports":[443],"port-range":{"operator":"COMPARISON_EQ","min":443}},
                     {"protocol":6},{"protocol":6,"port-range":{"operator":"COMPARISON_RANGE","min":100,"max":1}},
                     {"protocol":"6","ports":[80]}):
            self.assertIsNone(literal_service(body))

    def test_service_evidence_keeps_scope_and_missing_policy_type(self):
        policy={"name":"p","security-policy":{"type":"SECURITY_POLICY_TYPE_DEFAULT","policy-rule":[
                {"position":1,"condition":{"services":{"net-service":"svc"}}},
                {"position":2,"condition":{"services":{"unknown":"x"}}}]}}
        def view(profiles):
            return {"status":"list_parsed","profiles":profiles,"count_confirmed":True}
        def module(mapping):
            return {"scope_results":[{"scope":sid,"effective_view":v} for sid,v in mapping.items()]}
        bundle={"results":{"CAMPUS_AP":{"scopes":[{"id":"1","kind":"device"},{"id":"2","kind":"device"}],"modules":{
            "policies":module({"1":view({"p":policy}),"2":view({"p":policy})}),
            "net-services":module({"1":view({"svc":{"protocol":6,"ports":[443]}}),"2":view({})})}}},
            "library":{"modules":{"net-services":view({"svc":{"protocol":17,"ports":[53]}})}}}
        group=policy_rule_groups(bundle)[0]
        self.assertEqual(group["status"],"rule_schema_unqualified")
        self.assertFalse(group["findings"])
        evidence={row["location"]["scope"]:row["references"] for row in group["service_definition_evidence"]}
        self.assertEqual(evidence["1"][0]["status"],"literal_service_observed")
        self.assertEqual(evidence["1"][0]["literal_service"]["protocol"],"tcp")
        self.assertEqual(evidence["2"][0]["status"],"service_not_observed")
        self.assertNotIn("literal_service",evidence["2"][0])
        self.assertEqual(evidence["1"][1]["status"],"service_reference_shape_unqualified")
        self.assertFalse(evidence["1"][0]["safe_to_apply"])
