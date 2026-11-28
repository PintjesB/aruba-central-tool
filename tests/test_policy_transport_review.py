import unittest
from aruba_central.policy_rule_review import rule_review
from aruba_central.policy_transport_review import transport_review


class TransportReviewTests(unittest.TestCase):
    def body(self, transport, **condition_fields):
        condition={"rule-type":"RULE_TCP","source":{"type":"ADDRESS_ANY"},"destination":{"type":"ADDRESS_ANY"},
                   "ip-header":{"protocol":"IP_TCP"},"transport-fields":transport,**condition_fields}
        return {"security-policy":{"type":"SECURITY_POLICY_TYPE_DEFAULT","policy-rule":[{"position":1,"condition":condition,
                   "action":{"type":"ACTION_ALLOW"}}]}}
    def test_explicit_port_not_omitted_default(self):
        body=self.body({"source-port":{"operator":"COMPARISON_EQ","min":443},"established":False})
        result=rule_review("policies",body)
        self.assertEqual(result["status"],"rule_schema_unqualified")
        self.assertFalse(result["findings"])
        row=result["transport_evidence"][0]
        self.assertEqual(row["status"],"literal_clauses_observed")
        self.assertEqual(row["source_port"]["min"],443)
        self.assertEqual(row["destination_port"],{"state":"not_specified"})
        self.assertIs(row["established"],False)
        self.assertFalse(row["outer_policy_type_observed"])
        self.assertFalse(row["safe_to_apply"])
    def test_udp_range_and_conflicting_header(self):
        body=self.body({"destination-port":{"operator":"COMPARISON_RANGE","min":100,"max":200}},
                       **{"rule-type":"RULE_UDP","ip-header":{"protocol":"IP_UDP"}})
        row=transport_review(body)[0]
        self.assertEqual(row["status"],"literal_clauses_observed")
        self.assertEqual(row["destination_port"]["max"],200)
        body["security-policy"]["policy-rule"][0]["condition"]["ip-header"]["protocol"]="IP_TCP"
        self.assertEqual(transport_review(body)[0]["status"],"protocol_header_conflict")
    def test_invalid_ports_and_extra_fields_remain_unqualified(self):
        for transport,state in (({"source-port":{"operator":"COMPARISON_EQ","min":True}},"port_clause_unqualified"),
                                ({"source-port":{"operator":"COMPARISON_EQ","min":65536}},"port_clause_unqualified"),
                                ({"destination-port-net-group":"private"},"additional_transport_fields"),
                                ({"established":"false"},"additional_transport_fields"),
                                ({},"transport_without_port_clauses")):
            self.assertEqual(transport_review(self.body(transport))[0]["status"],state)
