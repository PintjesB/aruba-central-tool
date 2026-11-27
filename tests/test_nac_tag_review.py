import unittest
from aruba_central.nac_tag_review import tag_evidence, tag_review_view


class NACTagReviewTests(unittest.TestCase):
    def test_tag_drilldown_keeps_candidate_strength_and_rule_context(self):
        def reg(i, status, candidates):
            return {"id": i, "display_name": i, "enabled": True, "record": {"macAddress": "00:00:00:00:00:01"},
                    "references": [{"value": "Office", "status": status, "candidates": candidates}]}
        registrations = {"tag_definitions": {"t1": {"name": "Office"}, "t2": {"name": "Office"}},
                         "rows": [reg("exact", "observed_id", ["t1"]),
                                  reg("name", "observed_name_only", ["t1"]),
                                  reg("ambiguous", "ambiguous", ["t1", "t2"]),
                                  reg("other", "observed_id", ["t2"])]}
        condition = {"policy_id": "p1", "policy": "Policy", "rule": 1, "attribute": "attr",
                     "operator": "equals", "value": "Office", "tag_candidates": ["t1"]}
        target = {"policy_id": "p1", "policy": "Policy", "rule": 1, "vlan_id": "20", "value": "20",
                  "status": "conditional_vlan_candidate"}
        bindings = {"tag_condition_observations": [condition],
                    "vlan_targets": [target, {**target, "rule": 2, "value": "30"}, {**target, "policy_id": "p2", "value": "40"}],
                    "vlan_visibility": {"20": [{"persona": "ACCESS_SWITCH", "scope": "3", "device": "Switch", "status": "observed"}]}}
        result = tag_evidence(registrations, bindings, "t1")
        self.assertEqual([r["state"] for r in result["registrations"]], ["observed_id", "observed_name_only", "ambiguous"])
        self.assertEqual(result["vlan_targets"], [target])
        self.assertFalse(result["safe_to_apply"])
        html = tag_review_view("/test/", "capture.json", "", "", registrations, bindings, "t1")
        self.assertIn("Exact ID registrations", html)
        self.assertIn("not a tag-to-VLAN assignment", html)
        self.assertIn("scope=3", html)
        self.assertIn("module=layer2-vlan", html)
        with self.assertRaises(ValueError):
            tag_evidence(registrations, bindings, "unknown")
