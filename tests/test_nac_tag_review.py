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
        condition = {"policy_id": "p1", "policy": "Policy", "rule": 1, "rule_index": 0, "attribute": "attr",
                     "operator": "equals", "value": "Office", "tag_candidates": ["t1"]}
        target = {"policy_id": "p1", "policy": "Policy", "rule": 1, "rule_index": 0, "vlan_id": "20", "value": "20",
                  "status": "conditional_vlan_candidate"}
        bindings = {"tag_condition_observations": [condition],
                    "vlan_targets": [target, {**target, "rule": 2, "rule_index": 1, "value": "30"}, {**target, "policy_id": "p2", "value": "40"}],
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


    def test_duplicate_and_missing_positions_never_cross_join_rule_attributes(self):
        from aruba_central.nac_binding_review import nac_bindings, context_label
        reg = {"tag_definitions": {"t1": {"name": "Office"}}, "rows": []}
        condition = {"condition": [{"condition-group": [{"value": "Office"}]}]}
        def rule(position, value, matches):
            attrs = [{"kind": "defined-attr", "name": "ATTR_VLAN_ID", "value": value, "source": "rule"}]
            return {"position": position, "conditions": condition if matches else None, "enabled": False,
                    "combined_candidate_attributes": attrs, "attributes": attrs, "gaps": []}
        policy = {"id": "p", "name": "Policy", "conditions": None, "enabled": True, "default_gaps": [],
                  "default_attributes": [{"kind": "defined-attr", "name": "ATTR_VLAN_ID", "value": "100", "source": "default"}],
                  "rules": [rule(None, "20", True), rule(None, "30", False), rule(7, "40", True), rule(7, "50", False)]}
        bindings = nac_bindings({"results": {}}, reg, {"policies": [policy]})
        report = tag_evidence(reg, bindings, "t1")
        self.assertEqual([v["value"] for v in report["vlan_targets"]], ["20", "40"])
        self.assertEqual([v["rule_enabled"] for v in report["vlan_targets"]], [False, False])
        self.assertIn("position unknown", context_label(report["vlan_targets"][0]))
        self.assertIn("captured #3", context_label(report["vlan_targets"][1]))
