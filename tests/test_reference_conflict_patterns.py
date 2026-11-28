import unittest
import json
from aruba_central.standard_evidence import body_conflict_kind
from aruba_central.dependency_evidence import qualify_reference_edges
from aruba_central.engineering_qualification import reference_conflict_patterns


class ReferenceConflictPatternTests(unittest.TestCase):
    def test_body_difference_shapes(self):
        for a,b,kind in (({"a":1},{"a":1},None),
                         ({"a":{}},{"a":{"private":2}},"collection_missing_fields"),
                         ({"a":1,"b":2},{"a":1},"individual_missing_fields"),
                         ({"a":1},{"b":1},"field_presence_difference"),
                         ({"a":[1,2,1]},{"a":[1,1,2]},"list_order_difference"),
                         ({"a":[1,2]},{"a":[2,2]},"value_difference"),
                         ({"a":1},{"a":True},"value_difference"),
                         ({"a":1},{"a":2,"b":1},"mixed_difference")):
            self.assertEqual(body_conflict_kind(a,b),kind)

    def test_source_target_conflicts_remain_blocked_and_counts_deduplicate(self):
        def view(profiles):
            return {"status":"list_parsed","count_confirmed":True,"profiles":profiles}
        def read(body):
            return {"effective":{"status":"identity_observed","profile":body}}
        bundle={"results":{"ACCESS_SWITCH":{"scopes":[],"modules":{}}},
                "keyed_profile_details":{"profiles":{"ACCESS_SWITCH":{"1":{
                    "roles":{"private-role":read({"name":"private-role","extra":True})},
                    "layer2-vlan":{"10":read({"vlan":10,"description":"private-description"})}}}}}}
        effective={"ACCESS_SWITCH":{"roles":{"1":view({"private-role":{"name":"private-role"}})},
                     "layer2-vlan":{"1":view({})}}}
        base={"persona":"ACCESS_SWITCH","scope":"1","source_view":"effective","source_module":"roles",
              "source":"private-role","target_module":"layer2-vlan","target":"10","status":"not_observed"}
        refs=qualify_reference_edges(bundle,[{**base,"path":["a"]},{**base,"path":["b"]}],effective)
        self.assertTrue(all(r["status"]=="conflicting_observation" for r in refs))
        self.assertTrue(all(r["source_conflict_kind"]=="collection_missing_fields" for r in refs))
        self.assertTrue(all(r["target_conflict_kind"]=="count_confirmed_absence" for r in refs))
        counts=reference_conflict_patterns(refs)
        self.assertEqual(len(counts),2)
        self.assertTrue(all(r["observations"]==2 and r["distinct_endpoints"]==1 for r in counts))
        self.assertNotIn("private",json.dumps(counts))
