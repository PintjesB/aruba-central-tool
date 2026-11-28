import json
import unittest

from aruba_central.engineering_qualification import reference_identity_patterns


class FocusedEngineeringTests(unittest.TestCase):
    def test_reference_patterns_preserve_documented_fields_and_hide_values(self):
        base={"status":"unresolved","target":None,"source_module":"roles","target_module":"layer2-vlan",
              "source":"private-profile","scope":"private-scope","source_view":"effective"}
        records=[{**base,"path":["private-wrapper",0,"access-vlan-name"]},
                 {**base,"path":["private-wrapper",5,"access-vlan-name"]},
                 {**base,"path":["private-key"]},
                 {**base,"path":["private-key"],"source_module":"private-module","source_view":"private-view"},
                 {**base,"path":["private-key"],"status":"conflicting_observation"},
                 {**base,"path":["private-key"],"source_evidence":"nac_enforcement"},
                 {**base,"path":["private-key"],"target":"private-target"}]
        report=reference_identity_patterns(records)
        self.assertEqual(sum(r["observations"] for r in report),4)
        self.assertEqual(report[0],{"source_module":"roles","target_module":"layer2-vlan",
                                    "field":"access-vlan-name","path_shape":"list_member",
                                    "source_view":"effective","source_value_shape":"unknown","observations":2})
        self.assertNotIn("private",json.dumps(report))
        self.assertTrue(any(r["source_module"]=="other" and r["source_view"]=="other" for r in report))

    def test_unknown_value_shape_is_allowlisted(self):
        base={"status":"unresolved","target":None,"source_module":"roles","target_module":"layer2-vlan",
              "path":["access-vlan-name"],"source_view":"effective"}
        report=reference_identity_patterns([{**base,"source_value_shape":"empty_string"},
                                           {**base,"source_value_shape":"private-value"}])
        self.assertEqual({r["source_value_shape"] for r in report},{"empty_string","unknown"})
        self.assertNotIn("private",json.dumps(report))
