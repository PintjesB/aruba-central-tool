import json
import unittest

from aruba_central.keyed_qualification import keyed_qualification
from aruba_central.central_tool import field_differences


class KeyedQualificationTests(unittest.TestCase):
    def test_private_shapes_and_ordered_differences(self):
        identity = "private-profile"
        a = [{"name": "private-a"}, {"name": "private-b"}]
        b = list(reversed(a))
        bundle = {"keyed_profile_details": {"profiles": {
            "Library": {"": {
                "role-gpids": {identity: {"library": {"status": "schema_unresolved",
                    "raw": {"unexpected-private-envelope": [{"name": identity}], "metadata": {}, "extra": True}}}},
                "server-groups": {
                    identity: {"library": {"status": "identity_observed",
                        "differences": field_differences({"servers": a}, {"servers": b})}},
                    "another-private": {"library": {"status": "identity_observed",
                        "differences": field_differences({"servers": a, "unknown-private-field": False},
                                                         {"servers": b, "unknown-private-field": True})}}
                }
            }}
        }}}
        report = keyed_qualification(bundle)
        self.assertEqual(report["schema_shapes"][0]["exact_identity_candidates"], 1)
        self.assertTrue(any(row["level"] == "list_record" and row["field"] == "name" for row in report["schema_fields"]))
        self.assertTrue(any(row["level"] == "envelope" and row["field"] == "other" for row in report["schema_fields"]))
        self.assertEqual({r["category"] for r in report["profile_differences"]},
                         {"order_only", "includes_non_order_difference"})
        self.assertEqual(sum(r["reads"] for r in report["profile_differences"]), 2)
        self.assertFalse(report["order_equivalence_qualified"])
        self.assertNotIn("private", json.dumps(report))


    def test_anonymous_relationships_and_path_locations_do_not_reveal_values(self):
        from aruba_central.keyed_qualification import identity_relationship
        for returned, expected in (("PRIVATE", "case_only"), (" private ", "surrounding_whitespace_only"),
                                   (" PRIVATE ", "case_and_whitespace"), ("pr%69vate", "percent_decoding_only"),
                                   ("unrelated", "different_identity")):
            self.assertEqual(identity_relationship({"name": returned}, "name", "private"), expected)
        d = field_differences({"private-key": 2, "second-private": {"private-inner": 1}}, {"second-private": {}})
        bundle = {"keyed_profile_details": {"profiles": {"Library": {"": {
            "server-groups": {"private-profile": {"library": {"status": "identity_observed", "differences": d}}},
            "roles": {"private-role": {"library": {"status": "schema_unresolved", "raw": {"name": "PRIVATE-ROLE"}}}}
        }}}}}
        report = keyed_qualification(bundle)
        self.assertEqual(report["identity_relationships"][0]["relationship"], "case_only")
        self.assertEqual({v["path_shape"] for v in report["difference_locations"]}, {"field", "field/field"})
        self.assertEqual(len({v["anonymous_path_number"] for v in report["difference_locations"]}), 2)
        self.assertNotIn("private", json.dumps(report).lower())
        self.assertFalse(report["safe_to_apply"])


    def test_case_candidate_body_and_collision_without_identity_qualification(self):
        bundle = {"library": {"modules": {"roles": {"status": "list_parsed",
            "profiles": {"private-role": {"name": "private-role", "description": "private-value"}}}}},
            "keyed_profile_details": {"profiles": {"Library": {"": {"roles": {
                "private-role": {"library": {"status": "schema_unresolved",
                    "raw": {"name": "PRIVATE-ROLE", "description": "private-value"}}}}}}}}}
        report = keyed_qualification(bundle)
        self.assertEqual(report["role_case_collection_evidence"][0]["relationship"], "body_matches_except_name")
        self.assertFalse(report["safe_to_apply"])
        self.assertNotIn("private", json.dumps(report).lower())
        bundle["library"]["modules"]["roles"]["profiles"]["PRIVATE-ROLE"] = {"name": "PRIVATE-ROLE"}
        self.assertEqual(keyed_qualification(bundle)["role_case_collection_evidence"][0]["relationship"],
                         "observed_case_collision")

    def test_anonymous_server_count_relationship(self):
        read = {"status": "identity_observed", "profile": {"servers": [{"name": "private-server"}]},
                "differences": field_differences({"private-field": 1}, {})}
        bundle = {"keyed_profile_details": {"profiles": {"Library": {"": {"server-groups": {
            "private-group": {"library": read}}}}}}}
        report = keyed_qualification(bundle)
        self.assertEqual(report["server_group_integer_relationships"][0]["relationship"],
                         "equals_observed_server_count")
        self.assertFalse(report["safe_to_apply"])
        self.assertNotIn("private", json.dumps(report))
