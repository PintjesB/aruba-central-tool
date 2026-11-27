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
        self.assertEqual({r["category"] for r in report["profile_differences"]},
                         {"order_only", "includes_non_order_difference"})
        self.assertEqual(sum(r["reads"] for r in report["profile_differences"]), 2)
        self.assertFalse(report["order_equivalence_qualified"])
        self.assertNotIn("private", json.dumps(report))
