import unittest
from library_visibility import visibility_summary


class LibraryVisibilityTests(unittest.TestCase):
    def test_empty_objects_do_not_establish_absence(self):
        definitions = {"a": {"name": "a"}, "b": {"name": "b"}}
        assignments = [{"profile-type": "snmp", "profile-instance": "a",
                        "device-function": "ACCESS_SWITCH", "scope-id": str(i)}
                       for i in range(1, 5)]
        def scope(i, view):
            return {"scope": str(i), "effective_view": view}
        bundle = {"library": {"modules": {"snmp": {"status": "list_parsed", "profiles": definitions}},
                              "assignments": {"status": "response_received", "rows": assignments + assignments[:1]}},
                  "results": {"ACCESS_SWITCH": {"modules": {"snmp": {"scope_results": [
                      scope(1, {"status": "empty_object"}),
                      scope(2, {"status": "list_parsed", "profiles": {}, "count_confirmed": True}),
                      scope(3, {"status": "list_parsed", "profiles": {"a": {"name": "a"}}}),
                  ]}}}}}
        row, = visibility_summary(bundle)
        self.assertEqual(row["definitions"], 2)
        self.assertEqual(row["definitions_with_observed_assignments"], 1)
        self.assertEqual(row["observed_assignments"], 4)
        self.assertEqual(row["effective_views"], {"empty_object": 1, "confirmed_empty": 1, "positive": 1})
        self.assertEqual(row["assignment_visibility"], {"unverified": 2, "count_confirmed_absence": 1, "identity_observed": 1})
        self.assertFalse(row["complete"])

    def test_unassigned_definitions_are_not_proven_unused(self):
        bundle = {"library": {"modules": {"net-groups": {"status": "list_parsed", "profiles": {"a": {"name": "a"}}}}}}
        row, = visibility_summary(bundle)
        self.assertEqual(row["definitions_with_observed_assignments"], 0)
        self.assertEqual(row["assignment_capture_status"], "not_collected")
        self.assertFalse(row["complete"])
