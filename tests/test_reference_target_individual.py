import unittest
from aruba_central.dependency_evidence import qualify_reference_edges


class IndividualTargetTests(unittest.TestCase):
    def test_exact_context_positive_read_does_not_promote_incomplete_collection(self):
        persona = "ACCESS_SWITCH"
        ref = {"persona": persona, "scope": "1", "source_module": "roles", "source": "r",
               "source_view": "effective", "target_module": "policies", "target": "p",
               "status": "unresolved", "target_evidence": "target_collection_incomplete"}
        bundle = {"results": {}, "keyed_profile_details": {"profiles": {persona: {"1": {
            "policies": {"p": {"effective": {"status": "identity_observed", "profile": {"name": "p"}}}}}}}}}
        view = {"status": "list_parsed", "profiles": {}, "count_confirmed": False}
        effective = {persona: {"policies": {"1": view}}}
        records = [dict(ref), {**ref, "scope": "2"}, {**ref, "target": "q"}]
        qualify_reference_edges(bundle, records, effective)
        self.assertEqual(records[0]["target_individual_status"], "identity_observed")
        self.assertEqual(records[0]["status"], "unresolved")
        self.assertNotIn("target_individual_status", records[1])
        self.assertNotIn("target_individual_status", records[2])
        view["count_confirmed"] = True
        conflict = {**ref, "status": "not_observed"}
        qualify_reference_edges(bundle, [conflict], effective)
        self.assertEqual(conflict["status"], "conflicting_observation")
        self.assertTrue(conflict["target_body_conflict"])
        self.assertEqual(conflict["target_individual_status"], "identity_observed")

    def test_sampled_marker_never_becomes_identity_observation(self):
        ref = {"persona": "Library", "scope": "Library", "source_module": "roles", "source": "r",
               "source_view": "library", "target_module": "policies", "target": "p", "status": "unresolved"}
        bundle = {"results": {}, "keyed_profile_details": {"profiles": {"Library": {"": {
            "policies": {"p": {"library": {"status": "collection_only_sampled"}}}}}}}}
        qualify_reference_edges(bundle, [ref], {})
        self.assertEqual(ref["target_individual_status"], "collection_only_sampled")
        self.assertEqual(ref["status"], "unresolved")
