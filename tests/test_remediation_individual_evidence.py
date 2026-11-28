import unittest
from unittest.mock import patch
from aruba_central.remediation_review import captured_observation, verify_override
from aruba_central.promotion_verification import verify_promotion
from aruba_central.remediation_presentation import observation_comparison
from test_configuration_history import snapshot


class RemediationIndividualEvidenceTests(unittest.TestCase):
    def captures(self):
        a, b = snapshot(), snapshot()
        a["captured_at"] = "2026-01-01T00:00:00+00:00"
        b["captured_at"] = "2026-01-02T00:00:00+00:00"
        return a, b

    def test_count_confirmed_absence_cannot_override_positive_individual(self):
        a,b = self.captures()
        row = b["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]
        row["local_view"] = {"status":"list_parsed","profiles":{},"count_confirmed":True}
        row["effective_view"]["profiles"]["20"]["@"] = {"aruba-annotation:inherited":True}
        candidate = {"id":"test","persona":"ACCESS_SWITCH","module":"layer2-vlan","identity":"20",
                     "local":{"vlan":20,"name":"Office"},"sources":[{"scope":"4","kind":"device","name":"Target"}]}
        evidence = {"status":"identity_observed","profile":{"vlan":20,"name":"Office"}}
        b["keyed_profile_details"] = {"profiles":{"ACCESS_SWITCH":{"4":{"layer2-vlan":{"20":{"local":evidence}}}}}}
        with patch("aruba_central.remediation_review.override_candidates",return_value=[candidate]):
            report = verify_override(a,b,"test",confirmed=True)
        self.assertEqual(report["rows"][0]["status"],"individual_evidence_conflict")
        observed = report["rows"][0]["after_local"]
        self.assertEqual(observed["collection_state"],"absent")
        self.assertIn("conflicting individual evidence",observation_comparison("Local",report["rows"][0]["before_local"],observed))
        evidence["status"] = "collection_only_sampled"
        self.assertEqual(captured_observation(b,"ACCESS_SWITCH","layer2-vlan","4","local","20")["state"],"absent")

    def test_retained_library_body_conflict_prevents_promotion_destination_match(self):
        a,b = self.captures()
        candidate = {"id":"test","action":"reuse_library","persona":"ACCESS_SWITCH","module":"layer2-vlan","identity":"20",
                     "local":{"vlan":20,"name":"Office"},"sources":[{"scope":"4","kind":"device","name":"Target"}]}
        b["library"]["assignments"] = {"status":"response_received","rows":[{"profile-type":"layer2-vlan","profile-instance":"20","device-function":"ACCESS_SWITCH","scope-id":"4"}]}
        b["keyed_profile_details"] = {"profiles":{"Library":{"":{"layer2-vlan":{"20":{"library":{"status":"identity_observed","profile":{"vlan":20,"name":"Different"}}}}}}}}
        with patch("aruba_central.promotion_verification.promotion_candidates",return_value=[candidate]):
            report=verify_promotion(a,b,"test","library",confirmed=True)
        self.assertFalse(report["destination_and_assignments_observed"])
        self.assertEqual(report["after_destination"]["state"],"individual_evidence_conflict")
        self.assertFalse(report["safe_to_apply"])
