import unittest
from aruba_central.configuration_history import configuration_drift
from test_configuration_history import snapshot


class AdditionalDriftTests(unittest.TestCase):
    def test_exact_selectors_keep_raw_individual_and_nac_observations_separate(self):
        a,b=snapshot(),snapshot()
        for bundle,value in ((a,False),(b,0)):
            bundle["unadapted_profiles"]={"example":{"source_views":[
                {"persona":"ACCESS_SWITCH","scope":"3","committed":{"status":"response_received","raw":{"value":value}},
                 "effective":{"status":"response_received","raw":{"value":value}}},
                {"persona":"UNFILTERED_SCOPE","scope":"3","effective":{"status":"response_received","raw":{"value":value}}}]}}
            bundle["keyed_profile_details"]={"profiles":{"ACCESS_SWITCH":{"4":{"layer2-vlan":{
                "20":{"effective":{"status":"identity_observed","profile":{"vlan":20,"flag":value}}}}}}}}
            bundle["nac_configuration"]={"auth-profiles":{"status":"list_parsed","count_confirmed":True,
                "profiles":{"profile":{"name":"profile","flag":value}}}}
        report=configuration_drift(a,b,confirmed=True)
        self.assertEqual(report["counts"],{})
        extra=report["additional_evidence"]
        self.assertEqual(extra["counts"]["supplemental"]["response_changed"],3)
        self.assertEqual(extra["counts"]["individual"]["response_changed"],1)
        self.assertEqual(extra["counts"]["nac_configuration"]["selectors_with_observations"],1)
        self.assertEqual(len(extra["records"]),5)
        self.assertTrue(all(r["fields"][0]["kind"]=="type_difference" for r in extra["records"]))
        self.assertFalse(extra["safe_to_apply"])

    def test_sampled_missing_partial_and_replaced_device_are_not_configuration_changes(self):
        a,b=snapshot(),snapshot()
        for bundle,status in ((a,"identity_observed"),(b,"collection_only_sampled")):
            bundle["keyed_profile_details"]={"profiles":{"ACCESS_SWITCH":{"4":{"layer2-vlan":{
                "20":{"effective":{"status":status,"profile":{"vlan":20}}}}}}}}
        a["unadapted_profiles"]={"example":{"source_views":[{"persona":"ACCESS_SWITCH","scope":"3",
            "effective":{"status":"response_received","raw":{"value":1}}}]}}
        b["unadapted_profiles"]={"example":{"source_views":[{"persona":"ACCESS_SWITCH","scope":"3",
            "effective":{"status":"partial_response","raw":{"value":2},"pagination_status":"request_failed"}}]}}
        result=configuration_drift(a,b,confirmed=True)["additional_evidence"]
        self.assertEqual({r["status"] for r in result["records"]},{"read_status_changed"})
        b["results"]["ACCESS_SWITCH"]["scopes"][2]["metadata"]["serial"]="Replaced"
        result=configuration_drift(a,b,confirmed=True)["additional_evidence"]
        self.assertIn("scope_identity_unverified",{r["status"] for r in result["records"]})
        b["keyed_profile_details"]={}
        result=configuration_drift(a,b,confirmed=True)["additional_evidence"]
        self.assertIn("selector_observation_changed",{r["status"] for r in result["records"]})


    def test_sampled_and_unavailable_reasons_reconcile_without_claiming_loss(self):
        a,b=snapshot(),snapshot()
        def read(status):
            return {"status":status, "profile":{"name":"example"}} if status=="identity_observed" else {"status":status}
        for bundle,states in ((a,["collection_only_sampled","identity_observed","schema_unresolved"]),
                              (b,["collection_only_sampled","collection_only_sampled","identity_observed"])):
            bundle["keyed_profile_details"]={"profiles":{"ACCESS_SWITCH":{"4":{"roles":{
                str(i):{"effective":read(status)} for i,status in enumerate(states)}}}}}
            bundle["results"]["ACCESS_SWITCH"]["modules"]["dns"]={"scope_results":[
                {"scope":"4","local_view":{"status":"request_rejected"},"effective_view":{"status":"empty_object"}}]}
        report=configuration_drift(a,b,confirmed=True)
        self.assertEqual(report["unavailable_reasons"],{"same_unavailable_status":2})
        extra=report["additional_evidence"]
        reasons=extra["noncomparable_reasons"]["individual"]
        self.assertEqual(reasons,{"both_collection_only":1,"individual_to_collection_only":1,"one_positive_individual_response":1})
        self.assertEqual(sum(reasons.values()),extra["counts"]["individual"]["not_comparable"])
        self.assertEqual(len(extra["records"]),2)
        self.assertNotIn("response_changed",extra["counts"]["individual"])
