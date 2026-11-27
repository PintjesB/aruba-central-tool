import unittest
from unittest.mock import Mock, patch

from aruba_central.central_tool import capture_keyed_profile_details, inspect_unadapted_profiles
from aruba_central.nac_authorization import capture_nac_configuration, nac_collection


class NACCollectionContractTests(unittest.TestCase):
    def test_default_only_modules_are_not_scope_surveyed(self):
        modules = ["auth-profiles", "authz-policies", "identity-stores"]
        discovery = {
            "unknown_adapter_modules": modules,
            "survey_modules": modules,
            "tenant_default_modules": modules,
            "modules": {m: ["ACCESS_SWITCH"] for m in modules},
        }
        client = Mock()
        result = inspect_unadapted_profiles(
            client, discovery, {}, {}, deep_catalog=True,
            scopes_by_persona={"ACCESS_SWITCH": [{"id": "1", "kind": "global"}]},
        )
        self.assertEqual(result, {})
        client.get.assert_not_called()

    def test_keyed_nac_reads_use_default_queries(self):
        client = Mock()
        policy = {"policy-id": "p"}
        auth = {"auth-profile-id": "a"}
        with patch("aruba_central.central_tool.keyed_profile_contracts", return_value={}), patch(
            "aruba_central.central_tool.keyed_profile_read", return_value={"status": "identity_observed"}
        ) as read:
            result = capture_keyed_profile_details(
                client, {}, {"modules": {"auth-profiles": {
                    "status": "list_parsed", "profiles": {"a": auth},
                }}}, workers=1, nac_configuration={"authz-policies": {
                    "status": "list_parsed", "profiles": {"p": policy},
                }},
            )
        read.assert_any_call(client, "authz-policies", "policy-id", "p", {}, policy)
        read.assert_any_call(client, "auth-profiles", "auth-profile-id", "a", {}, auth)
        self.assertEqual(read.call_count, 2)
        self.assertEqual(result["profiles"]["NAC"][""]["authz-policies"]["p"]["tenant"]["status"],
                         "identity_observed")

    def test_checkpoint_only_reuses_count_confirmed_nac_collections(self):
        client = Mock()
        checkpoint = Mock()
        def observe(phase, selector, read, qualifies):
            self.assertEqual(phase, "nac_configuration")
            self.assertTrue(qualifies({"status": "list_parsed", "count_confirmed": True}))
            self.assertFalse(qualifies({"status": "list_parsed", "count_confirmed": False}))
            self.assertFalse(qualifies({"status": "read_failed"}))
            return read()
        checkpoint.observe.side_effect = observe
        with patch("aruba_central.central_tool.read_module_view", return_value={"status": "list_parsed", "count_confirmed": True}) as read:
            result = capture_nac_configuration(client, checkpoint=checkpoint)
        self.assertEqual(len(result), 3)
        self.assertEqual(checkpoint.observe.call_count, 3)
        for call in read.call_args_list:
            self.assertEqual(call.args[-1], {})

    def test_static_tag_fallback_keeps_failed_tenant_read_visible(self):
        bundle = {
            "nac_configuration": {"static-tag": {"status": "request_rejected"}},
            "unadapted_profiles": {"static-tag": {"library": {
                "status": "response_received",
                "raw": {"metadata": {"total": 1}, "static-tag": [{"tag-id": "t"}]},
            }}},
        }
        result = nac_collection(bundle, "static-tag")
        self.assertEqual(result["qualification"], "raw_library_fallback")
        self.assertEqual(result["tenant_read_status"], "request_rejected")
        self.assertIn("t", result["profiles"])
