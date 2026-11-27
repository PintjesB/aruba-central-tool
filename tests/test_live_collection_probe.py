import json
import unittest
from unittest.mock import Mock, patch

from live_collection_probe import probe, qualified_scopes


class LiveProbeTests(unittest.TestCase):
    def test_identity_guard_filters_replaced_devices(self):
        previous = {"region": "region", "inventory": [{"inventory": {"serial": "S1"}}],
                    "results": {"ACCESS_SWITCH": {"scopes": [{"id": "1", "kind": "global"}]}}}
        devices = [{"serial": "S1", "deviceFunction": "Access Switch"},
                   {"serial": "S2", "deviceFunction": "Access Switch"}]
        scopes = [{"id": "1", "kind": "global"},
                  {"id": "2", "kind": "device", "metadata": devices[0]},
                  {"id": "3", "kind": "device", "metadata": devices[1]}]
        with patch("live_collection_probe.inventory", return_value=devices), patch(
            "live_collection_probe.discover_scopes", return_value=(scopes, [])
        ):
            qualified = qualified_scopes(Mock(base="region"), previous)
            self.assertEqual([s["id"] for s in qualified["ACCESS_SWITCH"]["scopes"]], ["1", "2"])
            with self.assertRaises(ValueError):
                qualified_scopes(Mock(base="other-region"), previous)

    def test_probe_reads_live_collections_and_keyed_evidence_without_identifiers(self):
        scopes = {"ACCESS_SWITCH": {"scopes": [
            {"id": "100", "kind": "global"}, {"id": "200", "kind": "device"},
            {"id": "300", "kind": "device"}]}}
        view = {"status": "list_parsed", "profiles": {
            "1/1/24": {"name": "1/1/24", "description": "PRIVATE-VALUE"},
            "1/1/25": {"name": "1/1/25"}}, "count_confirmed": True}
        client = Mock()
        with patch("live_collection_probe.qualified_scopes", return_value=scopes), patch(
            "live_collection_probe.keyed_profile_contracts", return_value={"ethernet-interfaces": "name"}
        ), patch("live_collection_probe.read_module_view", return_value=view) as read, patch(
            "live_collection_probe.keyed_profile_read", return_value={"status": "identity_observed"}
        ) as keyed:
            result = probe(client, {}, ["ethernet-interfaces"], sample=1)
        self.assertEqual(read.call_count, 2)
        self.assertEqual(keyed.call_count, 2)
        for call in read.call_args_list:
            self.assertEqual(call.args[3]["scope-id"], "200")
        self.assertEqual({r["view"] for r in result["keyed"]}, {"local", "effective"})
        self.assertFalse(result["complete"])
        serialized = json.dumps(result)
        for secret in ("1/1/24", "1/1/25", "PRIVATE-VALUE", "200", "300"):
            self.assertNotIn(secret, serialized)


    def test_assignment_context_reads_assigned_group_not_arbitrary_device(self):
        from live_collection_probe import assignment_context
        scopes = {"ACCESS_SWITCH": {"scopes": [{"id": "100", "kind": "group"},
                                                 {"id": "200", "kind": "device"}]}}
        definition = {"name": "PRIVATE-PROFILE", "enable": True}
        library = {"status": "list_parsed", "profiles": {"PRIVATE-PROFILE": definition, "other": {"name": "other"}}}
        row = {"profile-type": "snmp", "profile-instance": "PRIVATE-PROFILE",
               "scope-id": "100", "device-function": "ACCESS_SWITCH"}
        assigned = {"status": "response_received", "collection_count_verified": True, "rows": [row, row]}
        shared = {"status": "list_parsed", "profiles": {"PRIVATE-PROFILE": {
            **definition, "@": {"aruba-annotation:object_type": "SHARED"}}}, "count_confirmed": True}
        with patch("central_tool.profile_inventory_view", side_effect=[assigned, assigned, {"status": "response_received", "rows": []}, assigned]) as inventory, patch(
            "live_collection_probe.read_module_view", side_effect=[shared, {"status": "empty_object"}, shared]
        ) as read:
            result = assignment_context(Mock(), "snmp", scopes, library, 1)
        self.assertEqual(inventory.call_args_list[0].kwargs, {"profile-type": "snmp"})
        self.assertEqual(inventory.call_args_list[1].kwargs, {})
        self.assertEqual(inventory.call_args_list[2].kwargs, {"scope-id": "200", "device-function": "ACCESS_SWITCH"})
        self.assertEqual(inventory.call_args_list[3].kwargs, {"scope-id": "100", "device-function": "ACCESS_SWITCH"})
        self.assertEqual(result["observed_assignments"], 1)
        self.assertEqual(result["library_profiles_without_observed_assignment"], 1)
        self.assertEqual(result["sampled_assignment_contexts"], 1)
        self.assertEqual(read.call_count, 3)
        self.assertTrue(all(c.args[3]["scope-id"] == "100" for c in read.call_args_list))
        self.assertEqual({v["observation"] for v in result["visibility"]},
                         {"matching_shared", "visibility_unverified"})
        self.assertFalse(result["complete"])
        self.assertNotIn("PRIVATE-PROFILE", json.dumps(result))
        self.assertNotIn('"100"', json.dumps(result))


    def test_empty_filtered_read_recovers_tenant_and_scoped_assignments(self):
        from live_collection_probe import assignment_context
        scopes = {"ACCESS_SWITCH": {"scopes": [{"id": "12345", "kind": "site"}]}}
        definition = {"name": "PRIVATE-NAME"}
        library = {"status": "list_parsed", "profiles": {"PRIVATE-NAME": definition}}
        row = {"profile-type": "net-groups", "profile-instance": "PRIVATE-NAME",
               "scope-id": "12345", "device-function": "ACCESS_SWITCH"}
        other = {**row, "profile-type": "other-type", "profile-instance": "PRIVATE-OTHER"}
        empty = {"status": "response_received", "rows": [],
                 "raw": {"config-assignment": []}, "collection_count_verified": True}
        tenant = {"status": "response_received", "rows": [row, other],
                  "raw": {"config-assignment": [row, other]}}
        with patch("central_tool.profile_inventory_view", side_effect=[empty, tenant, tenant]), patch(
            "live_collection_probe.read_module_view", return_value={"status": "empty_object"}
        ):
            result = assignment_context(Mock(), "net-groups", scopes, library, 1)
        self.assertEqual(result["observed_assignments"], 1)
        self.assertEqual(result["tenant_only_assignments"], 1)
        self.assertEqual(result["additional_assignments"], 1)
        self.assertFalse(result["assignment_count_confirmed"])
        self.assertEqual(result["assignment_reads"][1]["other_type_rows"], 1)
        self.assertEqual(result["assignment_reads"][0]["response_shape"], "expected_list")
        self.assertEqual(result["invalid_or_unrelated_rows"], 0)
        self.assertFalse(result["complete"])
        for secret in ("PRIVATE-NAME", "PRIVATE-OTHER", "12345", "other-type"):
            self.assertNotIn(secret, json.dumps(result))


    def test_specialized_probe_uses_bounded_current_scopes_and_anonymous_results(self):
        from live_collection_probe import specialized_probe
        scopes = {"ACCESS_SWITCH": {"scopes": [
            {"id": "12345", "kind": "global"}, {"id": "23456", "kind": "device"},
            {"id": "34567", "kind": "device"}]}}
        rows = [{"scope-id": "12345", "device-function": "ACCESS_SWITCH",
                 "profile-type": "dns", "profile-instance": "PRIVATE-" + str(i)}
                for i in range(5)]
        previous = {"library": {"assignments": {"rows": rows}},
                    "scope_hierarchy_evidence": {"records": [
                        {"scope": "23456", "kind": "device", "status": "request_rejected"},
                        {"scope": "45678", "kind": "device", "status": "request_rejected"}]}}
        view = {"status": "request_rejected", "http_error": 400}
        with patch("live_collection_probe.qualified_scopes", return_value=scopes), patch(
            "central_tool.read_raw_profile_collection", return_value=view) as read, patch(
            "scope_evidence.hierarchy_capture", return_value={"records": []}) as hierarchy, patch(
            "scope_evidence.keyed_assignment_capture", return_value={"outcomes": {"identity_observed": 2}}) as assignments, patch(
            "nac_assets.capture_portal_assets", return_value={"images": [], "count_confirmed": True,
                                                            "status": "list_parsed"}) as assets:
            result = specialized_probe(Mock(), previous)
        self.assertEqual(read.call_count, 18)
        self.assertEqual(len(result["collections"]), 18)
        self.assertTrue(all(c["http_error"] == 400 for c in result["collections"]))
        self.assertEqual(hierarchy.call_args.args[1], {"sample": [{"id": "23456", "kind": "device"}]})
        self.assertEqual(assignments.call_args.args[1]["rows"], rows[:2])
        self.assertEqual(assets.call_args.kwargs, {"detail_limit": 2})
        self.assertFalse(result["complete"])
        self.assertFalse(result["safe_to_apply"])
        for private in ("12345", "23456", "34567", "45678", "PRIVATE-"):
            self.assertNotIn(private, json.dumps(result))
