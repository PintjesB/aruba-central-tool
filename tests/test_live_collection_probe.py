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
        with patch("central_tool.profile_inventory_view", return_value=assigned) as inventory, patch(
            "live_collection_probe.read_module_view", side_effect=[shared, {"status": "empty_object"}, shared]
        ) as read:
            result = assignment_context(Mock(), "snmp", scopes, library, 1)
        self.assertEqual(inventory.call_args.kwargs, {"profile-type": "snmp"})
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
