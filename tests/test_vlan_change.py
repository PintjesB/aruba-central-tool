import copy
import unittest
from unittest.mock import Mock, patch

from aruba_central.vlan_change import (prepare, execute, transition, inverse, perform, direct_state,
                         device_state, writable, digest)

BODY = {"vlan": 100, "name": "Example", "enable": True}
LOCAL = {"aruba-annotation:object_type": "LOCAL", "aruba-annotation:inherited": False,
         "aruba-annotation:is_default": False}
SHARED = {**LOCAL, "aruba-annotation:object_type": "SHARED"}
INHERITED = {**LOCAL, "aruba-annotation:inherited": True}


def state(mode):
    ids = ("1", "2", "3", "4")
    st = {"region": "https://de2.api.central.arubanetworks.com", "persona": "ACCESS_SWITCH",
          "vlan": "100", "scope_identity": {i: {"entity": i} for i in ids},
          "kinds": {"1": "global", "2": "site", "3": "device", "4": "device"},
          "memberships": {i: {"global": "1", "site": "2", "group": None,
                              "collection": None, "complete": True} for i in ("3", "4")},
          "local": {i: {} for i in ids}, "effective": {i: {} for i in ids},
          "annotations": {i: {} for i in ids}, "assignments": [], "library": {},
          "svis": {"3": [], "4": []}, "operational": {"3": {"name": "Example"}, "4": {"name": "Example"}}}
    for i in ("3", "4"):
        st["local"][i]["100"] = copy.deepcopy(BODY)
        st["effective"][i]["100"] = copy.deepcopy(BODY)
        st["annotations"][i]["100"] = LOCAL.copy()
    if mode == "remove":
        st["local"]["1"]["100"] = BODY.copy()
        st["effective"]["1"]["100"] = BODY.copy()
        st["annotations"]["1"]["100"] = LOCAL.copy()
    return st


class Simulator:
    def __init__(self, initial, fail_verification=False):
        self.state = copy.deepcopy(initial)
        self.calls = []
        self.fail_verification = fail_verification

    def read(self, *_):
        return copy.deepcopy(self.state)

    def write(self, _client, _persona, vid, op):
        self.calls.append(op["kind"])
        self.state = transition(self.state, op)
        sid, kind = op.get("scope"), op["kind"]
        if kind == "create_local":
            self.state["annotations"][sid][vid] = LOCAL.copy()
            self.state["effective"][sid][vid] = op["body"].copy()
            if sid in ("3", "4"):
                self.state["operational"][sid]["name"] = "Example"
        elif kind == "delete_local":
            if sid in ("3", "4"):
                self.state["annotations"][sid][vid] = INHERITED.copy()
                if self.fail_verification:
                    self.state["operational"][sid]["name"] = "Changed"
            else:
                self.state["effective"][sid].pop(vid, None)
                self.state["annotations"][sid].pop(vid, None)
        elif kind == "assign":
            self.state["annotations"][sid][vid] = SHARED.copy()
            self.state["effective"][sid][vid] = self.state["library"][vid].copy()
        elif kind == "unassign":
            self.state["effective"][sid].pop(vid, None)
            self.state["annotations"][sid].pop(vid, None)


class VlanChangeTests(unittest.TestCase):
    def test_remove_promote_and_library(self):
        for mode, expected in (("remove", ["delete_local", "delete_local"]),
                               ("promote", ["create_local", "delete_local", "delete_local"]),
                               ("library", ["create_shared", "assign", "delete_local", "delete_local"])):
            with self.subTest(mode=mode):
                initial = state(mode)
                plan = prepare(initial, mode, ["4", "3"], None if mode == "remove" else "2")
                sim = Simulator(initial)
                journal = Mock()
                with patch("aruba_central.vlan_change.perform", side_effect=sim.write):
                    result = execute(Mock(), plan, journal, reader=sim.read, pause=lambda _: None)
                self.assertEqual(result, "verified_complete")
                self.assertEqual(sim.calls, expected)
                self.assertEqual(device_state(initial), device_state(sim.state))
                self.assertNotIn("100", sim.state["local"]["3"])
                self.assertTrue(any(call.args[0] == "verified_complete" for call in journal.record.call_args_list))

    def test_drift_and_conflicting_ancestor_and_extra_recipients_block(self):
        initial = state("remove")
        plan = prepare(initial, "remove", ["3", "4"])
        sim = Simulator(initial)
        sim.state["operational"]["3"]["name"] = "Changed"
        with patch("aruba_central.vlan_change.perform") as write:
            with self.assertRaises(ValueError):
                execute(Mock(), plan, Mock(), reader=sim.read)
            write.assert_not_called()
        initial["effective"]["2"]["100"] = {**BODY, "name": "Different"}
        with self.assertRaises(ValueError):
            prepare(initial, "remove", ["3", "4"])
        initial = state("promote")
        initial["memberships"]["5"] = initial["memberships"]["4"].copy()
        with self.assertRaises(ValueError):
            prepare(initial, "promote", ["3", "4"], "2")
        with self.assertRaises(ValueError):
            writable({**BODY, "is-l3-vlan": True})
        with self.assertRaises(ValueError):
            writable({**BODY, "unknown": False})

    def test_rollback_restores_before_removing_destination(self):
        initial = state("library")
        plan = prepare(initial, "library", ["3", "4"], "2")
        sim = Simulator(initial, fail_verification=True)
        with patch("aruba_central.vlan_change.perform", side_effect=sim.write):
            result = execute(Mock(), plan, Mock(), reader=sim.read, attempts=1)
        self.assertEqual(result, "restored")
        self.assertEqual(sim.calls, ["create_shared", "assign", "delete_local",
                                     "create_local", "unassign", "delete_shared"])
        self.assertEqual(direct_state(initial), direct_state(sim.state))
        self.assertEqual(device_state(initial), device_state(sim.state))

    def test_uncertain_write_never_retries_or_rolls_back_blindly(self):
        initial = state("remove")
        plan = prepare(initial, "remove", ["3", "4"])
        sim = Simulator(initial)
        with patch("aruba_central.vlan_change.perform", side_effect=TimeoutError) as write:
            result = execute(Mock(), plan, Mock(), reader=sim.read)
        self.assertEqual(result, "manual_recovery_required")
        write.assert_called_once()

    def test_explicit_api_contracts(self):
        client = Mock()
        perform(client, "ACCESS_SWITCH", "100", {"kind": "create_local", "scope": "123", "body": BODY})
        client.change.assert_called_once_with("POST", "/network-config/v1alpha1/layer2-vlan/100",
            {"object-type": "LOCAL", "scope-id": "123", "device-function": "ACCESS_SWITCH"}, BODY)
        client.reset_mock()
        perform(client, "ACCESS_SWITCH", "100", {"kind": "assign", "scope": "123"})
        client.change.assert_called_once_with("POST", "/network-config/v1alpha1/config-assignments", {},
            {"config-assignment": [{"scope-id": "123", "device-function": "ACCESS_SWITCH",
                                     "profile-type": "layer2-vlan", "profile-instance": "100"}]})
        client.reset_mock()
        perform(client, "ACCESS_SWITCH", "100", {"kind": "unassign", "scope": "123"})
        client.change.assert_called_once_with("DELETE",
            "/network-config/v1alpha1/config-assignments/123/ACCESS_SWITCH/layer2-vlan/100", {}, None)
