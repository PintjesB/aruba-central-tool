import unittest
from aruba_central.optimization_dependencies import attach_dependency_review


class OptimizationDependencyTests(unittest.TestCase):
    def test_context_and_unresolved_reference_evidence(self):
        def ref(persona, module, source, target_module, target, status="observed", scope="1"):
            return {"persona": persona, "scope": scope, "device": "Device", "source_module": module,
                    "source": source, "target_module": target_module, "target": target,
                    "status": status, "source_scope_kind": "device", "source_view": "effective"}
        finding = {"persona": "ACCESS_SWITCH", "module": "layer2-vlan", "identity": "20"}
        refs = [ref("ACCESS_SWITCH", "ethernet-interfaces", "1/1/1", "layer2-vlan", "20"),
                ref("ACCESS_SWITCH", "ethernet-interfaces", "1/1/2", "layer2-vlan", None, "unresolved"),
                ref("ACCESS_SWITCH", "layer2-vlan", "20", "roles", "role", "unresolved"),
                ref("CAMPUS_AP", "wlan-ssids", "ssid", "layer2-vlan", "20"),
                ref("Library", "sw-port-profiles", "p", "layer2-vlan", "20", "definition_observed")]
        report = attach_dependency_review([finding], refs)[0]["dependency_review"]
        self.assertEqual(len(report["consumers"]), 2)
        self.assertEqual(len(report["dependencies"]), 1)
        self.assertEqual(len(report["unresolved_target_observations"]), 1)
        self.assertEqual(report["observed_consumer_devices"], 2)
        self.assertEqual(len(report["unqualified_edges"]), 1)
        self.assertFalse(report["safe_to_apply"])
        self.assertFalse(report["complete"])
