import unittest
from aruba_central.port_conversion_review import port_conversion_review


class PortConversionTests(unittest.TestCase):
    def test_saved_effective_evidence_and_visibility(self):
        common = {"name": "1/1/1", "description": "desk", "switchport": {"access-vlan": 10}}
        portable = {"switchport": {"access-vlan": 10}}
        ports = [{"scope": "1", "port": "1/1/1", "device": "A", "before": common, "unsupported": []}]
        matches = [{"identity": "Office", "visibility": [{"scope": "1", "status": "matching"}]}]
        entry = {"modules": {"ethernet-interfaces": {"scope_results": [{"scope": "1", "local_view": {
            "status": "list_parsed", "profiles": {"1/1/1": common}}}]}}}
        row = port_conversion_review(entry, ports, portable, matches)[0]
        self.assertEqual(row["status"], "exact_saved_effective_match")
        self.assertEqual(row["retained_local_fields"], {"name": "1/1/1", "description": "desk"})
        self.assertEqual(row["proposed_shared_fields"], ["switchport"])
        self.assertEqual(row["candidate_visibility"], {"Office": "matching"})
        self.assertFalse(row["safe_to_apply"])
        entry["modules"]["ethernet-interfaces"]["scope_results"][0]["local_view"]["profiles"]["1/1/1"] = {"name": "1/1/1"}
        self.assertEqual(port_conversion_review(entry, ports, portable, matches)[0]["status"], "saved_effective_differ")
        entry["modules"]["ethernet-interfaces"]["scope_results"][0]["local_view"] = {}
        self.assertEqual(port_conversion_review(entry, ports, portable, matches)[0]["status"], "saved_configuration_unverified")
