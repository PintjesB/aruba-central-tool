import unittest

from aruba_central.port_conversion_review import port_conversion_review


class PortConversionIndexTests(unittest.TestCase):
    def test_visibility_and_saved_view_index_preserve_evidence(self):
        body = {"name": "1/1/1", "switchport": {"mode": "access"}}
        view = {"scope": "1", "local_view": {"status": "list_parsed", "profiles": {"1/1/1": body}}}
        entry = {"modules": {"ethernet-interfaces": {"scope_results": [view]}}}
        ports = [{"scope": sid, "port": "1/1/1", "device": sid,
                  "before": body, "unsupported": []} for sid in ("1", "2")]
        matches = [{"identity": "A", "visibility": [{"scope": "1", "status": "matching"}]},
                   {"identity": "B", "visibility": [{"scope": "1", "status": "different"},
                                                     {"scope": "1", "status": "matching"},
                                                     {"scope": "2", "status": "not_observed"}]}]
        portable = {"switchport": body["switchport"]}
        result = port_conversion_review(entry, ports, portable, matches, views={"1": view})
        self.assertEqual(result, port_conversion_review(entry, ports, portable, matches))
        self.assertEqual(result[0]["candidate_visibility"], {"A": "matching", "B": "different"})
        self.assertEqual(result[1]["candidate_visibility"], {"A": "unknown", "B": "not_observed"})
        self.assertEqual(result[0]["status"], "exact_saved_effective_match")
        self.assertEqual(result[1]["status"], "saved_configuration_unverified")
        self.assertTrue(all(not row["safe_to_apply"] for row in result))
