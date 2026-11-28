import json
import unittest
from unittest.mock import patch
from aruba_central.pacing_probe import pacing_probe, selectors


class PacingProbeTests(unittest.TestCase):
    def fixture(self):
        scopes = [{"id": str(i), "kind": "device"} for i in range(40)]
        views = [{"scope": str(i), "effective_view": {"status": "list_parsed"}} for i in range(40)]
        previous = {"results": {"ACCESS_SWITCH": {"modules": {"dns": {"scope_results": views}}}}}
        return previous, {"ACCESS_SWITCH": {"scopes": scopes}}

    def test_identical_private_selectors_and_restored_pacing_mode(self):
        previous, qualified = self.fixture()
        class Client:
            _pacing_compensation_enabled = True
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append((self._pacing_compensation_enabled, path, params))
                return {"private-key": "private-value"}
            def get_transport_metrics(self):
                return {"http_get_attempts": len(self.calls)}
            def get_network_metrics(self):
                return {}
        client = Client()
        with patch("aruba_central.pacing_probe.ordered_parallel", side_effect=lambda tasks, read, workers: [read(t) for t in tasks]):
            report = pacing_probe(client, previous, qualified)
        self.assertEqual(report["selectors"], 40)
        self.assertEqual(report["response_comparison"], {"exact_response_match": 40})
        self.assertEqual([x[1:] for x in client.calls[:40]], [x[1:] for x in client.calls[40:]])
        self.assertTrue(client._pacing_compensation_enabled)
        self.assertNotIn("private", json.dumps(report))
        self.assertFalse(report["safe_to_apply"])

    def test_small_or_unqualified_population_does_not_start_probe(self):
        previous, qualified = self.fixture()
        qualified["ACCESS_SWITCH"]["scopes"] = qualified["ACCESS_SWITCH"]["scopes"][:5]
        self.assertEqual(len(selectors(previous, qualified)), 5)
        self.assertEqual(pacing_probe(None, previous, qualified)["status"], "insufficient_observed_selectors")
