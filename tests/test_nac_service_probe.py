import json
import unittest
from aruba_central.nac_service_probe import nac_service_probe, ENDPOINTS


class NACServiceProbeTests(unittest.TestCase):
    def test_reads_only_safe_observed_identities_and_exports_counts(self):
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append((path, params))
                if path.endswith("/cnac-dpp-reg"):
                    return {"items": [{"id": "private-dpp", "uri": "private-uri"}], "count": 1}
                if path.endswith("/cnac-job"):
                    return {"items": [{"id": "private-job", "errorMessage": "private-error"}], "count": 1, "total": 1}
                if path.endswith("/private-dpp"):
                    return {"id": "private-dpp", "uri": "private-uri"}
                if path.endswith("/private-job/status"):
                    return {"id": "private-job", "status": "private-status"}
                raise AssertionError("Unexpected path")
        client = Client()
        report = nac_service_probe(client)
        self.assertEqual(len(client.calls), 4)
        self.assertEqual(report["operations"][1]["outcomes"], {"identity_observed": 1})
        self.assertEqual(report["operations"][3]["outcomes"], {"identity_observed": 1})
        self.assertEqual(report["endpoint_policy"]["cnac-certificate"], "requires_user_principal_name")
        self.assertNotIn("private", json.dumps(report))
        self.assertFalse(report["complete"])

    def test_no_detail_read_for_unsafe_or_duplicate_identities(self):
        class Client:
            def get(self, path, **params):
                self.assert_list(path)
                return {"items": [{"id": "../unsafe"}, {"id": "../unsafe"}]}
            def assert_list(self, path):
                if not path.endswith(("/cnac-dpp-reg", "/cnac-job")):
                    raise AssertionError("Detail read attempted")
        report = nac_service_probe(Client())
        self.assertEqual(report["operations"][0]["status"], "identity_or_page_unqualified")
        self.assertEqual(report["operations"][1]["attempted"], 0)
        self.assertEqual(report["operations"][3]["attempted"], 0)
