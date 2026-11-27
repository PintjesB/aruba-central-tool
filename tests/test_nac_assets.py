import unittest
from central_tool import APIError
from nac_assets import capture_portal_assets


class PortalAssetTests(unittest.TestCase):
    def test_list_and_details_with_exact_observed_identity(self):
        a = {"imageID": "image a", "fileName": "logo.png", "referencedBy": ["portal"]}
        b = {"imageID": "b", "fileName": "b.png"}
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append(path)
                if path.endswith("cnac-image"):
                    return {"count": 2, "items": [a, b]}
                if path.endswith("/b"):
                    raise APIError(path, 404)
                return {**a, "fileSize": 200}
        client = Client()
        result = capture_portal_assets(client)
        self.assertTrue(result["count_confirmed"])
        self.assertEqual(result["outcomes"], {"identity_observed": 1, "request_rejected": 1})
        self.assertIn("image%20a", client.calls[2])
        self.assertTrue(result["details"]["image a"]["differences"])
        self.assertFalse(result["safe_to_apply"])

    def test_singleton_image_envelope_requires_matching_identity_and_count(self):
        class Client:
            def __init__(self, body):
                self.body = body
            def get(self, path, **params):
                if path.endswith("cnac-image"):
                    return {"count": 1, "items": [{"imageID": "a"}]}
                return self.body
        good = {"count": 1, "items": [{"imageID": "a", "fileSize": 0}]}
        result = capture_portal_assets(Client(good))
        self.assertEqual(result["details"]["a"]["status"], "identity_observed")
        self.assertEqual(result["details"]["a"]["differences"][0]["reference_value"], 0)
        for bad in ({"count": 2, "items": [{"imageID": "a"}]},
                    {"count": 1, "items": [{"imageID": "b"}]},
                    {"items": [{"imageID": "a"}, {"imageID": "b"}]}):
            self.assertEqual(capture_portal_assets(Client(bad))["details"]["a"]["status"],
                             "identity_unresolved")

    def test_invalid_and_duplicate_ids_are_not_queried(self):
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append(path)
                if path.endswith("cnac-image"):
                    return {"count": 3, "items": [{"imageID": "a"}, {"imageID": "a"}, {"imageID": "../bad"}]}
                return {"imageID": "different"}
        client = Client()
        result = capture_portal_assets(client)
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(result["status"], "identity_unresolved")
        self.assertFalse(result["count_confirmed"])
        self.assertEqual(result["details"]["a"]["status"], "identity_unresolved")
        self.assertEqual(result["duplicate_records"], 1)
        self.assertEqual(result["invalid_records"], 1)


    def test_live_camelcase_image_identity_and_alias_conflicts(self):
        class Client:
            def __init__(self, rows, detail):
                self.rows, self.detail = rows, detail
                self.calls = []
            def get(self, path, **params):
                self.calls.append(path)
                if path.endswith("/cnac-image"):
                    return {"count": len(self.rows), "items": self.rows}
                return self.detail
        row = {"imageId": "a", "fileName": "logo.png", "referencedBy": ["portal"]}
        client = Client([row], {"count": 1, "items": [{"imageID": "a", "fileName": "logo.png",
                                                       "referencedBy": ["portal"]}]})
        result = capture_portal_assets(client)
        self.assertTrue(result["count_confirmed"])
        self.assertEqual(result["images"], [row])
        self.assertEqual(result["details"]["a"]["status"], "identity_observed")
        self.assertEqual(result["details"]["a"]["differences"], [])
        self.assertEqual(len(client.calls), 2)
        client = Client([{**row, "imageID": "b"}], {})
        result = capture_portal_assets(client)
        self.assertFalse(result["count_confirmed"])
        self.assertEqual(result["invalid_records"], 1)
        self.assertEqual(len(client.calls), 1)
