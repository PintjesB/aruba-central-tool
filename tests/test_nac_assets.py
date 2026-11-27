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
