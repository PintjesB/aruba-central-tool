import unittest
from central_tool import APIError
from scope_evidence import hierarchy_capture, keyed_assignment_capture


class ScopeEvidenceTests(unittest.TestCase):
    def test_hierarchy_reads_discovered_scopes_once_and_preserves_failures(self):
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append((path, params))
                if params["id"] == "2":
                    raise APIError(path, 403)
                return {"items": [{"id": params["id"], "Hierarchy": []}]}
        client = Client()
        shared = {"id": "1", "kind": "global"}
        result = hierarchy_capture(client, {
            "ACCESS_SWITCH": [shared, {"id": "2", "kind": "device"}],
            "CAMPUS_AP": [shared, {"id": "../invalid", "kind": "site"}]})
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(client.calls[0], ("/network-config/v1/hierarchy", {"id": "1", "type": "org"}))
        self.assertEqual(result["outcomes"], {"response_received": 1, "request_rejected": 1})
        self.assertEqual(result["records"][1]["http_error"], 403)
        self.assertFalse(result["complete"])

    def test_keyed_assignments_validate_exact_identity_and_encode_safe_selectors(self):
        a = {"scope-id": 12, "device-function": "ACCESS_SWITCH", "profile-type": "ethernet-interfaces",
             "profile-instance": "1/1/24"}
        b = {**a, "profile-type": "dns", "profile-instance": "profile name"}
        invalid = {**a, "profile-instance": "../bad"}
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append(path)
                return {"config-assignment": [a]} if path.endswith("1%2F1%2F24") else b | {"scope-id": 99}
        client = Client()
        result = keyed_assignment_capture(client, {"rows": [a, a, b, invalid]})
        self.assertEqual(len(client.calls), 2)
        self.assertIn("profile%20name", client.calls[0])
        self.assertIn("1%2F1%2F24", client.calls[1])
        self.assertEqual(result["outcomes"], {"identity_unresolved": 1, "identity_observed": 1, "invalid_selector": 1})
        self.assertTrue(result["records"][1]["body_matches_inventory"])
        self.assertFalse(result["safe_to_apply"])

    def test_keyed_assignment_requests_explicit_context_and_checks_metadata(self):
        row = {"scope-id": "12", "device-function": "ACCESS_SWITCH",
               "profile-type": "dns", "profile-instance": "example"}
        class Client:
            def __init__(self, raw):
                self.raw = raw
                self.calls = []
            def get(self, path, **params):
                self.calls.append((path, params))
                return self.raw
        for raw, expected in ((row, "identity_observed"),
                              ({"config-assignment": [row], "metadata": {"count": 1}}, "identity_observed"),
                              ({"config-assignment": [row], "metadata": {"total": 2}}, "count_mismatch"),
                              ({"config-assignment": [row], "metadata": "invalid"}, "count_mismatch")):
            client = Client(raw)
            result = keyed_assignment_capture(client, {"rows": [row]})
            self.assertEqual(result["outcomes"], {expected: 1})
            self.assertEqual(client.calls[0][1], {"view-type": "LOCAL", "scope-id": "12",
                    "device-function": "ACCESS_SWITCH", "effective": "false", "detailed": "true"})
            self.assertFalse(result["complete"])

    def test_authentication_and_rate_limit_failures_propagate(self):
        class Client:
            def get(self, path, **params):
                raise APIError(path, 429)
        with self.assertRaises(APIError):
            hierarchy_capture(Client(), {"ACCESS_SWITCH": [{"id": "1", "kind": "global"}]})


    def test_scope_only_assignment_response_is_not_identity_verification(self):
        row = {"scope-id": 12, "device-function": "ACCESS_SWITCH",
               "profile-type": "dns", "profile-instance": "example"}
        class Client:
            def __init__(self, raw):
                self.raw = raw
            def get(self, path, **params):
                return self.raw
        raw = {"scope-id": 12, "scope-name": "example", "other": [], "extra": {}}
        result = keyed_assignment_capture(Client(raw), {"rows": [row]})
        self.assertEqual(result["outcomes"], {"scope_only_observed": 1})
        record = result["records"][0]
        self.assertEqual(record["missing_identity_fields"], ["device-function", "profile-type", "profile-instance"])
        self.assertNotIn("body_matches_inventory", record)
        self.assertEqual(record["raw"], raw)
        self.assertFalse(result["complete"])
        for bad in ({**raw, "scope-id": 99}, {**raw, "profile-type": "ntp"}):
            result = keyed_assignment_capture(Client(bad), {"rows": [row]})
            self.assertEqual(result["outcomes"], {"identity_unresolved": 1})
