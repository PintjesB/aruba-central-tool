import unittest
from nac_review import read_mac_registrations, nac_review, normalized_mac


def row(id_, mac, tags=None):
    return {"id": id_, "macAddress": mac, "enable": True, "staticTags": tags or []}


class Client:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = []

    def get(self, path, **params):
        self.calls.append((path, params))
        return next(self.pages)


class NACReviewTests(unittest.TestCase):
    def test_cursor_collection_and_duplicate_mac_review(self):
        a, b = row("a", "AA:BB:CC:DD:EE:FF", ["tag-1"]), row("b", "aabb.ccdd.eeff", ["Office"])
        client = Client([{"items": [a], "macs": [a], "count": 1, "total": 2, "next": "page-2"},
                         {"items": [b], "count": 1, "total": 2, "next": ""}])
        data = read_mac_registrations(client)
        self.assertTrue(data["count_confirmed"])
        self.assertEqual(client.calls[1][1]["next"], "page-2")
        self.assertNotIn("offset", client.calls[1][1])
        bundle = {"nac_registrations": data, "unadapted_profiles": {"static-tag": {"library": {
            "status": "response_received", "raw": {"metadata": {"total": 1},
            "static-tag": [{"tag-id": "tag-1", "name": "Office"}]}}}}}
        report = nac_review(bundle)
        self.assertEqual(len(report["duplicate_mac_groups"]), 1)
        self.assertEqual(report["rows"][0]["references"][0]["status"], "observed_id")
        self.assertEqual(report["rows"][1]["references"][0]["status"], "observed_name_only")
        self.assertFalse(report["safe_to_apply"])

    def test_ambiguity_count_mismatch_and_duplicate_identity(self):
        a, b = row("a", "aa:bb:cc:dd:ee:ff"), row("b", "aa:bb:cc:dd:ee:11")
        data = read_mac_registrations(Client([{"items": [a], "macs": [b]}]))
        self.assertEqual(data["status"], "ambiguous_registration_envelope")
        self.assertFalse(data["count_confirmed"])
        data = read_mac_registrations(Client([{"items": [a], "total": 2, "next": "cursor"},
                                               {"items": [a], "total": 2}]))
        self.assertEqual(data["status"], "duplicate_or_unqualified_registration_identity")
        self.assertEqual(len(data["rows"]), 1)

    def test_offset_and_missing_count(self):
        a = row("a", "aa:bb:cc:dd:ee:ff")
        client = Client([{"macs": [a]}, {"macs": []}])
        data = read_mac_registrations(client)
        self.assertEqual(data["status"], "pagination_exhausted")
        self.assertFalse(data["count_confirmed"])
        self.assertEqual(client.calls[1][1]["offset"], 1)
        self.assertIsNone(normalized_mac("aa:bb:cc"))

    def test_absent_tag_field_is_not_empty(self):
        report = nac_review({"nac_registrations": {"rows": [{"id": "a", "macAddress": "aabbccddeeff"}]}})
        self.assertFalse(report["rows"][0]["tags_observed"])
        self.assertIsNone(report["rows"][0]["enabled"])
        self.assertFalse(report["count_confirmed"])
