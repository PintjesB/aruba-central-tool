import unittest
from unittest.mock import patch

from aruba_central.bulk_review import source_recipient_evidence, source_recipient_index
from aruba_central.consolidation import scope_memberships


class RecipientIndexTests(unittest.TestCase):
    def test_index_preserves_known_and_unknown_recipients(self):
        entry = {"scopes": [
            {"id": "1", "kind": "global", "name": "Global"},
            {"id": "2", "kind": "site", "metadata": {"id": 20}},
            {"id": "3", "kind": "group", "metadata": {"id": 30}},
            {"id": "4", "kind": "device", "name": "A", "metadata": {"siteId": 20, "deviceGroupId": 30}},
            {"id": "5", "kind": "device", "name": "B"},
        ]}
        index = source_recipient_index(entry)
        a, b = {"scope": "4", "name": "A"}, {"scope": "5", "name": "B"}
        cases = [
            ([{"scope": "2", "kind": "site"}], {"known": [a], "unknown": [b]}),
            ([{"scope": "2", "kind": "site"}, {"scope": "5", "kind": "device"}], {"known": [a, b], "unknown": [b]}),
            ([{"scope": "999", "kind": "site"}], {"known": [], "unknown": [a, b]}),
            ([{"scope": "2", "kind": "group"}], {"known": [], "unknown": [b]}),
            ([], {"known": [], "unknown": []}),
        ]
        with patch("aruba_central.bulk_review.scope_memberships", wraps=scope_memberships) as rebuild:
            for sources, expected in cases:
                self.assertEqual(source_recipient_evidence(entry, sources, index=index), expected)
            rebuild.assert_not_called()
        for sources, expected in cases:
            self.assertEqual(source_recipient_evidence(entry, sources), expected)
