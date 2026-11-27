import unittest
from unittest.mock import patch

from aruba_central.configuration_history import configuration_drift


class CountingRows(list):
    def __init__(self, rows):
        super().__init__(rows)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


class DriftScopeIndexTests(unittest.TestCase):
    def test_index_preserves_first_scope_observation_and_avoids_repeated_scans(self):
        scopes = [{"id": str(i), "kind": "site", "name": str(i)} for i in range(20)]
        def view(value):
            return {"status": "list_parsed", "count_confirmed": True,
                    "profiles": {"example": {"name": "example", "value": value}}}
        def capture(value):
            rows = CountingRows([{"scope": str(i), "local_view": view(value if i == 1 else 0),
                                  "effective_view": view(0)} for i in range(20)] +
                                [{"scope": "1", "local_view": view(999), "effective_view": view(999)}])
            return {"results": {"ACCESS_SWITCH": {"scopes": scopes, "modules": {"dns": {"scope_results": rows}}}}}, rows
        before, a = capture(0)
        after, b = capture(1)
        with patch("aruba_central.configuration_history.snapshot_identity_checks", return_value={}):
            result = configuration_drift(before, after, confirmed=True)
        self.assertEqual(a.iterations, 1)
        self.assertEqual(b.iterations, 1)
        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["records"][0]["scope"], "1")
        self.assertEqual(result["records"][0]["view"], "local")
        self.assertEqual(result["records"][0]["status"], "changed")
        self.assertFalse(result["safe_to_apply"])
