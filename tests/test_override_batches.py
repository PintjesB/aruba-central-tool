import unittest
from aruba_central.override_view import override_batch


class OverrideBatchTests(unittest.TestCase):
    def test_filtered_batches_are_complete_disjoint_and_sorted(self):
        findings = [{"device_name": f"device-{i:04}", "module": "roles", "identity": "role",
                     "result": "identical" if i % 2 else "different",
                     "review_candidate": bool(i % 2),
                     "removal": "review_removal" if i % 4 == 1 else "verification_required"}
                    for i in reversed(range(450))]
        expected = [f for f in reversed(findings) if f["review_candidate"]]
        batches = [override_batch(findings, offset=i) for i in range(0, len(expected), 100)]
        self.assertEqual([row for batch in batches for row in batch["rows"]], expected)
        self.assertTrue(all(batch["total"] == 225 for batch in batches))
        self.assertEqual([batch["truncated"] for batch in batches], [True, True, False])
        ready = override_batch(findings, result="all", readiness="review_removal", limit=1000)
        self.assertEqual(ready["rows"], [f for f in expected if f["removal"] == "review_removal"])
        self.assertEqual(override_batch(findings, offset=1000)["rows"], [])
        matching = override_batch(findings, result="all", query="device-0449 ROLES")
        self.assertEqual(matching["total"], 1)
        self.assertEqual(matching["rows"][0]["device_name"], "device-0449")
        with self.assertRaises(ValueError):
            override_batch(findings, offset=-1)
