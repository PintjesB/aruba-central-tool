import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from aruba_central.audit_windows import collect_audit_window


class AuditWindowTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 11, 20, tzinfo=timezone.utc)
        self.end = self.start + timedelta(hours=2)
        self.rows = [
            {"id": str(i), "occurredOn": (self.start + timedelta(seconds=i * 5)).isoformat()}
            for i in range(1200)
        ]

    def response(self, path, **params):
        lo = datetime.fromisoformat(params["start-at"].replace("Z", "+00:00"))
        hi = datetime.fromisoformat(params["end-at"].replace("Z", "+00:00"))
        rows = [r for r in self.rows if lo <= datetime.fromisoformat(r["occurredOn"]) <= hi]
        return {"items": rows[:1000], "total": len(rows), "count": 1000, "offset": 1}

    def test_truncated_window_reconciles(self):
        client = Mock()
        client.get.side_effect = self.response
        report, rows = collect_audit_window(client, self.start, self.end)
        self.assertTrue(report["complete_window"])
        self.assertTrue(report["subdivision_reconciled"])
        self.assertEqual(len(rows), 1200)
        self.assertEqual(client.get.call_count, 4)

    def test_budget_exhaustion_does_not_qualify(self):
        client = Mock()
        client.get.side_effect = self.response
        report, rows = collect_audit_window(client, self.start, self.end, max_requests=3)
        self.assertFalse(report["complete_window"])
        self.assertEqual(len(rows), 1000)
        self.assertEqual(client.get.call_count, 1)

    def test_parent_changes_do_not_qualify(self):
        client = Mock()
        calls = 0
        def response(path, **params):
            nonlocal calls
            calls += 1
            result = self.response(path, **params)
            if calls == 4:
                result["total"] += 1
            return result
        client.get.side_effect = response
        report, rows = collect_audit_window(client, self.start, self.end)
        self.assertFalse(report["complete_window"])
        self.assertFalse(report["parent_stable"])
        self.assertEqual(len(rows), 1200)
