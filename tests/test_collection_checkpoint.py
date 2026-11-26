import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone

from collection_checkpoint import ScopeCheckpoint, mark_complete, qualification_manifest


class CheckpointTests(unittest.TestCase):
    def test_resume_only_qualified_pairs_and_seal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkpoint.db"
            checkpoint = ScopeCheckpoint(path, "manifest")
            view = {"status": "list_parsed", "count_confirmed": True, "profiles": {"20": {"vlan": 20}}}
            checkpoint.save("ACCESS_SWITCH", "layer2-vlan", "1", view, view)
            checkpoint.save("ACCESS_SWITCH", "layer2-vlan", "2", {**view, "count_confirmed": False}, view)
            with self.assertRaises(ValueError):
                ScopeCheckpoint(path, "manifest")
            with self.assertRaises(ValueError):
                ScopeCheckpoint(path, "other-tenant", resume=True)
            resumed = ScopeCheckpoint(path, "manifest", resume=True)
            self.assertEqual(resumed.get("ACCESS_SWITCH", "layer2-vlan", "1")["local"], view)
            self.assertIsNone(resumed.get("ACCESS_SWITCH", "layer2-vlan", "2"))
            self.assertTrue(resumed.evidence()["mixed_capture_times"])
            self.assertEqual(resumed.evidence()["qualified_pairs_saved"], 1)
            mark_complete(path)
            with self.assertRaises(ValueError):
                ScopeCheckpoint(path, "manifest", resume=True)

    def test_expiry_and_inventory_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkpoint.db"
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            ScopeCheckpoint(path, "manifest", now=lambda: start)
            with self.assertRaises(ValueError):
                ScopeCheckpoint(path, "manifest", resume=True, now=lambda: start + timedelta(hours=25))
        plans = [("ACCESS_SWITCH", {"layer2-vlan": ("vlan", {"ACCESS_SWITCH"}, False)},
                  [{"id": "1", "kind": "global"}, {"id": "2", "kind": "device", "metadata": {"siteId": "3"}}])]
        inventory = [{"inventory": {"serial": "A"}}]
        a = qualification_manifest("region", plans, inventory, "catalog")
        plans[0][2][1]["metadata"]["siteId"] = "4"
        self.assertNotEqual(a, qualification_manifest("region", plans, inventory, "catalog"))
        with self.assertRaises(ValueError):
            qualification_manifest("region", plans, [], "catalog")

    def test_mixed_capture_not_valid_for_remediation(self):
        from remediation_review import comparable
        with self.assertRaisesRegex(ValueError, "fresh captures"):
            comparable({}, {"collection_checkpoint": {"mixed_capture_times": True}}, True)
