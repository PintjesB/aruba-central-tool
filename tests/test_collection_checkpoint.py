import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone

from aruba_central.collection_checkpoint import ScopeCheckpoint, mark_complete, qualification_manifest


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

    def test_fresh_checkpoint_misses_do_not_open_database(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            cp = ScopeCheckpoint(Path(tmp) / "checkpoint.db", "manifest")
            with patch.object(cp, "_connect", wraps=cp._connect) as connect:
                self.assertIsNone(cp.get("ACCESS_SWITCH", "dns", "1"))
                self.assertEqual(cp.observe("raw_catalog", ["missing"],
                                            lambda: {"ok": False}, lambda v: v["ok"]), {"ok": False})
                connect.assert_not_called()
                cp.observe("raw_catalog", ["saved"], lambda: {"ok": True}, lambda v: v["ok"])
                self.assertEqual(connect.call_count, 1)
                self.assertEqual(cp.observe("raw_catalog", ["saved"], lambda: self.fail("unexpected read"),
                                            lambda v: v["ok"]), {"ok": True})
                self.assertEqual(connect.call_count, 2)

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
        from aruba_central.remediation_review import comparable
        with self.assertRaisesRegex(ValueError, "fresh captures"):
            comparable({}, {"collection_checkpoint": {"mixed_capture_times": True}}, True)


    def test_phase_checkpoint_retries_incomplete_and_binds_selector(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkpoint.db"
            cp = ScopeCheckpoint(path, "manifest")
            qualified = lambda v: v.get("collection_count_verified") is True
            selector = ["module", {"scope-id": "1", "effective": "true"}]
            incomplete = {"status": "partial_response", "collection_count_verified": False}
            complete = {"status": "response_received", "collection_count_verified": True, "raw": {"profiles": []}}
            self.assertEqual(cp.observe("raw_catalog", selector, lambda: incomplete, qualified), incomplete)
            self.assertEqual(cp.observe("raw_catalog", selector, lambda: complete, qualified), complete)
            resumed = ScopeCheckpoint(path, "manifest", resume=True)
            def unexpected():
                self.fail("Qualified observation should be reused")
            self.assertEqual(resumed.observe("raw_catalog", selector, unexpected, qualified), complete)
            self.assertEqual(resumed.evidence()["additional_observations_reused"], {"raw_catalog": 1})
            self.assertTrue(resumed.evidence()["mixed_capture_times"])
            self.assertEqual(resumed.observe("raw_catalog", ["different"], lambda: incomplete, qualified), incomplete)
            self.assertEqual(resumed.observe("library", selector, lambda: incomplete, qualified), incomplete)
            self.assertEqual(resumed.evidence()["additional_observations_saved"], {"raw_catalog": 1})

    def test_workspace_lists_only_valid_checkpoints(self):
        from aruba_central.collection_checkpoint import available_checkpoints
        from aruba_central.config_app import Workspace
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path = directory / ("collection-" + "a" * 32 + ".db")
            cp = ScopeCheckpoint(path, "manifest")
            view = {"status": "list_parsed", "count_confirmed": True, "profiles": {}}
            cp.save("ACCESS_SWITCH", "layer2-vlan", "1", view, view)
            ScopeCheckpoint(directory / ("collection-" + "b" * 32 + ".db"), "manifest",
                            now=lambda: datetime.now(timezone.utc) - timedelta(hours=25))
            (directory / ("collection-" + "c" * 32 + ".db")).write_text("invalid")
            self.assertEqual([row["name"] for row in available_checkpoints(directory)], [path.name])
            html = Workspace(directory).home()
            self.assertIn("Collection recovery", html)
            self.assertIn(path.name, html)
            self.assertIn("1 saved scope pairs", html)
            mark_complete(path)
            self.assertEqual(available_checkpoints(directory), [])
            self.assertNotIn(path.name, Workspace(directory).home())


    def test_manifest_ignores_volatile_observations_but_not_identity_changes(self):
        device = {"scopeId": "2", "serial": "A", "siteId": "3", "deviceFunction": "ACCESS_SWITCH",
                  "model": "6200", "firmwareVersion": "10.15", "lastSeen": "yesterday", "status": "up"}
        plans = [("ACCESS_SWITCH", {"layer2-vlan": ("vlan", {"ACCESS_SWITCH"}, False)},
                  [{"id": "1", "kind": "global"}, {"id": "2", "kind": "device", "metadata": device}])]
        inventory = [{"inventory": device}]
        stable = qualification_manifest("region", plans, inventory, "catalog")
        legacy = qualification_manifest("region", plans, inventory, "catalog", legacy=True)
        device.update(lastSeen="today", status="down")
        self.assertEqual(stable, qualification_manifest("region", plans, inventory, "catalog"))
        self.assertNotEqual(legacy, qualification_manifest("region", plans, inventory, "catalog", legacy=True))
        device["firmwareVersion"] = "10.16"
        self.assertNotEqual(stable, qualification_manifest("region", plans, inventory, "catalog"))
        device["firmwareVersion"] = "10.15"
        device["siteId"] = "4"
        self.assertNotEqual(stable, qualification_manifest("region", plans, inventory, "catalog"))

    def test_legacy_compatibility_requires_exact_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkpoint.db"
            ScopeCheckpoint(path, "legacy")
            with self.assertRaises(ValueError):
                ScopeCheckpoint(path, "new", resume=True, compatible_manifests=["different"])
            resumed = ScopeCheckpoint(path, "new", resume=True, compatible_manifests=["legacy"])
            self.assertEqual(resumed.manifest, "legacy")
