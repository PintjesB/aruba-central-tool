import unittest
from aruba_central.configuration_history import configuration_drift, reference_compliance, view_changes


def view(name="Office", confirmed=True):
    return {"status": "list_parsed", "count_confirmed": confirmed,
            "profiles": {"20": {"vlan": 20, "name": name}}}


def snapshot(name="Office"):
    scopes = [{"id": "1", "kind": "global", "name": "Global"},
              {"id": "2", "kind": "site", "name": "Site"},
              {"id": "3", "kind": "device", "name": "Reference",
               "metadata": {"siteId": "2", "serial": "A"}},
              {"id": "4", "kind": "device", "name": "Target",
               "metadata": {"siteId": "2", "serial": "B"}},
              {"id": "5", "kind": "device", "name": "Unknown",
               "metadata": {"serial": "C"}}]
    records = [{"scope": sid, "scope_kind": next(s["kind"] for s in scopes if s["id"] == sid),
                "local_view": view(value), "effective_view": view(value)}
               for sid, value in (("1", "Office"), ("3", "Office"), ("4", name))]
    return {"schema": 1, "kind": "configuration_audit", "region": "https://de1.example",
            "inventory": [{"inventory": {"serial": s}} for s in ("A", "B", "C")],
            "results": {"ACCESS_SWITCH": {"scopes": scopes,
                        "modules": {"layer2-vlan": {"scope_results": records}}}},
            "library": {"modules": {"layer2-vlan": view(name)}}}


class HistoryTests(unittest.TestCase):
    def test_drift_separates_saved_effective_and_library(self):
        a, b = snapshot(), snapshot("Changed")
        with self.assertRaises(ValueError):
            configuration_drift(a, b)
        result = configuration_drift(a, b, confirmed=True)
        self.assertEqual(result["counts"], {"changed": 3})
        self.assertEqual({r["view"] for r in result["records"]}, {"local", "effective", "library"})
        self.assertFalse(result["identity_checks"]["same_tenant_verified"])
        self.assertFalse(result["safe_to_apply"])
        b["inventory"] = [{"inventory": {"serial": "Other"}}]
        with self.assertRaises(ValueError):
            configuration_drift(a, b, confirmed=True)

    def test_missing_collection_count_is_not_a_removal(self):
        a = view()
        b = {"status": "list_parsed", "profiles": {}}
        self.assertEqual(view_changes(a, b)[0]["status"], "presence_unverified")
        b["count_confirmed"] = True
        self.assertEqual(view_changes(a, b)[0]["status"], "removed")
        self.assertEqual(view_changes(a, {"status": "request_rejected"})[0]["status"], "unavailable")
        self.assertEqual(view_changes(view(confirmed=False), view())[0]["status"], "coverage_unverified")

    def test_reference_standard_scopes_and_missing_membership(self):
        bundle = snapshot("Changed")
        result = reference_compliance(bundle, "ACCESS_SWITCH", "layer2-vlan", "3", "2")
        self.assertEqual(result["target_count"], 1)
        self.assertEqual(result["unknown_membership"], 1)
        self.assertEqual({r["device"]: r["status"] for r in result["findings"]},
                         {"Target": "differences_observed", "Unknown": "membership_unverified"})
        result = reference_compliance(snapshot(), "ACCESS_SWITCH", "layer2-vlan", "3", "4")
        self.assertEqual(result["findings"][0]["status"], "matches_reference")

    def test_historical_standard_remains_fixed_and_checks_original_device(self):
        before, current = snapshot(), snapshot("Changed")
        with self.assertRaises(ValueError):
            reference_compliance(current, "ACCESS_SWITCH", "layer2-vlan", "3", "2", baseline=before)
        result = reference_compliance(current, "ACCESS_SWITCH", "layer2-vlan", "3", "2",
                                      baseline=before, confirmed=True)
        self.assertTrue(result["historical_baseline"])
        self.assertEqual(result["target_count"], 2)
        self.assertEqual({r["device"]: r["status"] for r in result["findings"]},
                         {"Reference": "matches_reference", "Target": "differences_observed",
                          "Unknown": "membership_unverified"})
        actual = current["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]
        actual["profiles"]["20"].pop("name")
        result = reference_compliance(current, "ACCESS_SWITCH", "layer2-vlan", "3", "4",
                                      baseline=before, confirmed=True)
        self.assertEqual(result["findings"][0]["status"], "verification_required")
        self.assertEqual(result["findings"][0]["differences"][0]["status"], "field_values_unavailable")

    def test_multi_module_standard_reports_differences_and_gaps_together(self):
        before, current = snapshot(), snapshot("Changed")
        entry = current["results"]["ACCESS_SWITCH"]
        entry["modules"]["dns"] = {"scope_results": [
            {"scope": "4", "effective_view": {"status": "request_rejected"}}]}
        result = reference_compliance(current, "ACCESS_SWITCH", "all", "3", "4",
                                      baseline=before, confirmed=True)
        finding = result["findings"][0]
        self.assertEqual(result["modules"], ["dns", "layer2-vlan"])
        self.assertEqual(finding["status"], "differences_observed")
        self.assertTrue(finding["has_gaps"])
        self.assertEqual(finding["module_results"]["dns"]["status"], "verification_required")
        self.assertEqual(finding["module_results"]["layer2-vlan"]["status"], "differences_observed")
        self.assertFalse(result["reference_count_confirmed"])

    def test_drift_groups_keep_views_separate_and_count_device_impact(self):
        from aruba_central.drift_review import drift_groups
        before, current = snapshot(), snapshot("Changed")
        result = configuration_drift(before, current, confirmed=True)
        groups = drift_groups(result["records"], current)
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(group["effective_device_count"], 1)
        self.assertEqual(group["saved_scope_count"], 1)
        self.assertEqual(group["library_count"], 1)
        self.assertEqual(len(group["observations"]), 3)
        self.assertFalse(group["safe_to_apply"])

    def test_drift_groups_do_not_merge_different_transitions(self):
        from aruba_central.drift_review import drift_groups
        current = snapshot("Changed")
        rows = configuration_drift(snapshot(), current, confirmed=True)["records"]
        rows[0]["after"] = {"name": "Other"}
        groups = drift_groups(rows, current)
        self.assertEqual(len(groups), 2)

    def test_browser_routes_render_and_show_explicit_selection(self):
        import json
        import tempfile
        from pathlib import Path
        from aruba_central.config_app import Workspace
        with tempfile.TemporaryDirectory() as directory:
            for name, data in (("config-audit-old.json", snapshot()),
                               ("config-audit-new.json", snapshot("Changed"))):
                (Path(directory) / name).write_text(json.dumps(data))
            w = Workspace(directory)
            html = w.drift({"snapshot": "config-audit-new.json", "previous": "config-audit-old.json", "confirmed": "yes"})
            self.assertIn("Change worklist", html)
            self.assertIn("Common device serials", html)
            self.assertIn("Profile change groups", html)
            self.assertIn("Review impact", html)
            self.assertIn("Export private report JSON", html)
            html = w.standards({"snapshot": "config-audit-new.json", "persona": "ACCESS_SWITCH",
                                "module": "layer2-vlan", "reference": "3", "target": "2"})
            self.assertIn("Reference standard results", html)
            self.assertIn("Differences observed", html)
            self.assertIn("Membership unverified", html)
            html = w.standards({"snapshot": "config-audit-new.json", "persona": "ACCESS_SWITCH",
                                "module": "all", "reference": "3", "target": "2"})
            self.assertIn("All standard modules", html)
            self.assertIn("Module results", html)
            self.assertIn("Export private report JSON", html)
            html = w.standards({"snapshot": "config-audit-new.json", "baseline": "config-audit-old.json",
                                "confirmed": "yes", "persona": "ACCESS_SWITCH", "module": "layer2-vlan",
                                "reference": "3", "target": "2"})
            self.assertIn("Approved baseline snapshot", html)
            self.assertIn("Reference standard results", html)
