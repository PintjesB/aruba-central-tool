import unittest
import copy
from aruba_central.consolidation import profile_recommendations
from aruba_central.central_tool import review_module_scope


def fixture():
    def view(bodies):
        return {"status": "list_parsed", "profiles": {str(v["vlan"]): v for v in bodies}}
    def vlan(number, name):
        return {"vlan": number, "name": name}
    global_profiles = [vlan(10, "Shared"), vlan(40, "Global")]
    scope_specs = [
        ("1", "global", "Global", [], global_profiles),
        ("2", "site", "Site", [], [vlan(10, "Different"), vlan(40, "Global")]),
        ("3", "device", "Switch A", [vlan(10, "Shared"), vlan(20, "Local repeat"), vlan(30, "Reuse"),
                                  vlan(40, "Exception"), vlan(50, "Unique")],
         [vlan(10, "Shared"), vlan(20, "Local repeat"), vlan(30, "Reuse"), vlan(40, "Exception"), vlan(50, "Unique")]),
        ("4", "device", "Switch B", [vlan(20, "Local repeat"), vlan(30, "Reuse")],
         [vlan(10, "Different"), vlan(20, "Local repeat"), vlan(30, "Reuse"), vlan(40, "Global")]),
        ("5", "device", "Unknown", [], []),
    ]
    scopes = []
    results = []
    for sid, kind, name, local, effective in scope_specs:
        scopes.append({"id": sid, "kind": kind, "name": name})
        local_view, effective_view = view(local), view(effective)
        if sid == "5":
            effective_view = {"status": "empty_object", "profiles": {}}
        review = review_module_scope(local_view, effective_view, view(global_profiles)["profiles"],
                                     is_global=kind == "global")
        results.append({"scope": sid, "scope_kind": kind, "local_view": local_view,
                        "effective_view": effective_view, "review": review})
    return {"schema": 1, "kind": "configuration_audit", "captured_at": "test",
            "results": {"ACCESS_SWITCH": {"scopes": scopes, "modules": {
                "layer2-vlan": {"scope_results": results, "device_scope_only": False},
                "system-info": {"scope_results": copy.deepcopy(results), "device_scope_only": False},
                "ethernet-interfaces": {"scope_results": copy.deepcopy(results), "device_scope_only": True}}}},
            "library": {"modules": {"layer2-vlan": view([vlan(30, "Reuse"), vlan(60, "Unassigned")])},
                        "assignments": {"status": "response_received", "rows": [
                            {"profile-type": "layer2-vlan", "profile-instance": "30"}]}}}


class ConsolidationTests(unittest.TestCase):
    def test_configuration_explorer_exposes_partial_values_without_recommending_changes(self):
        import tempfile
        import json
        from pathlib import Path
        from aruba_central.config_app import Workspace
        data = fixture()
        scope = data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]
        scope["local_view"] = {"status": "empty_object", "profiles": {}}
        scope["effective_view"] = {"status": "list_parsed", "profiles": {
            "999": {"vlan": 999, "name": "Partial profile"}}}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(data))
            html = Workspace(directory).report({"snapshot": name, "persona": "ACCESS_SWITCH",
                       "module": "layer2-vlan", "scope": "5", "view": "all"})
            self.assertIn("Partial profile", html)
            self.assertIn("Partial evidence", html)
            self.assertIn("Source and comparison are not verified", html)
        self.assertFalse(any(f["identity"] == "999" for f in profile_recommendations(data)))

    def test_recipient_index_matches_independent_membership_scan(self):
        from aruba_central.consolidation import placement_index
        scopes = [{"id": "1", "kind": "global"},
                  {"id": "2", "kind": "site", "metadata": {"id": 20, "collectionId": 40}},
                  {"id": "3", "kind": "site", "metadata": {"id": 30}},
                  {"id": "4", "kind": "collection", "metadata": {"id": 40}},
                  {"id": "5", "kind": "group", "metadata": {"id": 50}},
                  {"id": "6", "kind": "device", "metadata": {"siteId": 20, "deviceGroupId": 50}},
                  {"id": "7", "kind": "device", "metadata": {"siteId": 30}},
                  {"id": "8", "kind": "device"},
                  {"id": "9", "kind": "other"}]
        memberships, _, _, recipients = placement_index(scopes)
        for scope in scopes:
            sid, kind = scope["id"], scope["kind"]
            if kind == "device":
                expected = ({sid}, set())
            elif kind in ("global", "site", "group", "collection"):
                expected = ({dev for dev, m in memberships.items() if m[kind] == sid},
                            {dev for dev, m in memberships.items() if m[kind] is None})
            else:
                expected = (set(), set(memberships))
            self.assertEqual(recipients[sid], expected)
        self.assertIs(recipients["2"][1], recipients["3"][1])

    def test_consolidation_builds_membership_index_once_per_persona(self):
        from unittest.mock import patch
        from aruba_central.consolidation import scope_memberships, placement_evidence, placement_index
        from aruba_central.inheritance_review import nearest_fallback
        data = fixture()
        entry = data["results"]["ACCESS_SWITCH"]
        expected = profile_recommendations(data)
        before = copy.deepcopy(data)
        with patch("aruba_central.consolidation.scope_memberships", wraps=scope_memberships) as memberships:
            self.assertEqual(profile_recommendations(data), expected)
            self.assertEqual(memberships.call_count, 1)
        self.assertEqual(data, before)
        scopes = entry["scopes"]
        finding = next(f for f in expected if f["sources"])
        args = (scopes, finding["sources"], finding["observed_devices"], finding["scope_references"])
        self.assertEqual(placement_evidence(*args), placement_evidence(*args, index=placement_index(scopes)))
        device = next(s for s in entry["modules"]["layer2-vlan"]["scope_results"] if s["scope"] == "3")
        row = next(r for r in device["review"]["profiles"] if r["identity"] == "10")
        params = (entry, "layer2-vlan", "3", "10", row["local"], row["effective"], row.get("annotations", {}))
        index = (scope_memberships(scopes), {s["id"]: s for s in scopes},
                 {s["scope"]: s for s in entry["modules"]["layer2-vlan"]["scope_results"]})
        self.assertEqual(nearest_fallback(*params), nearest_fallback(*params, index=index))

    def test_advisor_groups_and_keeps_uncertainty(self):
        findings = profile_recommendations(fixture())
        by_id = {f["identity"]: f for f in findings}
        self.assertEqual(by_id["10"]["action"], "remove_override")
        self.assertFalse(by_id["10"]["preview_selectable"])
        self.assertEqual(by_id["10"]["fallbacks"][0]["status"], "unresolved")
        self.assertTrue(any("intermediate scope" in b for b in by_id["10"]["blockers"]))
        self.assertEqual(by_id["20"]["action"], "promote_local")
        self.assertEqual(len(by_id["20"]["sources"]), 2)
        self.assertEqual(len(by_id["20"]["observed_devices"]["unknown"]), 1)
        self.assertEqual(by_id["30"]["action"], "reuse_library")
        self.assertEqual(by_id["40"]["action"], "conflict")
        self.assertEqual(by_id["50"]["action"], "create_library")
        self.assertEqual(by_id["60"]["action"], "unassigned_library")
        self.assertTrue(all(f["module"] == "layer2-vlan" for f in findings))
        self.assertTrue(all(not f["safe_to_apply"] for f in findings))
        self.assertEqual(len({f["id"] for f in findings}), len(findings))

    def test_advisor_uses_nearest_group_instead_of_global(self):
        bundle = fixture()
        entry = bundle["results"]["ACCESS_SWITCH"]
        entry["scopes"][2]["metadata"] = {"deviceGroupId": "6"}
        entry["scopes"].append({"id": "6", "kind": "group", "name": "Group"})
        direct = {"aruba-annotation:inherited": False, "aruba-annotation:object_type": "LOCAL"}
        mod = entry["modules"]["layer2-vlan"]
        device = next(s for s in mod["scope_results"] if s["scope"] == "3")
        device["effective_view"]["profiles"]["10"]["@"] = direct
        baseline = mod["scope_results"][0]["effective_view"]["profiles"]
        device["review"] = review_module_scope(device["local_view"], device["effective_view"], baseline)
        group = {"status": "list_parsed", "count_confirmed": True,
                 "profiles": {"10": {"vlan": 10, "name": "Shared", "@": direct}}}
        mod["scope_results"].append({"scope": "6", "scope_kind": "group",
             "local_view": {"status": "list_parsed", "profiles": {}}, "effective_view": group,
             "review": {"qualified": True, "profiles": []}})
        finding = next(f for f in profile_recommendations(bundle) if f["identity"] == "10")
        self.assertTrue(finding["preview_selectable"])
        self.assertEqual(finding["fallbacks"][0]["source"]["scope"], "6")
        bundle["keyed_profile_details"] = {"profiles": {"ACCESS_SWITCH": {"6": {
            "layer2-vlan": {"10": {"effective": {"status": "identity_observed",
                "profile": {"vlan": 10, "name": "Shared", "enable": False}}}}
        }}}}
        finding = next(f for f in profile_recommendations(bundle) if f["identity"] == "10")
        self.assertFalse(finding["preview_selectable"])
        self.assertEqual(finding["fallbacks"][0]["status"], "individual_evidence_conflict")
        self.assertEqual(finding["fallbacks"][0]["individual_conflicts"][0]["scope"], "6")
        self.assertFalse(finding["safe_to_apply"])
        del bundle["keyed_profile_details"]
        group["profiles"]["10"]["name"] = "Different"
        finding = next(f for f in profile_recommendations(bundle) if f["identity"] == "10")
        self.assertFalse(finding["preview_selectable"])
        self.assertEqual(finding["target"], "Retain: nearer scope differs")

    def test_scope_impact_uses_exact_membership_and_keeps_unknown_devices(self):
        from aruba_central.consolidation import scope_memberships, placement_evidence
        bundle = fixture()
        entry = bundle["results"]["ACCESS_SWITCH"]
        scopes = entry["scopes"]
        scopes[1]["metadata"] = {"id": "202", "collectionId": "300"}
        scopes[2]["metadata"] = {"siteId": 202, "deviceGroupId": 400}
        scopes[3]["metadata"] = {"siteId": "202", "deviceGroupId": "400"}
        scopes[4]["metadata"] = {"siteId": 999, "deviceGroupId": 401}
        scopes.extend([{"id": "6", "kind": "collection", "name": "Collection", "metadata": {"id": 300}},
                       {"id": "7", "kind": "group", "name": "Switch Group", "metadata": {"id": 400}},
                       {"id": "8", "kind": "group", "name": "Other", "metadata": {"id": 401}}])
        membership = scope_memberships(scopes)
        self.assertEqual(membership["3"], {"global": "1", "site": "2", "group": "7", "collection": "6"})
        self.assertIsNone(membership["5"]["site"])
        self.assertEqual(membership["5"]["group"], "8")
        findings = profile_recommendations(bundle)
        repeated = next(f for f in findings if f["identity"] == "20")
        options = {p["scope"]: p for p in repeated["placement_options"]}
        self.assertEqual(options["7"]["membership_status"], "exact_observed_recipient_set")
        self.assertEqual(options["1"]["additional_devices"], [{"scope": "5", "name": "Unknown"}])
        self.assertEqual(options["2"]["unknown_membership"], [{"scope": "5", "name": "Unknown"}])
        self.assertFalse(options["7"]["safe_to_apply"])
        self.assertTrue(all(not p["safe_to_apply"] for p in options.values()))

    def test_ambiguous_scope_alias_does_not_infer_membership(self):
        from aruba_central.consolidation import scope_memberships
        scopes = [
            {"id": "1", "kind": "global"},
            {"id": "2", "kind": "site", "metadata": {"id": 20}},
            {"id": "3", "kind": "site", "metadata": {"id": 20}},
            {"id": "4", "kind": "device", "metadata": {"siteId": 20}},
        ]
        self.assertIsNone(scope_memberships(scopes)["4"]["site"])

    def test_missing_assignment_evidence_does_not_report_unused(self):
        bundle = fixture()
        bundle["library"]["assignments"] = {"status": "request_rejected", "rows": []}
        self.assertFalse(any(f["action"] == "unassigned_library" for f in profile_recommendations(bundle)))

    def test_advisor_page_is_read_only_and_selectable(self):
        import tempfile
        import json
        from pathlib import Path
        from aruba_central.config_app import Workspace
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            html = Workspace(directory).advisor({"snapshot": name})
            self.assertIn("Matches Global", html)
            self.assertIn("Repeated local profiles", html)
            self.assertIn("Matches Library", html)
            self.assertIn("Export private preview JSON", html)
            self.assertIn("Choose destination for review", html)
            self.assertIn("Library / exact source scopes", html)
            self.assertIn("not executable API operations", html)
            self.assertNotIn("Apply changes</button>", html)

    def test_workspace_overhaul_all_pages_and_snapshot_navigation(self):
        import tempfile
        import json
        from pathlib import Path
        from aruba_central.config_app import Workspace
        from html.parser import HTMLParser

        class Inspector(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = []
                self.active = []
                self.ids = []
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "a":
                    self.links.append(attrs.get("href", ""))
                    if attrs.get("aria-current") == "page":
                        self.active.append(attrs.get("data-nav"))
                if "id" in attrs:
                    self.ids.append(attrs["id"])

        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            other = "config-audit-other.json"
            bundle = fixture()
            bundle["results"]["ACCESS_SWITCH"]["scopes"][2]["name"] = "<script>alert(1)</script>"
            for filename in (name, other):
                (Path(directory) / filename).write_text(json.dumps(bundle))
            workspace = Workspace(directory)
            root = "/" + workspace.token + "/"
            query = {"snapshot": name}
            pages = [
                ("Overview", workspace.home(query)),
                ("Device overrides", workspace.overrides(query)),
                ("Consolidation", workspace.advisor(query)),
                ("Engineering", workspace.advanced(query)),
                ("Configuration", workspace.report(query)),
                ("Inventory", workspace.scopes(query)),
                ("Library", workspace.library(query)),
                ("Compare", workspace.comparison(query)),
                ("Coverage", workspace.coverage(query)),
            ]
            for active, html in pages:
                with self.subTest(active=active):
                    parser = Inspector()
                    parser.feed(html)
                    self.assertEqual(parser.active, [active])
                    self.assertIn(root + "advisor?snapshot=" + name, parser.links)
                    self.assertIn(root + "report?snapshot=" + name, parser.links)
                    self.assertIn("workspace-inspector", parser.ids)
                    self.assertEqual(len(parser.ids), len(set(parser.ids)))
                    self.assertNotIn("<script>alert(1)</script>", html)
            html = workspace.advisor(query)
            self.assertIn("data-action=", html)
            self.assertIn("Review selected", html)
            self.assertIn("Destination impact", html)
            self.assertIn("safe_to_apply:false", html)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
            html = workspace.report({**query, "persona": "ACCESS_SWITCH", "module": "layer2-vlan", "diagnostics": "1"})
            self.assertIn("Not qualified", html)
            self.assertIn("Incomplete API results", html)
            self.assertIn("legacy-report", html)
            html = workspace.comparison({**query, "persona": "ACCESS_SWITCH", "left": "3", "right": "4"})
            self.assertIn("Differences", html)
            self.assertIn("Identical modules", html)
            self.assertIn("Not comparable", html)
            self.assertIn("data-inspect", html)
            html = workspace.library({**query, "module": "layer2-vlan"})
            self.assertIn("Observed assignments", html)
            self.assertIn("Local instances", html)

    def test_explanations_separate_opportunities_and_optional_housekeeping(self):
        from aruba_central.workspace_views import ACTION_GUIDE, OPPORTUNITIES, vlan_explanation
        self.assertEqual(set(OPPORTUNITIES), {"remove_override", "promote_local", "reuse_library"})
        self.assertIn("does not prove", ACTION_GUIDE["unassigned_library"][1])
        self.assertIn("Keeping it local", ACTION_GUIDE["create_library"][1])
        html = vlan_explanation({"vlan": 10, "name": "Test"}, {"vlan": 10, "name": "Test", "enable": True})
        self.assertIn("Cannot compare: value unavailable", html)
        self.assertIn("Not returned", html)
        self.assertIn("the saved local field was omitted", html)
        html = vlan_explanation({"vlan": 10, "is-l3-vlan": True}, {"vlan": 10})
        self.assertIn("Cannot compare: value unavailable", html)
        import tempfile
        import json
        from pathlib import Path
        from aruba_central.config_app import Workspace
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            html = Workspace(directory).advisor({"snapshot": name})
            self.assertIn("Consolidation opportunities", html)
            self.assertIn("Settings to review", html)
            self.assertIn("Optional Library review", html)
            self.assertIn("No assignment observed", html)
            self.assertIn('class="review-decision"', html)
            self.assertIn("Validation required", html)
            self.assertIn('value="opportunities" selected', html)
            self.assertNotIn('id="action-tabs"', html)
            self.assertIn("if(!check.disabled)", html)
            self.assertNotIn(">Default differences<", html)

    def test_filtered_override_analysis_matches_full_results(self):
        from unittest.mock import patch
        from aruba_central.override_view import device_override_rows
        from aruba_central.inheritance_review import nearest_fallback
        data = fixture()
        before = copy.deepcopy(data)
        full, missing = device_override_rows(data, "ACCESS_SWITCH")
        for device, module in (("3", "layer2-vlan"), ("5", ""), ("", "layer2-vlan"), ("3", "")):
            with self.subTest(device=device, module=module):
                def selected(row):
                    return (not device or row["device"] == device) and (not module or row["module"] == module)
                with patch("aruba_central.override_view.nearest_fallback", wraps=nearest_fallback) as fallback:
                    actual, incomplete = device_override_rows(data, "ACCESS_SWITCH", device=device, module_filter=module)
                self.assertEqual(actual, [row for row in full if selected(row)])
                self.assertEqual(incomplete, [row for row in missing if selected(row)])
                self.assertEqual(fallback.call_count, len(actual))
                indexes = {}
                for call in fallback.call_args_list:
                    index = call.kwargs["index"]
                    self.assertIs(indexes.setdefault(call.args[1], index), index)
        self.assertEqual(data, before)

    def test_device_override_comparison_and_deep_links(self):
        from aruba_central.override_view import device_override_rows
        from aruba_central.config_app import Workspace
        from pathlib import Path
        import tempfile
        import json
        data = fixture()
        entry = data["results"]["ACCESS_SWITCH"]
        local = entry["modules"]["layer2-vlan"]["scope_results"][2]
        local["effective_view"]["profiles"]["10"]["@"] = {
            "aruba-annotation:object_type": "LOCAL", "aruba-annotation:inherited": False}
        from aruba_central.central_tool import refresh_configuration_review
        refresh_configuration_review(data)
        # Fixture views contain already-parsed reviews, not raw API responses.
        next(r for r in local["review"]["profiles"] if r["identity"] == "10")["annotations"] = {
            "aruba-annotation:object_type": "LOCAL", "aruba-annotation:inherited": False}
        findings, missing = device_override_rows(data, "ACCESS_SWITCH")
        by_id = {f["identity"]: f for f in findings if f["device"] == "3" and f["module"] == "layer2-vlan"}
        self.assertEqual(by_id["10"]["result"], "identical")
        self.assertEqual(by_id["40"]["result"], "different")
        self.assertEqual(by_id["20"]["result"], "no_global")
        self.assertTrue(by_id["10"]["review_candidate"])
        self.assertFalse(by_id["40"]["review_candidate"])
        self.assertFalse(by_id["20"]["review_candidate"])
        self.assertFalse(by_id["10"]["safe_to_apply"])
        # Matching Global does not mean a different applicable site is redundant.
        entry["scopes"][2]["metadata"] = {"siteId": 2}
        findings, _ = device_override_rows(data, "ACCESS_SWITCH")
        matched = next(f for f in findings if f["device"] == "3" and f["module"] == "layer2-vlan" and f["identity"] == "10")
        self.assertEqual(matched["result"], "identical")
        self.assertEqual(matched["removal"], "higher_scope_differs")
        self.assertTrue(matched["review_candidate"])
        entry["scopes"][2].pop("metadata")
        self.assertTrue(any(f["device"] == "5" for f in missing))
        self.assertFalse(any(f["module"] == "ethernet-interfaces" for f in findings))
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(data))
            w = Workspace(directory)
            html = w.overrides({"snapshot": name, "device": "3", "module": "layer2-vlan", "result": "identical"})
            self.assertIn("Compare with Global", html)
            self.assertIn("Matches Global", html)
            self.assertIn("Expected fallback after removing device-local copy", html)
            self.assertIn("Verify before removal", html)
            self.assertIn("Open matching consolidation preview", html)
            self.assertIn("identity=10", html)
            self.assertNotIn("VLAN 40", html)
            html = w.advisor({"snapshot": name, "persona": "ACCESS_SWITCH", "module": "layer2-vlan", "scope": "3", "identity": "10"})
            self.assertIn('data-action="remove_override"', html)
            self.assertNotIn('data-plan="{&quot;action&quot;: &quot;promote_local&quot;', html)
            self.assertIn("Scope precedence", w.advanced({"snapshot": name}))
            self.assertIn("Compare overrides", w.scopes({"snapshot": name}))

    def test_vlan_comparison_displays_effective_values_not_assumed_defaults(self):
        from aruba_central.workspace_views import vlan_explanation
        html = vlan_explanation({"vlan": 1}, {"vlan": 1, "enable": True, "name": "DEFAULT_VLAN_1"},
                                {"vlan": 1, "enable": False, "name": "Effective name"})
        self.assertIn("Saved locally", html)
        self.assertIn("Effective at source", html)
        self.assertIn("Global / reference", html)
        self.assertIn("Effective name", html)
        self.assertIn("Disabled", html)
        self.assertIn("Not returned", html)
        self.assertIn("not a live switch CLI", html)

    def test_vlan_comparison_exposes_effective_only_and_matching_fields(self):
        from aruba_central.workspace_views import vlan_explanation
        html = vlan_explanation({"vlan": 10, "name": "Same"},
                                {"vlan": 10, "name": "Same"},
                                {"vlan": 10, "name": "Same", "voice-enable": True})
        self.assertIn("Voice VLAN", html)
        self.assertIn("Enabled", html)
        self.assertIn("Same", html)
        self.assertIn("Not returned", html)

    def test_vlan_comparison_marks_settings_omitted_by_all_sources_unavailable(self):
        from aruba_central.workspace_views import vlan_explanation
        html = vlan_explanation({"vlan": 10}, {"vlan": 10}, {"vlan": 10})
        for label in ("IGMP snooping", "MLD snooping", "Voice VLAN",
                      "DHCPv4 snooping", "DHCPv6 snooping"):
            row = html.split("<td>" + label + "</td>", 1)[1].split("</tr>", 1)[0]
            self.assertIn("Not returned", row)
            self.assertEqual(row.count(">Unavailable<"), 3)
            self.assertIn("Cannot compare: value unavailable", row)
            self.assertNotIn(">Disabled<", row)
            self.assertNotIn("matches reference", row)
        html = vlan_explanation({"vlan": 10}, {"vlan": 10, "igmp": {"snooping": False}},
                                {"vlan": 10, "igmp": {"snooping": False}})
        row = html.split("<td>IGMP snooping</td>", 1)[1].split("</tr>", 1)[0]
        self.assertEqual(row.count(">Disabled<"), 2)
        self.assertNotIn(">Unavailable<", row)

    def test_protected_vlan_is_included_in_missing_field_diagnostics(self):
        from aruba_central.central_tool import refresh_configuration_review, vlan_evidence_summary
        data = fixture()
        views = data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"]
        views[0]["effective_view"]["profiles"]["1"] = {"vlan": 1, "name": "Default", "enable": True}
        for key in ("local_view", "effective_view"):
            views[2][key]["profiles"]["1"] = {"vlan": 1}
        refresh_configuration_review(data)
        summary = vlan_evidence_summary(data)
        self.assertGreaterEqual(summary["comparisons"]["protected_default_vlan"], 1)
        self.assertGreaterEqual(summary["remaining_fields"]["name"], 1)
        self.assertGreaterEqual(summary["remaining_fields"]["enable"], 1)

    def test_operational_vlan_context_does_not_infer_configured_enable(self):
        from aruba_central.central_tool import configuration_operational_vlan
        from aruba_central.workspace_views import operational_vlan_context
        data = {"operational_vlans": {"ACCESS_SWITCH": {"1": {
            "status": "response_received", "captured_at": "test",
            "payload": {"vlans": [{"id": 1, "name": "DEFAULT_VLAN_1", "status": "Up",
                                  "taggedPorts": ["1/1/1"], "untaggedPorts": []}]}}}}}
        obs = configuration_operational_vlan(data, "ACCESS_SWITCH", "1", "1")
        self.assertEqual(obs["status"], "observed")
        self.assertEqual(obs["fields"]["name"], "DEFAULT_VLAN_1")
        self.assertNotIn("enable", obs["fields"])
        self.assertEqual(configuration_operational_vlan(data, "ACCESS_SWITCH", "1", "2")["status"], "not_observed")
        self.assertEqual(configuration_operational_vlan({}, "ACCESS_SWITCH", "1", "1")["status"], "not_collected")
        sources = [{"kind": "device", "scope": "1", "name": "Switch A"}]
        html = operational_vlan_context(data, "ACCESS_SWITCH", sources, "1")
        self.assertIn("DEFAULT_VLAN_1", html)
        self.assertIn("Up", html)
        self.assertIn("1/1/1", html)
        self.assertIn("not the same field as configured enable", html)
        self.assertIn("Not collected in this snapshot", operational_vlan_context({}, "ACCESS_SWITCH", sources, "1"))
        data["operational_vlans"]["ACCESS_SWITCH"]["1"]["payload"]["vlans"].append({"id": 1})
        self.assertEqual(configuration_operational_vlan(data, "ACCESS_SWITCH", "1", "1")["status"], "identity_unresolved")

    def test_vlan_one_is_protected_and_missing_fields_not_actual_difference(self):
        from aruba_central.central_tool import refresh_configuration_review
        from aruba_central.override_view import device_override_rows
        from aruba_central.workspace_views import vlan_instance_context
        data = fixture()
        views = data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"]
        views[0]["effective_view"]["profiles"]["1"] = {"vlan": 1, "name": "DEFAULT_VLAN_1", "enable": True}
        views[0]["effective_view"]["profiles"]["70"] = {"vlan": 70, "name": "Example", "enable": True}
        for key in ("local_view", "effective_view"):
            views[2][key]["profiles"]["1"] = {"vlan": 1}
            views[2][key]["profiles"]["70"] = {"vlan": 70}
        data["library"]["modules"]["layer2-vlan"]["profiles"]["1"] = {"vlan": 1, "name": "DEFAULT_VLAN_1"}
        refresh_configuration_review(data)
        findings, _ = device_override_rows(data, "ACCESS_SWITCH")
        by_id = {f["identity"]: f for f in findings if f["module"] == "layer2-vlan" and f["device"] == "3"}
        self.assertEqual(by_id["1"]["result"], "protected")
        self.assertFalse(by_id["1"]["candidate"])
        self.assertEqual(by_id["70"]["result"], "omitted")
        self.assertFalse(any(f["identity"] == "1" for f in profile_recommendations(data)))
        data["vlan_instance_details"] = {"ACCESS_SWITCH": {"3": {"1": {
            "local": {"status": "source_unverified"},
            "effective": {"status": "observed", "profile": {"vlan": 1, "name": "Observed by ID"}}}}}}
        html = vlan_instance_context(data, "ACCESS_SWITCH", [{"kind": "device", "scope": "3", "name": "A"}], "1")
        self.assertIn("Observed by ID", html)
        self.assertIn("Local source not confirmed", html)
        self.assertIn("Not returned", html)
        self.assertIn("original snapshot", html)

    def test_additional_profile_inspector_preserves_values_without_identity_guesses(self):
        import tempfile
        import json
        from pathlib import Path
        from aruba_central.config_app import Workspace
        data = fixture()
        body = {"profiles": [{"arbitrary-field": "<script>example</script>", "enabled": False}]}
        read = {"status": "response_received", "raw": body}
        data["unadapted_profiles"] = {"new-module": {"library": read, "source_views": [
            {"persona": "ACCESS_SWITCH", "scope": "3", "observed_instances": [],
             "committed": read, "effective": {"status": "request_rejected", "http_error": 403}}]}}
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(data))
            workspace = Workspace(directory)
            q = {"snapshot": name, "module": "new-module"}
            html = workspace.unadapted(q)
            self.assertIn("arbitrary-field", html)
            self.assertIn("&lt;script&gt;example&lt;/script&gt;", html)
            self.assertNotIn("<script>example</script>", html)
            self.assertIn("Inspect settings", html)
            html = workspace.unadapted({**q, "persona": "ACCESS_SWITCH", "scope": "3"})
            self.assertIn("Committed configuration", html)
            self.assertIn("Effective configuration", html)
            self.assertIn("Structured settings unavailable", html)
            self.assertIn("All captured scopes", html)
            coverage = workspace.coverage({"snapshot": name})
            self.assertIn("Additional scoped configuration", coverage)

    def test_partial_vlan_matches_are_review_candidates_not_verified_removals(self):
        from aruba_central.central_tool import refresh_configuration_review
        from aruba_central.override_view import device_override_rows
        from aruba_central.workspace_views import vlan_explanation
        data = fixture()
        views = data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"]
        reference = {"vlan": 70, "name": "VOICE", "enable": True,
                     "voice-enable": False, "dhcpv4-snooping": {"enable": False},
                     "dhcpv6-snooping": {"enable": False}, "igmp": {"snooping": False},
                     "mld": {"snooping": False}}
        views[0]["effective_view"]["profiles"]["70"] = reference
        views[2]["local_view"]["profiles"]["70"] = {"vlan": 70}
        views[2]["effective_view"]["profiles"]["70"] = {"vlan": 70, "name": "VOICE"}
        data["switch_vlan_cli"] = {"ACCESS_SWITCH": {"3": {"status": "observed", "vlans": {
            "70": {"name": "VOICE", "enable": True, "dhcpv4-snooping": {"enable": False},
                   "dhcpv6-snooping": {"enable": False}}}}}}
        data["operational_vlans"] = {"ACCESS_SWITCH": {"3": {"status": "response_received",
            "payload": {"items": [{"id": 70, "voice": "Disabled"}]}}}}
        refresh_configuration_review(data)
        def finding():
            rows, _ = device_override_rows(data, "ACCESS_SWITCH")
            return next(f for f in rows if f["device"] == "3" and f["module"] == "layer2-vlan" and f["identity"] == "70")
        f = finding()
        self.assertEqual(f["result"], "partial_match")
        self.assertEqual(f["assessment"]["counts"], {"matching": 5, "different": 0, "unavailable": 2, "conflict": 0})
        self.assertTrue(f["review_candidate"])
        self.assertFalse(f["candidate"])
        self.assertFalse(f["safe_to_apply"])
        html = vlan_explanation(f["profile"]["local"], reference, f["profile"]["effective"], f["evidence"])
        self.assertIn("5 matching", html)
        self.assertIn("2 unavailable settings", html)
        self.assertIn('class="comparison-gaps"', html)
        import tempfile
        import json
        from pathlib import Path
        from aruba_central.config_app import Workspace
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(data))
            html = Workspace(directory).overrides({"snapshot": name, "result": "cleanup", "module": "layer2-vlan"})
            self.assertIn("VLAN 70", html)
            self.assertIn("Likely redundant", html)
            self.assertIn("5 match · 2 unavailable", html)
            self.assertNotIn("VLAN 40", html)
        # A real observed difference or a conflicting saved value excludes cleanup.
        data["switch_vlan_cli"]["ACCESS_SWITCH"]["3"]["vlans"]["70"]["enable"] = False
        f = finding()
        self.assertEqual(f["result"], "different")
        self.assertFalse(f["review_candidate"])
        data["switch_vlan_cli"]["ACCESS_SWITCH"]["3"]["vlans"]["70"]["enable"] = True
        views[2]["local_view"]["profiles"]["70"]["igmp"] = {"snooping": True}
        refresh_configuration_review(data)
        f = finding()
        self.assertEqual(f["result"], "source_uncertain")
        self.assertFalse(f["review_candidate"])

    def test_recovered_vlan_fields_change_comparison_not_saved_body(self):
        from aruba_central.central_tool import refresh_configuration_review, vlan_comparison_evidence
        from aruba_central.override_view import device_override_rows
        from aruba_central.workspace_views import vlan_explanation
        data = fixture()
        views = data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"]
        views[0]["effective_view"]["profiles"]["70"] = {"vlan": 70, "name": "Example", "enable": True}
        for key in ("local_view", "effective_view"):
            views[2][key]["profiles"]["70"] = {"vlan": 70}
        refresh_configuration_review(data)
        data["vlan_instance_details"] = {"ACCESS_SWITCH": {"3": {"70": {
            "effective": {"status": "observed", "profile": {"vlan": 70, "name": "Example"}}}}}}
        data["switch_vlan_cli"] = {"ACCESS_SWITCH": {"3": {"status": "observed",
            "vlans": {"70": {"name": "Example", "enable": True}}}}}
        findings, _ = device_override_rows(data, "ACCESS_SWITCH")
        f = next(f for f in findings if f["device"] == "3" and f["module"] == "layer2-vlan" and f["identity"] == "70")
        self.assertEqual(f["result"], "effective_match")
        self.assertFalse(f["candidate"])
        self.assertEqual(f["profile"]["local"], {"vlan": 70})
        self.assertEqual(f["evidence"]["comparison"], {"vlan": 70, "name": "Example", "enable": True})
        html = vlan_explanation(f["profile"]["local"], f["profile"]["global_reference"], f["profile"]["effective"], f["evidence"])
        self.assertIn("Central VLAN by ID", html)
        self.assertIn("Switch show vlan", html)
        data["switch_vlan_cli"]["ACCESS_SWITCH"]["3"]["vlans"]["70"]["name"] = "Other"
        findings, _ = device_override_rows(data, "ACCESS_SWITCH")
        f = next(f for f in findings if f["device"] == "3" and f["module"] == "layer2-vlan" and f["identity"] == "70")
        self.assertEqual(f["result"], "source_uncertain")
        self.assertIn("device.name", f["evidence"]["conflicts"])
        self.assertFalse(f["candidate"])

    def test_empty_multicast_interfaces_do_not_complete_vlan_comparison(self):
        from aruba_central.central_tool import vlan_comparison_evidence
        from aruba_central.workspace_views import vlan_explanation
        row = {"identity": "10", "local": {"vlan": 10}, "effective": {"vlan": 10},
               "global_reference": {"vlan": 10, "igmp": {"snooping": False},
                                    "mld": {"snooping": True}}}
        data = {"switch_vlan_cli": {"ACCESS_SWITCH": {"3": {"status": "observed",
            "vlans": {"10": {}}, "features": {
                "igmp": {"status": "no_multicast_interfaces"},
                "mld": {"status": "no_multicast_interfaces"}}}}}}
        evidence = vlan_comparison_evidence(data, "ACCESS_SWITCH", "3", row)
        self.assertNotIn("igmp", evidence["comparison"])
        self.assertNotIn("mld", evidence["comparison"])
        self.assertEqual(len(evidence["differences"]), 2)
        html = vlan_explanation(row["local"], row["global_reference"], row["effective"], evidence)
        self.assertIn("Layer 2 snooping not reported", html)
        self.assertIn('data-comparison="unavailable"', html)
        self.assertIn('class="comparison-summary"', html)
        self.assertFalse(evidence["safe_to_apply"])

    def test_monitoring_voice_uses_explicit_state_only(self):
        from aruba_central.central_tool import vlan_comparison_evidence
        row = {"identity": "10", "local": {"vlan": 10}, "effective": {"vlan": 10},
               "global_reference": {"vlan": 10, "voice-enable": False}}
        record = {"id": 10, "voice": "Disabled"}
        data = {"operational_vlans": {"ACCESS_SWITCH": {"3": {
            "status": "response_received", "payload": {"vlans": [record]}}}}}
        evidence = vlan_comparison_evidence(data, "ACCESS_SWITCH", "3", row)
        self.assertEqual(evidence["differences"], [])
        self.assertEqual(evidence["sources"]["comparison.voice-enable"], "Switch monitoring")
        self.assertEqual(evidence["local"], {"vlan": 10})
        self.assertEqual(evidence["effective"], {"vlan": 10})
        for unknown in (None, "Unknown", "N/A"):
            record["voice"] = unknown
            evidence = vlan_comparison_evidence(data, "ACCESS_SWITCH", "3", row)
            self.assertNotIn("voice-enable", evidence["comparison"])

    def test_feature_evidence_completes_nested_vlan_comparison(self):
        from aruba_central.central_tool import vlan_comparison_evidence
        row = {"identity": "10", "local": {"vlan": 10}, "effective": {"vlan": 10},
               "global_reference": {"vlan": 10, "igmp": {"snooping": True},
                                    "dhcpv4-snooping": {"enable": False}, "voice-enable": False}}
        data = {"switch_vlan_cli": {"ACCESS_SWITCH": {"3": {"status": "observed",
            "vlans": {"10": {"igmp": {"snooping": True},
                             "dhcpv4-snooping": {"enable": False}, "voice-enable": False}}}}}}
        evidence = vlan_comparison_evidence(data, "ACCESS_SWITCH", "3", row)
        self.assertEqual(evidence["differences"], [])
        self.assertEqual(evidence["local"], {"vlan": 10})
        self.assertEqual(evidence["effective"], {"vlan": 10})
        self.assertFalse(evidence["safe_to_apply"])
        row["global_reference"]["igmp"]["extra-setting"] = 1
        evidence = vlan_comparison_evidence(data, "ACCESS_SWITCH", "3", row)
        self.assertEqual(evidence["differences"][0]["path"], ["igmp", "extra-setting"])
        self.assertEqual(evidence["differences"][0]["kind"], "missing_local")

    def test_vlan_summary_reports_counts_without_tenant_values(self):
        from aruba_central.central_tool import vlan_evidence_summary, refresh_configuration_review
        import json
        data = fixture()
        views = data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"]
        views[0]["effective_view"]["profiles"]["70"] = {"vlan": 70, "name": "PRIVATE-CUSTOMER", "enable": True}
        for key in ("local_view", "effective_view"):
            views[2][key]["profiles"]["70"] = {"vlan": 70}
        refresh_configuration_review(data)
        summary = vlan_evidence_summary(data)
        self.assertGreaterEqual(summary["remaining_fields"]["name"], 1)
        self.assertGreaterEqual(summary["remaining_fields"]["enable"], 1)
        self.assertNotIn("PRIVATE-CUSTOMER", json.dumps(summary))
        data["switch_vlan_cli"] = {"ACCESS_SWITCH": {"3": {"status": "observed",
            "vlans": {"70": {"name": "PRIVATE-CUSTOMER", "enable": True}}}}}
        after = vlan_evidence_summary(data)
        self.assertEqual(after["recovered_values"]["Switch show vlan"], 2)
        self.assertGreater(after["comparisons"]["observed_match"], summary["comparisons"].get("observed_match", 0))
        self.assertNotIn("PRIVATE-CUSTOMER", json.dumps(after))


    def test_collection_gap_rows_distinguish_empty_failed_and_skipped_evidence(self):
        from aruba_central.workspace_views import collection_gap_rows
        bundle = {"results": {"ACCESS_SWITCH": {"modules": {"dns": {"scope_results": [
            {"local_view": {"status": "empty_object"},
             "effective_view": {"status": "list_parsed", "count_confirmed": True}},
            {"local_view": {"status": "request_rejected", "http_error": 400},
             "effective_view": {"status": "list_parsed", "count_confirmed": False,
                                "pagination_status": "request_failed"}}]}}}},
            "library": {"modules": {"dns": {"status": "list_parsed", "count_confirmed": False}}},
            "unadapted_profiles": {"dns": {"library": {"reused_exact_collection": True},
                "source_views": [{"persona": "ACCESS_SWITCH",
                   "committed": {"status": "empty_response"},
                   "effective": {"status": "partial_response", "reused_exact_collection": True}}],
                "catalog_scope_coverage": {"unfiltered_scopes_not_surveyed": 3}}}}
        rows = collection_gap_rows(bundle)
        self.assertEqual(rows[0]["reason"], "HTTP 400")
        self.assertEqual(len(rows), 6)
        self.assertEqual(sum(r["observations"] for r in rows), 8)
        self.assertEqual({r["reason"] for r in rows}, {"HTTP 400", "Unverified empty response",
            "Pagination unverified: Request failed", "Record count unverified", "Scopes not surveyed"})
        self.assertFalse(any(r["source"] == "Supplemental Library" for r in rows))
