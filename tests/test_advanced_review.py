import unittest
from advanced_review import advanced_analysis


def view(profiles):
    return {"status": "list_parsed", "profiles": profiles}


class AdvancedTests(unittest.TestCase):
    def test_grouping_references_and_shadowing(self):
        scopes = [{"id": "1", "kind": "global", "name": "Global"},
                  {"id": "2", "kind": "device", "name": "A"},
                  {"id": "3", "kind": "device", "name": "B"}]
        port = {"switchport": {"access-vlan": 10}, "routing": False}
        vlan = {"vlan": 10, "name": "local", "@": {
            "aruba-annotation:inherited": False, "aruba-annotation:object_type": "LOCAL"}}
        def module(mapping):
            return {"scope_results": [{"scope": sid, "effective_view": v} for sid, v in mapping.items()]}
        bundle = {"results": {"ACCESS_SWITCH": {"scopes": scopes, "modules": {
            "ethernet-interfaces": module({"2": view({"1": {"name": "1", **port},
                                                       "2": {"name": "2", "description": "desk", **port},
                                                       "3": {"name": "3", "sw-profile": "existing"},
                                                       "4": {"name": "4", "lag": {"id": 1}, **port}}),
                                           "3": view({"1": {"name": "1", **port}})}),
            "layer2-vlan": module({"1": view({"10": {"vlan": 10, "name": "global"}}),
                                   "2": view({"10": vlan}),
                                   "3": {"status": "empty_object", "profiles": {}}}),
            "sw-port-profiles": module({"2": view({"existing": {"profile-name": "existing"}})})}}},
            "library": {"modules": {"sw-port-profiles": view({
                "a": {"profile-name": "a", **port}, "b": {"profile-name": "b", **port}})}}}
        data = advanced_analysis(bundle)
        self.assertEqual(len(data["port_groups"]), 1)
        self.assertEqual(len(data["port_groups"][0]["ports"]), 3)
        self.assertEqual([m["identity"] for m in data["port_groups"][0]["matching_library_profiles"]], ["a", "b"])
        self.assertEqual(len(data["port_groups"][0]["proposed_mapping"]), 3)
        self.assertTrue(data["port_groups"][0]["dependencies"])
        self.assertEqual(data["library_duplicates"][0]["identities"], ["a", "b"])
        self.assertEqual(data["shadowed"][0]["relationship"], "different_body")
        self.assertTrue(any(r["target"] == "existing" and r["status"] == "observed" for r in data["references"]))
        self.assertTrue(any(r["scope"] == "3" and r["status"] == "unresolved" for r in data["references"]))
        self.assertFalse(data["reference_graph_complete"])
        self.assertFalse(data["safe_to_apply"])

    def test_group_shadows_site_and_global_when_membership_and_source_are_observed(self):
        scopes = [{"id": "1", "kind": "global", "name": "Global"},
                  {"id": "2", "kind": "site", "name": "Site", "metadata": {"id": 20}},
                  {"id": "3", "kind": "group", "name": "Group", "metadata": {"id": 30}},
                  {"id": "4", "kind": "device", "name": "Switch",
                   "metadata": {"siteId": 20, "deviceGroupId": 30}}]
        direct = {"aruba-annotation:inherited": False, "aruba-annotation:object_type": "LOCAL"}
        inherited = {**direct, "aruba-annotation:inherited": True}
        def vlan(name, ann):
            return view({"10": {"vlan": 10, "name": name, "@": ann}})
        data = {"results": {"ACCESS_SWITCH": {"scopes": scopes, "modules": {
            "layer2-vlan": {"scope_results": [
                {"scope": "1", "effective_view": vlan("Global", direct)},
                {"scope": "2", "effective_view": vlan("Site", direct)},
                {"scope": "3", "effective_view": vlan("Group", direct)},
                {"scope": "4", "effective_view": vlan("Group", inherited)}]}}}}}
        findings = advanced_analysis(data)["shadowed"]
        self.assertEqual({f["winning_scope"] for f in findings}, {"Group"})
        self.assertEqual({f["higher_scope"] for f in findings}, {"Site", "Global"})
        scopes[-1]["metadata"].pop("deviceGroupId")
        self.assertEqual(advanced_analysis(data)["shadowed"], [])

    def test_library_usage_separates_names_assignments_and_consumers(self):
        from advanced_review import library_usage, preferred_duplicate
        shared = {"aruba-annotation:object_type": "SHARED", "aruba-annotation:inherited": True}
        local = {"aruba-annotation:object_type": "LOCAL"}
        profiles = {"a": {"profile-name": "a", "enable": True},
                    "b": {"profile-name": "b", "enable": True}}
        scopes = [{"id": "1", "kind": "device", "name": "A"},
                  {"id": "2", "kind": "device", "name": "B"},
                  {"id": "3", "kind": "device", "name": "Unknown"}]
        assignments = [{"scope-id": "10", "device-function": "ACCESS_SWITCH",
                        "profile-type": "sw-port-profiles", "profile-instance": "a"}]
        data = {"results": {"ACCESS_SWITCH": {"scopes": scopes, "modules": {
            "sw-port-profiles": {"scope_results": [
                {"scope": "1", "effective_view": view({"a": {**profiles["a"], "@": shared},
                                                       "b": {**profiles["b"], "@": local}})},
                {"scope": "2", "effective_view": view({"a": {**profiles["a"], "@": shared}})},
                {"scope": "3", "effective_view": {"status": "empty_object", "profiles": {}}}]}}}},
            "library": {"modules": {"sw-port-profiles": view(profiles)},
                        "assignments": {"status": "response_received", "rows": assignments * 2}}}
        ref = {"persona": "ACCESS_SWITCH", "scope": "1", "device": "A",
               "source_module": "ethernet-interfaces", "source": "1/1/1",
               "target_module": "sw-port-profiles", "target": "a"}
        refs = [{**ref, "path": ["sw-profile"]}, {**ref, "path": ["other"]},
                {**ref, "source": "1/1/2", "path": ["sw-profile"]},
                {**ref, "target": "b", "path": ["sw-profile"]}]
        usage = library_usage(data, "sw-port-profiles", profiles, refs)
        self.assertEqual(usage["a"]["assignment_count"], 1)
        self.assertEqual(usage["a"]["reference_count"], 2)
        self.assertEqual(len(usage["a"]["shared_devices"]), 2)
        self.assertEqual(len(usage["b"]["matching_other_devices"]), 1)
        self.assertEqual(len(usage["b"]["shared_devices"]), 0)
        self.assertEqual(len(usage["a"]["unknown_devices"]), 1)
        self.assertFalse(usage["a"]["coverage_complete"])
        self.assertEqual(preferred_duplicate(usage), "a")
        data["library"]["assignments"]["status"] = "request_rejected"
        self.assertIsNone(preferred_duplicate(library_usage(data, "sw-port-profiles", profiles, refs)))


    def test_saved_and_library_dependencies_count_even_without_deployments(self):
        roles = view({"employee": {"name": "employee"}})
        wlan = view({"wifi": {"ssid": "wifi", "default-role": "employee",
                             "auth-server-group": "radgrp", "primary-auth-server": "rad1"}})
        groups = view({"radgrp": {"name": "radgrp"}})
        auth = view({"rad1": {"name": "rad1"}})
        data = {"results": {"CAMPUS_AP": {"scopes": [
            {"id": "1", "kind": "global", "name": "Global"}], "modules": {
            "wlan-ssids": {"scope_results": [{"scope": "1", "local_view": wlan, "effective_view": wlan}]},
            "roles": {"scope_results": [{"scope": "1", "effective_view": roles}]},
            "server-groups": {"scope_results": [{"scope": "1", "effective_view": groups}]},
            "auth-servers": {"scope_results": [{"scope": "1", "effective_view": auth}]}
        }}}, "library": {"modules": {"roles": roles, "wlan-ssids": wlan,
                                     "server-groups": groups, "auth-servers": auth}}}
        findings = advanced_analysis(data)
        references = findings["references"]
        self.assertEqual(len(references), 6)
        self.assertEqual({r["source_scope_kind"] for r in references}, {"global", "library"})
        self.assertTrue(all(r["status"] == "definition_observed" for r in references))
        from advanced_review import library_usage
        usage = library_usage(data, "roles", ["employee"], references)["employee"]
        self.assertEqual(usage["reference_count"], 2)
        self.assertEqual(usage["reference_devices"], 0)
        self.assertFalse(usage["coverage_complete"])


    def test_duplicate_migration_preview_separates_saved_edits_from_effective_impact(self):
        from advanced_review import duplicate_migration_preview
        base_ref = {"persona": "ACCESS_SWITCH", "scope": "2", "device": "Switch",
                    "source_module": "ethernet-interfaces", "source": "1/1/1",
                    "target_module": "sw-port-profiles", "target": "old",
                    "path": ["sw-profile"], "status": "observed"}
        common = {"different_devices": [], "unknown_devices": [], "references": [],
                  "assignments": []}
        usage = {"keep": {**common, "assignments": [{"scope-id": "1", "device-function": "ACCESS_SWITCH"}]},
                 "old": {**common, "assignments": [{"scope-id": "1", "device-function": "ACCESS_SWITCH"},
                                                   {"scope-id": "2", "device-function": "ACCESS_SWITCH"}],
                         "references": [{**base_ref, "source_view": "saved"},
                                        {**base_ref, "source_view": "effective"}]}}
        plan = duplicate_migration_preview("sw-port-profiles", usage, "keep")
        self.assertEqual(len(plan["assignments"]), 2)
        self.assertEqual([a["action"] for a in plan["assignments"]],
                         ["verify_existing_assignment", "review_target_assignment"])
        self.assertEqual(len(plan["saved_references"]), 1)
        self.assertEqual(len(plan["effective_references"]), 1)
        self.assertEqual(plan["saved_references"][0]["to"], "keep")
        self.assertFalse(plan["complete"])
        self.assertFalse(plan["safe_to_apply"])


    def test_migration_recipients_check_retained_profile_visibility(self):
        from advanced_review import library_usage, duplicate_migration_preview
        persona = "ACCESS_SWITCH"
        profiles = {"keep": {"profile-name": "keep", "enable": True},
                    "old": {"profile-name": "old", "enable": True}}
        shared = {"aruba-annotation:object_type": "SHARED"}
        scopes = [{"id": "1", "kind": "site", "name": "Site"},
                  {"id": "2", "kind": "device", "name": "A", "metadata": {"siteId": "1"}},
                  {"id": "3", "kind": "device", "name": "B", "metadata": {"siteId": "1"}},
                  {"id": "4", "kind": "device", "name": "Unknown"}]
        def captured(rows, confirmed=True):
            return {**view(rows), "count_confirmed": confirmed}
        bundle = {"results": {persona: {"scopes": scopes, "modules": {
            "sw-port-profiles": {"scope_results": [
                {"scope": "2", "effective_view": captured({"keep": {**profiles["keep"], "@": shared}})},
                {"scope": "3", "effective_view": captured({})},
                {"scope": "4", "effective_view": captured({}, False)}]}}}},
            "library": {"modules": {"sw-port-profiles": view(profiles)},
                        "assignments": {"status": "response_received", "rows": [
                            {"profile-type": "sw-port-profiles", "profile-instance": "old",
                             "scope-id": "1", "device-function": persona}]}}}
        usage = library_usage(bundle, "sw-port-profiles", profiles, [])
        plan = duplicate_migration_preview("sw-port-profiles", usage, "keep", bundle=bundle)
        rows = {r["scope"]: r for r in plan["recipient_review"]}
        self.assertEqual(rows["2"]["target_visibility"], "matching_shared")
        self.assertEqual(rows["3"]["target_visibility"], "count_confirmed_absence")
        self.assertEqual(rows["4"]["target_visibility"], "unverified")
        self.assertTrue(rows["4"]["uncertain_membership"])
        self.assertFalse(rows["2"]["uncertain_membership"])
        self.assertFalse(plan["safe_to_apply"])


    def test_documented_port_security_dependencies(self):
        from advanced_review import explicit_references
        body = {"profile-name": "Access", "aaa-profile": "dot1x", "fault-monitor-profile": "link",
                "macsec-policy": "secure", "mka-policy": "keys", "nd-snooping-profile": "ipv6",
                "dfp-profile": "fingerprint"}
        refs = {(module, name) for module, name, _ in explicit_references(body, module="sw-port-profiles")}
        self.assertEqual(refs, {("aaa-profile", "dot1x"), ("fault-monitor", "link"),
                                ("macsec", "secure"), ("mka", "keys"),
                                ("nd-snooping", "ipv6"), ("devicefingerprinting-profile", "fingerprint")})
        self.assertEqual(list(explicit_references({"profile-name": "fingerprint"}, module="devicefingerprinting-interface")),
                         [("devicefingerprinting-profile", "fingerprint", ("profile-name",))])
        self.assertFalse(list(explicit_references({"aaa-profile": "dot1x"}, module="unqualified")))


    def test_aaa_references_preserve_list_members_and_unresolved_values(self):
        from advanced_review import explicit_references
        body = {"authentication": {"dpp-netaccess-default-role": "guest",
                                  "dpp-netaccess-server-group": "radgrp",
                                  "rfc3576-server-list": ["coa-a", "coa-b", None]},
                "authorization": {"acct-server-group": "acctgrp"},
                "rfc3576-profile": "legacy-coa"}
        references = list(explicit_references(body, module="aaa-profile"))
        self.assertIn(("roles", "guest", ("authentication", "dpp-netaccess-default-role")), references)
        self.assertIn(("server-groups", "radgrp", ("authentication", "dpp-netaccess-server-group")), references)
        self.assertIn(("server-groups", "acctgrp", ("authorization", "acct-server-group")), references)
        self.assertIn(("auth-servers", "coa-a", ("authentication", "rfc3576-server-list", 0)), references)
        self.assertIn(("auth-servers", "coa-b", ("authentication", "rfc3576-server-list", 1)), references)
        self.assertIn(("auth-servers", None, ("authentication", "rfc3576-server-list", 2)), references)
        self.assertIn(("auth-servers", "legacy-coa", ("rfc3576-profile",)), references)
        self.assertEqual(list(explicit_references({"rfc3576-server-list": "unexpected"}, module="aaa-profile")),
                         [("auth-servers", None, ("rfc3576-server-list",))])
        self.assertFalse(list(explicit_references({"rfc3576-server-list": ["coa"]}, module="unqualified")))


    def test_duplicate_groups_preserve_separate_usage_after_indexing(self):
        from advanced_review import library_usage
        profiles = {name: {"profile-name": name, "enable": value}
                    for name, value in (("a", True), ("b", True), ("c", False), ("d", False))}
        rows = [{"profile-type": "sw-port-profiles", "profile-instance": name,
                 "device-function": "ACCESS_SWITCH", "scope-id": str(i)}
                for i, name in enumerate(("a", "c", "c"), 1)]
        bundle = {"results": {}, "library": {"modules": {"sw-port-profiles": view(profiles)},
                   "assignments": {"status": "response_received", "rows": rows}}}
        groups = advanced_analysis(bundle)["library_duplicates"]
        self.assertEqual([g["identities"] for g in groups], [["a", "b"], ["c", "d"]])
        self.assertEqual(groups[0]["usage"]["a"]["assignment_count"], 1)
        self.assertEqual(groups[1]["usage"]["c"]["assignment_count"], 2)
        self.assertEqual(groups[0]["suggested_keep"], "a")
        self.assertEqual(groups[1]["suggested_keep"], "c")
        self.assertEqual(library_usage(bundle, "sw-port-profiles", [], []), {})


    def test_policy_named_objects_are_context_specific_dependencies(self):
        from advanced_review import explicit_references
        body = {"security-policy": {"policy-rule": [
            {"condition": {"services": {"net-service": "dns-service"},
                           "transport-fields": {"destination-port-net-group": "ports"},
                           "source": {"role-options": {"net-group": "source-group"}},
                           "destination": {"role-options": {"net-group": "destination-group"},
                                           "address-group": "unqualified-family"}}},
            {"condition": {"services": {"net-service": None}}}
        ]}, "net-service": "unrelated"}
        refs = list(explicit_references(body, module="policies"))
        self.assertEqual({(m, v) for m, v, _ in refs}, {
            ("net-services", "dns-service"), ("net-groups", "ports"),
            ("net-groups", "source-group"), ("net-groups", "destination-group"),
            ("net-services", None)})
        self.assertIn(("net-services", "dns-service",
                       ("security-policy", "policy-rule", 0, "condition", "services", "net-service")), refs)
        self.assertFalse(list(explicit_references(body, module="unqualified")))


    def test_network_group_exclusion_counts_as_library_usage(self):
        from advanced_review import explicit_references
        body = {"name": "parent", "exclude": "child", "items": [{"exclude": "unrelated"}]}
        self.assertEqual(list(explicit_references(body, module="net-groups")),
                         [("net-groups", "child", ("exclude",))])
        self.assertFalse(list(explicit_references(body, module="unqualified")))
        self.assertEqual(list(explicit_references({"exclude": {}}, module="net-groups")),
                         [("net-groups", None, ("exclude",))])
        profiles = {"parent": body, "child": {"name": "child", "invert": False}}
        bundle = {"results": {}, "library": {"modules": {
            "net-groups": {"status": "list_parsed", "profiles": profiles}}}}
        refs = advanced_analysis(bundle)["references"]
        usage = library_usage(bundle, "net-groups", ["child"], refs)["child"]
        self.assertEqual(usage["reference_count"], 1)
        self.assertEqual(usage["definition_reference_count"], 1)
        self.assertEqual(usage["reference_devices"], 0)
        self.assertFalse(usage["coverage_complete"])
