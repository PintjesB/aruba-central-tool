import unittest
from aruba_central.central_tool import APIError, Central, EmptyCommittedLocal, EU_REGIONS, check_empty_local, detect_region, inventory, offset_rows, report, review_local_profiles, scoped_vlan_rows, vlan_map, vlan_rows


class Fake:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = []

    def get(self, path, **params):
        self.calls.append((path, params))
        return next(self.pages)


def scope(id_, kind, effective, local=()):
    return {"id": id_, "kind": kind, "name": id_, "effective": effective, "local": list(local)}


class RegionFake:
    def __init__(self, results):
        self.results = results
        self.calls = []
        self.base = None

    def get(self, path, **params):
        self.calls.append(self.base)
        status = self.results[self.base]
        if status != 200:
            raise APIError(path, status)
        return {"items": []}


class Tests(unittest.TestCase):
    def test_region_preferred_success(self):
        client = RegionFake({EU_REGIONS[1]: 200})
        self.assertEqual(detect_region(client, EU_REGIONS[1]), EU_REGIONS[1])
        self.assertEqual(client.calls, [EU_REGIONS[1]])

    def test_region_fallback(self):
        client = RegionFake(dict(zip(EU_REGIONS, (401, 200, 401))))
        self.assertEqual(detect_region(client, EU_REGIONS[0]), EU_REGIONS[1])
        self.assertEqual(client.base, EU_REGIONS[1])
        self.assertEqual(client.calls, list(EU_REGIONS))

    def test_region_without_preference(self):
        client = RegionFake(dict(zip(EU_REGIONS, (401, 200, 401))))
        self.assertEqual(detect_region(client), EU_REGIONS[1])

    def test_region_ambiguous(self):
        client = RegionFake(dict(zip(EU_REGIONS, (401, 200, 200))))
        with self.assertRaisesRegex(RuntimeError, "Multiple"):
            detect_region(client)

    def test_region_no_match(self):
        client = RegionFake(dict(zip(EU_REGIONS, (401, 401, 401))))
        with self.assertRaisesRegex(RuntimeError, "no authorized"):
            detect_region(client)

    def test_region_permission_failure_no_fallback(self):
        client = RegionFake({EU_REGIONS[0]: 403})
        with self.assertRaises(APIError):
            detect_region(client, EU_REGIONS[0])
        self.assertEqual(client.calls, [EU_REGIONS[0]])

    def test_cursor_pagination(self):
        client = Fake([{"items": [{"id": "1"}], "next": "2", "total": 2},
                       {"items": [{"id": "2"}], "total": 2}])
        self.assertEqual(len(inventory(client)), 2)
        self.assertEqual(client.calls[1][1]["next"], "2")

    def test_vlan_library_full_read_validated_against_total(self):
        full = [{"vlan": n} for n in range(1, 30)]
        client = Fake([{"l2-vlan": full[:10], "metadata":
                        {"total": 29, "count": 10, "offset": 10, "default_profiles_count": 1}},
                       {"l2-vlan": full}])
        self.assertEqual(vlan_rows(client, **{"view-type": "LIBRARY"}), full)
        self.assertEqual(client.calls[0][1]["limit"], 10)
        self.assertEqual(client.calls[0][1]["offset"], 0)
        self.assertNotIn("offset", client.calls[1][1])
        self.assertNotIn("limit", client.calls[1][1])

    def test_vlan_library_empty(self):
        client = Fake([{"l2-vlan": [], "metadata": {"total": 0, "count": 0, "offset": 0}},
                       {"l2-vlan": []}])
        self.assertEqual(vlan_rows(client, **{"view-type": "LIBRARY"}), [])

    def test_vlan_library_inconsistent_metadata_fails(self):
        client = Fake([{"l2-vlan": [{"vlan": 1}], "metadata":
                       {"total": 29, "count": 1, "offset": 10}}])
        with self.assertRaisesRegex(RuntimeError, "Inconsistent"):
            vlan_rows(client, **{"view-type": "LIBRARY"})

    def test_vlan_library_truncated_full_response_fails(self):
        full = [{"vlan": n} for n in range(1, 30)]
        client = Fake([{"l2-vlan": full[:10], "metadata": {"total": 29, "count": 10}},
                       {"l2-vlan": full[:20]}])
        with self.assertRaisesRegex(RuntimeError, "count mismatch"):
            vlan_rows(client, **{"view-type": "LIBRARY"})

    def test_vlan_library_changed_first_page_fails(self):
        client = Fake([{"l2-vlan": [{"vlan": 1}], "metadata": {"total": 1, "count": 1}},
                       {"l2-vlan": [{"vlan": 2}]}])
        with self.assertRaisesRegex(RuntimeError, "differs"):
            vlan_rows(client, **{"view-type": "LIBRARY"})

    def test_vlan_scoped_reads_unpaginated(self):
        data = [{"vlan": n} for n in range(1, 23)]
        client = Fake([{"l2-vlan": data, "metadata":
                       {"count_objects_in_module": {"LOCAL": 1, "SHARED": 21, "ANY": 22}}}])
        self.assertEqual(vlan_rows(client, **{"view-type": "LOCAL", "effective": "true"}), data)
        self.assertNotIn("limit", client.calls[0][1])
        self.assertNotIn("offset", client.calls[0][1])

    def test_observed_empty_object_only_for_committed_local(self):
        result = vlan_rows(Fake([{}]), **{"view-type": "LOCAL",
                          "object-type": "LOCAL", "effective": "false"})
        self.assertIsInstance(result, EmptyCommittedLocal)
        self.assertEqual(result, [])
        with self.assertRaisesRegex(RuntimeError, "Unrecognized"):
            vlan_rows(Fake([{}]), **{"view-type": "LOCAL", "effective": "true"})
        with self.assertRaisesRegex(RuntimeError, "Unrecognized"):
            vlan_rows(Fake([{}]), **{"view-type": "LOCAL", "object-type": "LOCAL",
                                    "effective": "true"})

    def test_empty_local_annotation_cross_check(self):
        def profile(inherited, kind):
            return {"vlan": 10, "@": {"aruba-annotation:inherited": inherited,
                                     "aruba-annotation:object_type": kind}}
        self.assertEqual(check_empty_local([profile(True, "LOCAL"), profile(False, "SHARED")]),
                         "consistent_with_effective_annotations")
        self.assertEqual(check_empty_local([profile(False, "LOCAL")]), "contradictory_local_profile")
        self.assertEqual(check_empty_local([{"vlan": 10}]), "unverified_annotations")
        self.assertEqual(check_empty_local([]), "no_effective_profiles")

    def test_scoped_missing_module_with_explicit_zero(self):
        response = {"metadata": {"count_objects_in_module": {"LOCAL": 0, "SHARED": 22, "ANY": 22}}}
        self.assertEqual(scoped_vlan_rows(response, "LOCAL"), [])
        with self.assertRaisesRegex(ValueError, "Unrecognized"):
            scoped_vlan_rows(response, "ANY")

    def test_scoped_null_module_with_explicit_zero(self):
        self.assertEqual(scoped_vlan_rows({"l2-vlan": None, "metadata":
                         {"count_objects_in_module": {"ANY": 0}}}), [])

    def test_scoped_unknown_is_not_empty(self):
        for response in ({}, {"metadata": {}},
                         {"metadata": {"count_objects_in_module": {"LOCAL": False}}},
                         {"error": "hidden", "metadata": {"count_objects_in_module": {"LOCAL": 0}}},
                         {"l2-vlan": {}, "metadata": {"count_objects_in_module": {"LOCAL": 0}}},
                         {"metadata": {"total": 1, "count_objects_in_module": {"LOCAL": 0}}}):
            with self.subTest(response=response), self.assertRaises(ValueError):
                scoped_vlan_rows(response, "LOCAL")

    def test_scoped_empty_list_positive_count_fails(self):
        with self.assertRaisesRegex(ValueError, "contradicts"):
            scoped_vlan_rows({"l2-vlan": [], "metadata": {"count_objects_in_module": {"LOCAL": 1}}}, "LOCAL")

    def test_scoped_error_does_not_expose_arbitrary_keys_or_values(self):
        with self.assertRaises(ValueError) as error:
            scoped_vlan_rows({"private-customer-name": "private-value", "metadata":
                              {"count_objects_in_module": {"LOCAL": 1}}}, "LOCAL")
        self.assertNotIn("private", str(error.exception))
        self.assertIn('"LOCAL":1', str(error.exception))

    def test_vlan_error_has_safe_parameters(self):
        class Reject:
            def get(self, path, **params):
                raise APIError(path, 400)
        with self.assertRaises(RuntimeError) as error:
            vlan_rows(Reject(), **{"view-type": "LOCAL", "scope-id": "123456789"})
        message = str(error.exception)
        self.assertIn("HTTP 400", message)
        self.assertIn("LOCAL", message)
        self.assertNotIn("123456789", message)

    def test_offset_pagination(self):
        client = Fake([{"items": [{"id": "1"}]}, {"items": [{"id": "2"}]}, {"items": []}])
        self.assertEqual(len(offset_rows(client, "/x", ("items",))), 2)
        self.assertEqual(client.calls[1][1]["offset"], 1)

    def test_inventory_pagination_keeps_previous_total_and_rejects_duplicate_records(self):
        for pages in (
            [{"items": [{"id": "1"}], "total": 2}, {"items": []}],
            [{"items": [{"id": "1"}], "total": 2}, {"items": [{"id": "2"}], "total": 3}],
            [{"items": [{"id": "1"}]}, {"items": [{"id": "1"}, {"id": "2"}]}],
        ):
            with self.assertRaises(ValueError):
                offset_rows(Fake(pages), "/x", ("items",))
        for pages in (
            [{"items": [{"id": "1"}], "next": "a", "total": 3}, {"items": [{"id": "2"}]}],
            [{"items": [{"id": "1"}], "next": "a"}, {"items": [{"id": "1"}, {"id": "2"}]}],
            [{"items": [{"id": "1"}], "next": "a", "total": 2}, {"items": [{"id": "2"}], "total": 3}],
        ):
            with self.assertRaises(ValueError):
                inventory(Fake(pages))
        self.assertEqual(len(inventory(Fake([{"items": [{"id": "1"}], "next": "a", "total": 2},
                                            {"items": [{"id": "2"}]}]))), 2)

    def test_repeated_page_fails(self):
        client = Fake([{"items": [{"id": "1"}]}] * 2)
        with self.assertRaises(ValueError):
            offset_rows(client, "/x", ("items",))

    def test_unknown_envelope_fails(self):
        with self.assertRaises(ValueError):
            inventory(Fake([{"unknown": []}]))

    def test_duplicate_vlan_fails(self):
        with self.assertRaises(ValueError):
            vlan_map([{"vlan": 30}, {"vlan": 30}])

    def test_untrusted_host_fails(self):
        with self.assertRaises(ValueError):
            Central("https://de1.api.central.arubanetworks.com.evil.example", token="fake")

    def test_exact_field_diff_distinguishes_missing_null_and_false(self):
        from aruba_central.central_tool import field_differences
        left = {"vlan": 10, "enable": False, "igmp": {"snooping": True}, "is-l3-vlan": None}
        right = {"vlan": 10, "enable": 0, "igmp": {"snooping": False}, "voice-enable": False}
        differences = {tuple(d["path"]): d for d in field_differences(left, right)}
        self.assertEqual(differences[("enable",)]["kind"], "type_difference")
        self.assertEqual(differences[("igmp", "snooping")]["kind"], "value_difference")
        self.assertEqual(differences[("is-l3-vlan",)]["kind"], "missing_reference")
        self.assertIsNone(differences[("is-l3-vlan",)]["local_value"])
        self.assertEqual(differences[("voice-enable",)]["kind"], "missing_local")
        self.assertNotIn("local_value", differences[("voice-enable",)])
        self.assertEqual(field_differences({"a": None}, {"a": False})[0]["kind"], "null_vs_value")
        self.assertEqual(field_differences({"a": 1, "b": 2}, {"b": 2, "a": 1}), [])
        self.assertTrue(field_differences([1, 2], [2, 1]))

    def test_summary_contains_no_customer_values_or_unknown_keys(self):
        import contextlib
        import io
        from aruba_central.central_tool import field_differences, print_review_summary
        diff = field_differences({"name": "private-name", "private-key": "secret-value"},
                                 {"name": "other-private-name", "private-key": "other-secret-value"})
        data = {"local_profile_review": [{"recommendation": "resolve_library_conflict",
                 "library_differences": diff}], "scope_comparisons": [], "excluded_device_count": 0}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            print_review_summary(data)
        result = output.getvalue()
        for private in ("private-name", "private-key", "secret-value"):
            self.assertNotIn(private, result)
        self.assertIn("[other-field]", result)
        self.assertIn("name: value_difference", result)

    def test_default_aware_assessment_does_not_assume_multicast_or_l3_equivalence(self):
        from aruba_central.central_tool import assess_vlan_reference
        local = {"vlan": 10}
        shared = {"vlan": 10, "enable": True, "voice-enable": False,
                  "dhcpv4-snooping": {"enable": False}}
        self.assertEqual(assess_vlan_reference(local, shared)["classification"],
                         "documented_defaults_only")
        for reference in ({"vlan": 10, "igmp": {"snooping": False}},
                          {"vlan": 10, "mld": {"snooping": True}},
                          {"vlan": 10, "is-l3-vlan": None},
                          {"vlan": 10, "name": "private"},
                          {"vlan": 10, "enable": False},
                          {"vlan": 10, "dhcpv4-snooping": {"enable": True}}):
            with self.subTest(reference=reference):
                self.assertEqual(assess_vlan_reference(local, reference)["classification"],
                                 "requires_validation")
        self.assertEqual(assess_vlan_reference({"vlan": 10, "name": "A"},
                         {"vlan": 10, "name": "B"})["classification"], "explicit_difference")
        self.assertEqual(assess_vlan_reference({"vlan": 10, "voice-enable-alias": "x"},
                         {"vlan": 10, "voice-enable-alias": "x", "voice-enable": False})["classification"],
                         "requires_validation")

    def test_review_does_not_propose_global_scope_for_library_only_vlan(self):
        a = {"vlan": 10}
        b = {"vlan": 10, "enable": True}
        s = scope("2", "device", [a], [a])
        review = review_local_profiles([s], {}, {"10": b})[0]
        self.assertEqual(review["proposed_review"], "review_library_reuse_at_existing_scope")
        self.assertEqual(review["status"], "review_only")

    def test_device_capabilities_detect_known_and_unknown(self):
        from aruba_central.central_tool import inventory_capabilities
        records = inventory_capabilities([
            {"model": "6100", "firmwareVersion": "PL.10.16.1006", "deviceFunction": "Access Switch"},
            {"model": "6200", "firmwareVersion": "FL.10.99.1000", "deviceFunction": "Core Switch"},
            {"model": "505", "softwareVersion": "8.13.3.1", "deviceFunction": "Campus AP"},
            {}])
        self.assertEqual(len(records), 4)
        self.assertTrue(records[0]["multicast_defaults"]["igmp"])
        self.assertTrue(records[1]["vlan_scan_supported_persona"])
        self.assertEqual(records[1]["multicast_defaults"]["status"], "unknown")
        self.assertFalse(records[2]["vlan_scan_supported_persona"])
        self.assertEqual(records[3]["identity"]["persona"], "UNKNOWN")

    def test_scan_all_uses_discovered_personas(self):
        from unittest.mock import patch
        from aruba_central.central_tool import scan_all, select_snapshot
        devices = [{"deviceFunction": "Access Switch"}, {"deviceFunction": "Core Switch"},
                   {"deviceFunction": "Campus AP"}, {"deviceFunction": "Access Switch"}]
        class Client:
            base = "test"
        with patch("aruba_central.central_tool.inventory", return_value=devices), patch("aruba_central.central_tool.scan") as scan:
            scan.side_effect = lambda client, persona, devices: {"persona": persona}
            result = scan_all(Client())
        self.assertEqual(set(result["snapshots"]), {"ACCESS_SWITCH", "CORE_SWITCH"})
        self.assertEqual(len(result["inventory"]), 4)
        self.assertEqual(scan.call_count, 2)
        self.assertEqual(select_snapshot(result, "CORE_SWITCH")["persona"], "CORE_SWITCH")
        with self.assertRaises(ValueError):
            select_snapshot(result)

    def test_audit_reviews_every_discovered_persona_and_reports_unqualified(self):
        from unittest.mock import patch
        from aruba_central.central_tool import audit
        class Client:
            base = "test"
        source = {"kind": "multi_persona_scan", "region": "test", "inventory": [
            {"identity": {"persona": "ACCESS_SWITCH"}, "vlan_scan_supported_persona": True},
            {"identity": {"persona": "CORE_SWITCH"}, "vlan_scan_supported_persona": True},
            {"identity": {"persona": "CAMPUS_AP"}, "vlan_scan_supported_persona": False}],
            "snapshots": {p: {"persona": p, "region": "test"} for p in ("ACCESS_SWITCH", "CORE_SWITCH")}}
        with patch("aruba_central.central_tool.scan_all", return_value=source) as scan, \
             patch("aruba_central.central_tool.discover_dependencies", return_value={}) as probe, \
             patch("aruba_central.central_tool.report", return_value={}), \
             patch("aruba_central.central_tool.dependency_review", return_value={"safe_to_apply": False}) as review, \
             patch("aruba_central.central_tool.print_review_summary"), patch("aruba_central.central_tool.print_dependency_summary"):
            result = audit(Client())
            self.assertEqual(set(result["results"]), {"ACCESS_SWITCH", "CORE_SWITCH"})
            self.assertEqual(result["unqualified_personas"], {"CAMPUS_AP": 1})
            self.assertFalse(result["safe_to_apply"])
            self.assertEqual(probe.call_count, 2)
            self.assertEqual(review.call_count, 2)
            self.assertEqual(scan.call_count, 1)
            scan.return_value = {**source, "region": "other"}
            with self.assertRaises(ValueError):
                audit(Client())

    def test_dependencies_probe_distinguishes_empty_from_permission(self):
        from aruba_central.central_tool import discover_dependencies
        class Probe:
            def get(self, path, **params):
                if path.endswith("sw-port-profiles"):
                    raise APIError(path, 403)
                return {}
        data = discover_dependencies(Probe(), {"region": "test", "persona": "ACCESS_SWITCH",
                                               "scopes": [scope("2", "device", [])]})
        caps = data["devices"][0]["capabilities"]
        self.assertEqual(caps["mgmd-global"], "empty_response")
        self.assertEqual(caps["sw-port-profiles"], "permission_denied")

    def test_dependency_review_protects_svi_and_multicast(self):
        from aruba_central.central_tool import dependency_review
        local = {"vlan": 10, "is-l3-vlan": True}
        shared = {"vlan": 10, "igmp": {"snooping": False}}
        device = scope("2", "device", [local], [local])
        device["metadata"] = {"model": "6100", "firmwareVersion": "PL.10.16.1006"}
        snapshot = {"schema": 1, "captured_at": "example", "region": "example",
                    "persona": "ACCESS_SWITCH", "library": [shared], "excluded_devices": [],
                    "scopes": [scope("1", "global", [shared]), device]}
        deps = {"region": "example", "persona": "ACCESS_SWITCH", "devices": [
            {"scope_id": "2", "modules": {
                "vlan-interfaces": {"interface": [{"id": "vlan10"}]},
                "ethernet-interfaces": {"interface": [{"name": "1/1/1"}]},
                "sw-port-profiles": {"profile": [{"name": "test"}]}, "mgmd-global": {}}}]}
        result = dependency_review(snapshot, deps, report(snapshot))
        row = result["local_profile_review"][0]
        self.assertIn("preserve_svi", row["dependency_blockers"])
        self.assertIn("potential_aoscx_10_16_multicast_behavior_change", row["dependency_blockers"])
        self.assertFalse(row["migration_eligible"])
        self.assertEqual(result["dependency_review"]["devices"][0]["svi_ids"], ["10"])
        self.assertEqual(result["dependency_review"]["devices"][0]["issues"], [])
        deps["devices"] = []
        with self.assertRaisesRegex(ValueError, "coverage mismatch"):
            dependency_review(snapshot, deps, report(snapshot))

    def test_reference_candidates_keep_unresolved_and_ignore_annotations(self):
        from aruba_central.central_tool import reference_candidates
        payload = {"interfaces": [{"switchport": {"native-vlan": 10, "allowed-vlans": ["20-22", 40]},
                                   "unknown-vlan-field": 99, "name": "1/1/10",
                                   "@": {"vlan": 123}, "metadata": {"vlan": 100}},
                                  {"switchport": {"allowed-vlans": "all"}},
                                  {"switchport": {"allowed-vlans": []}}]}
        result = reference_candidates(payload)
        self.assertEqual([r["vlan_ids"] for r in result["references"]], [["10"], ["20", "21", "22", "40"]])
        self.assertEqual(len(result["unresolved_paths"]), 3)

    def test_operational_probe_uses_known_inventory_identity_only(self):
        from aruba_central.central_tool import probe_operational_vlans, operational_vlan_summary
        fake = Fake([{"items": [{"id": 10, "igmp": True}]}])
        self.assertEqual(probe_operational_vlans(fake, {"serialNumber": "../bad"})["status"], "identity_unresolved")
        self.assertEqual(fake.calls, [])
        result = probe_operational_vlans(fake, {"serialNumber": "ABC123"})
        self.assertEqual(fake.calls[0][0], "/network-monitoring/v1/switches/ABC123/vlans")
        self.assertEqual(operational_vlan_summary(result)["rows"], 1)
        self.assertEqual(operational_vlan_summary(result)["status"], "schema_observed")

    def test_operational_probe_falls_back_to_discovered_serial(self):
        from aruba_central.central_tool import probe_operational_vlans, operational_vlan_summary
        class Probe:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append(path)
                if "STACK1" in path:
                    raise APIError(path, 404)
                return {"items": [{"id": 10, "name": "A"}, {"id": 20, "name": "B"}]}
        fake = Probe()
        result = probe_operational_vlans(fake, {"stackId": "STACK1", "serialNumber": "SERIAL1"})
        self.assertEqual(result["identity_field"], "serialNumber")
        self.assertEqual(result["attempts"], [{"identity_field": "stackId", "http_error": 404}])
        summary = operational_vlan_summary(result, {"10": {"name": "C"}, "30": {"name": "D"}})
        self.assertEqual(summary["missing_ids"], ["30"])
        self.assertEqual(summary["additional_ids"], ["20"])
        self.assertEqual(summary["name_mismatches"], ["10"])
        self.assertFalse(summary["multicast_operational_verified"])

    def test_role_reference_resolution_is_exact_and_unambiguous(self):
        from aruba_central.central_tool import reference_candidates
        payload = {"roles": [{"vlan-type": "VLAN_NAME", "access-vlan-name": "A"},
                             {"vlan-type": "VLAN_ID", "access-vlan-id": 30},
                             {"access-vlan-name": "B"}, {"access-vlan-name": "unknown"}]}
        result = reference_candidates(payload, {"10": {"name": "A"}, "20": {"name": "B"},
                                                "21": {"name": "B"}})
        self.assertEqual([r["vlan_ids"] for r in result["references"]], [["10"], ["30"]])
        self.assertEqual(len(result["unresolved_paths"]), 2)

    def test_audit_compare_distinguishes_local_removal_from_effective_change(self):
        from aruba_central.central_tool import compare_audits
        def bundle(local, effective):
            snapshot = {"persona": "ACCESS_SWITCH", "region": "test",
                        "scopes": [scope("g", "global", [{"vlan": 10}]),
                                   scope("s", "device", effective, local)],
                        "library": [{"vlan": 10}]}
            return {"schema": 1, "kind": "tenant_audit", "region": "test",
                    "results": {"ACCESS_SWITCH": {"snapshot": snapshot}}}
        body = {"vlan": 10}
        old = bundle([body], [body])
        new = bundle([], [body])
        comparison = compare_audits(old, new)
        change = comparison["results"]["ACCESS_SWITCH"]["scope_changes"][0]
        self.assertEqual(change["local"]["removed"], ["10"])
        self.assertEqual(change["local_removal_outcomes"][0]["status"], "effective_body_unchanged")
        self.assertFalse(any(change["effective"].values()))
        changed = compare_audits(old, bundle([], [{"vlan": 10, "enable": True}]))
        self.assertEqual(changed["results"]["ACCESS_SWITCH"]["scope_changes"][0]
                         ["local_removal_outcomes"][0]["status"], "effective_body_changed")
        self.assertFalse(comparison["same_tenant_verified"])

    def test_offline_review_keeps_reference_previews_nonexecutable(self):
        from aruba_central.central_tool import offline_audit_review
        from unittest.mock import patch
        body = {"vlan": 10}
        snapshot = {"persona": "ACCESS_SWITCH", "region": "test",
                    "scopes": [scope("g", "global", [body]), scope("s", "device", [body], [body])],
                    "library": [body]}
        bundle = {"schema": 1, "kind": "tenant_audit", "region": "test",
                  "results": {"ACCESS_SWITCH": {"snapshot": snapshot, "dependencies": {}}}}
        row = {"vlan": "10", "scope": "s", "scope_kind": "device", "profile": body,
               "proposed_review": "review_restore_global_inheritance",
               "dependency_blockers": ["operational_equivalence_unverified"], "reference_candidate_modules": []}
        with patch("aruba_central.central_tool.report", return_value={}), patch("aruba_central.central_tool.dependency_review",
                   return_value={"local_profile_review": [row]}):
            result = offline_audit_review(bundle)
        preview = result["results"]["ACCESS_SWITCH"]["previews"][0]
        self.assertEqual(preview["reference_kind"], "global_effective_reference")
        self.assertEqual(preview["reference_differences"], [])
        self.assertFalse(preview["executable"])
        self.assertFalse(preview["effective_after_change_verified"])

    def test_assignment_evidence_filters_persona_type_and_instance(self):
        from aruba_central.central_tool import vlan_assignment_evidence
        base = {"scope-id": "g", "profile-type": "layer2-vlan",
                "device-function": "ACCESS_SWITCH", "profile-instance": "10"}
        snap = {"persona": "ACCESS_SWITCH", "scopes": [scope("g", "global", [])],
                "assignments_raw": {"config-assignment": [base, {**base, "device-function": "CAMPUS_AP"},
                                  {**base, "profile-type": "roles"}, {**base, "profile-instance": "20"}]}}
        evidence = vlan_assignment_evidence(snap, "10", "device")
        self.assertEqual(evidence["matches"], [base])
        self.assertTrue(evidence["global_assignment"])
        self.assertFalse(evidence["inheritance_verified"])

    def test_removal_evidence_detects_changed_fields_without_claiming_equivalence(self):
        from aruba_central.central_tool import removal_evidence
        def bundle(name):
            return {"results": {"ACCESS_SWITCH": {"dependencies": {"devices": [
                {"scope_id": "s", "operational_vlans": {"status": "response_received",
                 "payload": {"items": [{"id": 10, "name": name, "taggedPorts": ["1/1/1"]}]}}}]}}}}
        result = removal_evidence(bundle("A"), bundle("B"), "ACCESS_SWITCH", "s", "10",
                                  {"vlan": 10}, {"vlan": 10, "enable": True})
        self.assertEqual(result["effective_assessment"], "documented_defaults_only")
        self.assertEqual(result["observed_fields"]["name"], "changed")
        self.assertEqual(result["observed_fields"]["taggedPorts"], "unchanged")
        self.assertFalse(result["behavior_preserved_verified"])

    def test_generic_module_preserves_exact_differences_and_sources(self):
        from aruba_central.central_tool import module_view, review_module_scope
        base = {"name": "profile", "enabled": True, "description": "base"}
        local = module_view({"profiles": [{"name": "profile", "enabled": False}]}, "name", "LOCAL")
        effective = module_view({"profiles": [
            {"name": "profile", "enabled": False, "@": {"aruba-annotation:object_type": "LOCAL",
                                                        "aruba-annotation:inherited": False}},
            {"name": "other", "@": {"aruba-annotation:inherited": True}}]}, "name")
        review = review_module_scope(local, effective, {"profile": base})
        self.assertTrue(review["qualified"])
        rows = {r["identity"]: r for r in review["profiles"]}
        self.assertEqual(rows["profile"]["status"], "local_differs_from_global")
        self.assertEqual({d["kind"] for d in rows["profile"]["global_differences"]},
                         {"missing_local", "value_difference"})
        self.assertEqual(rows["other"]["status"], "inherited")
        self.assertFalse(review["safe_to_apply"])
        self.assertEqual(review_module_scope(local, effective, {"profile": base}, True)
                         ["profiles"][1]["status"], "device_local_profile")

    def test_generic_module_rejects_partial_unknown_and_duplicate_shapes(self):
        from aruba_central.central_tool import module_view, review_module_scope
        self.assertEqual(module_view({"profiles": [{"name": "a"}], "metadata": {"total": 2}}, "name")
                         ["status"], "count_mismatch")
        self.assertEqual(module_view({"profiles": [{"name": "a"}, {"name": "a"}]}, "name")
                         ["status"], "identity_unresolved")
        self.assertEqual(module_view({"unexpected": {"name": "a"}}, "name")["status"], "schema_unresolved")
        local = module_view({}, "name")
        effective = module_view({"profiles": [{"name": "a", "@": {"aruba-annotation:object_type": "LOCAL",
                                                                  "aruba-annotation:inherited": False}}]}, "name")
        self.assertFalse(review_module_scope(local, effective, {})["qualified"])
        effective = module_view({"profiles": [{"name": "a", "@": {"aruba-annotation:inherited": True}}]}, "name")
        self.assertTrue(review_module_scope(local, effective, {})["qualified"])
        self.assertFalse(review_module_scope(local, module_view({}, "name"), {})["qualified"])

    def test_documented_catalog_contains_verified_configuration_get_paths(self):
        from aruba_central.central_tool import documented_profile_catalog
        catalog = documented_profile_catalog()
        self.assertEqual(catalog["folders_read"], 25)
        self.assertEqual(catalog["get_requests"], 427)
        self.assertEqual(catalog["unique_get_paths"], 399)
        for module in ("aaa-profile", "dhcp-snooping", "server-groups", "stp",
                       "vrfs", "multicast-global", "radios", "first-hop-security", "dos"):
            self.assertIn(module, catalog["modules"])
        self.assertTrue(catalog["modules"]["aaa-profile"]["all_function_scope"])
        self.assertFalse(catalog["modules"]["first-hop-security"]["all_function_scope"])
        self.assertNotIn("config-assignments", catalog["modules"])
        self.assertFalse(catalog["exhaustive"])

    def test_documented_global_survey_is_independent_of_assignments(self):
        from aruba_central.central_tool import inspect_unadapted_profiles
        discovery = {"unknown_adapter_modules": [], "survey_modules": ["aaa-profile"],
                     "modules": {}, "documented_catalog": {"modules": {
                         "aaa-profile": {"all_function_scope": True}}}}
        payload = {"profiles": [{"name": "example", "@": {
            "aruba-annotation:device_function": "ACCESS_SWITCH"}}]}
        fake = Fake([payload, payload, {"profiles": []}, {"profiles": []},
                     {"profiles": []}, {"profiles": []}, {"profiles": []}])
        result = inspect_unadapted_profiles(fake, discovery, {}, {},
                    scopes_by_persona={"ACCESS_SWITCH": [{"id": "1", "kind": "global"},
                                                         {"id": "12", "kind": "device"}]})
        evidence = result["aaa-profile"]
        global_view = next(v for v in evidence["source_views"] if v["persona"] == "ALL_DEVICE_FUNCTIONS")
        self.assertEqual(global_view["scope"], "1")
        self.assertNotIn("device-function", fake.calls[0][1])
        self.assertEqual(evidence["catalog_scope_coverage"]["global_observed_functions"], ["ACCESS_SWITCH"])
        self.assertEqual(evidence["catalog_scope_coverage"]["all_function_scopes_not_surveyed"], 1)
        self.assertEqual({v["scope"] for v in evidence["source_views"] if v["persona"] == "ACCESS_SWITCH"}, {"1", "12"})
        self.assertFalse(evidence["safe_to_apply"])

    def test_deep_catalog_surveys_lower_scopes_without_assignments(self):
        from aruba_central.central_tool import inspect_unadapted_profiles
        discovery = {"unknown_adapter_modules": [], "survey_modules": ["example"],
                     "modules": {}, "documented_catalog": {"modules": {
                         "example": {"source": "vendor_collection", "all_function_scope": True}}}}
        scopes = {"ACCESS_SWITCH": [{"id": "1", "kind": "global"},
                                   {"id": "12", "kind": "device"}],
                  "CAMPUS_AP": [{"id": "1", "kind": "global"},
                                {"id": "13", "kind": "device"}]}
        fake = Fake([{"profiles": []}, {"profiles": []},
                     {"profiles": [{"name": "local-only"}]}, {"profiles": []},
                     {"profiles": []}, {"profiles": []}, {"profiles": []}])
        result = inspect_unadapted_profiles(fake, discovery, {}, {},
                    scopes_by_persona=scopes, deep_catalog=True)["example"]
        views = result["source_views"]
        self.assertEqual({v["scope"] for v in views}, {"1", "12", "13"})
        self.assertEqual(len(views), 3)
        self.assertEqual(next(v for v in views if v["scope"] == "12")["committed"]["raw"],
                         {"profiles": [{"name": "local-only"}]})
        self.assertEqual(len(fake.calls), 7)
        self.assertTrue(all("device-function" not in params for _, params in fake.calls))
        coverage = result["catalog_scope_coverage"]
        self.assertEqual(coverage["unfiltered_scopes_not_surveyed"], 0)
        self.assertEqual(coverage["global_scopes_attempted"], 1)
        self.assertFalse(coverage["complete"])
        self.assertFalse(result["safe_to_apply"])

    def test_single_supplemental_module_uses_parallel_scope_workers(self):
        from aruba_central.central_tool import inspect_unadapted_profiles
        import threading
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        calls = []

        class ScopeClient:
            def get(self, path, **params):
                with lock:
                    calls.append(dict(params))
                if params.get("scope-id") in ("12", "13") and params.get("effective") == "false":
                    barrier.wait(timeout=5)
                return {}

        discovery = {"unknown_adapter_modules": [], "survey_modules": ["example"],
                     "modules": {}, "documented_catalog": {"modules": {
                         "example": {"source": "vendor_collection", "all_function_scope": True}}}}
        scopes = {"ACCESS_SWITCH": [{"id": "12", "kind": "device"},
                                   {"id": "13", "kind": "device"}]}
        result = inspect_unadapted_profiles(ScopeClient(), discovery, {}, {}, workers=2,
                    scopes_by_persona=scopes, deep_catalog=True)["example"]
        self.assertEqual([view["scope"] for view in result["source_views"]], ["12", "13"])
        self.assertEqual(len(calls), 5)
        self.assertEqual(result["catalog_scope_coverage"]["unfiltered_scopes_not_surveyed"], 0)

    def test_targeted_catalog_limits_empty_modules_and_expands_positive_evidence(self):
        from aruba_central.central_tool import inspect_unadapted_profiles
        discovery = {"unknown_adapter_modules": [], "survey_modules": ["example"],
                     "modules": {}, "documented_catalog": {"modules": {
                         "example": {"source": "vendor_collection", "all_function_scope": True}}}}
        scopes = {"ACCESS_SWITCH": [{"id": "1", "kind": "global"},
                                   {"id": "12", "kind": "device"},
                                   {"id": "13", "kind": "device"}]}
        fake = Fake([{}] * 3)
        result = inspect_unadapted_profiles(fake, discovery, {}, {},
                    scopes_by_persona=scopes, deep_catalog=True,
                    targeted_catalog=True)["example"]
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(result["catalog_scope_coverage"]["unfiltered_scopes_not_surveyed"], 2)
        self.assertFalse(result["catalog_scope_coverage"]["complete"])
        for responses in ([{"profiles": [{"name": "library"}]}] + [{}] * 6,
                          [{}, {"profiles": [{"name": "global"}]}] + [{}] * 5):
            fake = Fake(responses)
            result = inspect_unadapted_profiles(fake, discovery, {}, {},
                        scopes_by_persona=scopes, deep_catalog=True,
                        targeted_catalog=True)["example"]
            self.assertEqual(len(fake.calls), 7)
            self.assertEqual(result["catalog_scope_coverage"]["unfiltered_scopes_not_surveyed"], 0)
        fake = Fake([{}] * 7)
        result = inspect_unadapted_profiles(fake, discovery, {}, {},
                    scopes_by_persona=scopes, deep_catalog=True,
                    targeted_catalog=True, structured_results={"ACCESS_SWITCH": {"modules": {
                        "example": {"scope_results": [{"scope": "12", "local_view": {
                            "raw": {"profiles": [{"name": "local"}]}}, "effective_view": {}}]}}}})["example"]
        self.assertEqual(len(fake.calls), 7)
        self.assertEqual(result["catalog_scope_coverage"]["unfiltered_scopes_not_surveyed"], 0)

    def test_deep_catalog_handles_documented_scope_without_function_selector(self):
        from aruba_central.central_tool import inspect_unadapted_profiles
        discovery = {"unknown_adapter_modules": [], "survey_modules": ["example"],
                     "modules": {}, "documented_catalog": {"modules": {
                         "example": {"source": "vendor_collection", "all_function_scope": False}}}}
        fake = Fake([{"profiles": []}] * 3)
        result = inspect_unadapted_profiles(fake, discovery, {}, {},
                    scopes_by_persona={"ACCESS_SWITCH": [{"id": "12", "kind": "device"}]},
                    deep_catalog=True)["example"]
        self.assertEqual(result["source_views"][0]["persona"], "UNFILTERED_SCOPE")
        self.assertIsNone(result["catalog_scope_coverage"]["all_function_scopes_not_surveyed"])
        self.assertEqual(result["catalog_scope_coverage"]["unfiltered_scopes_not_surveyed"], 0)

    def test_configuration_health_preserves_issues_and_checks_inventory(self):
        from aruba_central.central_tool import capture_configuration_health
        fake = Fake([{"devices": [{"serial": "A", "configStatus": "Failure",
                                   "activeIssues": 1}], "total": 2},
                     {"devices": [{"serialNumber": "B", "activeIssues": 0}], "total": 2},
                     {"issues": [{"message": "deployment failed"}]}, {"issues": []}, {"issues": []}])
        inventory = [{"inventory": {"serialNumber": "A"}}, {"inventory": {"serialNumber": "C"}},
                     {"inventory": {}}]
        result = capture_configuration_health(fake, inventory, workers=1)
        self.assertTrue(result["count_confirmed"])
        self.assertEqual([p["raw"]["total"] for p in result["summary_pages"]], [2, 2])
        self.assertEqual(fake.calls[1][1]["offset"], 1)
        self.assertEqual(set(result["active_issues"]), {"A", "B", "C"})
        self.assertEqual(result["inventory_serials_missing_from_summary"], ["C"])
        self.assertEqual(result["inventory_entries_without_serial"], 1)
        self.assertEqual(result["active_issues"]["A"]["raw"]["issues"][0]["message"], "deployment failed")
        self.assertFalse(result["safe_to_apply"])

    def test_configuration_health_does_not_accept_repeated_pages(self):
        from aruba_central.central_tool import capture_configuration_health
        page = {"devices": [{"serial": "A"}]}
        fake = Fake([page, page, {"issues": []}])
        result = capture_configuration_health(fake, [], workers=1)
        self.assertEqual(result["summary_status"], "identity_unqualified")
        self.assertFalse(result["count_confirmed"])
        self.assertEqual(len(result["summary_pages"]), 2)
        self.assertEqual(len(result["devices"]), 1)

    def test_configuration_health_unverified_count_with_no_total(self):
        from aruba_central.central_tool import capture_configuration_health
        fake = Fake([{"devices": [{"serial": "A"}]}, {"devices": []}, {"issues": []}])
        result = capture_configuration_health(fake, [], workers=1)
        self.assertEqual(result["summary_status"], "pagination_exhausted")
        self.assertFalse(result["count_confirmed"])

    def test_keyed_profile_reads_preserve_additional_fields_without_overwriting(self):
        from aruba_central.central_tool import keyed_profile_contracts, capture_keyed_profile_details
        self.assertEqual(keyed_profile_contracts()["dns"], "name")
        self.assertNotIn("layer2-vlan", keyed_profile_contracts())
        profile = {"name": "example name"}
        library = {"modules": {"dns": {"status": "list_parsed", "profiles": {"example name": profile}}}}
        results = {"ACCESS_SWITCH": {"modules": {"dns": {"scope_results": [
            {"scope": "12", "local_view": {"status": "list_parsed", "profiles": {"example name": profile}},
             "effective_view": {"status": "list_parsed", "profiles": {}}}
        ]}}}}
        fake = Fake([{"dns": {"name": "example name", "enable": False}},
                     {"profiles": [{"name": "example name", "enable": True}]},
                     {"name": "example name", "enable": True}])
        evidence = capture_keyed_profile_details(fake, results, library, workers=1)
        self.assertEqual(evidence["outcomes"], {"identity_observed": 3})
        self.assertEqual(fake.calls[0][0].split("/")[-1], "example%20name")
        self.assertEqual(fake.calls[0][1]["view-type"], "LIBRARY")
        self.assertEqual(fake.calls[1][1]["object-type"], "LOCAL")
        self.assertEqual(fake.calls[2][1]["effective"], "true")
        lib = evidence["profiles"]["Library"][""]["dns"]["example name"]["library"]
        self.assertFalse(lib["profile"]["enable"])
        self.assertEqual(lib["differences"][0]["kind"], "missing_local")
        self.assertFalse(lib["source_verified"])
        self.assertFalse(evidence["safe_to_apply"])
        self.assertNotIn("enable", profile)

    def test_keyed_details_include_effective_only_and_deduplicate_local_identity(self):
        from aruba_central.central_tool import capture_keyed_profile_details
        both = {"name": "both"}
        inherited = {"name": "inherited"}
        results = {"ACCESS_SWITCH": {"modules": {"dns": {"scope_results": [
            {"scope": "12", "local_view": {"status": "list_parsed", "profiles": {"both": both}},
             "effective_view": {"status": "list_parsed", "profiles": {"both": both, "inherited": inherited}}},
            {"scope": "13", "local_view": {"status": "empty_object"},
             "effective_view": {"status": "list_parsed", "profiles": {"inherited": inherited}}}
        ]}}}}
        fake = Fake([both, both, inherited, inherited])
        evidence = capture_keyed_profile_details(fake, results, {}, workers=1)
        self.assertEqual(evidence["outcomes"], {"identity_observed": 4})
        for sid in ("12", "13"):
            self.assertEqual(set(evidence["profiles"]["ACCESS_SWITCH"][sid]["dns"]["inherited"]), {"effective"})
        self.assertEqual(set(evidence["profiles"]["ACCESS_SWITCH"]["12"]["dns"]["both"]), {"local", "effective"})
        self.assertEqual(sum(call[1].get("effective") == "true" for call in fake.calls), 3)
        self.assertFalse(evidence["safe_to_apply"])

    def test_keyed_reads_include_observed_raw_profiles_without_mixed_scope_guessing(self):
        from aruba_central.central_tool import capture_keyed_profile_details, keyed_profile_contracts
        self.assertEqual(keyed_profile_contracts(include_raw=True)["portals"], "portal-id")
        self.assertNotIn("portals", keyed_profile_contracts())
        self.assertNotIn("policy-groups", keyed_profile_contracts(include_raw=True))
        profile = {"portal-id": "portal"}
        local = {"portal-id": "local", "@": {"aruba-annotation:object_type": "LOCAL",
                                              "aruba-annotation:inherited": False}}
        shared = {"portal-id": "shared", "@": {"aruba-annotation:object_type": "SHARED",
                                                "aruba-annotation:inherited": False}}
        def view(*profiles):
            return {"status": "response_received", "raw": {"profiles": list(profiles)}}
        extra = {"portals": {"library": view(profile), "source_views": [
            {"persona": "CAMPUS_AP", "scope": "12", "effective": view(profile, local, shared),
             "committed": view(local, shared)},
            {"persona": "ALL_DEVICE_FUNCTIONS", "scope": "13", "effective": view(profile)},
        ]}}
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append((path, params))
                return {"portal-id": path.rsplit("/", 1)[-1]}
        fake = Client()
        result = capture_keyed_profile_details(fake, {}, {}, workers=1, unadapted=extra)
        self.assertEqual(result["supplemental_raw_reads"], 6)
        self.assertEqual(result["outcomes"], {"identity_observed": 6})
        self.assertEqual(len(fake.calls), 6)
        self.assertEqual(sum(p.get("object-type") == "LOCAL" for _, p in fake.calls), 1)
        unfiltered = [p for _, p in fake.calls if p.get("scope-id") == "13"]
        self.assertEqual(len(unfiltered), 1)
        self.assertNotIn("device-function", unfiltered[0])
        self.assertIn("portal", result["profiles"]["ALL_DEVICE_FUNCTIONS"]["13"]["portals"])
        self.assertEqual(set(result["profiles"]["CAMPUS_AP"]["12"]["portals"]["local"]), {"local", "effective"})
        self.assertEqual(set(result["profiles"]["CAMPUS_AP"]["12"]["portals"]["shared"]), {"effective"})
        self.assertFalse(result["safe_to_apply"])

    def test_unfiltered_details_preserve_conflicting_bodies_and_local_only_observations(self):
        from aruba_central.central_tool import capture_keyed_profile_details
        profile = {"name": "dns", "enable": True}
        local = {"name": "local", "@": {"aruba-annotation:object_type": "LOCAL",
                                        "aruba-annotation:inherited": False}}
        def view(*profiles):
            return {"status": "response_received", "raw": {"profiles": list(profiles)}}
        extra = {"dns": {"source_views": [
            {"persona": "ACCESS_SWITCH", "scope": "12", "effective": view(profile),
             "committed": view()},
            {"persona": "ALL_DEVICE_FUNCTIONS", "scope": "12",
             "effective": view({**profile, "enable": False}), "committed": view(local)},
            {"persona": "ACCESS_SWITCH", "scope": "13", "effective": view(profile)},
            {"persona": "ALL_DEVICE_FUNCTIONS", "scope": "13", "effective": view(profile)}
        ]}}
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append((path, params))
                return {"name": path.rsplit("/", 1)[-1]}
        client = Client()
        result = capture_keyed_profile_details(client, {}, {}, workers=1, unadapted=extra)
        self.assertEqual(len(client.calls), 5)
        unfiltered = result["profiles"]["ALL_DEVICE_FUNCTIONS"]
        self.assertEqual(set(unfiltered), {"12"})
        self.assertEqual(set(unfiltered["12"]["dns"]["local"]), {"local", "effective"})
        self.assertIn("dns", unfiltered["12"]["dns"])
        self.assertEqual(len([p for _, p in client.calls if p.get("scope-id") == "13"]), 1)

    def test_supplemental_collection_reuses_exact_successful_reads(self):
        from aruba_central.central_tool import inspect_unadapted_profiles
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append((path, params))
                return {}
        client = Client()
        raw = {"dns": [{"name": "example"}]}
        view = {"status": "list_parsed", "raw": raw, "count_confirmed": True}
        result = inspect_unadapted_profiles(
            client, {"unknown_adapter_modules": [], "survey_modules": ["dns"],
                     "modules": {"dns": ["ACCESS_SWITCH"]}, "documented_catalog": {"modules": {}}},
            {}, {}, scopes_by_persona={"ACCESS_SWITCH": [{"id": "1", "kind": "device"}]},
            deep_catalog=True,
            structured_results={"ACCESS_SWITCH": {"modules": {"dns": {"scope_results": [
                {"scope": "1", "effective_view": view}]}}}},
            structured_library={"modules": {"dns": view}})
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0][1]["effective"], "false")
        self.assertTrue(result["dns"]["library"]["reused_exact_collection"])
        self.assertTrue(result["dns"]["source_views"][0]["effective"]["reused_exact_collection"])
        self.assertEqual(result["dns"]["source_views"][0]["effective"]["raw"], raw)

    def test_supplemental_reuses_counted_raw_even_when_identity_unqualified(self):
        from aruba_central.central_tool import inspect_unadapted_profiles
        raw = {"dns": [{"name": "same", "value": 1}, {"name": "same", "value": 2}],
               "metadata": {"total": 2, "count": 2}}
        for status, payload, pagination, expected_calls in (
                ("identity_unresolved", raw, None, 1),
                ("schema_unresolved", raw, "request_failed", 3),
                ("identity_unresolved", {"dns": raw["dns"], "metadata": {"total": 3}}, None, 3),
                ("read_failed", raw, None, 3)):
            view = {"status": status, "raw": payload, "pagination_status": pagination}
            fake = Fake([{}] * expected_calls)
            result = inspect_unadapted_profiles(
                fake, {"unknown_adapter_modules": [], "survey_modules": ["dns"],
                       "modules": {"dns": ["ACCESS_SWITCH"]}, "documented_catalog": {"modules": {}}},
                {}, {}, scopes_by_persona={"ACCESS_SWITCH": [{"id": "1", "kind": "device"}]},
                deep_catalog=True, structured_results={"ACCESS_SWITCH": {"modules": {
                    "dns": {"scope_results": [{"scope": "1", "effective_view": view}]}}}},
                structured_library={"modules": {"dns": view}})
            self.assertEqual(len(fake.calls), expected_calls)
            if expected_calls == 1:
                evidence = result["dns"]["source_views"][0]["effective"]
                self.assertTrue(evidence["collection_count_verified"])
                self.assertTrue(evidence["reused_raw_identity_unqualified"])
                self.assertEqual(evidence["raw"], raw)
                self.assertFalse(result["dns"]["safe_to_apply"])

    def test_supplemental_collection_reuses_exact_committed_fallback(self):
        from aruba_central.central_tool import inspect_unadapted_profiles
        raw = {"dns": [{"name": "example"}]}
        view = {"status": "list_parsed", "raw": raw, "count_confirmed": True}
        local = {"status": "list_parsed", "alternate_raw": raw,
                 "alternate_evidence": {"status": "list_parsed", "count_confirmed": True}}
        fake = Fake([])
        result = inspect_unadapted_profiles(
            fake, {"unknown_adapter_modules": [], "survey_modules": ["dns"],
                   "modules": {"dns": ["ACCESS_SWITCH"]}, "documented_catalog": {"modules": {}}},
            {}, {}, scopes_by_persona={"ACCESS_SWITCH": [{"id": "1", "kind": "device"}]},
            deep_catalog=True, structured_results={"ACCESS_SWITCH": {"modules": {
                "dns": {"scope_results": [{"scope": "1", "effective_view": view, "local_view": local}]}}}},
            structured_library={"modules": {"dns": view}})
        self.assertEqual(fake.calls, [])
        self.assertTrue(result["dns"]["source_views"][0]["committed"]["reused_exact_collection"])
        self.assertEqual(result["dns"]["source_views"][0]["committed"]["raw"], raw)

    def test_adaptive_verification_preserves_direct_interface_and_local_counterparts(self):
        from aruba_central.central_tool import capture_keyed_profile_details
        annotation = {"aruba-annotation:inherited": True, "aruba-annotation:object_type": "SHARED"}
        def entry(module, identity):
            profile = {"name": identity, "@": annotation}
            return {"scope_results": [
                {"scope": str(i), "scope_kind": "device",
                 "local_view": {"status": "list_parsed", "profiles": {identity: profile} if i == 2 else {}},
                 "effective_view": {"status": "list_parsed", "profiles": {identity: profile}}}
                for i in range(1, 5)]}
        results = {"ACCESS_SWITCH": {"modules": {"ethernet-interfaces": entry("ethernet-interfaces", "1/1/1"),
                                                 "dns": entry("dns", "dns"),
                                                 "server-groups": entry("server-groups", "dns")}}}
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append((path, params))
                return {"name": "1/1/1" if "/ethernet-interfaces/" in path else "dns"}
        client = Client()
        result = capture_keyed_profile_details(client, results, {}, workers=1, adaptive=True)
        self.assertEqual(sum("/ethernet-interfaces/" in p for p, _ in client.calls), 5)
        self.assertEqual(result["profiles"]["ACCESS_SWITCH"]["2"]["dns"]["dns"]["effective"]["status"], "identity_observed")
        self.assertEqual(sum("/server-groups/" in p for p, _ in client.calls), 5)
        self.assertEqual(result["collection_only_by_module"], {"dns": 1})

    def test_adaptive_device_persona_reference_requires_matching_fresh_pairs(self):
        from aruba_central.central_tool import capture_keyed_profile_details
        mapping = {"device-type": "SWITCH", "device-functions": ["ACCESS_SWITCH"]}
        def fixture():
            return {"ACCESS_SWITCH": {"modules": {"device-persona-mapping": {"scope_results": [
                {"scope": str(i), "scope_kind": "device",
                 "local_view": {"status": "list_parsed", "profiles": {"SWITCH": dict(mapping)}},
                 "effective_view": {"status": "list_parsed", "profiles": {"SWITCH": dict(mapping)}}}
                for i in range(1, 7)]}}}}
        class Client:
            def __init__(self, differs=False):
                self.calls = []
                self.differs = differs
            def get(self, path, **params):
                self.calls.append((params["scope-id"], params["effective"]))
                return {**mapping, **({"additional-field": True} if self.differs and params["effective"] == "false" else {})}
        for adaptive, differs, expected in ((True, False, 4), (True, True, 12), (False, False, 12)):
            client = Client(differs)
            result = capture_keyed_profile_details(client, fixture(), {}, workers=1, adaptive=adaptive)
            self.assertEqual(len(client.calls), expected)
            self.assertEqual(result["candidate_reads"], 12)
            self.assertEqual(result["actual_reads"], expected)
            if expected == 4:
                self.assertEqual(set(client.calls), {("1", "true"), ("1", "false"), ("6", "true"), ("6", "false")})
                self.assertEqual(result["collection_only_by_module"], {"device-persona-mapping": 8})
                for view in ("local", "effective"):
                    observation = result["profiles"]["ACCESS_SWITCH"]["2"]["device-persona-mapping"]["SWITCH"][view]
                    self.assertEqual(observation["status"], "collection_only_sampled")
                    self.assertEqual(observation["sampling_reason"], "device_persona_reference")
                    self.assertFalse(observation["safe_to_apply"])
                    self.assertNotIn("profile", observation)
        data = fixture()
        scopes = data["ACCESS_SWITCH"]["modules"]["device-persona-mapping"]["scope_results"]
        scopes[1]["local_view"]["profiles"]["SWITCH"]["@"] = {"aruba-annotation:object_type": "LOCAL"}
        scopes[2]["effective_view"]["profiles"]["SWITCH"]["device-functions"] = ["CORE_SWITCH"]
        client = Client()
        result = capture_keyed_profile_details(client, data, {}, workers=1, adaptive=True)
        for i in ("2", "3"):
            self.assertIn((i, "true"), client.calls)
            self.assertIn((i, "false"), client.calls)
            self.assertEqual(result["profiles"]["ACCESS_SWITCH"][i]["device-persona-mapping"]["SWITCH"]["local"]["status"],
                             "identity_observed")

    def test_adaptive_unfiltered_details_keep_selectors_separate_and_expand_on_difference(self):
        from aruba_central.central_tool import capture_keyed_profile_details
        profile = {"name": "service", "enable": True, "@": {
            "aruba-annotation:inherited": True, "aruba-annotation:object_type": "SHARED"}}
        def view(*profiles):
            return {"status": "response_received", "raw": {"profiles": list(profiles)}}
        results = {"CAMPUS_AP": {"modules": {}, "scopes": [
            {"id": str(i), "kind": "device"} for i in range(1, 7)]}}
        extra = {"net-services": {"source_views": [
            {"persona": "ALL_DEVICE_FUNCTIONS", "scope": str(i), "effective": view(profile)}
            for i in range(1, 7)]}}
        class Client:
            def __init__(self, differs=False):
                self.calls = []
                self.differs = differs
            def get(self, path, **params):
                self.calls.append(params)
                return {"name": "service", "enable": not self.differs}
        client = Client()
        capture = capture_keyed_profile_details(client, results, {}, workers=1,
                                                unadapted=extra, adaptive=True)
        self.assertEqual(len(client.calls), 2)
        self.assertTrue(all("device-function" not in p for p in client.calls))
        self.assertEqual(capture["collection_only_by_module"], {"net-services": 4})
        self.assertEqual(capture["profiles"]["ALL_DEVICE_FUNCTIONS"]["2"]["net-services"]["service"]["effective"]["status"],
                         "collection_only_sampled")
        for adaptive, differs in ((True, True), (False, False)):
            client = Client(differs)
            capture_keyed_profile_details(client, results, {}, workers=1,
                                          unadapted=extra, adaptive=adaptive)
            self.assertEqual(len(client.calls), 6)

    def test_adaptive_inherited_higher_scopes_are_grouped_by_scope_kind(self):
        from aruba_central.central_tool import capture_keyed_profile_details
        profile = {"name": "dns", "@": {"aruba-annotation:inherited": True}}
        scopes = [{"scope": str(i), "scope_kind": kind,
                   "local_view": {"status": "list_parsed", "profiles": {}},
                   "effective_view": {"status": "list_parsed", "profiles": {"dns": profile}}}
                  for kind, numbers in (("site", range(1, 5)), ("group", range(5, 8)))
                  for i in numbers]
        results = {"ACCESS_SWITCH": {"modules": {"dns": {"scope_results": scopes}}}}
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append(params["scope-id"])
                return {"name": "dns"}
        client = Client()
        result = capture_keyed_profile_details(client, results, {}, workers=1, adaptive=True)
        self.assertEqual(client.calls, ["1", "4", "5", "7"])
        self.assertEqual(result["candidate_reads_by_module"], {"dns": 7})
        self.assertEqual(result["initial_reads_by_module"], {"dns": 4})
        self.assertEqual(result["collection_only_by_module"], {"dns": 3})
        self.assertEqual(result["profiles"]["ACCESS_SWITCH"]["2"]["dns"]["dns"]["effective"]["status"],
                         "collection_only_sampled")
        client = Client()
        capture_keyed_profile_details(client, results, {}, workers=1, adaptive=False)
        self.assertEqual(len(client.calls), 7)

    def test_adaptive_keyed_details_keep_scope_data_and_expand_on_disagreement(self):
        from aruba_central.central_tool import capture_keyed_profile_details
        profile = {"name": "dns", "enable": True, "@": {
            "aruba-annotation:inherited": True, "aruba-annotation:object_type": "SHARED"}}
        scopes = [{"scope": str(i), "scope_kind": "device",
                   "local_view": {"status": "list_parsed", "profiles": {}},
                   "effective_view": {"status": "list_parsed", "profiles": {"dns": profile}}}
                  for i in range(1, 7)]
        results = {"ACCESS_SWITCH": {"modules": {"dns": {"scope_results": scopes}}}}
        class Client:
            def __init__(self, differs=False):
                self.calls = []
                self.differs = differs
            def get(self, path, **params):
                self.calls.append(params["scope-id"])
                return {"name": "dns", "enable": True, **({"new-field": 1} if self.differs else {})}
        client = Client()
        result = capture_keyed_profile_details(client, results, {}, workers=1, adaptive=True)
        self.assertEqual(client.calls, ["1", "6"])
        self.assertEqual(result["actual_reads"], 2)
        self.assertEqual(result["candidate_reads"], 6)
        self.assertEqual(result["collection_only_by_module"], {"dns": 4})
        skipped = result["profiles"]["ACCESS_SWITCH"]["2"]["dns"]["dns"]["effective"]
        self.assertEqual(skipped["status"], "collection_only_sampled")
        self.assertNotIn("profile", skipped)
        self.assertEqual(scopes[1]["effective_view"]["profiles"]["dns"], profile)
        client = Client(differs=True)
        result = capture_keyed_profile_details(client, results, {}, workers=1, adaptive=True)
        self.assertEqual(len(client.calls), 6)
        self.assertEqual(result["expanded_groups_reads"], 4)
        self.assertEqual(result["collection_only_by_module"], {})
        client = Client()
        result = capture_keyed_profile_details(client, results, {}, workers=1, adaptive=False)
        self.assertEqual(len(client.calls), 6)
        self.assertEqual(result["detail_strategy"], "exhaustive")

    def test_parseable_first_page_does_not_hide_later_positive_observations(self):
        from aruba_central.central_tool import observed_profile_candidates
        a, b, c = ({"name": name, "enable": False} for name in ("a", "b", "c"))
        view = {"status": "list_parsed", "count_confirmed": False,
                "profiles": {"a": a, "b": b}, "raw": {"profiles": [a, b]},
                "pagination_status": "request_failed",
                "raw_pages": [{"profiles": [c, {**b, "enable": True}]}]}
        self.assertEqual(observed_profile_candidates(view, "name"), {"a": a, "c": c})
        self.assertEqual(view["profiles"], {"a": a, "b": b})
        self.assertFalse(view["count_confirmed"])

    def test_partial_profile_candidates_keep_valid_rows_and_exclude_conflicts(self):
        from aruba_central.central_tool import observed_profile_candidates, capture_keyed_profile_details
        a, b, c = ({"name": name, "enable": False} for name in ("a", "b", "c"))
        partial = {"status": "count_mismatch", "profiles": {}, "raw": {"profiles": [a, b]},
                   "raw_pages": [{"profiles": [a, c, {"invalid": True}]},
                                 {"profiles": [{**b, "enable": True}]}]}
        self.assertEqual(observed_profile_candidates(partial, "name"), {"a": a, "c": c})
        self.assertEqual(partial["profiles"], {})
        self.assertEqual(partial["status"], "count_mismatch")
        result = capture_keyed_profile_details(Fake([a, c]), {},
                     {"modules": {"dns": partial}}, workers=1)
        self.assertEqual(result["outcomes"], {"identity_observed": 2})
        self.assertEqual(set(result["profiles"]["Library"][""]["dns"]), {"a", "c"})
        self.assertFalse(result["safe_to_apply"])

    def test_keyed_singleton_metadata_is_validated_without_discarding_fields(self):
        from aruba_central.central_tool import keyed_profile_read
        profile = {"name": "example", "enabled": False, "future-field": {"value": 0}}
        for raw in ({**profile, "metadata": {"count": 1}},
                    {"dns": profile, "metadata": {"count_objects_in_module": {"ANY": 1}}}):
            result = keyed_profile_read(Fake([raw]), "dns", "name", "example", {}, None)
            self.assertEqual(result["status"], "identity_observed")
            self.assertEqual(result["profile"], profile)
            self.assertFalse(result["source_verified"])
        for meta in ({"count": 2}, {"offset": 3}, {"count_objects_in_module": {"ANY": 0}}):
            result = keyed_profile_read(Fake([{"dns": profile, "metadata": meta}]), "dns", "name", "example", {}, None)
            self.assertEqual(result["status"], "count_mismatch")
        result = keyed_profile_read(Fake([{"dns": profile, "unexpected": {"name": "example"}}]),
                                    "dns", "name", "example", {}, None)
        self.assertEqual(result["status"], "schema_unresolved")

    def test_deep_keyed_vlan_reads_cover_library_and_all_observed_scopes(self):
        from aruba_central.central_tool import capture_keyed_profile_details, keyed_profile_read
        profile = {"vlan": 10, "name": "example"}
        def view(*profiles):
            return {"status": "list_parsed", "profiles": {str(p["vlan"]): p for p in profiles}}
        library = {"modules": {"layer2-vlan": view(profile)}}
        results = {"ACCESS_SWITCH": {"modules": {"layer2-vlan": {"scope_results": [
            {"scope": "1", "scope_kind": "global", "local_view": view(profile), "effective_view": view(profile)},
            {"scope": "2", "scope_kind": "device", "local_view": view(), "effective_view": view(profile)},
        ]}}}}
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append((path, params))
                return {"l2-vlan": profile, "metadata": {"count": 1}}
        client = Client()
        result = capture_keyed_profile_details(client, results, library, workers=1)
        self.assertEqual(result["outcomes"], {"identity_observed": 4})
        self.assertTrue(all(path.endswith("/layer2-vlan/10") for path, _ in client.calls))
        self.assertEqual(set(result["profiles"]["ACCESS_SWITCH"]["2"]["layer2-vlan"]["10"]), {"effective"})
        self.assertEqual(set(result["profiles"]["ACCESS_SWITCH"]["1"]["layer2-vlan"]["10"]), {"local", "effective"})
        for vid in ("0", "4095", "10-20", "0010"):
            detail = keyed_profile_read(client, "layer2-vlan", "vlan", vid, {}, None)
            self.assertEqual(detail["status"], "invalid_selector")
        self.assertEqual(len(client.calls), 4)

    def test_keyed_profile_rejects_ambiguous_identity_and_unsafe_selectors(self):
        from aruba_central.central_tool import keyed_profile_read
        fake = Fake([{"profiles": [{"name": "different"}]}])
        result = keyed_profile_read(fake, "dns", "name", "expected", {}, None)
        self.assertEqual(result["status"], "identity_unresolved")
        for selector in ("..", "a/b", "a%2fb"):
            self.assertEqual(keyed_profile_read(fake, "dns", "name", selector, {}, None)["status"], "invalid_selector")
        self.assertEqual(len(fake.calls), 1)

    def test_keyed_ethernet_numeric_interface_is_encoded_as_one_segment(self):
        from aruba_central.central_tool import keyed_profile_read, ALPHA
        fake = Fake([{"ethernet-interface": {"name": "1/1/24", "enable": True}}])
        result = keyed_profile_read(fake, "ethernet-interfaces", "name", "1/1/24",
                                    {"scope-id": "1"}, {"name": "1/1/24"})
        self.assertEqual(result["status"], "identity_observed")
        self.assertEqual(fake.calls[0][0], ALPHA + "/ethernet-interfaces/1%2F1%2F24")
        for selector in ("../1/24", "1/../24", "1/1/24/extra", "1%2F1%2F24", "a/b/c", "/1/1"):
            self.assertEqual(keyed_profile_read(fake, "ethernet-interfaces", "name", selector, {}, None)["status"],
                             "invalid_selector")
        self.assertEqual(keyed_profile_read(fake, "dns", "name", "1/1/24", {}, None)["status"], "invalid_selector")
        self.assertEqual(len(fake.calls), 1)

    def test_observed_named_adapters_have_exact_keyed_contracts(self):
        from aruba_central.central_tool import CONFIG_MODULES, keyed_profile_contracts
        contracts = keyed_profile_contracts()
        for module in ("net-services", "named-vlan", "role-gpids", "radios", "dot1xauth",
                       "captive-portal", "auth-server-global-config", "devicefingerprinting",
                       "client-iptracker", "traffic-insight"):
            self.assertEqual(CONFIG_MODULES[module][0], "name")
            self.assertEqual(contracts[module], "name")
            self.assertFalse(CONFIG_MODULES[module][2])
        self.assertIn("CAMPUS_AP", CONFIG_MODULES["radios"][1])
        self.assertNotIn("ACCESS_SWITCH", CONFIG_MODULES["radios"][1])
        self.assertIn("ACCESS_SWITCH", CONFIG_MODULES["dot1xauth"][1])

    def test_observed_profile_adapters_have_documented_contracts_and_raw_surveys(self):
        from aruba_central.central_tool import CONFIG_MODULES, keyed_profile_contracts, SUPPLEMENTAL_RAW_MODULES
        contracts = keyed_profile_contracts()
        expected = {
            "airgroup-policies": "name", "airgroup-service-definitions": "name",
            "arc": "name", "auth-survivability": "name",
            "certificate-rcp": "name", "certificate-store": "name",
            "certificate-usage": "name", "certificates": "name",
            "custom-messages": "message-id", "default-custom-messages": "message-id",
            "device-certificates": "name", "device-persona-mapping": "device-type",
            "firewall": "name", "ids": "name", "ipm": "name", "lldp": "name",
            "local-management": "name", "loopback-interfaces": "id",
            "mgmt-interfaces": "name", "nae-agents": "agent-name",
            "nae-scripts": "name", "passpoint-identity": "name",
            "qos-schedules": "sched-profile-name", "rmon-alarms": "name",
            "stateful-dot1x-profiles": "name", "static-route": "name",
            "telemetry": "name", "time-ranges": "name", "vrfs": "name",
        }
        for module, key in expected.items():
            self.assertEqual(CONFIG_MODULES[module][0], key)
            self.assertEqual(contracts[module], key)
            self.assertIn(module, SUPPLEMENTAL_RAW_MODULES)
        self.assertNotIn("lacp", CONFIG_MODULES)
        self.assertNotIn("policy-groups", CONFIG_MODULES)

    def test_shared_scope_discovery_reuses_tenant_inventory(self):
        from aruba_central.central_tool import discover_scopes
        from unittest.mock import patch
        shared = [{"id": "1", "kind": "global", "name": "Global"},
                  {"id": "2", "kind": "site", "name": "Site"}]
        devices = [{"deviceFunction": "Campus AP", "scopeId": 3},
                   {"deviceFunction": "Access Switch", "scopeId": 4}]
        with patch("aruba_central.central_tool.discover_shared_scopes", return_value=shared) as read:
            ap, _ = discover_scopes(object(), "CAMPUS_AP", devices)
            switch, _ = discover_scopes(object(), "ACCESS_SWITCH", devices,
                                        shared_scopes=[s for s in ap if s["kind"] != "device"])
        read.assert_called_once()
        self.assertEqual(ap[:2], switch[:2])
        self.assertEqual(ap[-1]["kind"], "device")
        self.assertEqual(switch[-1]["kind"], "device")
        self.assertNotEqual(ap[-1]["id"], switch[-1]["id"])

    def test_configuration_audit_uses_persona_catalog(self):
        from aruba_central.central_tool import configuration_audit
        from unittest.mock import patch
        class Client:
            base = "test"
            def get(self, path, **params):
                if path.endswith("/config-assignments"):
                    return {"config-assignment": []}
                if path.endswith("/scope-maps"):
                    return {"scope-map": []}
                return {"profiles": []}
        devices = [{"deviceFunction": "Campus AP"}, {"deviceFunction": "Access Switch"},
                   {"deviceFunction": "Hybrid NAC"}]
        with patch("aruba_central.central_tool.inventory", return_value=devices), patch("aruba_central.central_tool.discover_scopes",
             return_value=([scope("1", "global", []), scope("2", "device", [])], [])):
            published = {}
            data = configuration_audit(Client(), module_completed=lambda persona, module, evidence, scopes:
                                       published.__setitem__((persona, module), evidence))
        self.assertEqual(set(published), {(persona, module) for persona, entry in data["results"].items()
                                          for module in entry["modules"]})
        self.assertTrue(all(evidence == data["results"][persona]["modules"][module]
                            for (persona, module), evidence in published.items()))
        self.assertIn("wlan-ssids", data["results"]["CAMPUS_AP"]["modules"])
        self.assertNotIn("wlan-ssids", data["results"]["ACCESS_SWITCH"]["modules"])
        self.assertIn("switch-system", data["results"]["ACCESS_SWITCH"]["modules"])
        for module in ("aliases", "net-groups", "policies", "role-acls", "alg"):
            self.assertIn(module, data["results"]["ACCESS_SWITCH"]["modules"])
            self.assertIn(module, data["library"]["modules"])
        self.assertIn("gw-system", data["library"]["modules"])
        self.assertIn("policy-groups", data["unadapted_profiles"])
        self.assertIn("arc", data["unadapted_profiles"])
        self.assertEqual(data["unadapted_profiles"]["arc"]["status"], "supplemental_raw")
        self.assertIn("lldp", data["results"]["ACCESS_SWITCH"]["modules"])
        self.assertIn("airgroup-policies", data["results"]["CAMPUS_AP"]["modules"])
        self.assertIn("qos-schedules", data["library"]["modules"])
        self.assertFalse(data["catalog_exhaustive"])
        self.assertEqual(len(data["results"]["ACCESS_SWITCH"]["modules"]["ethernet-interfaces"]["scope_results"]), 1)
        self.assertEqual(data["unqualified_personas"], ["HYBRID_NAC"])
        self.assertFalse(data["safe_to_apply"])

    def test_configuration_browser_escapes_evidence_and_marks_unknown(self):
        from aruba_central.central_tool import configuration_html, configuration_view_shape
        view = {"status": "count_mismatch", "raw": {"profiles": [{"name": "CUSTOMER_SECRET"}],
                "metadata": {"total": 2, "count_objects_in_module": {"LOCAL": 1, "SHARED": 1}}}}
        shape = configuration_view_shape(view)
        self.assertEqual(shape["list_lengths"], [1])
        self.assertEqual(shape["object_counts"], {"LOCAL": 1, "SHARED": 1})
        self.assertNotIn("CUSTOMER_SECRET", str(shape))
        row = {"identity": "<script>alert(1)</script>", "status": "local_differs_from_global",
               "local": {"name": "<img src=x>"}, "effective": {}, "global_reference": {},
               "global_differences": [], "annotations": {}}
        scope = {"scope": "1", "scope_kind": "device", "review": {"qualified": True, "profiles": [row]},
                 "local_view": view, "effective_view": view}
        bad = {**scope, "review": {"qualified": False, "profiles": [], "local_status": "count_mismatch",
                                 "effective_status": "schema_unresolved"}}
        bundle = {"schema": 1, "kind": "configuration_audit", "results": {"ACCESS_SWITCH":
                  {"scopes": [{"id": "1", "kind": "device", "name": "Switch"}], "modules": {
                  "roles": {"scope_results": [scope, bad]}}}}}
        html = configuration_html(bundle)
        self.assertIn("scope_unqualified", html)
        self.assertIn("Qualified module scopes: 1/2", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<img src=x>", html)
        self.assertNotIn("CUSTOMER_SECRET", html)
        self.assertIn("default-src 'none'", html)

    def test_metadata_only_zero_requires_requested_count(self):
        from aruba_central.central_tool import module_view
        payload = {"metadata": {"count_objects_in_module": {"LOCAL": 0, "SHARED": 3, "ANY": 3}}}
        result = module_view(payload, "name", "LOCAL")
        self.assertEqual(result["status"], "list_parsed")
        self.assertTrue(result["count_confirmed"])
        self.assertEqual(result["profiles"], {})
        self.assertEqual(module_view(payload, "name", "ANY")["status"], "schema_unresolved")
        self.assertEqual(module_view({}, "name", "LOCAL")["status"], "empty_object")
        self.assertEqual(module_view({**payload, "metadata": {**payload["metadata"], "total": 3}},
                                     "name", "LOCAL")["status"], "count_mismatch")
        self.assertEqual(module_view({**payload, "profiles": [{"name": "unexpected"}]},
                                     "name", "LOCAL")["status"], "count_mismatch")

    def test_refresh_saved_config_requalifies_only_proven_empty(self):
        from aruba_central.central_tool import refresh_configuration_review
        local = {"status": "schema_unresolved", "raw": {
            "metadata": {"count_objects_in_module": {"LOCAL": 0, "SHARED": 1, "ANY": 1}}}}
        effective = {"status": "list_parsed", "raw": {"profiles": [
            {"name": "a", "@": {"aruba-annotation:object_type": "SHARED",
                                "aruba-annotation:inherited": False}}],
            "metadata": {"count_objects_in_module": {"ANY": 1}}}}
        scope = {"scope": "1", "scope_kind": "global", "local_view": local, "effective_view": effective}
        module = {"scope_results": [scope]}
        bundle = {"schema": 1, "kind": "configuration_audit", "results": {
            "ACCESS_SWITCH": {"modules": {"roles": module}}}}
        refresh_configuration_review(bundle)
        self.assertTrue(scope["review"]["qualified"])
        self.assertEqual(scope["review"]["profiles"][0]["status"], "shared")
        self.assertEqual(module["summary"]["qualified_scopes"], 1)

    def test_dashboard_distinguishes_infrastructure_and_exact_repeat_groups(self):
        from aruba_central.config_dashboard import finding_category, repeated_local_profiles
        def record(module, sid, body, status="local_differs_from_global", persona="ACCESS_SWITCH"):
            row = {"identity": "10", "status": status, "local": body}
            return persona, module, sid, {"scope": sid, "scope_kind": "device",
                   "review": {"qualified": True, "profiles": [row]}}
        a = record("layer2-vlan", "a", {"vlan": 10, "name": "Example"})
        b = record("layer2-vlan", "b", {"name": "Example", "vlan": 10})
        c = record("layer2-vlan", "c", {"vlan": 10, "name": "Different"})
        d = record("ethernet-interfaces", "d", {"vlan": 10, "name": "Example"})
        e = record("ethernet-interfaces", "e", {"vlan": 10, "name": "Example"})
        other = record("layer2-vlan", "f", {"vlan": 10, "name": "Example"}, persona="CORE_SWITCH")
        groups = repeated_local_profiles([a, a, b, c, d, e, other])
        self.assertEqual(len(groups), 1)
        self.assertEqual(set(next(iter(groups.values()))), {"a", "b"})
        self.assertEqual(finding_category(d[1], d[3], d[3]["review"]["profiles"][0]), "infrastructure")
        self.assertEqual(finding_category(a[1], a[3], a[3]["review"]["profiles"][0]), "candidate")

    def test_annotated_committed_recovery_requires_complete_count_and_sources(self):
        from aruba_central.central_tool import annotated_committed_local
        shared = {"name": "a", "@": {"aruba-annotation:object_type": "SHARED",
                                     "aruba-annotation:inherited": False}}
        local = {"name": "b", "@": {"aruba-annotation:object_type": "LOCAL",
                                    "aruba-annotation:inherited": False}}
        payload = {"profiles": [shared, local], "metadata": {
            "count_objects_in_module": {"ANY": 2, "LOCAL": 1, "SHARED": 1}}}
        recovered = annotated_committed_local(payload, "name")
        self.assertEqual(recovered["profiles"], {"b": {"name": "b"}})
        self.assertEqual(recovered["qualification"], "annotated_committed_local")
        bad = {**payload, "profiles": [shared, {"name": "b"}]}
        self.assertEqual(annotated_committed_local(bad, "name")["status"], "annotation_recovery_unverified")
        bad = {**payload, "metadata": {"count_objects_in_module": {"ANY": 2, "LOCAL": 0}}}
        self.assertEqual(annotated_committed_local(bad, "name")["status"], "annotation_recovery_unverified")

    def test_explicit_initial_page_avoids_replaying_offset_zero(self):
        from aruba_central.central_tool import read_module_view, read_raw_profile_collection
        a, b, c = ({"name": name} for name in ("a", "b", "c"))
        for reader in (lambda client, deep: read_module_view(client, "dns", "name", {"view-type": "LOCAL"}, paginate_uncounted=deep),
                       lambda client, deep: read_raw_profile_collection(client, "dns", {"view-type": "LOCAL"}, paginate_uncounted=deep)):
            for total in (3, None):
                def page(rows, offset):
                    return {"metadata": {"offset": offset, "count": len(rows), "limit": 2,
                                         **({"total": total} if total is not None else {})},
                            "profiles": rows}
                initial = page([a, b], 0)
                fake = Fake([initial, page([c], 2)] + ([page([], 3)] if total is None else []))
                result = reader(fake, total is None)
                self.assertEqual(result["raw"]["profiles"], [a, b, c])
                self.assertEqual(result["initial_raw"], initial)
                self.assertEqual([p["offset"] for _, p in fake.calls[1:]], [2, 3] if total is None else [2])
                self.assertEqual(result["pagination_status"], "pagination_exhausted" if total is None else "complete")
                self.assertEqual(result.get("count_confirmed", result.get("collection_count_verified")), total is not None)

    def test_generic_module_recovers_truncated_collection(self):
        from aruba_central.central_tool import read_module_view
        def page(names):
            return {"metadata": {"total": 3, "count": len(names)},
                    "profiles": [{"name": name} for name in names]}
        fake = Fake([page(["a"]), page(["a", "b"]), page(["c"])])
        view = read_module_view(fake, "sw-port-profiles", "name", {"view-type": "LIBRARY"})
        self.assertEqual(view["status"], "list_parsed")
        self.assertEqual(view["pagination_status"], "complete")
        self.assertEqual(set(view["profiles"]), {"a", "b", "c"})
        self.assertEqual([params.get("offset") for _, params in fake.calls], [None, 0, 2])
        self.assertEqual(len(view["raw_pages"]), 2)

    def test_module_recovers_count_only_truncation_and_next_offsets(self):
        from aruba_central.central_tool import read_module_view, module_view
        def page(names, offset, total=3):
            return {"metadata": {"count_objects_in_module": {"LOCAL": total, "ANY": total},
                                 "count": len(names), "offset": offset},
                    "profiles": [{"name": name} for name in names]}
        for offsets in ((0, 2), (2, 3)):
            fake = Fake([page(["a"], 1), page(["a", "b"], offsets[0]), page(["c"], offsets[1])])
            result = read_module_view(fake, "snmp", "name", {"object-type": "LOCAL"})
            self.assertEqual(result["status"], "list_parsed")
            self.assertEqual(result["pagination_status"], "complete")
            self.assertEqual(set(result["profiles"]), {"a", "b", "c"})
            self.assertTrue(result["count_confirmed"])
        self.assertEqual(module_view(page(["a", "b", "c"], 3), "name")["status"], "list_parsed")
        fake = Fake([page(["a"], 1), page(["a", "b"], 2), page(["c"], 3, 4)])
        self.assertEqual(read_module_view(fake, "snmp", "name", {})["pagination_status"], "count_changed")

    def test_generic_module_rejects_repeated_or_changed_pages(self):
        from aruba_central.central_tool import read_module_view
        def page(names, total=3):
            return {"metadata": {"total": total, "count": len(names)},
                    "profiles": [{"name": name} for name in names]}
        cases = [
            ([page(["a"]), page(["a", "b"]), page(["b"])], "duplicate_or_invalid_identity"),
            ([page(["a"]), page(["b", "c", "d"])], "initial_response_changed"),
            ([page(["a"]), page(["a", "b"], 4)], "count_changed"),
            ([page(["a"]), page([])], "count_changed"),
        ]
        for pages, reason in cases:
            with self.subTest(reason=reason):
                view = read_module_view(Fake(pages), "sw-port-profiles", "name", {})
                self.assertEqual(view["status"], "count_mismatch")
                self.assertEqual(view["pagination_status"], reason)
                self.assertEqual(view["profiles"], {})

    def test_explicit_null_envelope_requires_zero_count(self):
        from aruba_central.central_tool import module_view
        self.assertEqual(module_view({"metadata": {"count_objects_in_module": {"ANY": 0}}, "snmp": None}, "name")["status"], "list_parsed")
        self.assertNotEqual(module_view({"snmp": None}, "name")["status"], "list_parsed")
        self.assertNotEqual(module_view({"metadata": {"count_objects_in_module": {"ANY": 0}, "total": 1}, "snmp": None}, "name")["status"], "list_parsed")

    def test_empty_local_is_retried_only_when_direct_local_is_observed(self):
        from aruba_central.central_tool import recover_local_view
        ann = {"aruba-annotation:object_type": "LOCAL", "aruba-annotation:inherited": False}
        profile = {"name": "one", "@": ann}
        effective = {"status": "list_parsed", "profiles": {"one": profile}}
        local = {"status": "empty_object", "profiles": {}, "raw": {}}
        raw = {"metadata": {"count_objects_in_module": {"ANY": 1, "LOCAL": 1}}, "snmp": [profile]}
        fake = Fake([raw])
        recovered = recover_local_view(fake, "snmp", "name", {"scope-id": "1"}, local, effective)
        self.assertEqual(recovered["profiles"], {"one": {"name": "one"}})
        self.assertEqual(recovered["qualification"], "annotated_committed_local")
        self.assertEqual(recovered["raw"], {})
        self.assertEqual(recovered["alternate_raw"], raw)
        no_retry = Fake([])
        self.assertEqual(recover_local_view(no_retry, "snmp", "name", {}, local,
                         {"status": "list_parsed", "profiles": {}}), local)
        self.assertEqual(no_retry.calls, [])

    def test_library_reads_nac_with_default_parameters_once(self):
        from aruba_central.central_tool import library_inventory
        fake = Fake([{"profiles": [{"auth-profile-id": "a"}]},
                     {"profiles": [{"vlan": 10}]}, {"config-assignment": []}])
        result = library_inventory(fake, {"auth-profiles", "layer2-vlan", "ethernet-interfaces"})
        self.assertEqual(fake.calls[0][1], {})
        self.assertEqual(fake.calls[1][1], {"view-type": "LIBRARY", "detailed": "true"})
        self.assertNotIn("ethernet-interfaces", result["modules"])
        self.assertEqual(result["modules"]["auth-profiles"]["status"], "list_parsed")
        self.assertFalse(result["assignment_coverage_verified"])

    def test_scoped_assignment_reads_recover_and_cross_check(self):
        from aruba_central.central_tool import collect_scoped_assignments, discover_profile_types
        def row(sid, name, module="snmp"):
            return {"scope-id": sid, "device-function": "ACCESS_SWITCH",
                    "profile-instance": name, "profile-type": module}
        original = row("1", "one")
        extra = row("2", "two", "new-module")
        fake = Fake([{"config-assignment": []},
                     {"config-assignment": [extra, extra]},
                     {"config-assignment": [row("4", "wrong-scope")]}])
        result = collect_scoped_assignments(fake, {"status": "response_received", "rows": [original]},
                    {"ACCESS_SWITCH": [{"id": "1"}, {"id": "2"}, {"id": "3"}]})
        self.assertEqual(result["rows"], [original, extra])
        self.assertEqual(result["additional_assignments"], 1)
        self.assertEqual(result["scope_read_outcomes"], {"tenant_scope_disagreement": 1,
                         "response_received": 1, "selector_mismatch": 1})
        self.assertFalse(result["coverage_verified"])
        self.assertIn("new-module", discover_profile_types(result, {})["modules"])
        self.assertEqual(fake.calls[1][1], {"scope-id": "2", "device-function": "ACCESS_SWITCH"})

    def test_assignment_inventory_recovers_pages_and_retains_partial_observations(self):
        from aruba_central.central_tool import profile_inventory_view, collect_scoped_assignments
        def record(name):
            return {"scope-id": "1", "device-function": "ACCESS_SWITCH",
                    "profile-type": "new-module", "profile-instance": name}
        def page(items, total=2, offset=0):
            return {"metadata": {"total": total, "count": len(items), "offset": offset},
                    "config-assignment": items}
        a, b = record("a"), record("b")
        initial = page([a])
        fake = Fake([initial, page([a]), page([b], offset=1)])
        result = profile_inventory_view(fake, "config-assignments", "config-assignment")
        self.assertEqual(result["rows"], [a, b])
        self.assertTrue(result["collection_count_verified"])
        partial = collect_scoped_assignments(Fake([initial, page([a]), page([a], offset=1)]),
                    {"status": "response_received", "rows": []}, {"ACCESS_SWITCH": [{"id": "1"}]})
        self.assertEqual(partial["rows"], [a])
        self.assertEqual(partial["scope_read_outcomes"], {"partial_response": 1})
        self.assertFalse(partial["coverage_verified"])

    def test_profile_failures_preserve_other_collection_work(self):
        from aruba_central.central_tool import read_module_view, read_raw_profile_collection
        class Client:
            def __init__(self, failure):
                self.failure = failure
            def get(self, path, **params):
                raise self.failure
        for read in (lambda c: read_module_view(c, "dns", "name", {}),
                     lambda c: read_raw_profile_collection(c, "dns", {})):
            for failure in (APIError("test", 500), OSError("offline"), ValueError("invalid json")):
                result = read(Client(failure))
                self.assertEqual(result["status"], "read_failed")
            for code in (401, 429):
                with self.assertRaises(APIError):
                    read(Client(APIError("test", code)))

    def test_partial_assignment_pages_and_mixed_responses_retain_exact_matches(self):
        from aruba_central.central_tool import collect_scoped_assignments
        def record(sid, name):
            return {"scope-id": sid, "device-function": "ACCESS_SWITCH",
                    "profile-type": "dns", "profile-instance": name}
        a, b, wrong = record("1", "a"), record("1", "b"), record("2", "wrong")
        def page(items, offset):
            return {"metadata": {"total": 4, "count": len(items), "offset": offset},
                    "config-assignment": items}
        fake = Fake([page([a], 0), page([a, b], 0), page([wrong], 2), {}])
        result = collect_scoped_assignments(fake, {"status": "response_received", "rows": []},
                                            {"ACCESS_SWITCH": [{"id": "1"}]})
        self.assertEqual(result["rows"], [a, b])
        self.assertEqual(result["scope_reads"]["ACCESS_SWITCH"]["1"]["rejected_rows"], 1)
        self.assertEqual(result["scope_read_outcomes"], {"selector_mismatch": 1})
        self.assertFalse(result["coverage_verified"])

    def test_profile_type_discovery_keeps_unknown_and_scope_map_evidence(self):
        from aruba_central.central_tool import discover_profile_types
        assignments = {"rows": [{"profile-type": "layer2-vlan", "device-function": "ACCESS_SWITCH"},
                               {"profile-type": "dns", "device-function": "CAMPUS_AP"},
                               {"profile-type": "../private", "device-function": "ACCESS_SWITCH"}]}
        maps = {"rows": [{"resource": "dns/example", "persona": "ACCESS_SWITCH"},
                         {"resource": "unknown-profile/a/b", "persona": "CAMPUS_AP"},
                         {"resource": "policy-groups", "persona": "ACCESS_SWITCH"}]}
        data = discover_profile_types(assignments, maps)
        self.assertEqual(data["modules"]["dns"], ["ACCESS_SWITCH", "CAMPUS_AP"])
        self.assertEqual(data["unknown_adapter_modules"], ["policy-groups", "unknown-profile"])
        self.assertEqual(data["unresolved_records"], 1)
        self.assertFalse(data["complete"])

    def test_deep_uncounted_profile_pagination_preserves_all_records_without_proof(self):
        from aruba_central.central_tool import read_module_view, read_raw_profile_collection
        a, b, c = ({"name": name} for name in ("a", "b", "c"))
        initial = {"profiles": [a]}
        pages = [initial, {"profiles": [a, b]}, {"profiles": [c]}, {"profiles": []}]
        fake = Fake(pages)
        view = read_module_view(fake, "dns", "name", {"view-type": "LOCAL"}, paginate_uncounted=True)
        self.assertEqual(set(view["profiles"]), {"a", "b", "c"})
        self.assertFalse(view["count_confirmed"])
        self.assertEqual(view["pagination_status"], "pagination_exhausted")
        self.assertEqual(view["initial_raw"], initial)
        self.assertEqual([call[1]["offset"] for call in fake.calls[1:]], [0, 2, 3])
        raw = read_raw_profile_collection(Fake(pages), "dns", {}, paginate_uncounted=True)
        self.assertEqual(raw["raw"]["profiles"], [a, b, c])
        self.assertFalse(raw["collection_count_verified"])

    def test_uncounted_library_and_persona_mapping_preserve_unverified_records(self):
        from aruba_central.central_tool import read_module_view, read_raw_profile_collection
        for module, key, params, reason in (
            ("dns", "name", {"view-type": "LIBRARY"}, "library_pagination_unavailable"),
            ("device-persona-mapping", "device-type", {"view-type": "LOCAL"}, "offset_behavior_unverified")):
            initial = {"profiles": [{key: "example"}]}
            for read in (lambda c: read_module_view(c, module, key, params, paginate_uncounted=True),
                         lambda c: read_raw_profile_collection(c, module, params, paginate_uncounted=True)):
                fake = Fake([initial])
                view = read(fake)
                self.assertEqual(len(fake.calls), 1)
                self.assertEqual(view["raw"], initial)
                self.assertEqual(view["pagination_status"], reason)
                self.assertFalse(view.get("count_confirmed", view.get("collection_count_verified")))
                self.assertEqual(view["raw_pages"], [])

    def test_uncounted_pages_reject_ignored_offsets_and_conflicting_identities(self):
        from aruba_central.central_tool import read_module_view, read_raw_profile_collection
        a, b = {"name": "a"}, {"name": "b"}
        initial = {"profiles": [a]}
        for page, reason in (({"profiles": [a]}, "duplicate_records"),
                             ({"profiles": [{"name": "a", "enable": True}]}, "duplicate_or_invalid_identity"),
                             ({"metadata": {"offset": 10}, "profiles": [b]}, "count_or_offset_changed"),
                             ({}, "schema_changed")):
            view = read_module_view(Fake([initial, initial, page]), "dns", "name", {}, paginate_uncounted=True)
            self.assertEqual(view["pagination_status"], reason)
            self.assertFalse(view["count_confirmed"])
            self.assertEqual(view["raw"], initial)
            self.assertEqual(len(view["raw_pages"]), 2)
        raw = read_raw_profile_collection(Fake([initial, initial, initial]), "dns", {}, paginate_uncounted=True)
        self.assertEqual(raw["status"], "partial_response")
        self.assertEqual(raw["raw"], initial)
        self.assertFalse(raw["collection_count_verified"])

    def test_uncounted_pagination_is_opt_in_and_requires_documented_path(self):
        from aruba_central.central_tool import read_module_view
        initial = {"profiles": [{"name": "a"}]}
        for module, enabled in (("dns", False), ("undocumented", True)):
            fake = Fake([initial])
            view = read_module_view(fake, module, "name", {}, paginate_uncounted=enabled)
            self.assertEqual(len(fake.calls), 1)
            self.assertNotIn("pagination_status", view)

    def test_raw_profile_collection_recovers_explicitly_truncated_pages(self):
        from aruba_central.central_tool import read_raw_profile_collection
        def page(total, offset, items):
            return {"metadata": {"total": total, "offset": offset, "count": len(items)}, "profiles": items}
        a, b, c = {"name": "one"}, {"name": "two"}, {"name": "three"}
        initial = page(3, 0, [a])
        fake = Fake([initial, page(3, 0, [a, b]), page(3, 2, [c])])
        result = read_raw_profile_collection(fake, "arc", {"view-type": "LIBRARY"})
        self.assertEqual(result["raw"]["profiles"], [a, b, c])
        self.assertEqual(result["initial_raw"], initial)
        self.assertTrue(result["collection_count_verified"])
        self.assertEqual(result["pagination_status"], "complete")
        self.assertEqual(fake.calls[-1][1]["offset"], 2)
        for bad in (page(4, 2, [c]), page(3, 1, [c]), page(3, 2, [b])):
            result = read_raw_profile_collection(Fake([initial, page(3, 0, [a,b]), bad]), "arc", {})
            self.assertEqual(result["status"], "partial_response")
            self.assertFalse(result["collection_count_verified"])
            self.assertEqual(result["raw"], initial)
        result = read_raw_profile_collection(Fake([{"profiles": [a]}]), "arc", {})
        self.assertFalse(result["collection_count_verified"])

    def test_unadapted_profile_inspection_deduplicates_source_views_and_rejects_bad_selectors(self):
        from aruba_central.central_tool import discover_profile_types, inspect_unadapted_profiles
        assignments = {"rows": [{"profile-type": "new-module", "profile-instance": "a",
                                 "device-function": "ACCESS_SWITCH", "scope-id": "12"}]}
        maps = {"rows": [{"resource": "new-module/a", "persona": "ACCESS_SWITCH", "scope-id": 12},
                         {"resource": "new-module/b", "persona": "ACCESS_SWITCH", "scope-id": 12},
                         {"resource": "new-module/c", "persona": "ACCESS_SWITCH", "scope-id": "../bad"}]}
        discovery = discover_profile_types(assignments, maps)
        fake = Fake([{"profiles": [{"name": "a"}]}, {"profiles": [{"name": "b"}]}, {}])
        result = inspect_unadapted_profiles(fake, discovery, assignments, maps)
        view = result["new-module"]
        self.assertEqual(view["status"], "unqualified_adapter")
        self.assertFalse(view["safe_to_apply"])
        self.assertEqual(len(view["source_views"]), 1)
        self.assertEqual(view["source_views"][0]["observed_instances"], ["a", "b"])
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(fake.calls[0][1]["scope-id"], "12")
        self.assertEqual(fake.calls[2][1], {"view-type": "LIBRARY", "detailed": "true"})

    def test_discovered_modules_are_surveyed_across_unassigned_scopes(self):
        from aruba_central.central_tool import discover_profile_types, inspect_unadapted_profiles
        assignments = {"rows": [{"profile-type": "new-module", "profile-instance": "a",
                                 "device-function": "ACCESS_SWITCH", "scope-id": "12"}]}
        discovery = discover_profile_types(assignments, {})
        fake = Fake([{"profiles": []}] * 7)
        result = inspect_unadapted_profiles(fake, discovery, assignments, {},
                  scopes_by_persona={"ACCESS_SWITCH": [{"id": "1"}, {"id": "12"}, {"id": "13"}],
                                     "CAMPUS_AP": [{"id": "20"}]})
        evidence = result["new-module"]
        self.assertEqual([s["scope"] for s in evidence["source_views"]], ["1", "12", "13"])
        self.assertEqual(evidence["source_views"][1]["observed_instances"], ["a"])
        self.assertEqual(evidence["source_views"][2]["observed_instances"], [])
        self.assertEqual(evidence["scope_read_outcomes"], {"response_received": 6})
        self.assertEqual(len(fake.calls), 7)
        self.assertFalse(evidence["safe_to_apply"])

    def test_runtime_identity_requires_unique_inventory_match_and_counts(self):
        from aruba_central.central_tool import qualify_observed_identities
        def source(ambiguous=False):
            rows = [{"identifier": v, "description": v if ambiguous else "example",
                     "@": {"aruba-annotation:object_type": "LOCAL",
                           "aruba-annotation:inherited": False}} for v in ("a", "b")]
            raw = {"profiles": rows, "metadata": {
                "count_objects_in_module": {"ANY": 2, "LOCAL": 2, "SHARED": 0}}}
            return {"persona": "ACCESS_SWITCH", "scope": "1", "observed_instances": ["a", "b"],
                    "committed": {"raw": raw}, "effective": {"raw": raw}}
        result = qualify_observed_identities({"source_views": [source()]})["ACCESS_SWITCH"]
        self.assertEqual(result["status"], "source_identity_observed")
        self.assertEqual(result["identity_field"], "identifier")
        self.assertEqual(result["comparable_source_scopes"], 1)
        self.assertFalse(result["safe_to_apply"])
        ambiguous = qualify_observed_identities({"source_views": [source(True)]})["ACCESS_SWITCH"]
        self.assertEqual(ambiguous["status"], "identity_unresolved")
        broken = source()
        broken["committed"]["raw"]["metadata"]["count_objects_in_module"]["ANY"] = 3
        self.assertEqual(qualify_observed_identities({"source_views": [broken]})
                         ["ACCESS_SWITCH"]["status"], "identity_unresolved")

    def test_ordered_parallel_bounds_workers_and_preserves_order(self):
        import threading
        import time
        from aruba_central.central_tool import ordered_parallel, AUDIT_WORKERS
        lock = threading.Lock()
        active = peak = 0
        updates = []
        def read(i):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(.02)
            with lock:
                active -= 1
            return i * 2
        self.assertEqual(ordered_parallel(range(12), read, 4,
                         lambda done, total: updates.append((done, total))), list(range(0, 24, 2)))
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, AUDIT_WORKERS)
        self.assertEqual(updates, [(i, 12) for i in range(1, 13)])

    def test_config_validator_metrics_are_aggregate_and_ignore_other_requests(self):
        from aruba_central.central_tool import Central, ALPHA
        from urllib.request import Request
        from types import SimpleNamespace
        base = "https://de1.api.central.arubanetworks.com"
        client = Central(base, token="token")
        def observe(path, headers, method="GET"):
            client._observe_config_validators(Request(base + path, method=method),
                                              SimpleNamespace(headers=headers))
        observe(ALPHA + "/dns", {"ETag": '"private-tag"', "Last-Modified": "private-date"})
        observe(ALPHA + "/dns/example", {"ETag": 'W/"private-weak"'})
        observe(ALPHA + "/dns", {})
        observe(ALPHA + "/dns", {"ETag": '"private-post"'}, "POST")
        observe("/network-monitoring/v1/devices", {"ETag": '"private-other"'})
        self.assertEqual(client.get_validator_metrics(),
                         {"collection_responses": 2, "collection_strong_etag": 1,
                          "collection_last_modified": 1, "keyed_responses": 1,
                          "keyed_weak_etag": 1})

    def test_direct_https_handler_reuses_connection_and_discards_errors(self):
        from aruba_central.central_tool import PersistentCentralHTTPS
        from urllib.request import Request
        from unittest.mock import Mock, patch
        from types import SimpleNamespace
        handler = PersistentCentralHTTPS()
        first = Request(EU_REGIONS[0] + "/example")
        second = Request(EU_REGIONS[1] + "/example")
        first.timeout = second.timeout = 30
        with patch("aruba_central.central_tool.HTTPSConnection") as factory:
            connection = factory.return_value
            connection.getresponse.side_effect = [
                SimpleNamespace(status=200, reason="OK"), SimpleNamespace(status=200, reason="OK"),
                SimpleNamespace(status=503, reason="Unavailable"), SimpleNamespace(status=200, reason="OK")]
            handler.https_open(first)
            handler.https_open(first)
            self.assertEqual(factory.call_count, 1)
            handler.https_open(first)
            self.assertIsNone(handler.connection)
            handler.https_open(second)
            self.assertEqual(factory.call_count, 2)
            self.assertEqual(factory.call_args.args[0], second.host)
            handler.close()
            self.assertIsNone(handler.connection)
        with patch("urllib.request.HTTPSHandler.https_open", return_value="standard") as fallback:
            self.assertEqual(handler.https_open(Request(EU_REGIONS[0] + "/example", method="POST")), "standard")
            self.assertEqual(handler.https_open(Request("https://sso.common.cloud.hpe.com/example")), "standard")
            proxy = Request(EU_REGIONS[0] + "/example")
            proxy.set_proxy("proxy.example:8080", "https")
            self.assertEqual(handler.https_open(proxy), "standard")
            self.assertEqual(fallback.call_count, 3)

    def test_worker_budget_adapts_only_with_enough_successful_latency_samples(self):
        from aruba_central.central_tool import AUDIT_WORKERS, AUDIT_MAX_WORKERS
        client = Central(EU_REGIONS[0], token="test")
        client._successful_get_latency.extend([2.0] * 31)
        self.assertEqual(client.recommended_audit_workers(AUDIT_WORKERS), AUDIT_WORKERS)
        client._successful_get_latency.append(2.0)
        self.assertEqual(client.recommended_audit_workers(AUDIT_WORKERS), AUDIT_MAX_WORKERS)
        client._request_interval = 1 / 8
        self.assertEqual(client.recommended_audit_workers(AUDIT_WORKERS), AUDIT_WORKERS)
        client._request_interval = 1 / 9
        client._successful_get_latency.extend([.05] * 128)
        self.assertEqual(client.recommended_audit_workers(AUDIT_WORKERS), AUDIT_WORKERS)

    def test_pacing_gate_rechecks_cooldown_after_sleep(self):
        from unittest.mock import patch
        client = Central(EU_REGIONS[0], token="test")
        clock = [100.0]
        sleeps = []
        client._next_request_at = 100.1
        def sleep(seconds):
            sleeps.append(seconds)
            clock[0] += seconds
            if len(sleeps) == 1:
                # A concurrent response can extend the shared cooldown
                # while the next admission waits.
                client._rate_limit_response(2)
        with patch("aruba_central.central_tool.time.monotonic", side_effect=lambda: clock[0]), patch(
            "aruba_central.central_tool.time.sleep", side_effect=sleep
        ):
            client._wait_rate_limit()
        self.assertEqual(len(sleeps), 2)
        self.assertAlmostEqual(sleeps[0], .1)
        self.assertAlmostEqual(sleeps[1], 2)
        self.assertAlmostEqual(client._next_request_at, clock[0] + 1 / 8)

    def test_rate_limit_backoff_and_gradual_recovery_respects_cap(self):
        from unittest.mock import patch
        client = Central(EU_REGIONS[0], token="test")
        with patch("aruba_central.central_tool.time.monotonic", return_value=100):
            client._rate_limit_response(5)
            self.assertAlmostEqual(1 / client._request_interval, 8)
            self.assertEqual(client._retry_at, 105)
            client._rate_limit_response(10)
            self.assertAlmostEqual(1 / client._request_interval, 7)
            self.assertEqual(client._retry_at, 110)
        with patch("aruba_central.central_tool.time.monotonic", return_value=150):
            client._wait_rate_limit()
            self.assertAlmostEqual(1 / client._request_interval, 7)
        for now, rate in ((170, 7.5), (200, 8), (230, 8.5), (260, 9), (290, 9)):
            with patch("aruba_central.central_tool.time.monotonic", return_value=now):
                client._wait_rate_limit()
                self.assertAlmostEqual(1 / client._request_interval, rate)
        self.assertEqual(client._retry_delay("12", 0), 12)
        self.assertEqual(client._retry_delay("invalid", 2), 4)
        self.assertEqual(client._retry_delay("Thu, 01 Jan 1970 00:00:00 GMT", 0), 0)

    def test_conditional_validator_probe_never_returns_headers_or_bodies(self):
        from unittest.mock import patch
        import json
        client = Central(EU_REGIONS[0], token="PRIVATE-TOKEN")
        path = "/network-config/v1alpha1/dns"
        params = {"view-type": "LOCAL", "scope-id": "12345", "effective": "true"}
        def response(request, label, *, response_headers=None):
            if request.get_header("If-none-match"):
                self.assertEqual(request.get_header("If-none-match"), '"PRIVATE-TAG"')
                raise APIError(label, 304)
            response_headers({"ETag": '"PRIVATE-TAG"'})
            return {"private": "PRIVATE-BODY"}
        with patch.object(client, "_request", side_effect=response) as read:
            result = client.probe_config_validator(path, params)
            self.assertEqual(result, {"status": "not_modified", "http_status": 304})
            self.assertEqual(read.call_count, 2)
            self.assertEqual(read.call_args_list[0].args[0].full_url,
                             read.call_args_list[1].args[0].full_url)
        def weak(request, label, *, response_headers=None):
            response_headers({"ETag": 'W/"PRIVATE-TAG"'})
            return {"private": "PRIVATE-BODY"}
        with patch.object(client, "_request", side_effect=weak) as read:
            self.assertEqual(client.probe_config_validator(path, params),
                             {"status": "strong_validator_unavailable"})
            read.assert_called_once()
        def ignored(request, label, *, response_headers=None):
            response_headers({"ETag": '"PRIVATE-TAG"'})
            return {"private": "PRIVATE-BODY"}
        with patch.object(client, "_request", side_effect=ignored):
            result = client.probe_config_validator(path, params)
            self.assertEqual(result["status"], "full_response")
            self.assertTrue(result["body_identical"])
            self.assertTrue(result["strong_validator_unchanged"])
        self.assertNotIn("PRIVATE", json.dumps(result))
        with self.assertRaises(ValueError):
            client.probe_config_validator("/unqualified", params)

    def test_transient_get_errors_retry_but_tls_and_post_do_not(self):
        from io import BytesIO
        from urllib.error import URLError
        from urllib.request import Request
        from unittest.mock import Mock, patch
        import ssl
        client = Central(EU_REGIONS[0], token="test")
        client._http.opener = Mock()
        request = Request(client.base + "/network-config/v1alpha1/dns")
        with patch.object(client, "_wait_rate_limit"), patch("aruba_central.central_tool.time.sleep"):
            client._http.opener.open.side_effect = [URLError(TimeoutError()), ConnectionResetError(),
                                                       BytesIO(b'{"items":[]}')]
            self.assertEqual(client._request(request, "dns"), {"items": []})
            self.assertEqual(client.get_transport_metrics()["http_get_transient_errors"], 2)
            self.assertEqual(client.get_transport_metrics()["http_get_retries"], 2)
            client._http.opener.open.reset_mock()
            client._http.opener.open.side_effect = URLError(ssl.SSLCertVerificationError())
            with self.assertRaises(URLError):
                client._request(request, "dns")
            self.assertEqual(client._http.opener.open.call_count, 1)
            client._http.opener.open.reset_mock()
            client._http.opener.open.side_effect = TimeoutError()
            with self.assertRaises(TimeoutError):
                client._request(Request(request.full_url, method="POST"), "post")
            self.assertEqual(client._http.opener.open.call_count, 1)
            client._http.opener.open.reset_mock()
            with self.assertRaisesRegex(RuntimeError, "retry budget exhausted"):
                client._request(request, "dns")
            self.assertEqual(client._http.opener.open.call_count, 4)

    def test_repeated_custom_api_500s_reduce_retries_without_skipping_gets(self):
        from io import BytesIO
        from urllib.error import HTTPError
        from urllib.request import Request
        from unittest.mock import Mock, patch
        client = Central(EU_REGIONS[0], token="test")
        client._http.opener = Mock()
        custom = Request(client.base + "/network-config/v1alpha1/custom-get-api?scope-id=12")
        other = Request(client.base + "/network-config/v1alpha1/dns")
        def failure(request, **kwargs):
            raise HTTPError(request.full_url, 500, "error", {}, None)
        client._http.opener.open.side_effect = failure
        with patch.object(client, "_wait_rate_limit"), patch("aruba_central.central_tool.time.sleep"):
            for _ in range(3):
                with self.assertRaises(APIError):
                    client._request(custom, "custom")
            self.assertEqual(client._http.opener.open.call_count, 12)
            with self.assertRaises(APIError):
                client._request(custom, "custom")
            self.assertEqual(client._http.opener.open.call_count, 13)
            with self.assertRaises(APIError):
                client._request(other, "other")
            self.assertEqual(client._http.opener.open.call_count, 17)
            client._http.opener.open.side_effect = None
            client._http.opener.open.return_value = BytesIO(b'{"items":[]}')
            self.assertEqual(client._request(custom, "custom"), {"items": []})
            self.assertEqual(client._custom_api_terminal_500s, 0)
            client._http.opener.open.side_effect = failure
            with self.assertRaises(APIError):
                client._request(custom, "custom")
            self.assertEqual(client._http.opener.open.call_count, 22)
            self.assertEqual(client.get_transport_metrics(), {"http_get_attempts": 22,
                "http_get_retries": 15, "http_get_5xx": 21,
                "custom_500_retry_sequences_suppressed": 1})

    def test_ordered_parallel_bounded_submission_and_order(self):
        from aruba_central.central_tool import ordered_parallel
        from unittest.mock import patch
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event, Thread
        release = Event()
        submitted = []
        result = []
        class RecordingExecutor(ThreadPoolExecutor):
            def submit(self, fn, *args, **kwargs):
                submitted.append(args[0])
                if len(submitted) == 4:
                    release.set()
                return super().submit(fn, *args, **kwargs)
        def collect(value):
            if not release.wait(5):
                raise RuntimeError("scheduler failed to replenish")
            return value * 2
        progress = []
        with patch("aruba_central.central_tool.ThreadPoolExecutor", RecordingExecutor):
            result = ordered_parallel(range(100), collect, workers=2,
                                      completed=lambda done, total: progress.append((done, total)))
        self.assertEqual(result, [i * 2 for i in range(100)])
        self.assertEqual(progress, [(i, 100) for i in range(1, 101)])
        self.assertEqual(submitted, list(range(100)))

    def test_ordered_parallel_does_not_admit_entire_queue_on_failure(self):
        from aruba_central.central_tool import ordered_parallel
        from unittest.mock import patch
        from concurrent.futures import ThreadPoolExecutor
        submitted = []
        class RecordingExecutor(ThreadPoolExecutor):
            def submit(self, fn, *args, **kwargs):
                submitted.append(args[0])
                return super().submit(fn, *args, **kwargs)
        def collect(value):
            if value == 0:
                raise ValueError("fatal")
            return value
        with patch("aruba_central.central_tool.ThreadPoolExecutor", RecordingExecutor):
            with self.assertRaisesRegex(ValueError, "fatal"):
                ordered_parallel(range(10000), collect, workers=2)
        self.assertLessEqual(len(submitted), 4)

    def test_concurrent_token_refresh_is_single_flight(self):
        import time
        from unittest.mock import patch
        from aruba_central.central_tool import Central, EU_REGIONS, ordered_parallel
        client = Central(EU_REGIONS[0], client_id="test", client_secret="secret")
        def token(*args):
            time.sleep(.02)
            return {"access_token": "token", "expires_in": 3600}
        with patch.object(client, "_request", side_effect=token) as request:
            self.assertEqual(ordered_parallel(range(8), lambda _: client._token(), 4), ["token"] * 8)
            self.assertEqual(request.call_count, 1)

    def test_configuration_operational_capture_is_best_effort_and_switch_only(self):
        from unittest.mock import patch
        from aruba_central.central_tool import capture_configuration_operational_vlans
        results = {
            "ACCESS_SWITCH": {"scopes": [{"id": "1", "kind": "global"},
                                         {"id": "2", "kind": "device", "metadata": {"serial": "a"}},
                                         {"id": "3", "kind": "device", "metadata": {"serial": "b"}}]},
            "CAMPUS_AP": {"scopes": [{"id": "4", "kind": "device"}]}}
        def probe(client, metadata):
            if metadata["serial"] == "a":
                return {"status": "response_received", "payload": {"vlans": []}}
            raise RuntimeError("sanitized failure")
        with patch("aruba_central.central_tool.probe_operational_vlans", side_effect=probe) as read:
            data = capture_configuration_operational_vlans(object(), results, workers=1)
        self.assertEqual(read.call_count, 2)
        self.assertEqual(data["ACCESS_SWITCH"]["2"]["status"], "response_received")
        self.assertEqual(data["ACCESS_SWITCH"]["3"]["status"], "monitoring_read_failed")
        self.assertNotIn("CAMPUS_AP", data)

    def test_vlan_instance_reads_validate_identity_and_local_source(self):
        from aruba_central.central_tool import read_vlan_instance, VLAN
        annotation = {"aruba-annotation:object_type": "LOCAL",
                      "aruba-annotation:inherited": False}
        fake = Fake([{"l2-vlan": [{"vlan": 1, "name": "DEFAULT_VLAN_1", "enable": True, "@": annotation}]},
                     {"vlan": 1, "name": "Observed"},
                     {"vlan": 2, "name": "Wrong"},
                     {"vlan": 1, "name": "Unverified local"}])
        local = read_vlan_instance(fake, "ACCESS_SWITCH", "12", "1", False)
        self.assertEqual(local["status"], "observed")
        self.assertEqual(local["profile"]["enable"], True)
        self.assertEqual(fake.calls[0][0], VLAN + "/1")
        self.assertEqual(fake.calls[0][1]["object-type"], "LOCAL")
        self.assertEqual(fake.calls[0][1]["detailed"], "true")
        actual = read_vlan_instance(fake, "ACCESS_SWITCH", "12", "1", True)
        self.assertEqual(actual["profile"]["name"], "Observed")
        self.assertNotIn("enable", actual["profile"])
        self.assertNotIn("object-type", fake.calls[1][1])
        self.assertNotEqual(read_vlan_instance(fake, "ACCESS_SWITCH", "12", "1", True)["status"], "observed")
        self.assertEqual(read_vlan_instance(fake, "ACCESS_SWITCH", "12", "1", False)["status"], "source_unverified")

    def test_vlan_instance_capture_only_targets_omitted_fields(self):
        from aruba_central.central_tool import capture_vlan_instance_details
        from unittest.mock import patch
        data = {"ACCESS_SWITCH": {"modules": {"layer2-vlan": {"scope_results": [
            {"scope": "12", "scope_kind": "device", "review": {"qualified": True, "profiles": [
                {"identity": "1", "local": {"vlan": 1}, "effective": {"vlan": 1}},
                {"identity": "10", "local": {"vlan": 10, "name": "Complete", "enable": True},
                 "effective": {"vlan": 10, "name": "Complete", "enable": True}},
                {"identity": "20", "local": None, "effective": {"vlan": 20}}]}}]}}}}
        with patch("aruba_central.central_tool.read_vlan_instance", return_value={"status": "observed", "profile": {"vlan": 1}}) as read:
            details = capture_vlan_instance_details(object(), data, workers=1)
        self.assertEqual(read.call_count, 2)
        self.assertEqual(set(details["ACCESS_SWITCH"]["12"]["1"]), {"local", "effective"})
        self.assertNotIn("10", details["ACCESS_SWITCH"]["12"])

    def test_vlan_detail_reuses_exact_keyed_response_with_source_validation(self):
        from aruba_central.central_tool import capture_vlan_instance_details
        from unittest.mock import patch
        data = {"ACCESS_SWITCH": {"modules": {"layer2-vlan": {"scope_results": [
            {"scope": "12", "scope_kind": "device", "review": {"qualified": True, "profiles": [
                {"identity": "1", "local": {"vlan": 1}, "effective": {"vlan": 1}}]}}]}}}}
        raw = {"vlan": 1, "name": "Observed"}
        keyed = {"profiles": {"ACCESS_SWITCH": {"12": {"layer2-vlan": {"1": {
            "local": {"status": "identity_observed", "raw": raw},
            "effective": {"status": "identity_observed", "raw": raw}}}}}}}
        with patch("aruba_central.central_tool.read_vlan_instance") as read:
            result = capture_vlan_instance_details(object(), data, workers=1, keyed_details=keyed)
            read.assert_not_called()
        self.assertEqual(result["ACCESS_SWITCH"]["12"]["1"]["local"]["status"], "source_unverified")
        self.assertEqual(result["ACCESS_SWITCH"]["12"]["1"]["effective"]["status"], "observed")
        self.assertTrue(result["ACCESS_SWITCH"]["12"]["1"]["effective"]["reused_exact_individual"])
        keyed["profiles"]["ACCESS_SWITCH"]["12"]["layer2-vlan"]["1"]["effective"] = {
            "status": "collection_only_sampled"}
        with patch("aruba_central.central_tool.read_vlan_instance", return_value={"status": "observed"}) as read:
            capture_vlan_instance_details(object(), data, workers=1, keyed_details=keyed)
            self.assertEqual(read.call_count, 1)

    def test_monitoring_voice_filters_require_a_complete_disjoint_partition(self):
        from aruba_central.central_tool import collect_monitoring_voice_filter
        metadata = {"serial": "ABC123"}
        evidence = {"status": "response_received", "identity_field": "serial",
                    "payload": {"items": [{"id": 1}, {"id": 10}]}}
        enabled = {"items": [{"id": 10}]}
        disabled = {"items": [{"id": 1}]}
        fake = Fake([enabled, disabled])
        result = collect_monitoring_voice_filter(fake, metadata, evidence)
        self.assertEqual(result["values"], {"1": False, "10": True})
        self.assertEqual(result["status"], "observed")
        self.assertEqual(fake.calls[0][1]["filter"], "voice eq 'Enabled'")
        self.assertEqual(fake.calls[1][1]["filter"], "voice eq 'Disabled'")
        for pages in ([enabled, enabled], [enabled, {"items": []}],
                      [{"items": [{"id": 10, "voice": "Disabled"}]}, disabled],
                      [enabled, {"items": [{"id": 99}]}]):
            self.assertEqual(collect_monitoring_voice_filter(Fake(pages), metadata, evidence)["values"], {})
        complete = {**evidence, "payload": {"items": [{"id": 1, "voice": "Disabled"}]}}
        self.assertEqual(collect_monitoring_voice_filter(Fake([]), metadata, complete)["status"], "not_needed_or_unavailable")

    def test_multicast_interface_absence_does_not_prove_snooping_disabled(self):
        from aruba_central.central_tool import multicast_interface_evidence, monitoring_vlan_records
        ids = {"1", "10"}
        for field in ("igmp", "mld"):
            text = f"\n{field.upper()} is not enabled on any of the interfaces.\n"
            result = multicast_interface_evidence(text, field, ids)
            self.assertEqual(result, {"status": "no_multicast_interfaces", "vlans": {}})
            self.assertEqual(multicast_interface_evidence("Unrecognized response", field, ids)["status"],
                             "schema_unresolved")
        self.assertEqual(monitoring_vlan_records({"items": [{"id": 1, "voice": "Disabled"}],
                                                  "count": 1, "total": 1, "offset": 0}),
                         {"1": {"id": 1, "voice": "Disabled"}})
        self.assertIsNone(monitoring_vlan_records({"items": [{"id": 1}], "count": 1, "total": 2, "offset": 0}))
        self.assertIsNone(monitoring_vlan_records({"items": [{"id": 1}], "count": 1, "total": 1, "offset": 1}))

    def test_multicast_interface_commands_use_explicit_snooping_flag(self):
        from aruba_central.central_tool import parse_multicast_interface_output
        for field in ("igmp", "mld"):
            label = field.upper()
            text = (f"VRF Name : default\nInterface : vlan10\n{label} Operating Version : 2\n"
                    f"{label} Snoop Enabled on VLAN : True\nInterface : vlan20\n"
                    f"{label} Snoop Enabled on VLAN : False\nInterface : vlan30\n"
                    f"{label} Operating Version : 2\nInterface : 1/1/1\n"
                    f"{label} Snoop Enabled on VLAN : True")
            result = parse_multicast_interface_output(text, field, {"10", "20", "30"})
            self.assertEqual(result, {"10": {"snooping": True}, "20": {"snooping": False}})
            self.assertEqual(parse_multicast_interface_output("No entries found", field, {"10"}), {})

    def test_live_dhcp_output_and_central_rejection(self):
        from aruba_central.central_tool import parse_vlan_feature, supported_show_commands
        ids = {"1", "1000"}
        def envelope(command, output):
            return {"status": "COMPLETED", "output": {"results": [
                {"command": command, "output": output}], "commands": [command]}}
        samples = {
            "dhcpv4-snooping": "\n DHCPv4-Snooping Information\n\n  DHCPv4-Snooping         : No          Verify MAC Address  : Yes\n  Allow Overwrite Binding : No          Enabled VLANs       : \n  Static Attributes : No \n",
            "dhcpv6-snooping": "\n DHCPv6-Snooping Information\n\n  DHCPv6-Snooping      : No   Enabled VLANs        : \n  Trusted Port Bindings Enabled VLANs : \n  Client Event Logs                   : No \n",
        }
        for field, output in samples.items():
            with self.subTest(field=field):
                parsed = parse_vlan_feature(envelope("show " + field, output), field, ids)
                self.assertEqual(parsed["status"], "observed")
                self.assertEqual(parsed["vlans"], {vid: {"enable": False} for vid in ids})
        enabled = "DHCPv6-Snooping : Yes   Enabled VLANs : 1000"
        self.assertEqual(parse_vlan_feature(envelope("show dhcpv6-snooping", enabled),
                         "dhcpv6-snooping", ids)["vlans"], {"1": {"enable": False}, "1000": {"enable": True}})
        rejected = envelope("show vlan voice", "Command 'show vlan voice' not allowed\n")
        self.assertEqual(parse_vlan_feature(rejected, "voice-enable", ids)["status"], "command_not_allowed")
        self.assertEqual(supported_show_commands({"commands": ["show vlan", "show running-config all", "description"]}),
                         {"show vlan", "show running-config all"})

    def test_running_config_only_recovers_explicit_vlan_context(self):
        from aruba_central.central_tool import parse_vlan_running_config
        text = ("Current configuration:\n!\nvlan 1\n    no voice\n"
                "vlan 10,20\n    voice\n    ip igmp snooping enable\n"
                "    ipv6 mld snooping disable\n"
                "interface vlan 1\n    ip igmp snooping enable\n"
                "vlan 30\n    name Voice\n")
        result = parse_vlan_running_config(text, {"1", "10", "20", "30"})
        self.assertEqual(result["1"], {"voice-enable": False})
        self.assertEqual(result["10"], {"voice-enable": True, "igmp": {"snooping": True}, "mld": {"snooping": False}})
        self.assertEqual(result["20"], result["10"])
        self.assertNotIn("30", result)

    def test_vlan_feature_parsers_require_explicit_evidence(self):
        from aruba_central.central_tool import parse_vlan_feature
        ids = {"1", "10", "20"}
        voice = "VLAN Name Status Type Interfaces\n10 Phone up static 1/1/1"
        self.assertEqual(parse_vlan_feature(voice, "voice-enable", ids)["vlans"],
                         {"1": False, "10": True, "20": False})
        self.assertEqual(parse_vlan_feature("Voice VLAN not configured", "voice-enable", ids)["vlans"],
                         {vid: False for vid in ids})
        dhcp = "DHCPv4-Snooping : Yes\nEnabled VLANs : 1,10"
        self.assertEqual(parse_vlan_feature(dhcp, "dhcpv4-snooping", ids)["vlans"],
                         {"1": {"enable": True}, "10": {"enable": True}, "20": {"enable": False}})
        self.assertEqual(parse_vlan_feature(dhcp, "dhcpv6-snooping", ids)["status"], "schema_unresolved")
        self.assertEqual(parse_vlan_feature("DHCPv6-Snooping : No\nEnabled VLANs : unknown",
                                            "dhcpv6-snooping", ids)["status"], "schema_unresolved")
        for field in ("igmp", "mld"):
            label = field.upper()
            body = (f"VLAN ID : 1\n{label} Snooping is not enabled\n"
                    f"VLAN ID : 10\n{label} Operating Version : 2\nVLAN ID : 20")
            self.assertEqual(parse_vlan_feature(body, field, ids)["vlans"],
                             {"1": {"snooping": False}, "10": {"snooping": True}})
            self.assertEqual(parse_vlan_feature("Invalid input", field, ids)["status"], "schema_unresolved")

    def test_show_vlan_parser_distinguishes_shutdown_from_link_state(self):
        from aruba_central.central_tool import parse_show_vlan
        output = "VLAN Name Status Reason Type Interfaces\n1 DEFAULT_VLAN_1 up ok static 1/1/1\n20 Management VLAN down admin_down static 1/1/2\n30 Guest down no_member_port static\n"
        evidence = parse_show_vlan({"status": "COMPLETED", "output": [{"command": "show vlan", "output": output}]})
        self.assertEqual(evidence["status"], "observed")
        self.assertEqual(evidence["vlans"]["1"]["enable"], True)
        self.assertEqual(evidence["vlans"]["20"]["enable"], False)
        self.assertEqual(evidence["vlans"]["20"]["name"], "Management VLAN")
        self.assertNotIn("enable", evidence["vlans"]["30"])
        self.assertEqual(parse_show_vlan({"output": "show vlan failed"})["status"], "schema_unresolved")

    def test_svi_identity_does_not_guess(self):
        from aruba_central.central_tool import svi_vlan_id
        self.assertEqual(svi_vlan_id({"id": 10, "vlan": "10"}), "10")
        for item in ({"id": "1/1/10"}, {"name": "vlan10"}, {"id": 10, "vlan": 20}):
            with self.subTest(item=item), self.assertRaises(ValueError):
                svi_vlan_id(item)

    def test_single_local_profiles_are_reviewed(self):
        base = {"vlan": 10, "name": "Corp"}
        extra = {"vlan": 30, "name": "CCTV"}
        conflict = {"vlan": 40, "name": "Different"}
        scopes = [scope("1", "global", [base]),
                  scope("2", "device", [base, extra, conflict], [base, extra, conflict]),
                  scope("3", "device", [base])]
        results = review_local_profiles(scopes, {"10": base},
                    {"30": extra, "40": {"vlan": 40, "name": "Other"}})
        by_vlan = {r["vlan"]: r for r in results}
        self.assertEqual(by_vlan["10"]["recommendation"], "review_restore_global_inheritance")
        self.assertEqual(by_vlan["10"]["global_coverage"], "all_scanned_devices_match")
        self.assertEqual(by_vlan["30"]["recommendation"], "review_reuse_library_profile")
        self.assertEqual(by_vlan["30"]["missing_devices"], ["3"])
        self.assertEqual(by_vlan["30"]["global_coverage"], "not_all_scanned_devices_match")
        self.assertEqual(by_vlan["40"]["recommendation"], "resolve_library_conflict")
        self.assertTrue(all(r["status"] == "review_only" for r in results))

    def test_local_effective_mismatch_and_defaults_are_not_promoted(self):
        local = {"vlan": 10, "name": "Local"}
        actual = {"vlan": 10, "name": "Effective"}
        s = scope("2", "device", [actual], [local])
        self.assertEqual(review_local_profiles([s], {}, {})[0]["recommendation"],
                         "inspect_local_effective_difference")
        s["annotated"] = [{**actual, "@": {"aruba-annotation:is_default": True}}]
        self.assertEqual(review_local_profiles([s], {}, {})[0]["recommendation"], "retain_default")

    def test_report_distinguishes_coverage_and_conflicts(self):
        base = {"vlan": 10, "name": "Corp"}
        local = {"vlan": 30, "name": "CCTV"}
        conflicting = {"vlan": 30, "name": "Other"}
        snapshot = {"schema": 1, "captured_at": "example", "persona": "ACCESS_SWITCH",
                    "library": [conflicting], "excluded_devices": [{}],
                    "scopes": [scope("1", "global", [base]),
                               scope("2", "device", [base, local], [local]),
                               scope("3", "device", [base, local], [local]),
                               scope("4", "device", [base], [base])]}
        result = report(snapshot)
        candidate = result["duplicate_local_candidates"][0]
        self.assertEqual(candidate["matching_scanned_devices"], ["2", "3"])
        self.assertEqual(candidate["other_scanned_devices"], ["4"])
        self.assertEqual(candidate["library_state"], "conflict")
        self.assertEqual(result["scope_comparisons"][3]["local_matching_global"], ["10"])
        self.assertFalse(result["safe_to_apply"])


if __name__ == "__main__":
    unittest.main()
