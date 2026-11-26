import unittest
from central_tool import APIError, Central, EmptyCommittedLocal, EU_REGIONS, check_empty_local, detect_region, inventory, offset_rows, report, review_local_profiles, scoped_vlan_rows, vlan_map, vlan_rows


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
        from central_tool import field_differences
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
        from central_tool import field_differences, print_review_summary
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
        from central_tool import assess_vlan_reference
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
        from central_tool import inventory_capabilities
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
        from central_tool import scan_all, select_snapshot
        devices = [{"deviceFunction": "Access Switch"}, {"deviceFunction": "Core Switch"},
                   {"deviceFunction": "Campus AP"}, {"deviceFunction": "Access Switch"}]
        class Client:
            base = "test"
        with patch("central_tool.inventory", return_value=devices), patch("central_tool.scan") as scan:
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
        from central_tool import audit
        class Client:
            base = "test"
        source = {"kind": "multi_persona_scan", "region": "test", "inventory": [
            {"identity": {"persona": "ACCESS_SWITCH"}, "vlan_scan_supported_persona": True},
            {"identity": {"persona": "CORE_SWITCH"}, "vlan_scan_supported_persona": True},
            {"identity": {"persona": "CAMPUS_AP"}, "vlan_scan_supported_persona": False}],
            "snapshots": {p: {"persona": p, "region": "test"} for p in ("ACCESS_SWITCH", "CORE_SWITCH")}}
        with patch("central_tool.scan_all", return_value=source) as scan, \
             patch("central_tool.discover_dependencies", return_value={}) as probe, \
             patch("central_tool.report", return_value={}), \
             patch("central_tool.dependency_review", return_value={"safe_to_apply": False}) as review, \
             patch("central_tool.print_review_summary"), patch("central_tool.print_dependency_summary"):
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
        from central_tool import discover_dependencies
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
        from central_tool import dependency_review
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
        from central_tool import reference_candidates
        payload = {"interfaces": [{"switchport": {"native-vlan": 10, "allowed-vlans": ["20-22", 40]},
                                   "unknown-vlan-field": 99, "name": "1/1/10",
                                   "@": {"vlan": 123}, "metadata": {"vlan": 100}},
                                  {"switchport": {"allowed-vlans": "all"}},
                                  {"switchport": {"allowed-vlans": []}}]}
        result = reference_candidates(payload)
        self.assertEqual([r["vlan_ids"] for r in result["references"]], [["10"], ["20", "21", "22", "40"]])
        self.assertEqual(len(result["unresolved_paths"]), 3)

    def test_operational_probe_uses_known_inventory_identity_only(self):
        from central_tool import probe_operational_vlans, operational_vlan_summary
        fake = Fake([{"items": [{"id": 10, "igmp": True}]}])
        self.assertEqual(probe_operational_vlans(fake, {"serialNumber": "../bad"})["status"], "identity_unresolved")
        self.assertEqual(fake.calls, [])
        result = probe_operational_vlans(fake, {"serialNumber": "ABC123"})
        self.assertEqual(fake.calls[0][0], "/network-monitoring/v1/switches/ABC123/vlans")
        self.assertEqual(operational_vlan_summary(result)["rows"], 1)
        self.assertEqual(operational_vlan_summary(result)["status"], "schema_observed")

    def test_operational_probe_falls_back_to_discovered_serial(self):
        from central_tool import probe_operational_vlans, operational_vlan_summary
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
        from central_tool import reference_candidates
        payload = {"roles": [{"vlan-type": "VLAN_NAME", "access-vlan-name": "A"},
                             {"vlan-type": "VLAN_ID", "access-vlan-id": 30},
                             {"access-vlan-name": "B"}, {"access-vlan-name": "unknown"}]}
        result = reference_candidates(payload, {"10": {"name": "A"}, "20": {"name": "B"},
                                                "21": {"name": "B"}})
        self.assertEqual([r["vlan_ids"] for r in result["references"]], [["10"], ["30"]])
        self.assertEqual(len(result["unresolved_paths"]), 2)

    def test_svi_identity_does_not_guess(self):
        from central_tool import svi_vlan_id
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
