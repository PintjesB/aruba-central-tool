"""Offline snapshot drift and explicit reference-device standards checks."""
from collections import Counter
from central_tool import canonical, field_differences, profile_body, health_serial
from consolidation import scope_memberships

# Exact module-body comparisons for these explicit reference choices are useful.
# Physical topology, system identity and other device-specific modules are not
# included in the default standards worklist.
STANDARD_MODULES = {"layer2-vlan", "roles", "wlan-ssids", "dns", "ntp", "snmp",
                    "snmp-trap", "logging", "sw-port-profiles", "ap-port-profiles",
                    "gw-port-profiles", "interface-profiles", "auth-servers",
                    "server-groups", "qos-queues", "macauth", "aliases",
                    "net-groups", "policies", "role-acls", "alg", "object-groups"}


def snapshot_identity_checks(before, after):
    def global_ids(bundle):
        return {str(s["id"]) for entry in bundle["results"].values()
                for s in entry["scopes"] if s["kind"] == "global"}
    def serials(bundle):
        return {serial for record in bundle.get("inventory", [])
                if (serial := health_serial(record.get("inventory")))}
    a, b = global_ids(before), global_ids(after)
    sa, sb = serials(before), serials(after)
    if not before.get("region") or before.get("region") != after.get("region"):
        raise ValueError("Different or unavailable API regions")
    if len(a) != 1 or a != b:
        raise ValueError("Different or unavailable Global scope identity")
    if not sa & sb:
        raise ValueError("No common device serial; tenant comparison not established")
    return {"common_serial_count": len(sa & sb), "same_tenant_verified": False}


def view_changes(before, after, *, include_source=True):
    """Compare positive bodies, and require verified counts for absence claims."""
    before, after = before or {}, after or {}
    if before.get("status") != "list_parsed" or after.get("status") != "list_parsed":
        return [{"identity": "", "status": "unavailable", "before_status": before.get("status", "not_collected"),
                 "after_status": after.get("status", "not_collected")}]
    a, b = before["profiles"], after["profiles"]
    changes = []
    for identity in sorted(a.keys() | b.keys()):
        old, new = a.get(identity), b.get(identity)
        if old is None or new is None:
            absent_view = before if old is None else after
            state = ("added" if old is None else "removed") if absent_view.get("count_confirmed") is True else "presence_unverified"
            changes.append({"identity": identity, "status": state,
                            "before": profile_body(old) if old is not None else None,
                            "after": profile_body(new) if new is not None else None})
            continue
        x, y = profile_body(old), profile_body(new)
        fields = field_differences(x, y)
        source_fields = ("aruba-annotation:object_type", "aruba-annotation:inherited",
                         "aruba-annotation:scope_id", "aruba-annotation:device_function")
        def source(row):
            ann = row.get("@")
            return {k: ann[k] for k in source_fields if k in ann} if isinstance(ann, dict) else {}
        annotations = field_differences(source(old), source(new)) if include_source else []
        if fields or annotations:
            changes.append({"identity": identity, "status": "changed" if fields else "source_changed",
                            "before": x, "after": y, "fields": fields, "source_fields": annotations})
    if not changes and not (before.get("count_confirmed") and after.get("count_confirmed")):
        return [{"identity": "", "status": "coverage_unverified"}]
    return changes


def configuration_drift(before, after, *, confirmed=False):
    if not confirmed:
        raise ValueError("Confirm that both snapshots belong to the same tenant")
    identity_checks = snapshot_identity_checks(before, after)
    records = []
    def compare(persona, scope, name, module, kind, a, b):
        for row in view_changes(a, b):
            records.append({"persona": persona, "scope": scope, "scope_name": name,
                            "module": module, "view": kind, **row})
    for persona in sorted(before["results"].keys() | after["results"].keys()):
        a, b = before["results"].get(persona, {}), after["results"].get(persona, {})
        sa = {s["id"]: s for s in a.get("scopes", [])}
        sb = {s["id"]: s for s in b.get("scopes", [])}
        for sid in sorted(sa.keys() | sb.keys()):
            x, y = sa.get(sid), sb.get(sid)
            name = (y or x).get("name") or sid
            if x is None or y is None:
                records.append({"persona": persona, "scope": sid, "scope_name": name, "module": "Scope inventory",
                                "view": "inventory", "identity": "", "status": "scope_presence_changed"})
                continue
            if x["kind"] != y["kind"] or (x["kind"] == "device" and
                    (not health_serial(x.get("metadata")) or health_serial(x.get("metadata")) != health_serial(y.get("metadata")))):
                records.append({"persona": persona, "scope": sid, "scope_name": name, "module": "Scope inventory",
                                "view": "inventory", "identity": "", "status": "scope_identity_unverified"})
                continue
            ma, mb = x.get("metadata") or {}, y.get("metadata") or {}
            fields = field_differences({"name": x.get("name"), **{k: ma[k] for k in ("siteId", "deviceGroupId", "collectionId") if k in ma}},
                                      {"name": y.get("name"), **{k: mb[k] for k in ("siteId", "deviceGroupId", "collectionId") if k in mb}})
            if fields:
                records.append({"persona": persona, "scope": sid, "scope_name": name, "module": "Scope inventory",
                                "view": "inventory", "identity": "", "status": "changed", "fields": fields})
            for module in sorted(a.get("modules", {}).keys() | b.get("modules", {}).keys()):
                def at(entry):
                    return next((v for v in entry.get("modules", {}).get(module, {}).get("scope_results", [])
                                 if v["scope"] == sid), {})
                va, vb = at(a), at(b)
                if not va and not vb:
                    continue
                for kind in ("local", "effective"):
                    compare(persona, sid, name, module, kind, va.get(kind + "_view"), vb.get(kind + "_view"))
    a = (before.get("library") or {}).get("modules", {})
    b = (after.get("library") or {}).get("modules", {})
    for module in sorted(a.keys() | b.keys()):
        compare("Library", "", "Library", module, "library", a.get(module), b.get(module))
    # Assignment capture is not exhaustive. Report observed set differences
    # without asserting that absence means a real assignment was deleted.
    def assignments(bundle):
        view = (bundle.get("library") or {}).get("assignments") or {}
        rows = view.get("rows", [])
        keys = ("scope-id", "device-function", "profile-type", "profile-instance")
        return {tuple(str(row[k]) for k in keys) for row in rows
                if all(type(row.get(k)) in (str, int) for k in keys)}
    aa, bb = assignments(before), assignments(after)
    for sid, persona, module, profile in sorted(aa ^ bb):
        records.append({"persona": persona, "scope": sid, "scope_name": sid, "module": module,
                        "view": "assignment", "identity": profile,
                        "status": "assignment_observation_changed",
                        "before": (sid, persona, module, profile) in aa,
                        "after": (sid, persona, module, profile) in bb})
    return {"identity_checks": identity_checks, "records": records,
            "counts": dict(Counter(r["status"] for r in records)), "complete": False, "safe_to_apply": False}


def reference_compliance(bundle, persona, module, reference, target_scope, *, baseline=None, confirmed=False, selected_modules=None, include_reference=False, field_rules=None):
    """Compare a selected standard against explicitly selected device recipients.

    This is an exact observed-body check, not a claim of operational compliance.
    Unknown reads and count-unverified absence never become violations.
    """
    entry = bundle["results"][persona]
    historical = baseline is not None and baseline is not bundle
    if historical:
        if not confirmed:
            raise ValueError("Confirm the baseline and current snapshots belong to the same tenant")
        snapshot_identity_checks(baseline, bundle)
    baseline_entry = (baseline if historical else bundle)["results"].get(persona, {})
    scopes = {s["id"]: s for s in entry["scopes"]}
    baseline_devices = {s["id"]: s for s in baseline_entry.get("scopes", []) if s["kind"] == "device"}
    available = STANDARD_MODULES & (entry["modules"].keys() | baseline_entry.get("modules", {}).keys())
    if (reference not in baseline_devices or target_scope not in scopes
            or (module != "all" and module not in available)):
        raise ValueError("Invalid reference, module or target scope")
    modules = sorted(available) if module == "all" else [module]
    if selected_modules is not None:
        if not selected_modules or not set(selected_modules) <= STANDARD_MODULES:
            raise ValueError("Invalid frozen module set")
        modules = sorted(set(selected_modules))
    if field_rules is not None:
        if not field_rules or not {rule["module"] for rule in field_rules} <= set(modules):
            raise ValueError("Invalid field standard")
        modules = sorted({rule["module"] for rule in field_rules})
    if not modules:
        raise ValueError("No supported standards modules available")
    members = scope_memberships(entry["scopes"])
    kind = scopes[target_scope]["kind"]
    targets = {target_scope} if kind == "device" else {sid for sid, m in members.items() if m.get(kind) == target_scope}
    unknown = set() if kind == "device" else {sid for sid, m in members.items() if m.get(kind) is None}
    if not historical and not include_reference:
        targets.discard(reference)
        unknown.discard(reference)
    def effective_views(entry, name):
        return {v["scope"]: v.get("effective_view", {}) for v in
                entry.get("modules", {}).get(name, {}).get("scope_results", [])}

    current_views = {name: effective_views(entry, name) for name in modules}
    expected_views = {name: effective_views(baseline_entry, name).get(reference, {}) for name in modules}
    findings = []
    for sid in sorted(targets):
        changes = []
        module_results = {}
        for name in modules:
            expected = expected_views[name]
            actual = current_views[name].get(sid, {})
            if expected.get("status") != "list_parsed":
                observations = [{"identity": "", "status": "reference_unavailable"}]
            elif not expected.get("profiles") and not expected.get("count_confirmed"):
                observations = [{"identity": "", "status": "reference_unavailable"}]
            elif field_rules is not None:
                from field_standards import compare_fields
                observations = compare_fields(expected, actual, [rule for rule in field_rules if rule["module"] == name])
            else:
                observations = view_changes(expected, actual, include_source=False)
            for change in observations:
                if change["status"] == "changed" and all(
                        d["kind"] in ("missing_local", "missing_reference", "null_vs_value")
                        for d in change.get("fields", [])):
                    change["status"] = "field_values_unavailable"
            differences = any(r["status"] in ("added", "removed", "changed", "field_profile_absent") for r in observations)
            gaps = any(r["status"] not in ("added", "removed", "changed", "field_profile_absent") for r in observations)
            # A difference and an evidence gap may coexist in one profile.
            gaps = gaps or expected.get("count_confirmed") is not True or actual.get("count_confirmed") is not True
            gaps = gaps or any(d["kind"] in ("missing_local", "missing_reference", "null_vs_value")
                               for row in observations for d in row.get("fields", []))
            if differences:
                state = "differences_observed"
            elif gaps:
                state = "verification_required"
            else:
                state = "matches_reference"
            module_results[name] = {"status": state, "has_gaps": gaps,
                                    "difference_count": len(observations)}
            changes.extend({**row, "module": name} for row in observations)
        states = {row["status"] for row in module_results.values()}
        state = ("differences_observed" if "differences_observed" in states else
                 "verification_required" if "verification_required" in states else "matches_reference")
        findings.append({"scope": sid, "device": scopes[sid].get("name") or sid,
                         "status": state, "differences": changes, "module_results": module_results,
                         "has_gaps": any(row["has_gaps"] for row in module_results.values())})
    for sid in sorted(unknown):
        findings.append({"scope": sid, "device": scopes[sid].get("name") or sid,
                         "status": "membership_unverified", "differences": []})
    return {"findings": findings, "historical_baseline": historical,
            "reference_scope": reference, "reference_name": baseline_devices[reference].get("name") or reference,
            "reference_count_confirmed": all(v.get("count_confirmed") is True for v in expected_views.values()),
            "modules": modules,
            "target_count": len(targets), "unknown_membership": len(unknown), "safe_to_apply": False}
