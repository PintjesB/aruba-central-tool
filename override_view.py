"""Device-first review of committed local settings against Global."""
from collections import Counter
from central_tool import canonical, profile_body, PERSONAS, vlan_comparison_evidence
from consolidation import scope_memberships, REUSABLE
from workspace_ui import e, page, intro, badge, raw, table, tr, inspect, diff_table, property_table, module_label, persona_label
from workspace_views import load, url, select, title_profile, vlan_explanation, operational_vlan_context, vlan_instance_context, scope_filter_form, device_options, module_options

RESULTS = {
    "identical": "Identical to Global",
    "effective_match": "Observed settings match Global",
    "omitted": "Comparison incomplete",
    "protected": "Protected default VLAN",
    "different": "Different from Global",
    "no_global": "No matching Global profile",
    "global_unknown": "Global comparison unavailable",
    "source_uncertain": "Local source or effective settings disagree",
}
NEXT_STEP = {
    "identical": "Review possible override removal",
    "effective_match": "Review removal only after verifying saved definition and inheritance",
    "omitted": "Retain until unavailable settings can be verified",
    "protected": "Retain VLAN 1; inspect default settings only",
    "different": "Keep local unless the difference is unnecessary",
    "no_global": "Local definition, not a proven Global override",
    "global_unknown": "Validate Global configuration first",
    "source_uncertain": "Validate the saved and effective configuration",
}


def device_override_rows(bundle, persona):
    entry = bundle["results"][persona]
    names = {s["id"]: s.get("name") or s["id"] for s in entry["scopes"]}
    membership = scope_memberships(entry["scopes"])
    kinds = {s["kind"] for s in entry["scopes"]}
    findings, incomplete = [], []
    for module, data in sorted(entry["modules"].items()):
        if data.get("device_scope_only"):
            continue
        views = {s["scope"]: s for s in data["scope_results"]}
        for sid, member in membership.items():
            review = views.get(sid, {}).get("review", {})
            if not review.get("qualified"):
                incomplete.append({"device": sid, "module": module})
                continue
            global_view = views.get(member["global"], {}).get("effective_view", {})
            for row in review["profiles"]:
                identity = row["identity"]
                protected = module == "layer2-vlan" and persona in PERSONAS and identity == "1"
                if row["local"] is None or (row["status"] == "default_profile" and not protected):
                    continue
                local, ref = row["local"], row["global_reference"]
                evidence = vlan_comparison_evidence(bundle, persona, sid, row) if module == "layer2-vlan" else None
                if protected:
                    state = "protected"
                elif row["status"] in ("source_conflict", "local_effective_mismatch") or (evidence and evidence["conflicts"]):
                    state = "source_uncertain"
                elif global_view.get("status") != "list_parsed":
                    state = "global_unknown"
                elif ref is None:
                    state = "no_global"
                elif canonical(local) == canonical(ref):
                    state = "identical"
                elif evidence and evidence["differences"] == []:
                    state = "effective_match"
                elif evidence and evidence["differences"] and all(d["kind"] in ("missing_local", "missing_reference") for d in evidence["differences"]):
                    state = "omitted"
                else:
                    state = "different"
                chain = []
                for kind in ("group", "site", "collection", "global"):
                    ancestor = member[kind]
                    if ancestor is None:
                        if kind in kinds:
                            chain.append({"name": kind.capitalize(), "state": "Membership unknown"})
                        continue
                    view = views.get(ancestor, {}).get("effective_view", {})
                    if view.get("status") != "list_parsed":
                        text = "Cannot compare"
                    elif identity not in view["profiles"]:
                        text = "Profile not returned"
                    else:
                        text = "Saved body matches" if canonical(profile_body(view["profiles"][identity])) == canonical(local) else "Saved body differs"
                    chain.append({"name": names[ancestor], "state": text, "kind": kind})
                ann = row.get("annotations", {})
                direct = ann.get("aruba-annotation:object_type") == "LOCAL" and ann.get("aruba-annotation:inherited") is False
                findings.append({"device": sid, "device_name": names[sid], "module": module,
                                 "identity": identity, "result": state, "profile": row, "chain": chain,
                                 "direct_confirmed": direct, "evidence": evidence,
                                 "candidate": state == "identical" and module in REUSABLE and direct})
    return findings, incomplete


def overrides_view(workspace, query):
    loaded, empty = load(workspace, query, "Device overrides", "overrides")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    personas = sorted(bundle["results"])
    if not personas:
        return page("Device overrides", intro("Device overrides", "No device functions captured.", picker), workspace.nav(name))
    persona = query.get("persona", "ACCESS_SWITCH" if "ACCESS_SWITCH" in personas else personas[0])
    if persona not in personas:
        raise ValueError("Unknown device function")
    entry = bundle["results"][persona]
    devices = [(s["id"], s.get("name") or s["id"]) for s in entry["scopes"] if s["kind"] == "device"]
    modules = sorted(m for m, data in entry["modules"].items() if not data.get("device_scope_only"))
    device, module, result = query.get("device", ""), query.get("module", ""), query.get("result", "")
    if (device and device not in dict(devices)) or (module and module not in modules) or (result and result not in RESULTS):
        raise ValueError("Unknown comparison filter")
    findings, incomplete = device_override_rows(bundle, persona)
    scoped = [f for f in findings if (not device or f["device"] == device) and (not module or f["module"] == module)]
    missing = [f for f in incomplete if (not device or f["device"] == device) and (not module or f["module"] == module)]
    counts = Counter(f["result"] for f in scoped)
    filters = scope_filter_form(root, "overrides", name, bundle, persona, (
        ("device", "Device", device, device_options),
        ("module", "Configuration", module, lambda entry: module_options(entry, "All modules", comparable=True))),
        submit="Compare with Global", extra_fields=(("result", "Result", result,
            [("", "All results")] + list(RESULTS.items())),))
    short_action = {
        "identical": "Review removal",
        "effective_match": "Verify inheritance",
        "omitted": "Retain pending verification",
        "protected": "Retain protected VLAN",
        "different": "Retain unless unnecessary",
        "no_global": "Review local definition",
        "global_unknown": "Validate Global",
        "source_uncertain": "Validate source",
    }
    rows = []
    for f in sorted(scoped, key=lambda f: (list(RESULTS).index(f["result"]), f["device_name"], f["module"], f["identity"])):
        if result and f["result"] != result:
            continue
        p = f["profile"]
        label = title_profile(f["identity"], p["local"])
        if f["module"] == "layer2-vlan":
            label = "VLAN " + label
        state = f["result"]
        next_step = NEXT_STEP[state]
        if state == "identical" and not f["candidate"]:
            next_step = "Verify direct source and module support; do not remove yet"
        comparison = diff_table(p["global_differences"], "Device local", "Global")
        if f["module"] == "layer2-vlan" and p["global_reference"] is not None:
            comparison = vlan_explanation(p["local"], p["global_reference"], p["effective"], f["evidence"]) or comparison
        extra = ('<h3>Saved device settings</h3>' + property_table(p["local"])
                 + '<h3>Effective device settings in Central</h3>' + property_table(p["effective"])
                 + '<h3>Global settings</h3>' + property_table(p["global_reference"]))
        if f["module"] == "layer2-vlan":
            sources = [{"kind": "device", "scope": f["device"], "name": f["device_name"]}]
            extra += vlan_instance_context(bundle, persona, sources, f["identity"]) + operational_vlan_context(bundle, persona, sources, f["identity"])
        detail = ('<div class="review-decision"><div>' + badge(RESULTS[state], "warn" if state in ("different", "omitted", "source_uncertain") else "neutral")
                  + '<p><strong>Next step:</strong> ' + e(next_step) + '.</p></div><div class="review-context"><small>Device</small><strong>'
                  + e(f["device_name"]) + '</strong></div></div>'
                  + comparison
                  + '<details><summary>Inheritance and higher scopes</summary>'
                  + table(("Scope", "Saved local vs captured scope body"), [tr(e(v["name"]), e(v["state"])) for v in f["chain"]])
                  + '<p class="note">Captured bodies can differ because fields are omitted. These are not verified effective differences. Verify inheritance and dependencies before removal.</p></details>'
                  + '<details><summary>Source evidence</summary>' + extra + raw(p) + '</details>')
        if f["candidate"]:
            detail += f'<p><a href="{url(root, "advisor", snapshot=name, finding="remove_override", module=f["module"], persona=persona, scope=f["device"], identity=f["identity"])}">Open matching consolidation preview</a></p>'
        action_label = "Verify source first" if state == "identical" and not f["candidate"] else short_action[state]
        rows.append(tr(f'<strong>{e(f["device_name"])}</strong>',
                       f'<strong>{e(label)}</strong><small>{e(module_label(f["module"]))}</small>',
                       badge(RESULTS[state], "good" if state == "identical" else "warn" if state == "different" else "neutral")
                       + f'<small title="{e(next_step)}">{e(action_label)}</small>',
                       inspect(label, detail, "Compare settings")))
    result_summary = '<div class="result-summary" aria-label="Comparison results">' + "".join(
        f'<span><strong>{counts[key]}</strong> {e(label)}</span>' for key, label in (
            ("identical", "identical saved bodies"), ("effective_match", "observed matches"),
            ("different", "different"), ("omitted", "incomplete"), ("no_global", "no Global profile"),
            ("protected", "protected"), ("global_unknown", "Global unavailable"),
            ("source_uncertain", "source conflict")) if counts[key]) + '</div>'
    from central_tool import vlan_evidence_summary
    diagnostics = vlan_evidence_summary(bundle)
    report = '<details><summary>VLAN evidence collection results (entire snapshot)</summary>' + table(
        ("Source", "Read outcomes"), [tr(e(label), e(", ".join(f"{key}: {value}" for key, value in diagnostics[key].items()) or "No observations"))
         for key, label in (("individual_vlan_reads", "Individual VLAN API"), ("switch_cli", "Switch show vlan"),
                            ("monitoring", "Switch monitoring"), ("recovered_values", "Recovered field values"),
                            ("remaining_fields", "Unresolved field occurrences"))] +
        [tr(e(field), e(", ".join(f"{key}: {value}" for key, value in outcomes.items())))
         for field, outcomes in sorted(diagnostics["feature_cli"].items())]) + '</details>'
    body = (intro("Device overrides", "Find saved device-level configuration and compare it directly with Global.", picker)
            + '<section class="worklist"><div class="worklist-controls">' + filters + '</div>'
            + '<div class="worklist-summary"><h2>Device-local configuration</h2>' + result_summary + '</div>'
            + table(("Device", "Profile / configuration", "Assessment", ""), rows, search=True, style="override-table")
            + f'<p class="filter-hint">{len(missing)} device/module reads unavailable. VLAN 1 is protected; device-only interfaces are excluded. Review only.</p></section>'
            + report)
    return page("Device overrides", body, workspace.nav(name))
