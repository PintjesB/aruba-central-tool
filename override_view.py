"""Device-first review of committed local settings against Global."""
from collections import Counter
from central_tool import canonical, profile_body, PERSONAS, vlan_comparison_evidence, comparison_fields, field_differences
from consolidation import scope_memberships, REUSABLE
from inheritance_review import nearest_fallback
from workspace_ui import e, page, intro, badge, raw, table, tr, inspect, diff_table, property_table, module_label, persona_label
from workspace_views import load, url, select, title_profile, vlan_explanation, operational_vlan_context, vlan_instance_context, scope_filter_form, device_options, module_options

RESULTS = {
    "identical": "Matches Global",
    "nearest_match": "Matches nearest inherited definition",
    "nearest_settings_match": "Nearest settings match; profile identity changes",
    "effective_match": "Effective settings match Global",
    "partial_match": "Likely redundant",
    "omitted": "Insufficient comparable settings",
    "protected": "Protected default VLAN",
    "different": "Different from Global",
    "no_global": "No matching Global profile",
    "global_unknown": "Global comparison unavailable",
    "source_uncertain": "Local source or effective settings disagree",
}
NEXT_STEP = {
    "identical": "Review whether removing the local copy preserves these settings",
    "nearest_match": "Review removal against the observed nearest inherited definition",
    "nearest_settings_match": "Verify profile references before replacing the local identity",
    "effective_match": "Potentially redundant: verify saved definition and inheritance before removal",
    "partial_match": "Known settings match Global; verify unavailable settings before removal",
    "omitted": "No sufficient observed settings to assess redundancy",
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
                assessment = comparison_fields(evidence["comparison"] if evidence else row["effective"], ref,
                                               vlan=module == "layer2-vlan", conflicts=evidence["conflicts"] if evidence else (),
                                               saved=evidence["local"] if evidence else local)
                counts = assessment["counts"]
                # A sparse VLAN local/effective response is not by itself a
                # source conflict. Explicit discrepancies and source annotations
                # still take precedence over a possible match.
                ann = row.get("annotations", {})
                omission_only = (evidence and isinstance(local, dict) and isinstance(row["effective"], dict)
                                 and all(d["kind"] in ("missing_local", "missing_reference")
                                         for d in field_differences(local, row["effective"]))
                                 and ann.get("aruba-annotation:inherited") is not True
                                 and ann.get("aruba-annotation:object_type") != "SHARED")
                if protected:
                    state = "protected"
                elif (row["status"] == "source_conflict" or
                      (row["status"] == "local_effective_mismatch" and not omission_only)
                      or (evidence and evidence["conflicts"])):
                    state = "source_uncertain"
                elif global_view.get("status") != "list_parsed":
                    state = "global_unknown"
                elif ref is None:
                    state = "no_global"
                elif counts["different"] or (evidence and any(d["path"] == ["is-l3-vlan"] and
                        d["kind"] not in ("missing_local", "missing_reference", "null_vs_value")
                        for d in evidence["differences"] or [])):
                    state = "different"
                elif any(d["kind"] not in ("missing_local", "missing_reference", "null_vs_value")
                         for d in field_differences(local, ref)):
                    # An explicit saved difference cannot be dismissed because
                    # the effective read omitted that setting.
                    state = "source_uncertain"
                elif canonical(local) == canonical(ref):
                    state = "identical"
                elif evidence and evidence["differences"] == [] and counts["matching"]:
                    state = "effective_match"
                elif evidence and counts["matching"] and counts["unavailable"]:
                    state = "partial_match"
                elif counts["unavailable"]:
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
                        inherited = profile_body(view["profiles"][identity])
                        inherited_fields = comparison_fields(evidence["comparison"] if evidence else row["effective"], inherited,
                                                             vlan=module == "layer2-vlan",
                                                             conflicts=evidence["conflicts"] if evidence else ())
                        comparison_counts = inherited_fields["counts"]
                        text = ("Observed differences" if comparison_counts["different"] else
                                "Conflicting observations" if comparison_counts["conflict"] else
                                "No observed differences" if comparison_counts["matching"] else "Insufficient evidence")
                        text += " · " + ", ".join(f"{comparison_counts[key]} {label}" for key, label in
                            (("matching", "match"), ("different", "different"), ("unavailable", "unavailable"), ("conflict", "conflict"))
                            if comparison_counts[key])
                    chain.append({"name": names[ancestor], "state": text, "kind": kind})
                ann = row.get("annotations", {})
                direct = ann.get("aruba-annotation:object_type") == "LOCAL" and ann.get("aruba-annotation:inherited") is False
                # Redundancy relative to Global is independent of write support.
                # Higher-scope differences and missing evidence affect removal,
                # not whether the captured device-local body matches Global.
                higher_exception = any(v.get("kind") != "global" and v["state"].startswith("Observed differences") for v in chain)
                inheritance_unknown = any(v["state"] in ("Membership unknown", "Cannot compare")
                                          or "unavailable" in v["state"] or v["state"].startswith(("Insufficient evidence", "Conflicting observations"))
                                          for v in chain)
                if higher_exception:
                    removal = "higher_scope_differs"
                elif state != "identical" or counts["unavailable"] or not direct or inheritance_unknown:
                    removal = "verification_required"
                else:
                    removal = "review_removal"
                fallback = nearest_fallback(entry, module, sid, identity, local, row["effective"], row.get("annotations", {}))
                if fallback["status"] == "matching_fallback" and state in ("different", "no_global", "global_unknown"):
                    state = "nearest_match"
                if fallback["status"] == "matching_settings_identity_changed":
                    state = "nearest_settings_match"
                    removal = "verification_required"
                elif fallback["status"] == "matching_fallback":
                    removal = "review_removal"
                elif fallback["status"] == "different_fallback":
                    removal = "higher_scope_differs"
                elif removal == "review_removal":
                    removal = "verification_required"
                findings.append({"device": sid, "device_name": names[sid], "module": module,
                                 "identity": identity, "result": state, "profile": row, "chain": chain,
                                 "direct_confirmed": direct, "evidence": evidence, "assessment": assessment,
                                 "candidate": state in ("identical", "nearest_match") and module in REUSABLE and direct,
                                 "review_candidate": state in ("identical", "effective_match", "partial_match", "nearest_match", "nearest_settings_match"),
                                 "fallback": fallback,
                                 "removal": removal,
                                 "safe_to_apply": False})
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
    device, module, result = query.get("device", ""), query.get("module", ""), query.get("result", "cleanup")
    if (device and device not in dict(devices)) or (module and module not in modules) or (result and result not in RESULTS and result != "cleanup"):
        raise ValueError("Unknown comparison filter")
    findings, incomplete = device_override_rows(bundle, persona)
    scoped = [f for f in findings if (not device or f["device"] == device) and (not module or f["module"] == module)]
    missing = [f for f in incomplete if (not device or f["device"] == device) and (not module or f["module"] == module)]
    counts = Counter(f["result"] for f in scoped)
    filters = scope_filter_form(root, "overrides", name, bundle, persona, (
        ("device", "Device", device, device_options),
        ("module", "Configuration", module, lambda entry: module_options(entry, "All modules", comparable=True))),
        submit="Compare with Global", extra_fields=(("result", "Result", result,
            [("cleanup", "Redundant and likely redundant"), ("", "All local definitions")] + list(RESULTS.items())),))
    short_action = {
        "identical": "Review redundant local copy",
        "nearest_match": "Review nearest-scope match",
        "nearest_settings_match": "Verify identity change",
        "effective_match": "Verify inheritance",
        "partial_match": "Potential cleanup; verify gaps",
        "omitted": "Not enough evidence",
        "protected": "Retain protected VLAN",
        "different": "Retain unless unnecessary",
        "no_global": "Review local definition",
        "global_unknown": "Validate Global",
        "source_uncertain": "Validate source",
    }
    rows = []
    for f in sorted(scoped, key=lambda f: (list(RESULTS).index(f["result"]), f["device_name"], f["module"], f["identity"])):
        if result == "cleanup":
            if not f["review_candidate"]:
                continue
        elif result and f["result"] != result:
            continue
        p = f["profile"]
        label = title_profile(f["identity"], p["local"])
        if f["module"] == "layer2-vlan":
            label = "VLAN " + label
        state = f["result"]
        next_step = NEXT_STEP[state]
        if f["review_candidate"]:
            if f["removal"] == "higher_scope_differs":
                next_step = "Keep for now: removing the local copy may expose a different higher-scope definition"
            elif f["removal"] == "verification_required":
                next_step += ". Removal still requires source, field and inheritance verification"
            else:
                next_step = "Remove the redundant local copy after checking the inherited source and dependencies"
        comparison = diff_table(p["global_differences"], "Device local", "Global")
        if f["module"] == "layer2-vlan" and p["global_reference"] is not None:
            comparison = vlan_explanation(p["local"], p["global_reference"], p["effective"], f["evidence"]) or comparison
        extra = ('<h3>Saved device settings</h3>' + property_table(p["local"])
                 + '<h3>Effective device settings in Central</h3>' + property_table(p["effective"])
                 + '<h3>Global settings</h3>' + property_table(p["global_reference"]))
        if f["module"] == "layer2-vlan":
            sources = [{"kind": "device", "scope": f["device"], "name": f["device_name"]}]
            extra += vlan_instance_context(bundle, persona, sources, f["identity"]) + operational_vlan_context(bundle, persona, sources, f["identity"])
        higher_differences = [v["name"] for v in f["chain"] if v["state"].startswith("Observed differences") and v.get("kind") != "global"]
        inheritance_warning = ('<p class="note"><strong>Higher-scope exception:</strong> observed differences at '
                               + e(", ".join(higher_differences)) + '. A Global match alone is not enough to remove this override.</p>') if higher_differences and f["fallback"]["status"] != "matching_fallback" else ""
        fallback = f["fallback"]
        fallback_html = '<h3>Expected fallback after removing device-local copy</h3>'
        if fallback["source"]:
            source = fallback["source"]
            fallback_html += '<p><strong>' + e(source["kind"].title() + " / " + source["name"]) + '</strong> · ' + e(fallback["status"].replace("_", " ")) + '</p>'
            fallback_html += diff_table(fallback["differences"], "Saved device", "Nearest higher scope") + property_table(source["body"])
        else:
            fallback_html += '<p>Cannot identify a direct higher-scope definition.</p>'
        fallback_html += table(("Precedence", "Scope", "Evidence"), [tr(e(v["kind"]), e(v.get("name") or "Unknown"), e(v["status"].replace("_", " "))) for v in fallback["chain"]])
        if fallback["blockers"]:
            fallback_html += "<ul>" + "".join("<li>" + e(v) + "</li>" for v in fallback["blockers"]) + "</ul>"
        fallback_html += '<p class="note">Observed candidate only. Verify assignment restoration, full field coverage and dependencies before any removal.</p>'
        detail = ('<div class="review-decision"><div>' + badge(RESULTS[state], "warn" if state in ("different", "omitted", "source_uncertain") else "info" if state in ("partial_match", "effective_match") else "neutral")
                  + '<p><strong>Next step:</strong> ' + e(next_step) + '.</p></div><div class="review-context"><small>Device</small><strong>'
                  + e(f["device_name"]) + '</strong></div></div>'
                  + inheritance_warning + fallback_html + comparison
                  + '<details><summary>Inheritance and higher scopes</summary>'
                  + table(("Scope", "Observed device vs scope settings"), [tr(e(v["name"]), e(v["state"])) for v in f["chain"]])
                  + '<p class="note">Scope membership does not establish inheritance precedence. Compare the actual inherited source and dependencies before removal.</p></details>'
                  + '<details><summary>Source evidence</summary>' + extra + raw(p) + '</details>')
        if f["candidate"]:
            detail += f'<p><a href="{url(root, "advisor", snapshot=name, finding="remove_override", module=f["module"], persona=persona, scope=f["device"], identity=f["identity"])}">Open matching consolidation preview</a></p>'
        action_label = short_action[state]
        if f["review_candidate"]:
            action_label = {"higher_scope_differs": "Keep: higher scope differs",
                            "verification_required": "Verify before removal",
                            "review_removal": "Remove redundant copy (review)"}[f["removal"]]
        counts_for_row = f["assessment"]["counts"]
        evidence_line = ""
        if p["global_reference"] is not None:
            evidence_line = '<small class="field-counts">' + " · ".join(
                f'{counts_for_row[key]} {label}' for key, label in (("matching", "match"), ("different", "different"),
                        ("unavailable", "unavailable"), ("conflict", "conflict")) if counts_for_row[key]) + '</small>'
        rows.append(tr(f'<strong>{e(f["device_name"])}</strong>',
                       f'<strong>{e(label)}</strong><small>{e(module_label(f["module"]))}</small>',
                       badge(RESULTS[state], "good" if state == "identical" else "warn" if state == "different" else "info" if state in ("partial_match", "effective_match") else "neutral")
                       + evidence_line + f'<small title="{e(next_step)}">{e(action_label)}</small>',
                       inspect(label, detail, "Compare settings")))
    result_summary = '<div class="result-summary" aria-label="Comparison results">' + "".join(
        f'<span><strong>{counts[key]}</strong> {e(label)}</span>' for key, label in (
            ("identical", "Global matches"), ("nearest_match", "nearest-scope matches"), ("nearest_settings_match", "identity changes"), ("effective_match", "effective matches"),
            ("partial_match", "likely redundant"), ("different", "different"), ("omitted", "insufficient evidence"), ("no_global", "no Global profile"),
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
    body = (intro("Device overrides", "Find device-local copies that match Global or the observed nearest higher-scope definition. Review genuine exceptions separately.", picker)
            + '<section class="worklist"><div class="worklist-controls">' + filters + '</div>'
            + '<div class="worklist-summary"><h2>Device-local configuration</h2>' + result_summary + '</div>'
            + '<p class="filter-hint">Global matches are not proof of redundancy. Nearest-scope matches use the observed precedence chain. Removal readiness is assessed separately.</p>'
            + table(("Device", "Profile / configuration", "Assessment", ""), rows, search=True, style="override-table")
            + f'<p class="filter-hint">{len(missing)} device/module reads unavailable. VLAN 1 is protected; device-only interfaces are excluded. Review only.</p></section>'
            + report)
    return page("Device overrides", body, workspace.nav(name))
