"""Task-oriented workspace screens. Analysis and write eligibility are unchanged."""
import json
from collections import Counter
from urllib.parse import urlencode

from .workspace_ui import (e, page, intro, metrics, snapshot_picker, module_label,
                          persona_label, pretty, status, badge, raw, table, tr, profile_state_label,
                          inspect, diff_table, property_table)


def load(workspace, query, title, route):
    from .config_app import audit_files
    root = "/" + workspace.token + "/"
    files = audit_files(workspace.directory)
    if not files:
        return None, page(title, intro(title) + '<section class="empty">No snapshots available. Connect from Overview.</section>', workspace.nav())
    name = query.get("snapshot", files[0].name)
    bundle = workspace.reviewed_snapshot(name)
    picker = snapshot_picker(root, route, files, name)
    from .filter_presets import preset_link
    try:
        picker += preset_link(root, name, route, query)
    except ValueError:
        pass  # An invalid preset selection must not change the existing page behavior.
    if bundle.get("collection_checkpoint", {}).get("mixed_capture_times"):
        picker += '<p class="note">Resumed collection: some scope evidence predates the final capture. Do not use this snapshot to verify remediation.</p>'
    return (root, name, bundle, picker), None


def url(root, route, **query):
    return e(root + route + "?" + urlencode(query))


def title_profile(identity, body):
    name = body.get("name") if isinstance(body, dict) else None
    if name and str(name) != str(identity):
        return f"{identity} · {name}"
    return str(identity)


def select(name, values, selected="", label=None):
    return f'<label>{e(label or pretty(name))}<select name="{e(name)}" id="{e(name)}">' + "".join(
        f'<option value="{e(key)}"{" selected" if key == selected else ""}>{e(value)}</option>'
        for key, value in values) + '</select></label>'


def scope_filter_form(root, route, snapshot, bundle, persona, fields, submit="Apply filters", extra_fields=()):
    """Single GET form; dependent selectors change locally with device function."""
    options_by_persona = {}
    for function, entry in sorted(bundle["results"].items()):
        options_by_persona[function] = {name: choices(entry) for name, _, _, choices in fields}
    controls = select("persona", [(p, persona_label(p)) for p in options_by_persona], persona, "Device function")
    for name, label, selected, _ in fields:
        controls += select(name, options_by_persona[persona][name], selected, label)
    for name, label, selected, choices in extra_fields:
        controls += select(name, choices, selected, label)
    return (f'<form class="filter-bar" method="get" action="{e(root + route)}" data-scope-filters="{e(json.dumps(options_by_persona))}">'
            f'<input type="hidden" name="snapshot" value="{e(snapshot)}">' + controls
            + f'<button type="submit">{e(submit)}</button>'
            + f'<a class="button reset-link" href="{url(root, route, snapshot=snapshot)}">Reset</a></form>')


def device_options(entry, placeholder="All devices"):
    return [("", placeholder)] + sorted(
        [(s["id"], s.get("name") or s["id"]) for s in entry["scopes"] if s["kind"] == "device"],
        key=lambda pair: pair[1].casefold())


def module_options(entry, placeholder="All modules", comparable=False):
    return [("", placeholder)] + sorted(
        [(m, module_label(m)) for m, data in entry["modules"].items()
         if not comparable or not data.get("device_scope_only")], key=lambda pair: pair[1].casefold())


def list_items(values, ordered=False):
    tag = "ol" if ordered else "ul"
    return f"<{tag}>" + "".join(f"<li>{e(v)}</li>" for v in values) + f"</{tag}>" if values else '<p class="muted">None observed.</p>'


# User-facing labels describe evidence and intent, not internal action codes.
ACTION_GUIDE = {
    "remove_override": ("Matches Global or nearest scope", "Local settings match Global or an observed nearest definition. Removal preview requires matching fallbacks for every source.", "Review actual inheritance before removing."),
    "promote_local": ("Repeated local profiles", "The same profile identity and settings occur at multiple scopes. Consider a common higher scope or a Library assignment.", "Choose where the shared configuration belongs."),
    "reuse_library": ("Matches Library", "An existing Library profile has the same identity and settings. Reuse it instead of maintaining another copy, if assignment and inheritance allow.", "Review assignment and removal of local copies."),
    "create_library": ("Optional Library placement", "A local definition could be reusable, but repeated use has not been established. Keeping it local may be appropriate.", "Leave local unless there is a reason to reuse it."),
    "conflict": ("Different definitions", "The same profile identity has different settings in the captured configuration. The difference may be intentional.", "Compare settings and retain intentional exceptions."),
    "default_review": ("VLAN settings to verify", "The VLAN comparison includes omitted fields, possible defaults or Layer 3 indicators. Equal network behavior is not established.", "Verify the differences before considering removal."),
    "unassigned_library": ("No assignment observed", "The captured assignment records contain no matching entry. This does not prove the profile is unused or safe to delete.", "Check references and intended future use; retain by default."),
}
OPPORTUNITIES = ("remove_override", "promote_local", "reuse_library")
SHORT_REASON = {
    "remove_override": "Global or nearest-scope match",
    "promote_local": "Identical settings at multiple scopes",
    "reuse_library": "Exact match with an existing profile",
    "create_library": "Reuse not established",
    "conflict": "Same identity, different settings",
    "default_review": "Defaults, omitted fields or Layer 3 state",
    "unassigned_library": "Assignment coverage not verified",
}
ASSESSMENT_LABELS = {
    "documented_default_candidate": "May equal documented default",
    "verify_multicast_default": "Verify multicast snooping behavior on this firmware",
    "verify_l3_state": "Check whether a routed VLAN interface exists",
    "unresolved_alias": "Check alternate API field",
    "unresolved_omission": "Meaning of omitted field not established",
    "explicit_difference": "Explicit setting difference",
}


def vlan_explanation(local, reference, effective=None, evidence=None):
    from .central_tool import comparison_fields
    from .workspace_ui import setting_value
    if local is None or reference is None:
        return ""
    if evidence is not None:
        local = evidence["local"]
        effective = evidence["comparison"]
    assessment = comparison_fields(effective, reference, vlan=True,
                                   conflicts=(evidence or {}).get("conflicts", ()), saved=local)
    comparisons = assessment["rows"]
    def observed_cell(body, path, source_key):
        value = body
        for key in path:
            if isinstance(value, dict) and key in value:
                value = value[key]
            elif isinstance(value, list) and isinstance(key, int) and 0 <= key < len(value):
                value = value[key]
            else:
                if (source_key == "comparison" and path[0] in ("igmp", "mld")
                        and (evidence or {}).get("feature_status", {}).get(path[0]) == "no_multicast_interfaces"):
                    return '<span class="muted">Unavailable</span><small>Layer 2 snooping not reported by Central</small>'
                return '<span class="muted">Not returned</span>' if source_key == "local" else '<span class="muted">Unavailable</span>'
        source = (evidence or {}).get('sources', {}).get(source_key + '.' + '.'.join(map(str, path)))
        if source is None and source_key == 'comparison':
            source = (evidence or {}).get('sources', {}).get('effective.' + '.'.join(map(str, path)))
        if isinstance(value, dict) and set(value) in ({"enable"}, {"snooping"}) and type(next(iter(value.values()))) is bool:
            value = next(iter(value.values()))
        if type(value) is bool:
            display = "Enabled" if value else "Disabled"
        elif value is None:
            display = "Unavailable"
        elif isinstance(value, str):
            display = value
        else:
            return setting_value(value) + (f'<small>{e(source)}</small>' if source else '')
        return e(display) + (f'<small>{e(source)}</small>' if source else '')
    def result_for(d):
        return {
            "matching": ("matching", "Match", "Observed value matches reference"),
            "different": ("different", "Different", "Observed value differs from reference"),
            "unavailable": ("unavailable", "Unavailable", "Cannot compare: value unavailable"),
            "conflict": ("conflict", "Conflict", "Check conflicting observations"),
        }[d["state"]]
    conflict = ('<p class="note">Conflicting observations: ' + e(', '.join(evidence['conflicts'])) + '. Resolve before changing configuration.</p>') if evidence and evidence['conflicts'] else ''
    labels = {"vlan": "VLAN ID", "name": "Name", "enable": "Administrative state",
              "voice-enable": "Voice VLAN", "igmp": "IGMP snooping", "mld": "MLD snooping",
              "dhcpv4-snooping": "DHCPv4 snooping", "dhcpv6-snooping": "DHCPv6 snooping",
              "is-l3-vlan": "Layer 3 VLAN"}
    def field_label(path):
        if len(path) == 1 or (len(path) == 2 and path[0] in labels and path[1] in ("enable", "snooping")):
            return labels.get(path[0], pretty(path[0]))
        return ".".join(map(str, path))
    rows = []
    unavailable_rows = []
    context_rows = []
    counts = assessment["counts"]
    priority = {"different": 0, "conflict": 1, "matching": 2, "unavailable": 3}
    ordered = sorted(comparisons, key=lambda d: (
        priority[result_for(d)[0]], list(labels).index(d["path"][0]) if d["path"][0] in labels else len(labels),
        tuple(map(str, d["path"]))))
    for d in ordered:
        kind, label, explanation = result_for(d)
        tone = {"matching": "good", "different": "warn", "conflict": "warn", "unavailable": "neutral"}[kind]
        result = f'<span class="tag {tone}" title="{e(explanation)}">{e(label)}</span>'
        # Operational context does not count toward comparable configuration.
        target = context_rows if d["path"][0] in ("vlan", "is-l3-vlan") else unavailable_rows if kind == "unavailable" else rows
        target.append(tr(e(field_label(d["path"])), observed_cell(local, d["path"], "local"),
                         observed_cell(effective, d["path"], "comparison"), observed_cell(reference, d["path"], "reference"),
                         result, attrs=f' data-comparison="{kind}"'))
    summary = '<div class="comparison-summary" aria-label="Comparison summary">' + "".join(
        badge(f"{counts[kind]} {label}", tone) for kind, label, tone in (
            ("different", "different", "warn"), ("conflict", "conflicting", "warn"),
            ("matching", "matching", "good"), ("unavailable", "unavailable", "neutral")) if counts[kind]) + '</div>'
    headers = ("Setting", "Saved locally", "Effective at source", "Global / reference", "Result")
    main = table(headers, rows, style="comparison-table") if rows else '<p class="empty">No verified configuration values to compare.</p>'
    gaps = (f'<details class="comparison-gaps"{" open" if not rows else ""}><summary>{len(unavailable_rows)} unavailable settings</summary>'
            + table(headers, unavailable_rows, style="comparison-table")
            + '<p class="note">Unavailable fields remain unverified; they are not assumed equal or disabled.</p></details>') if unavailable_rows else ""
    context = ('<details><summary>VLAN identity and operational context</summary>'
               + table(headers, context_rows, style="comparison-table") + '</details>') if context_rows else ""
    return summary + main + gaps + context + conflict + '<p class="note">Not returned: the saved local field was omitted. A named switch source indicates device evidence; otherwise the value is from Central configuration, not a live switch CLI measurement.</p>'


def vlan_instance_context(bundle, persona, sources, identity):
    """Keep instance-specific observations distinct from collection bodies."""
    evidence = bundle.get("vlan_instance_details", {}).get(persona, {})
    rows = []
    for source in sources:
        if source["kind"] != "device":
            continue
        details = evidence.get(source["scope"], {}).get(identity, {})
        for kind in ("local", "effective"):
            result = details.get(kind)
            if result is None:
                continue
            profile = result.get("profile", {})
            def value(key):
                return e(json.dumps(profile[key], ensure_ascii=False)) if key in profile else (
                    '<span class="muted">Not returned</span>' if result["status"] == "observed" else
                    '<span class="muted">Unavailable</span>')
            label = {"observed": "Read by ID", "source_unverified": "Local source not confirmed",
                     "request_rejected": "Request rejected", "permission_denied": "Access denied",
                     "schema_unresolved": "Response format not recognized", "read_failed": "Read failed"}.get(result["status"], pretty(result["status"]))
            rows.append(tr(e(source["name"]), "Saved locally" if kind == "local" else "Effective", value("name"), value("enable"),
                           e(label) + (f' (HTTP {e(result["http_error"])})' if "http_error" in result else ""),
                           raw(result, "Response")))
    if not rows:
        return '<p class="note">No targeted VLAN read by ID captured. Refresh to check omitted name or administrative state, if applicable.</p>'
    return ('<h3>Targeted VLAN reads by ID</h3>'
            + table(("Switch", "View", "VLAN name", "Administrative enable", "Read result", "Evidence"), rows)
            + '<p class="note">These are independent Central responses. If the values differ from the collection, review the discrepancy; the original snapshot and comparison are not overwritten. If both omit a field, its configured value is still unverified.</p>')


def operational_vlan_context(bundle, persona, sources, identity):
    from .central_tool import configuration_operational_vlan
    states = {"not_collected": "Not collected in this snapshot",
              "not_observed": "VLAN not observed in monitoring response",
              "permission_denied": "Monitoring access denied",
              "identity_unresolved": "Switch or VLAN identity could not be resolved",
              "request_rejected": "Monitoring request rejected",
              "monitoring_read_failed": "Monitoring read failed",
              "schema_unresolved": "Monitoring response not recognized"}
    observations = [(s["name"], configuration_operational_vlan(bundle, persona, s["scope"], identity))
                    for s in sources if s["kind"] == "device"]
    if not observations:
        return '<h3>Operational VLAN evidence</h3><p class="muted">No device source selected for operational comparison.</p>'
    rows = []
    for name, evidence in observations:
        fields = evidence.get("fields", {})
        def cell(key):
            if key not in fields:
                return '<span class="muted">Not returned</span>' if evidence["status"] == "observed" else '<span class="muted">Unavailable</span>'
            return e(fields[key]) if isinstance(fields[key], str) else e(json.dumps(fields[key], ensure_ascii=False))
        state = "Observed VLAN" if evidence["status"] == "observed" else states.get(evidence["status"], pretty(evidence["status"]))
        if evidence.get("may_be_truncated"):
            state += " (response may be incomplete)"
        rows.append(tr(e(name), cell("name"), cell("status"), cell("taggedPorts"), cell("untaggedPorts"),
                       e(state) + (f'<small>{e(evidence["captured_at"])}</small>' if evidence.get("captured_at") else "")))
    return ('<h3>Operational VLAN evidence</h3>'
            + table(("Switch", "Reported VLAN name", "Reported status", "Tagged ports", "Untagged ports", "Monitoring result"), rows)
            + '<p class="note">This is captured switch monitoring data, not a live CLI check. Reported status is not the same field as configured enable. It does not establish default semantics, multicast behavior or safe removal.</p>')


def enrich_advisor_findings(workspace,bundle,findings):
    from .bulk_review import source_recipient_evidence, source_recipient_index
    recipient_indexes = {}
    for finding in findings:
        persona = finding["persona"]
        entry = bundle["results"].get(persona)
        if entry:
            if persona not in recipient_indexes:
                recipient_indexes[persona] = source_recipient_index(entry)
            finding["recipient_evidence"] = source_recipient_evidence(entry, finding["sources"], index=recipient_indexes[persona])
        else:
            finding["recipient_evidence"] = {"known": [], "unknown": []}
    from .optimization_dependencies import attach_dependency_review
    attach_dependency_review(findings, workspace.advanced_snapshot(bundle)["references"])
    return findings


def advisor_export_evidence(workspace,query):
    """Return complete private evidence only for one exact selectable finding."""
    from .review_dispositions import snapshot_binding
    if set(query)!={"snapshot","group","binding"}:
        raise ValueError("Invalid advisor export selector")
    name=query["snapshot"]
    bundle=workspace.reviewed_snapshot(name)
    if snapshot_binding(workspace,name,bundle)!=query["binding"]:
        raise ValueError("Snapshot changed; reopen advisor")
    findings=[dict(f) for f in workspace.consolidation_snapshot(bundle)
              if f["id"]==query["group"] and f["action"] in OPPORTUNITIES and f["preview_selectable"]]
    if len(findings)!=1:
        raise ValueError("Unknown or blocked advisor finding")
    enrich_advisor_findings(workspace,bundle,findings)
    if snapshot_binding(workspace,name,bundle)!=query["binding"]:
        raise ValueError("Snapshot changed during advisor export")
    return findings[0]


def advisor_preview_payload(finding):
    """Keep exact gate inputs and summary counts, not repeated raw evidence."""
    fields=("id","identity","module","persona","action","target","sources","observed_devices",
            "placement_options","fallbacks","recipient_evidence","steps","blockers")
    payload={k:finding[k] for k in fields}
    evidence=finding["dependency_review"]
    dependencies=[]
    seen=set()
    for ref in evidence["dependencies"]:
        if (ref["status"] not in ("observed","definition_observed") or ref["target"] is None
                or ref.get("source_view") not in ("effective","library")
                or ref["source_module"]!=finding["module"] or ref["source"]!=finding["identity"]):
            continue
        key=(ref["persona"],ref["target_module"],ref["target"])
        if key not in seen:
            seen.add(key)
            dependencies.append(ref)
    payload["dependency_review"]={"dependencies":dependencies}
    payload["dependency_counts"]={
        "other":sum(len(evidence[k]) for k in ("other_function_consumers","other_function_dependencies","other_function_unresolved_targets")),
        "gaps":len(evidence["unqualified_edges"])+len(evidence["unresolved_target_observations"]),
        "nac":sum(r.get("source_evidence")=="nac_enforcement" for r in evidence["other_function_consumers"])}
    return payload


def advisor_view(workspace, query):
    loaded, empty = load(workspace, query, "Consolidation advisor", "advisor")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    from .review_dispositions import snapshot_binding
    binding = snapshot_binding(workspace, name, bundle)
    findings = [dict(f) for f in workspace.consolidation_snapshot(bundle)]
    if query.get("group"):
        findings = [f for f in findings if f["id"] == query["group"]]
    # Exact deep links from the device override inspector preserve the full group.
    scope_filter, identity_filter = query.get("scope"), query.get("identity")
    if scope_filter and identity_filter:
        findings = [f for f in findings if f["action"] == "remove_override"
                    and f["persona"] == query.get("persona") and f["module"] == query.get("module")
                    and f["identity"] == identity_filter and any(s["scope"] == scope_filter for s in f["sources"])]
    detail_only = query.get("detail") == "1"
    if detail_only and (not query.get("group") or len(findings) != 1 or query.get("binding") != binding):
        raise ValueError("Finding or snapshot changed; reopen the worklist")
    render_details = detail_only or bool(query.get("group") or (scope_filter and identity_filter))
    enrich_advisor_findings(workspace,bundle,findings)
    short = {key: value[0] for key, value in ACTION_GUIDE.items()}
    counts = Counter(f["action"] for f in findings)
    recommendation_options = [
        ("opportunities", f"Consolidation opportunities ({sum(counts[k] for k in OPPORTUNITIES)})"),
        ("review", f"Settings to review ({counts['conflict'] + counts['default_review']})"),
        ("optional", f"Optional Library review ({counts['create_library'] + counts['unassigned_library']})"),
        ("", f"All findings ({len(findings)})")] + [(k, f"{v[0]} ({counts[k]})") for k, v in ACTION_GUIDE.items()]
    selected_recommendation = query.get("finding", "opportunities")
    if selected_recommendation not in dict(recommendation_options):
        selected_recommendation = "opportunities"
    rows = []
    for f in findings:
        action = f["action"]
        sources = f["sources"]
        observed = f["observed_devices"]
        profile = title_profile(f["identity"], f["local"] or f["reference"])
        names = ", ".join(s["name"] for s in sources[:2])
        if len(sources) > 2:
            names += f" +{len(sources)-2}"
        summary = f'<strong>{e(profile)}</strong><small>{e(module_label(f["module"]))} · {e(persona_label(f["persona"]))}</small>'
        placement = e(f["target"] if action == "remove_override" or f.get("individual_conflicts") or f.get("blocked_destinations") else ACTION_GUIDE[action][2])
        if action == "promote_local" and f["preview_selectable"]:
            choices = [("", "Choose destination for review")]
            if not any(d["destination"] == "library" for d in f.get("blocked_destinations", [])):
                choices.append(("library", "Library / exact source scopes"))
            choices += [(p["scope"], f'{pretty(p["kind"])} / {p["name"]} · {len(p["additional_devices"])} extra ({len(p["additional_not_confirmed_matching"])} not confirmed matching), {len(p["unknown_membership"])} unknown')
                        for p in f["placement_options"]]
            placement = '<select class="destination" aria-label="Proposed destination">' + "".join(
                f'<option value="{e(key)}">{e(value)}</option>' for key, value in choices) + '</select>'
        if render_details:
            source_table = table(("Scope", "Type", "Finding"), [tr(e(s["name"]), e(pretty(s["kind"])), e(profile_state_label(s["status"]))) for s in sources]) if sources else '<p class="muted">Library definition.</p>'
            device_rows = [tr(e(d["name"]), status(k)) for k in ("matching", "different", "absent", "unknown") for d in observed.get(k, [])]
            scope_rows = [tr(e(s["name"]), e(pretty(s["kind"])), status(s["effective"])) for s in f["scope_references"]]
            placement_rows = [tr(e(p["name"]), e(pretty(p["kind"])), str(len(p["intended_devices"])),
                               str(len(p["additional_devices"])), str(len(p["additional_not_confirmed_matching"])), str(len(p["unknown_membership"])), status(p["effective"]))
                              for p in f["placement_options"]]
            reference_label = "Library" if action == "reuse_library" else "Nearest inherited" if action == "remove_override" and f["preview_selectable"] else "Global" if action in ("remove_override", "default_review") else "Reference"
            comparison = ""
            if action == "default_review":
                from .central_tool import vlan_comparison_evidence
                sections = []
                for source in sources:
                    if source["kind"] != "device":
                        continue
                    row = {"identity": f["identity"], "local": f["local"], "effective": f["local"],
                           "global_reference": f["reference"]}
                    evidence = vlan_comparison_evidence(bundle, f["persona"], source["scope"], row)
                    sections.append(f'<h3>{e(source["name"])}</h3>' + vlan_explanation(f["local"], f["reference"], f["local"], evidence))
                comparison = "".join(sections) or vlan_explanation(f["local"], f["reference"], f["local"])
            if not comparison:
                comparison = '<h3>Configuration comparison</h3>' + diff_table(f["differences"], "Local", reference_label)
            fallback_html = ""
            if f["fallbacks"]:
                fallback_html = '<h3>Expected inherited definition for each source</h3>' + table(("Source", "Nearest observed scope", "Result", "Blockers"), [tr(e(x["name"]), e((x.get("source") or {}).get("name", "Unavailable")), e(pretty(x["status"])), list_items(x["blockers"])) for x in f["fallbacks"]])
                for x in f["fallbacks"]:
                    if x.get("source"):
                        fallback_html += '<h4>' + e(x["name"]) + '</h4>' + diff_table(x.get("differences"), "Local", "Nearest higher scope")
                    for conflict in x.get("individual_conflicts", []):
                        fallback_html += '<h4>Conflicting individual evidence</h4><p>' + e(
                            str(conflict["scope"]) + " / " + str(conflict["identity"]) + " / " + conflict["view"]) + '</p>'
                        fallback_html += diff_table(conflict["differences"], "Collection", "Individual read")
            for conflict in f.get("individual_conflicts", []):
                fallback_html += '<h4>Conflicting individual evidence</h4><p>' + e(
                    str(conflict["persona"]) + " / " + str(conflict["scope"]) + " / " + conflict["view"]) + '</p>'
                fallback_html += diff_table(conflict["differences"], "Collection", "Individual read")
            for blocked in f.get("blocked_destinations", []):
                fallback_html += '<h4>Blocked destination: ' + e(blocked["name"]) + '</h4>'
                for conflict in blocked["individual_conflicts"]:
                    fallback_html += '<p>' + e(conflict["view"] + " / " + pretty(conflict["collection_presence"])) + '</p>'
                    fallback_html += diff_table(conflict["differences"], "Collection", "Individual read")
                for conflict in blocked.get("existing_definition_conflicts", []):
                    fallback_html += '<p>Existing definition must be retained: ' + e(conflict["existing_identity"]) + ' → proposed ' + e(conflict["proposed_identity"]) + '</p>'
                    fallback_html += diff_table(conflict["differences"], "Existing committed definition", "Proposed definition")
            dep = f["dependency_review"]
            dependency_rows = []
            for key, label in (("consumers", "Consumer"), ("dependencies", "Prerequisite"), ("unresolved_target_observations", "Unresolved target")):
                for ref in dep[key]:
                    dependency_rows.append(tr(e(label), e(ref["device"]), e(ref["source_module"] + " / " + str(ref["source"])),
                                              e(ref["target_module"] + " / " + str(ref["target"] or "Unknown")),
                                              badge(pretty(ref["status"]))))
            other_rows = []
            for key, label in (("other_function_consumers", "Same-name consumer"), ("other_function_dependencies", "Same-name prerequisite"),
                               ("other_function_unresolved_targets", "Unresolved target")):
                for ref in dep.get(key, []):
                    other_rows.append(tr(e(label), e(persona_label(ref["persona"])), e(ref["device"]),
                                         e(ref["source_module"] + " / " + str(ref["source"])),
                                         e(ref["target_module"] + " / " + str(ref["target"] or "Unknown")), badge(pretty(ref["status"]))))
            cross_context = ('<details><summary>Other device functions: ' + str(len(other_rows)) +
                             ' potential dependency observations</summary><p>Especially relevant for Library destinations. These are same-name or unresolved references, not proven consumers of this definition. They do not determine dependency order.</p>'
                             + table(("Relationship", "Function", "Scope", "Source", "Target", "Evidence"), other_rows, search=True) + '</details>') if other_rows else ""
            dependency_html = ('<h3>Observed dependencies</h3><p>' + str(dep["observed_consumer_devices"])
                               + ' effective consumer device/function pairs; ' + str(len(dep["unqualified_edges"]))
                               + ' unqualified edges; ' + str(len(dep["unresolved_target_observations"]))
                               + ' unresolved target observations. Same-name references may belong to another scope; no complete dependency claim.</p>'
                               + table(("Relationship", "Scope", "Source", "Target", "Evidence"), dependency_rows, search=True)
                               + cross_context
                               + f'<p><a href="{url(root, "impact", snapshot=name, module=f["module"], identity=f["identity"])}">Trace direct and transitive impact</a></p>')
            details = (
                f'<div class="review-decision"><div><strong>{e(f["target"] if action == "remove_override" else ACTION_GUIDE[action][2])}</strong><p>{e(ACTION_GUIDE[action][1])}</p></div></div>'
                + fallback_html + comparison + dependency_html
                + ('<h3>Destination impact</h3>' + table(("Destination", "Type", "Intended", "Additional", "Additional not confirmed matching", "Unknown", "Current"), placement_rows) if placement_rows else "")
                + '<h3>Proposed workflow</h3>' + list_items(f["steps"], ordered=True)
                + '<h3>Validation required</h3>' + list_items(f["blockers"])
                + '<details><summary>Affected scopes and devices</summary>' + source_table
                + ('<h3>Observed device configuration</h3>' + table(("Device", "Profile state"), device_rows) if device_rows else "")
                + ('<h3>Higher-scope configuration</h3>' + table(("Scope", "Type", "Effective body"), scope_rows) if scope_rows else "") + '</details>'
                + '<details><summary>Source evidence</summary>'
                + (vlan_instance_context(bundle, f["persona"], sources, f["identity"]) + operational_vlan_context(bundle, f["persona"], sources, f["identity"]) if f["module"] == "layer2-vlan" else "") + raw(f) + '</details>')
            if detail_only:
                return '<template data-advisor-evidence><div class="inspector-title"><h2>' + e(profile) + '</h2></div>' + details + '</template>'
            review_control = inspect(profile, details, "Review")
        else:
            endpoint = url(root, "advisor", snapshot=name, group=f["id"], detail="1", binding=binding)
            href = url(root, "advisor", snapshot=name, group=f["id"], finding=action)
            review_control = (f'<button class="quiet inspect-trigger" type="button" data-inspect data-inspect-url="{endpoint}">Review</button>'
                              f'<noscript><a href="{href}">Review</a></noscript>')
        matching = len(observed.get("matching", []))
        unknown = len(observed.get("unknown", []))
        device_summary = f'<strong>{matching} / {sum(len(v) for v in observed.values())}</strong>' + (f'<small>{unknown} not comparable</small>' if unknown else "") if observed else '<span class="muted">Not assessed</span>'
        # Filter by row metadata; the inspector and plan payload are inert.
        selectable = action in OPPORTUNITIES and f["preview_selectable"]
        readiness = ("destination" if selectable and action == "promote_local" else
                     "selectable" if selectable else "blocked" if action in OPPORTUNITIES else "review")
        readiness_text = {"destination": "Choose destination", "selectable": "Preview available",
                          "blocked": "Evidence blocks preview", "review": "Inspection only"}[readiness]
        # Inspection-only findings cannot enter selection() or preview export.
        # Keep only the fields required by the filtered CSV and row identity.
        plan = advisor_preview_payload(f) if selectable else {k: f[k] for k in ("id", "identity", "module", "persona", "action")}
        if not selectable:
            plan["sources"] = [{"name": source["name"]} for source in sources]
            plan["observed_counts"] = {key: len(values) for key, values in observed.items()}
        rows.append(tr(
            f'<input type="checkbox" class="choose" aria-label="Select {e(profile)}" data-plan="{e(json.dumps(plan, ensure_ascii=False))}"{" disabled" if not selectable else ""}>',
            summary, badge(short[action], "warn" if action in ("conflict", "default_review") else "info" if action in OPPORTUNITIES else "neutral") + f'<small>{e(SHORT_REASON[action])}</small><small><strong>{e(readiness_text)}</strong></small>',
            f'<strong>{len(sources)}</strong><small>{e(names or "Library definition")}</small>', placement, device_summary,
            review_control,
            attrs=f' data-readiness="{readiness}" data-source-count="{len(sources)}" data-action="{e(action)}" data-module="{e(f["module"])}" data-persona="{e(f["persona"])}" data-search="{e(profile+" "+str([s["name"] for s in sources]))}"'))
    filters = (
        '<div class="filter-bar advisor-filters">'
        + select("finding-type", recommendation_options, selected_recommendation, "Recommendation")
        + select("module", [("", "All modules")] + [(m, module_label(m)) for m in sorted({f["module"] for f in findings})], label="Module")
        + select("persona", [("", "All functions")] + [(p, persona_label(p)) for p in sorted({f["persona"] for f in findings})], label="Device function")
        + select("readiness", [("", "All findings"), ("preview", "Preview candidates"), ("blocked", "Evidence blocks preview"), ("review", "Inspection only")], label="Review readiness")
        + select("advisor-sort", [("", "Default recommendation order"), ("copies", "Most local copies first")], label="Sort")
        + '<label class="searchbox">Search<input id="search" type="search" placeholder="Profile or scope"></label>'
        '<button id="clear" type="button" class="quiet">Reset</button></div>')
    listing = '<div id="advisor-table">' + table(("Select", "Profile", "Why flagged", "Local copies", "Suggested next step", "Devices with identical settings", ""), rows) + '</div>'
    bar = ('<div class="selection-bar"><div><strong id="selected" aria-live="polite">0 selected</strong>'
           '<small id="hidden-selected" aria-live="polite"></small><small>Preview only · no Central writes</small></div><div class="selection-actions">'
           '<button id="select-visible" type="button">Select all filtered</button><button id="clear-selection" type="button">Clear</button>'
           '<button id="open-preview" type="button" class="primary" disabled>Review selected</button></div></div>')
    dialog = ('<dialog id="plan-dialog" class="inspector" aria-labelledby="plan-title"><div class="inspector-head"><h2 id="plan-title">Selected change preview</h2>'
              '<button id="close-preview" type="button">Close</button></div><div class="plan-content">'
              '<p class="note">These steps are not executable API operations. All writes require separate qualification and approval.</p>'
              '<div id="preview"></div><button id="export-plan" type="button" class="primary" disabled>Export private preview JSON</button>'
              '</div></dialog>')
    return page("Consolidation advisor", intro("Consolidation", "Choose a task, inspect the evidence, and prepare a change preview.", picker)
                + '<section><div id="snapshot-label" hidden data-snapshot="' + e(name) + '" data-binding="' + e(binding) + '" data-export-endpoint="' + e(root+"advisor-plan") + '"></div>'
                + filters + '<div class="table-toolbar"><span id="visible-count" class="muted" aria-live="polite"></span>'
                '<button id="advisor-export-csv" type="button" title="Export all recommendations matching the current filters, including other pages">Export filtered CSV</button>'
                '<div><button id="advisor-prev" type="button">Previous</button> <span id="advisor-page" class="muted"></span> '
                '<button id="advisor-next" type="button">Next</button></div></div>'
                + listing + '<p id="advisor-empty" class="empty" hidden>No matching recommendations.</p></section>'
                + bar + dialog + '<script>' + ADVISOR_JS + '</script>', workspace.nav(name), ADVISOR_CSS)


ADVISOR_CSS = """
.advisor-filters{margin-bottom:14px}.advisor-filters select{min-width:135px}.advisor-filters .searchbox{min-width:150px}
#advisor-table td:nth-child(2){min-width:145px}#advisor-table td:nth-child(5){max-width:290px;min-width:160px}
#advisor-table td:nth-child(5) select{width:100%;font-size:12px}
#advisor-table th:first-child{font-size:0;width:38px}.selection-bar{position:sticky;bottom:12px;z-index:3;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:14px 18px;background:var(--surface);border:1px solid var(--line);box-shadow:0 5px 24px #0002;border-radius:10px}
.selection-bar small{display:block}.selection-actions{display:flex;gap:8px;flex-wrap:wrap}.plan-content{flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:22px}.plan-item{padding:14px 0;border-bottom:1px solid var(--line)}.plan-item h3{margin:0 0 5px}.preview-metrics,.preview-transition{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:10px 0}.preview-metrics>div,.preview-transition>div,.preview-decision{border:1px solid var(--line);border-radius:9px;padding:12px;min-width:0;overflow-wrap:anywhere}.preview-metrics strong{font-size:24px}.preview-metrics small,.preview-transition small{display:block;color:var(--muted)}.preview-decision{background:var(--bg)}.preview-transition ul{padding-left:18px;margin-bottom:0}.plan-item p{margin:4px 0}.tabs button[aria-pressed=true]{border-bottom-color:var(--accent);color:var(--accent);font-weight:700}
"""
from .inheritance_review import ATOMIC as _ATOMIC_MODULES

ADVISOR_JS = r"""
(()=>{
'use strict';
const $=id=>document.getElementById(id), rows=Array.from($('advisor-table').querySelectorAll(':scope > .data-grid > .table-scroll > table > tbody > tr'));
const checks=rows.map(r=>r.querySelector('.choose'));
const categories={opportunities:['remove_override','promote_local','reuse_library'],review:['conflict','default_review'],optional:['create_library','unassigned_library']};
let page=0, filtered=[],exporting=false;const size=30;
function filter(reset=true){
 if(reset)page=0;
 const terms=$('search').value.toLowerCase().trim().split(/\s+/).filter(Boolean);
 const action=$('finding-type').value;
 const readiness=$('readiness').value;
 filtered=rows.filter(r=>(!action||(categories[action]?categories[action].includes(r.dataset.action):r.dataset.action===action))&&(!$('module').value||r.dataset.module===$('module').value)&&(!$('persona').value||r.dataset.persona===$('persona').value)&&(!readiness||(readiness==='preview'?['selectable','destination'].includes(r.dataset.readiness):r.dataset.readiness===readiness))&&terms.every(term=>(r.dataset.search+' '+r.textContent).toLowerCase().includes(term)));
 const ordered=$('advisor-sort').value==='copies'?rows.slice().sort((a,b)=>Number(b.dataset.sourceCount)-Number(a.dataset.sourceCount)):rows;
 const included=new Set(filtered);filtered=ordered.filter(r=>included.has(r));
 const tbody=rows[0]?.parentElement;
 if(tbody){const fragment=document.createDocumentFragment();for(const row of ordered)fragment.append(row);tbody.append(fragment);}
 const pages=Math.max(1,Math.ceil(filtered.length/size));page=Math.min(page,pages-1);
 const visible=new Set(filtered.slice(page*size,(page+1)*size));
 for(const r of rows)r.hidden=!visible.has(r);
 $('visible-count').textContent=filtered.length+' of '+rows.length+' recommendations';
 $('advisor-page').textContent=(page+1)+' / '+pages;$('advisor-prev').disabled=page===0;$('advisor-next').disabled=page+1>=pages;
 $('advisor-empty').hidden=filtered.length>0;
 $('advisor-export-csv').disabled=!filtered.length;
 $('advisor-prev').parentElement.hidden=pages<=1;
 updateHiddenSelection();
}
function updateHiddenSelection(){
 const included=new Set(filtered);
 const hidden=checks.filter(c=>c.checked&&!c.disabled&&!included.has(c.closest('tr'))).length;
 $('hidden-selected').textContent=hidden?hidden+' selected outside current filters':'';
}
function dependencyOrder(chosen){
 const byId=new Map(chosen.map(f=>[f.id,f]));
 const outgoing=new Map(chosen.map(f=>[f.id,new Set()]));
 const incoming=new Map(chosen.map(f=>[f.id,0]));
 const relationships=[];
 const seen=new Set();
 const matches=(f,ref)=>f.module===ref.target_module&&f.identity===ref.target&&
  (f.persona===ref.persona||ref.persona==='Library');
 for(const consumer of chosen){
  for(const ref of (consumer.dependency_review||{}).dependencies||[]){
   if(!['observed','definition_observed'].includes(ref.status)||ref.target==null||
      !['effective','library'].includes(ref.source_view))continue;
   if(ref.source_module!==consumer.module||ref.source!==consumer.identity)continue;
   for(const prerequisite of chosen){
    if(prerequisite.id===consumer.id||!matches(prerequisite,ref))continue;
    const key=JSON.stringify([prerequisite.id,consumer.id]);
    if(seen.has(key))continue;seen.add(key);
    outgoing.get(prerequisite.id).add(consumer.id);
    incoming.set(consumer.id,incoming.get(consumer.id)+1);
    relationships.push({prerequisite:prerequisite.id,consumer:consumer.id,evidence:ref});
   }
  }
 }
 const order=[];
 const ready=chosen.filter(f=>incoming.get(f.id)===0).map(f=>f.id);
 while(ready.length){
  const id=ready.shift();order.push(id);
  for(const next of outgoing.get(id)){
   incoming.set(next,incoming.get(next)-1);
   if(incoming.get(next)===0)ready.push(next);
  }
 }
 const blocked=chosen.filter(f=>!order.includes(f.id)).map(f=>f.id);
 return {order:[...order,...blocked],blocked,relationships,complete:false};
}
function bulkReview(chosen){
 const known=new Map(),unknown=new Map(),touches=new Map(),library=new Map(),recipientTouches=new Map(),fallbacks=[];
 const collisions=[],seen=new Set(),stages={prepare:[],verify:[],cleanup:[]};
 const missing=[];
 const key=(...parts)=>JSON.stringify(parts);
 const atomicModules=new Set(__ATOMIC_MODULES__);
 const touchIdentity=f=>atomicModules.has(f.module)?null:f.identity;
 function collision(a,b,message){
  if(a===b)return;
  const k=key(...[a,b].sort(),message);
  if(!seen.has(k)){seen.add(k);collisions.push({first:a,second:b,reason:message});}
 }
 function addTouch(map,k,f,message){
  if(!map.has(k))map.set(k,new Set());
  const ids=map.get(k);
  for(const id of ids)collision(id,f.id,message);
  ids.add(f.id);
 }
 function touch(k,f){
  addTouch(touches,k,f,'Overlapping source or destination profile or atomic module at the same scope');
 }
 function recipients(f,items,map){
  for(const d of items||[]){
   map.set(key(f.persona,d.scope),{persona:f.persona,...d});
   if(map===known)addTouch(recipientTouches,key(f.persona,f.module,touchIdentity(f),d.scope),f,'Selected proposals affect the same profile or atomic module at an observed device recipient');
  }
 }
 for(const f of chosen){
  const recipient=f.recipient_evidence||{};
  recipients(f,recipient.known,known);recipients(f,recipient.unknown,unknown);
  const scopeKey=s=>key(f.persona,f.module,touchIdentity(f),s);
  for(const source of f.sources)touch(scopeKey(source.scope),f);
  if(f.action==='promote_local'){
   const d=f.selected_destination;
   if(!d){missing.push(f.id);}
   else if(d.kind==='library'){
    const k=key(f.module,f.identity);
    addTouch(library,k,f,'Multiple proposals use the same Library identity; reconcile the target definition');
    stages.prepare.push({id:f.id,step:'Review Library definition and exact source-scope assignments'});
   }else{
    touch(scopeKey(d.scope),f);
    recipients(f,d.intended_devices,known);recipients(f,d.additional_devices,known);
    recipients(f,d.unknown_membership,unknown);
    stages.prepare.push({id:f.id,step:'Review destination scope and additional recipients'});
   }
  }else if(f.action==='reuse_library'){
   const k=key(f.module,f.identity);
   // Reuse/reuse alone is not a conflict, but a selected promotion to the
   // same Library identity must be reconciled before combining the work.
   if(library.has(k))for(const id of library.get(k))collision(id,f.id,'Selected Library reuse overlaps a proposed Library promotion');
   stages.prepare.push({id:f.id,step:'Verify existing Library definition and proposed assignments'});
  }
  for(const x of f.fallbacks||[]){
   if(x.source)fallbacks.push({id:f.id,key:scopeKey(x.source.scope)});
  }
  stages.verify.push({id:f.id,step:'Verify scope, assignments, references and expected effective settings'});
  stages.cleanup.push({id:f.id,step:'Review local removal only after preceding verification; capture fresh evidence'});
 }
 // Also detect reuse preceding promotion (selection order must not affect checks).
 for(const f of chosen)if(f.action==='reuse_library'){
  const k=key(f.module,f.identity);
  if(library.has(k))for(const id of library.get(k))collision(id,f.id,'Selected Library reuse overlaps a proposed Library promotion');
 }
 for(const f of fallbacks)if(touches.has(f.key))for(const id of touches.get(f.key))collision(id,f.id,'A selected proposal touches another proposal’s expected inherited definition');
 const dependency_order=dependencyOrder(chosen);
 const rank=new Map(dependency_order.order.map((id,i)=>[id,i]));
 for(const phase of ['prepare','verify'])stages[phase].sort((a,b)=>rank.get(a.id)-rank.get(b.id));
 stages.cleanup.sort((a,b)=>rank.get(b.id)-rank.get(a.id));
 return {known_recipients:[...known.values()],unknown_recipients:[...unknown.values()],collisions,missing_destinations:missing,stages,dependency_order,safe_to_apply:false};
}
function selection(){
 const chosen=checks.filter(c=>c.checked&&!c.disabled).map(c=>{
  const f=JSON.parse(c.dataset.plan), field=c.closest('tr').querySelector('.destination');
  if(field){
   const v=field.value;
   f.selected_destination=v==='library'?{kind:'library',assignment_scopes:f.sources.map(s=>s.scope)}:f.placement_options.find(p=>p.scope===v)||null;
   if(v==='library')f.target='Library / exact source scopes';
   else if(f.selected_destination)f.target=f.selected_destination.kind+' / '+f.selected_destination.name+' ('+f.selected_destination.additional_devices.length+' additional, '+f.selected_destination.unknown_membership.length+' unknown members)';
   else f.target='Destination not selected';
  }else if(f.action==='reuse_library'){
   f.selected_destination={kind:'library',assignment_scopes:f.sources.map(s=>s.scope),reuse_existing:true};
   f.target='Existing Library / exact source scopes';
  }
  return f;
 });
 $('selected').textContent=chosen.length+' selected';
 updateHiddenSelection();
 $('clear-selection').disabled=!chosen.length;
 $('open-preview').disabled=!chosen.length;
 const review=bulkReview(chosen);
 $('export-plan').disabled=exporting||!chosen.length||review.missing_destinations.length>0||review.collisions.length>0||review.dependency_order.blocked.length>0;
 return chosen;
}
function el(tag,text){const n=document.createElement(tag);n.textContent=text;return n;}
function preview(){
 const chosen=selection();$('preview').replaceChildren();
 const review=bulkReview(chosen);
 const summary=el('section','');
 summary.append(el('h3','Bulk review summary'));
 const cards=el('div','');cards.className='preview-metrics';
 for(const [value,label] of [[chosen.length,'Selected proposals'],[review.known_recipients.length,'Observed recipient pairs'],[review.unknown_recipients.length,'Uncertain recipient pairs']]){
  const card=el('div','');card.append(el('strong',String(value)),el('small',label));cards.append(card);
 }
 summary.append(cards,el('p','Counts include source recipients and selected destination impact. They are not a simulated deployment.'));
 const restrictions=[];
 if(review.missing_destinations.length)restrictions.push(review.missing_destinations.length+' missing destination selections');
 if(review.collisions.length)restrictions.push(review.collisions.length+' overlapping proposal conflicts');
 if(review.dependency_order.blocked.length)restrictions.push(review.dependency_order.blocked.length+' proposals with blocked dependency order');
 const decision=el('div','');decision.className='preview-decision';
 decision.append(el('strong',restrictions.length?'Resolve export blockers':'Review export available'),
  el('p',restrictions.length?restrictions.join(' · '):'You can export this private review plan. It is not an approved or executable change.'));
 summary.append(decision);
 const recipients=el('details','');recipients.append(el('summary','Review recipient evidence'));
 const recipientList=el('ul','');
 for(const d of review.known_recipients)recipientList.append(el('li',d.name+' ('+d.persona+') · known'));
 for(const d of review.unknown_recipients)recipientList.append(el('li',d.name+' ('+d.persona+') · uncertain membership'));
 recipients.append(recipientList);summary.append(recipients);
 if(review.collisions.length){
  summary.append(el('h3','Resolve overlapping proposals before exporting'));
  const list=el('ul','');
  const labels=new Map(chosen.map(f=>[f.id,f.module+' / '+f.identity+' ('+f.persona+')']));
  for(const c of review.collisions)list.append(el('li',labels.get(c.first)+' ↔ '+labels.get(c.second)+': '+c.reason));
  summary.append(list);
 }
 const dep=review.dependency_order;
 const labels=new Map(chosen.map(f=>[f.id,f.module+' / '+f.identity+' ('+f.persona+')']));
 summary.append(el('h3','Dependency-aware review order'),
  el('p',dep.relationships.length+' observed relationship(s) between selected profile identities. Prepare prerequisites before consumers; review cleanup in reverse order. Same-name evidence does not establish exact source identity.'));
 if(dep.relationships.length){
  const deps=el('ul','');
  for(const r of dep.relationships)deps.append(el('li',labels.get(r.prerequisite)+' before '+labels.get(r.consumer)+' · '+r.evidence.device));
  summary.append(deps);
 }
 if(dep.blocked.length){
  summary.append(el('h3','Dependency cycle or blocked order'),el('p','Review cyclic or dependent selections separately before exporting: '+dep.blocked.map(id=>labels.get(id)).join('; ')));
 }
 const phases=el('ol','');
 for(const [phase,items] of Object.entries(review.stages)){
  const li=el('li',({prepare:'Prepare destinations and assignments',verify:'Verify effective configuration and dependencies',cleanup:'Review local cleanup after validation'})[phase]+' ('+items.length+')');
  const sub=el('ul','');for(const task of items){const f=chosen.find(x=>x.id===task.id);sub.append(el('li',f.module+' / '+f.identity+': '+task.step));}li.append(sub);phases.append(li);
 }
 summary.append(phases);$('preview').append(summary);
 for(const f of chosen){
  const item=document.createElement('div');item.className='plan-item';
  item.append(el('h3',f.module+' / '+f.identity),el('p',({remove_override:'Review matching nearest inheritance',promote_local:'Consolidate repeated local profiles',reuse_library:'Reuse matching Library profile'}[f.action]||f.action)+' · '+f.target));
  const evidence=f.dependency_review||{};
  const {other=0,gaps=0,nac=0}=f.dependency_counts||{};
  if(gaps||nac||(other&&f.selected_destination?.kind==='library')){
   item.append(el('p',gaps+' unqualified or unresolved dependency observations; '+other+' other-function potential observations. Review the captured evidence before manual changes.'));
  }
  const flow=el('div','');flow.className='preview-transition';
  const before=el('div','');before.append(el('small','Captured configuration'),el('strong',f.sources.length+' local definition(s)'));
  const sourceNames=el('ul','');for(const source of f.sources)sourceNames.append(el('li',source.name+' ('+source.kind+')'));before.append(sourceNames);
  const after=el('div','');after.append(el('small','Proposed configuration source'),el('strong',f.target));
  if(f.action==='remove_override'){
   const fallbacks=el('ul','');for(const x of f.fallbacks||[])fallbacks.append(el('li',x.name+' → '+(x.source?.name||'Unknown source')));after.append(fallbacks);
  }else if(f.action==='promote_local'&&f.selected_destination&&f.selected_destination.kind!=='library'){
   const dest=f.selected_destination;
   after.append(el('p',dest.additional_devices.length+' additional recipients; '+dest.unknown_membership.length+' uncertain members.'));
   const notMatching=dest.additional_not_confirmed_matching||[];
   if(notMatching.length||dest.unknown_membership.length){
    const caution=el('div','');caution.className='preview-decision';
    caution.append(el('strong','Destination impact requires review'),
     el('p',notMatching.length+' additional recipients are not confirmed to have matching effective settings. This review choice may extend the configuration beyond the intended recipients.'));
    const list=el('ul','');
    for(const d of notMatching)list.append(el('li',d.name+' · not confirmed matching'));
    for(const d of dest.unknown_membership)list.append(el('li',d.name+' · uncertain membership'));
    caution.append(list);after.append(caution);
   }else if(!dest.additional_devices.length){
    after.append(el('p','Exact observed recipient set. Effective behavior still requires fresh verification.'));
   }else{
    after.append(el('p','Additional recipients have matching observed settings. This does not establish safe deployment.'));
   }
  }
  const goal=el('p','Expected goal: retain effective settings at intended recipients. Not a simulated or verified outcome.');
  flow.append(before,after);item.append(flow,goal);
  const steps=document.createElement('ol');for(const s of f.steps)steps.append(el('li',s));item.append(steps);
  const blockers=document.createElement('details');blockers.append(el('summary','Validation required ('+f.blockers.length+')'));
  const ul=document.createElement('ul');for(const b of f.blockers)ul.append(el('li',b));blockers.append(ul);item.append(blockers);$('preview').append(item);
 }
 if(chosen.some(f=>f.action==='promote_local'&&!f.selected_destination))$('preview').append(el('p','Select a destination for each consolidation recommendation before exporting.'));
}
for(const k of ['module','persona','finding-type','readiness','advisor-sort'])$(k).addEventListener('change',()=>filter());
$('search').addEventListener('input',()=>filter());
$('clear').addEventListener('click',()=>{$('finding-type').value='opportunities';$('module').value='';$('persona').value='';$('readiness').value='';$('advisor-sort').value='';$('search').value='';filter();});
$('advisor-prev').addEventListener('click',()=>{page--;filter(false);});$('advisor-next').addEventListener('click',()=>{page++;filter(false);});
for(const c of checks)c.addEventListener('change',selection);
for(const field of document.querySelectorAll('.destination'))field.addEventListener('change',selection);
$('select-visible').addEventListener('click',()=>{for(const r of filtered){const check=r.querySelector('.choose');if(!check.disabled)check.checked=true;}selection();});
$('clear-selection').addEventListener('click',()=>{for(const c of checks)c.checked=false;selection();});
$('open-preview').addEventListener('click',()=>{preview();$('plan-dialog').showModal();$('plan-dialog').querySelector('.plan-content').scrollTop=0;});
$('close-preview').addEventListener('click',()=>$('plan-dialog').close());
$('advisor-export-csv').addEventListener('click',()=>{
 function csvCell(value){
  let text=String(value??'');
  if(/^[\s\u0000-\u001f]*[=+\-@]/.test(text)||/^[\t\r\n]/.test(text))text="'"+text;
  return '"'+text.replaceAll('"','""')+'"';
 }
 const records=[['Finding ID','Profile','Module','Device function','Recommendation','Readiness','Local copies','Source scopes','Suggested next step','Devices matching','Device observations','Devices not comparable','Selected for preview']];
 for(const row of filtered){
  const check=row.querySelector('.choose'),f=JSON.parse(check.dataset.plan);
  const field=row.querySelector('.destination'),observed=f.observed_counts||Object.fromEntries(Object.entries(f.observed_devices||{}).map(([key,values])=>[key,values.length]));
  records.push([f.id,f.identity,f.module,f.persona,f.action,row.dataset.readiness,f.sources.length,f.sources.map(s=>s.name).join('; '),
   field?field.selectedOptions[0]?.textContent:row.cells[4].textContent.trim(),
   observed.matching??'',Object.keys(observed).length?Object.values(observed).reduce((n,v)=>n+v,0):'',observed.unknown??'',check.checked&&!check.disabled?'Yes':'No']);
 }
 const content='\uFEFF'+records.map(row=>row.map(csvCell).join(',')).join('\r\n');
 const u=URL.createObjectURL(new Blob([content],{type:'text/csv;charset=utf-8'})),a=document.createElement('a');
 a.href=u;a.download='central-consolidation-worklist.csv';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);
});
$('export-plan').addEventListener('click',async()=>{
 const chosen=selection();if($('export-plan').disabled)return;
 const snapshot=$('snapshot-label').dataset;
 const selection_manifest={schema:1,kind:'consolidation_selection',snapshot:snapshot.snapshot,snapshot_binding:snapshot.binding,
  selections:chosen.map(f=>({id:f.id,destination:f.action==='promote_local'?(f.selected_destination.kind==='library'?'library':f.selected_destination.scope):null}))};
 exporting=true;selection();
 try{
  const full=[];
  for(const selected of chosen){
   const params=new URLSearchParams({snapshot:snapshot.snapshot,binding:snapshot.binding,group:selected.id});
   const response=await fetch(snapshot.exportEndpoint+'?'+params,{cache:'no-store'});
   if(!response.ok)throw Error('Unavailable evidence');
   const record=await response.json();
   if(record.id!==selected.id||record.preview_selectable!==true)throw Error('Changed evidence');
   full.push({...record,target:selected.target,...(selected.selected_destination?{selected_destination:selected.selected_destination}:{})});
  }
  const review=bulkReview(full);
  if(review.missing_destinations.length||review.collisions.length||review.dependency_order.blocked.length)throw Error('Review gates changed');
  const content=JSON.stringify({schema:1,kind:'consolidation_preview',safe_to_apply:false,snapshot:snapshot.snapshot,selection_manifest,bulk_review:review,recommendations:full},null,2);
  const u=URL.createObjectURL(new Blob([content],{type:'application/json'})),a=document.createElement('a');a.href=u;a.download='consolidation-preview.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);
 }catch(_){
  const message=el('p','Full review evidence is unavailable or changed. Reopen the advisor and review the selection again.');
  message.setAttribute('role','alert');$('preview').append(message);
 }finally{exporting=false;selection();}
});
filter();selection();
})();
""".replace("__ATOMIC_MODULES__", json.dumps(sorted(_ATOMIC_MODULES)))


def usage_cells(usage):
    assignments = (str(usage["assignment_count"]) if usage["assignment_status"] == "response_received" else "Unknown")
    return (e(assignments), str(len(usage["shared_devices"])), str(usage["reference_count"]),
            str(len(usage["unknown_devices"])))


def usage_detail(usage, *, root=None, snapshot=None, module=None):
    from .library_usage_presentation import visibility_detail_link
    return ('<h3>Observed usage</h3>'
            + table(("Measure", "Count"), [
                tr("Distinct scope/function assignments", usage_cells(usage)[0]),
                tr("Devices with matching shared profile", usage_cells(usage)[1]),
                tr("Distinct configuration objects referencing this name", usage_cells(usage)[2]),
                tr("Saved definitions referencing this name", str(usage.get("definition_reference_count", 0))),
                tr("Effective objects referencing this name", str(usage.get("effective_reference_count", 0))),
                tr("Conditional NAC enforcement observations", str(usage.get("conditional_nac_observations",0))),
                tr("Conflicting individual reference observations", str(usage.get("conflicting_reference_count", 0))),
                tr("Individual Library definition conflict", "Yes" if usage.get("library_individual_conflict") else "Not observed"),
                tr("Device/function pairs with contradictory profile evidence", str(len(usage.get("individual_conflict_devices", [])))),
                tr("Devices with incomplete module reads", usage_cells(usage)[3]),
                tr("Devices with matching settings but unverified Library source", str(len(usage["matching_other_devices"])))])
            + '<h3>Assigned at</h3>' + table(("Scope", "Device function"), [
                tr(e(a.get("scope-name", a.get("scope-id", "Unknown"))), e(persona_label(a.get("device-function", "")))) for a in usage["assignments"]])
            + visibility_detail_link(usage, root=root, snapshot=snapshot, module=module)
            + '<h3>Configuration references</h3>' + table(("Source scope", "View", "Module", "Object", "Field", "Evidence"), [
                tr(e(r["device"]), e(pretty(r.get("source_view", "effective"))), e(module_label(r["source_module"])), e(r["source"]), e(".".join(map(str, r.get("path", [])))),
                   badge("Conflicting observation", "warn") if r.get("collection_conflict") else e("Conditional NAC candidate" if r.get("source_evidence")=="nac_enforcement" else "Individual read" if r.get("source_evidence") == "individual" else "Collection")) for r in usage["references"]])
            + '<p class="note">These are separate observations, not traffic usage. Zero observed references does not prove a profile is unused. Reference coverage is incomplete.</p>')


def port_group_label(settings):
    """Describe only captured portable configuration, without guessing port role."""
    switchport = settings.get("switchport", {})
    if not isinstance(switchport, dict):
        return "Shared port settings"
    parts = []
    for key, label in (("mode", "Mode"), ("access-vlan", "Access VLAN"),
                       ("native-vlan", "Native VLAN"), ("trunk-allowed-vlans", "Allowed VLANs"),
                       ("allowed-vlans", "Allowed VLANs"), ("vlan-mode", "VLAN mode")):
        value = switchport.get(key)
        if type(value) in (str, int) and str(value):
            parts.append(f"{label} {value}")
        elif isinstance(value, list) and value and all(type(item) in (str, int) for item in value):
            parts.append(f"{label} " + ", ".join(map(str, value[:4])) + (f" +{len(value)-4}" if len(value) > 4 else ""))
    return " · ".join(parts) or "Shared switchport settings"


def port_dependency_rows(record):
    """Deduplicate actual port dependency observations, keeping unresolved paths."""
    unique = {}
    for r in record.get("dependencies", []):
        key = (r["scope"], r["source"], r["target_module"], r["target"], tuple(r["path"]) if r["target"] is None else ())
        unique.setdefault(key, r)
    return list(unique.values())


def reference_worklist(workspace, root, name, bundle, query, records, workflow):
    """Bound the rendered worklist and load exact snapshot-bound evidence on demand."""
    from .review_dispositions import snapshot_binding, digest
    from .history_view import private_export
    binding = digest([snapshot_binding(workspace, name, bundle), workflow])
    params = {"snapshot": name, "workflow": workflow}
    if query.get("reference_detail") is not None:
        if query.get("binding") != binding:
            raise ValueError("Reference evidence changed; reopen the worklist")
        try:
            index = int(query["reference_detail"])
        except (ValueError, TypeError):
            raise ValueError("Invalid reference evidence selector") from None
        if not 0 <= index < len(records):
            raise ValueError("Unknown reference evidence")
        return '<template data-advisor-evidence><div class="inspector-title"><h2>Reference evidence</h2></div>' + property_table(records[index]) + '</template>'
    states = sorted({r["status"] for r in records})
    personas = sorted({r["persona"] for r in records})
    modules = sorted({r["target_module"] for r in records})
    state, persona, module, keyword = (query.get(k, "") for k in ("ref_state", "ref_persona", "ref_module", "ref_q"))
    if state not in ("", *states) or persona not in ("", *personas) or module not in ("", *modules) or len(keyword) > 200:
        raise ValueError("Invalid reference filter")
    terms = keyword.casefold().split()
    fields = ("device", "persona", "scope", "source_view", "source_module", "source",
              "target_module", "target", "status", "target_evidence", "path")
    selected = [(i, r) for i, r in enumerate(records)
                if (not state or r["status"] == state) and (not persona or r["persona"] == persona)
                and (not module or r["target_module"] == module)
                and all(term in " ".join(str(r.get(k, "")) for k in fields).casefold() for term in terms)]
    filters = {**params, "ref_state": state, "ref_persona": persona, "ref_module": module, "ref_q": keyword}
    if query.get("reference_export") == "1":
        if query.get("binding") != binding:
            raise ValueError("Reference evidence changed; reopen the worklist")
        return page("Private reference report", intro("Private reference report", "All observations matching the current filters, not a complete dependency graph.")
                    + private_export("reference-review", {"selection": filters, "references": [r for _, r in selected],
                                     "complete": False, "safe_to_apply": False}), workspace.nav(name))
    try:
        offset = int(query.get("ref_offset", "0"))
    except (ValueError, TypeError):
        raise ValueError("Invalid reference page") from None
    if offset < 0 or offset % 50 or (offset and offset >= len(selected)):
        raise ValueError("Invalid reference page")
    controls = (f'<form method="get" class="filter-bar" action="{e(root+"advanced")}">'
                + "".join(f'<input type="hidden" name="{e(k)}" value="{e(v)}">' for k,v in params.items())
                + select("ref_state", [("", "All states")] + [(v, pretty(v)) for v in states], state, "State")
                + select("ref_persona", [("", "All functions")] + [(v, persona_label(v)) for v in personas], persona, "Function")
                + select("ref_module", [("", "All target modules")] + [(v, module_label(v)) for v in modules], module, "Target module")
                + f'<label>Search all observations<input name="ref_q" maxlength="200" value="{e(keyword)}"></label>'
                + '<button type="submit">Filter</button></form>')
    controls += f'<p>Showing {offset+1 if selected else 0}–{min(len(selected),offset+50)} of {len(selected)} matching observations ({len(records)} in this workflow). '
    for label, position in (("Previous", offset-50), ("Next", offset+50)):
        if 0 <= position < len(selected):
            controls += f'<a class="button" href="{url(root,"advanced",**filters,ref_offset=position)}">{label}</a> '
    controls += f'<a class="button" href="{url(root,"advanced",**filters,reference_export="1",binding=binding)}">Export all matching private JSON</a></p>'
    rows = []
    for index, r in selected[offset:offset+50]:
        detail_url = url(root, "advanced", **params, reference_detail=index, binding=binding)
        control = f'<button class="quiet inspect-trigger" type="button" data-inspect data-inspect-url="{detail_url}">Inspect</button>'
        rows.append(tr(e(r["device"]), e(persona_label(r["persona"])),
                       f'{e(module_label(r["source_module"]))}<small>{e(r["source"])}</small>',
                       f'{e(module_label(r["target_module"]))}<small>{e(r["target"] if r["target"] is not None else "Unknown")}</small>',
                       status(r["status"]) + (f'<small>{e(pretty(r["target_evidence"]))}</small>' if r.get("target_evidence") else ""),
                       e("Keep reference; verify before profile removal" if r["status"] in ("observed","definition_observed") else
                         "Verify target profile and scope" if r["status"] == "not_observed" else "Collect or interpret missing reference evidence"), control))
    return controls + table(("Source scope", "Function", "Source", "Target", "State", "Suggested next step", ""), rows)


def engineering_view(workspace, query):
    from .advanced_review import library_usage, preferred_duplicate
    from .central_tool import field_differences
    loaded, empty = load(workspace, query, "Engineering review", "advanced")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    data = workspace.advanced_snapshot(bundle)
    reference_rows = {"references": [], "resolved": []}
    for ref in data["references"]:
        key = "resolved" if ref["status"] in ("observed", "definition_observed") else "references"
        reference_rows[key].append(ref)
    if "reference_detail" in query or "reference_export" in query:
        workflow = query.get("workflow")
        if workflow not in reference_rows:
            raise ValueError("Unknown reference workflow")
        return reference_worklist(workspace, root, name, bundle, query, reference_rows[workflow], workflow)
    # Group the same winning/higher scope and bodies across devices instead of repeating rows.
    grouped = {}
    from .central_tool import canonical
    for rec in data["shadowed"]:
        key = (rec["persona"], rec["module"], rec["identity"], rec["winning_scope_id"], rec["higher_scope_id"],
               canonical(rec["effective"]), canonical(rec["higher_body"]))
        grouped.setdefault(key, []).append(rec)
    variants = workspace.policy_snapshot(bundle, 'variants')
    rules = workspace.policy_snapshot(bundle, 'rules')
    counts = {"ports": len(data["port_groups"]), "shadow": len(grouped), "variants": len(variants),
              "rules": len(rules), "duplicates": len(data["library_duplicates"]),
              **{key: len(rows) for key, rows in reference_rows.items()}}
    selected = query.get("workflow", "")
    if selected not in counts:
        selected = next((key for key in ("duplicates", "ports", "shadow", "references", "variants", "rules", "resolved") if counts[key]), "ports")
    from .optimization_worklist import engineering_group_id
    selected_group = query.get("group", "")
    from .review_dispositions import snapshot_binding
    binding = snapshot_binding(workspace, name, bundle)
    detail_only = query.get("detail") == "1"
    if detail_only and (selected not in ("duplicates", "ports") or not selected_group or query.get("binding") != binding):
        raise ValueError("Finding or snapshot changed; reopen the worklist")
    def review_button(workflow, record, label, action):
        group = engineering_group_id(workflow, record)
        href = url(root, "advanced", snapshot=name, workflow=workflow, group=group)
        detail_url = url(root, "advanced", snapshot=name, workflow=workflow, group=group, detail="1", binding=binding)
        return (f'<button type="button" class="secondary" data-inspect data-inspect-url="{detail_url}">{e(action)}</button>'
                f'<noscript><a href="{href}">{e(label)}: {e(action)}</a></noscript>')
    panels = []
    def panel(key, label, hint, headers, rows, count):
        content = (f'<section data-panel="{key}" data-group="engineering"><p class="filter-hint">{e(hint)}</p>'
                   + table(headers, rows, search=True) + '</section>') if key == selected else ""
        panels.append((key, label, count, content))
    rows = []
    if selected == "ports":
        for record in sorted(data["port_groups"], key=lambda r: (-len(r["ports"]), r["persona"])):
            if selected_group and engineering_group_id("ports", record) != selected_group:
                continue
            ports = record["ports"]
            matches = record.get("matching_library_profiles", [])
            devices = sorted({p["device"] for p in ports})
            settings = record["portable_settings"]
            label = port_group_label(settings)
            dependencies = port_dependency_rows(record)
            unresolved = sum(r["status"] != "observed" for r in dependencies)
            match_usage = library_usage(bundle, "sw-port-profiles", [m["identity"] for m in matches], data["references"])
            preferred = preferred_duplicate(match_usage) if len(match_usage) > 1 else next(iter(match_usage), None)
            library_available = record["library_status"] == "list_parsed"
            target = preferred or ("Choose matching profile" if matches else "New profile candidate" if library_available else "Library unavailable")
            action = ("Review unsupported settings first" if record["unsupported_fields"] else
                      "Verify saved port configuration" if any(v["status"] != "exact_saved_effective_match" for v in record["conversion_review"]) else
                      "Resolve dependency evidence" if unresolved else
                      "Review existing profile assignment" if matches else
                      "Review a new reusable profile" if library_available else "Retrieve Library definitions first")
            device_summary = Counter(p["device"] for p in ports)
            if selected_group:
                visibility = []
                for match in matches:
                    visibility_counts = Counter(v["status"] for v in match["visibility"])
                    visibility.append(tr(e(match["identity"]), *usage_cells(match_usage[match["identity"]]),
                                         e(f'{visibility_counts["matching"]}/{len(devices)} matching; {visibility_counts["unknown"]} unknown')))
                mapping = table(("Device", "Port", "Description", "Proposed profile"), [
                    tr(e(p["device"]), e(p["port"]), e(p.get("description") or "—"),
                       '<span data-port-target>' + e(preferred or "Not selected") + '</span>') for p in ports], search=len(ports) > 30)
                conversion = record["conversion_review"]
                conversion_rows = []
                for item in conversion:
                    detail = ('<h3>Saved port settings</h3>' + property_table(item["saved"])
                              + '<h3>Effective port settings</h3>' + property_table(item["effective"])
                              + '<h3>Shared fields to review</h3>' + list_items(item["proposed_shared_fields"])
                              + '<h3>Saved fields to retain locally</h3>' + property_table(item["retained_local_fields"])
                              + '<h3>Saved shared settings versus candidate</h3>' + diff_table(item["saved_vs_shared"], "Saved", "Candidate"))
                    conversion_rows.append(tr(e(item["device"]), e(item["port"]), badge(pretty(item["status"])),
                                              e(", ".join(item["proposed_shared_fields"]) or "None observed"),
                                              e(", ".join(item["retained_local_fields"]) or "None observed"),
                                              inspect(item["port"], detail, "Compare")))
                conversion_table = table(("Device", "Port", "Saved evidence", "Shared field candidates", "Retain locally", ""), conversion_rows, search=True)
                chooser = ""
                if matches:
                    chooser = ('<label>Profile to review<select data-port-profile aria-label="Profile to review">'
                               + '<option value="">Choose matching profile</option>' + "".join(
                                   f'<option value="{e(m["identity"])}"{" selected" if m["identity"] == preferred else ""}>{e(m["identity"])}</option>'
                                   for m in matches) + '</select></label>')
                details = ('<div class="review-decision"><div><strong>' + e(action) + '</strong><p>Preserve every port identity and description. This is a review preview, not an executable change.</p></div></div>'
                           + '<div class="comparison-summary">' + badge(f"{len(ports)} ports", "info") + badge(f"{len(devices)} devices", "neutral")
                           + (badge(f"{unresolved} unresolved dependencies", "warn") if unresolved else badge(f"{len(dependencies)} observed dependencies", "neutral")) + '</div>'
                           + '<h3>Shared configuration</h3>' + property_table(settings)
                           + ('<h3>Matching Library profiles</h3>' + table(("Profile", "Assignments", "Shared devices", "References", "Unknown reads", "Visibility on affected devices"), visibility) if matches else
                              '<p class="note">' + e("No exact Library match in captured profiles." if library_available else "Library coverage unavailable; an existing profile may be present.") + '</p>')
                           + '<div data-port-review><h3>Proposed port mapping</h3>' + chooser + mapping
                           + '<h3>Per-port conversion evidence</h3><p>These fields are candidates for review, not instructions to delete them. Saved/effective differences or unsupported settings require separate validation.</p>'
                           + conversion_table + '</div>'
                           + ('<h3>Unsupported fields</h3>' + list_items(record["unsupported_fields"]) if record["unsupported_fields"] else "")
                           + ('<details' + (' open' if unresolved else '') + '><summary>Port dependencies</summary>' +
                              table(("Device", "Port", "Target", "Evidence"), [tr(e(r["device"]), e(r["source"]),
                                  e(module_label(r["target_module"]) + " / " + str(r["target"] if r["target"] is not None else "Unresolved")), status(r["status"]))
                                  for r in sorted(dependencies, key=lambda r: r["status"] == "observed")], search=len(dependencies) > 30) + '</details>' if dependencies else '<p class="note">No dependencies observed; reference coverage is incomplete.</p>')
                           + '<details><summary>Validation required</summary>' + list_items(record.get("blockers", [])) + '</details>' + raw(record))
                control = inspect(label, details, "Review mapping")
                if detail_only:
                    return control.replace("<template>", '<template data-advisor-evidence>', 1)
            else:
                control = review_button("ports", record, label, "Review mapping")
            device_names = ", ".join(f"{dev} ({device_summary[dev]})" for dev in devices[:2])
            if len(devices) > 2:
                device_names += f" +{len(devices)-2} more"
            rows.append(tr(f'<strong>{e(label)}</strong><small>{e(persona_label(record["persona"]))}</small>',
                           f'<strong>{len(ports)} ports</strong><small>{e(device_names)}</small>',
                           f'<strong>{e(target)}</strong>' + (f'<small>{len(matches)} matching Library profiles</small>' if matches else ""),
                           badge(action, "warn" if record["unsupported_fields"] or unresolved or not library_available else "info"),
                           control))
    panel("ports", "Port consolidation", "Review shared settings, choose a reusable profile and verify port mappings and dependencies.",
          ("Shared configuration", "Affected ports", "Proposed target", "Next step", ""), rows, counts["ports"])
    rows = []
    if selected == "shadow":
        for members in grouped.values():
            r = members[0]
            same = r["relationship"] == "same_body"
            why = ("The applied profile has identical settings to the higher-scope profile. The lower-scope definition may be redundant, but removing it could expose a different intermediate definition."
                   if same else "The applied profile takes precedence over a different higher-scope profile. This is normal inheritance behavior and may be intentional.")
            details = '<h3>Why this appears</h3><p>' + e(why) + '</p><h3>Applied vs higher-scope settings</h3>' + diff_table(field_differences(r["effective"], r["higher_body"]), "Applied configuration", "Higher scope") + '<h3>Devices using the applied definition</h3>' + list_items([v["device"] for v in members]) + '<p class="note">Do not remove the higher-scope profile merely because it is overridden on these devices. Other devices may still depend on it.</p>' + raw(members)
            if r["winning_scope_kind"] == "device":
                details += f'<p><a href="{url(root, "overrides", snapshot=name, persona=r["persona"], device=r["scope"], module=r["module"])}">Compare this device with Global</a></p>'
            rows.append(tr(f'<strong>{e(title_profile(r["identity"], r["effective"]))}</strong><small>{e(module_label(r["module"]))}</small>',
                           e(r["winning_scope"]), e(r["higher_scope"]), str(len({v["scope"] for v in members})),
                           badge("Identical settings" if same else "Different settings", "neutral"),
                           e("Review lower-scope redundancy" if same else "Retain if intentional"), inspect(r["identity"], details)))
    panel("shadow", "Scope precedence", "Shows which configuration takes precedence over a higher-scope definition. This is normal inheritance, not necessarily a problem. Identical definitions may warrant reviewing the lower-scope copy; do not delete the higher-scope profile.",
          ("Profile", "Applied from", "Higher-scope definition", "Devices", "Settings compared", "Suggested next step", ""), rows, counts["shadow"])
    rows = []
    if selected == "variants":
        for finding in variants:
            variants = finding["variants"]
            detail = '<p>The largest observed variant is a comparison reference only; it is not automatically an approved standard.</p>'
            for i, variant in enumerate(variants, 1):
                detail += '<h3>Variant ' + str(i) + ' · ' + str(len(variant["devices"])) + ' devices</h3>' + property_table(variant["body"])
                if variant["differences"]:
                    detail += diff_table(variant["differences"], "Largest variant", "This variant")
                detail += table(("Device", "Source evidence"), [tr(e(d["name"]), f'<a href="{url(root, "sources", snapshot=name, persona=finding["persona"], device=d["scope"], module=finding["module"], identity=finding["identity"])}">Trace source</a>') for d in variant["devices"]])
            distributions = finding.get("membership_distribution",{})
            detail += '<h3>Observed membership distribution</h3><p>Multiple variant numbers in one scope indicate mixed settings within that observed membership; a single variant does not establish approved policy or intentional exceptions.</p>'
            detail += table(("Membership type","Scope","Observed variants"),[
                tr(e(pretty(kind)),e(r["name"]),e(", ".join(map(str,r["variant_numbers"]))))
                for kind,records in distributions.items() for r in records])
            if finding.get("individual_conflicts"):
                detail += '<h3>Contradictory individual profile evidence</h3><p>These devices are excluded from qualified variant and absence counts.</p>'
                detail += table(("Device","Evidence"),[
                    tr(e(r["name"]),raw(r)) for r in finding["individual_conflicts"]],search=True)
            detail += '<h3>Confirmed absent</h3>' + list_items([d["name"] for d in finding["absent"]])
            detail += '<h3>Unavailable or unqualified presence</h3>' + list_items([d["name"] for d in finding["unknown"]])
            rows.append(tr(e(module_label(finding["module"])), e(finding["identity"]), e(persona_label(finding["persona"])),
                           str(len(variants)), str(finding["present_count"]), str(len(finding["unknown"])) + (f'<small>{len(finding["individual_conflicts"])} conflicting</small>' if finding.get("individual_conflicts") else ""),
                           badge(pretty(finding["status"])), inspect(finding["identity"], detail, "Compare variants")))
    panel("variants", "Policy variants", "Review same-name effective profiles with different captured settings within the same device function. These may be intentional site or device differences, not necessarily policy conflicts.",
          ("Module", "Profile", "Function", "Variants", "Observed devices", "Unknown presence", "Evidence", ""), rows, counts["variants"])
    rows = []
    if selected == "rules":
        for finding in rules:
            observations = finding["findings"]
            detail = '<p>Captured rule comparisons only. Actual resultant policy order, service and address expansion, device applicability and traffic behavior remain unverified.</p>'
            detail += '<h3>Captured locations</h3>' + list_items([v["name"] for v in finding["locations"]])
            if finding.get("individual_conflict"):
                detail += '<h3>Contradictory individual policy evidence</h3>' + raw(finding["individual_conflict"])
            if finding.get("unsupported_reasons"):
                detail += '<h3>Unsupported rule observations</h3>'+table(("Reason","Rules"),[
                    tr(e(pretty(reason)),str(count)) for reason,count in sorted(finding["unsupported_reasons"].items())])
            if finding.get("acl_unsupported_reasons"):
                detail += '<h3>ACL predicate rejection details</h3>'+table(("Reason","Rules"),[
                    tr(e(pretty(reason)),str(count)) for reason,count in sorted(finding["acl_unsupported_reasons"].items())])
            detail += '<h3>Rule comparisons</h3>'
            for item in observations:
                earlier = item.get("earlier_position", item.get("earlier_index"))
                later = item.get("later_position", item.get("later_index"))
                detail += '<h4>' + e(pretty(item["status"])) + ' · ' + e(str(earlier)) + ' / ' + e(str(later)) + '</h4>'
                if item["status"] == "identical_unsupported_security_rule_body":
                    detail += '<p>Identical captured rule fields except position. Predicate semantics are unsupported; this is not a shadowing or removal recommendation.</p>'
                if "condition_relationship" in item:
                    detail += '<p>Match relationship: '+e(pretty(item["condition_relationship"]))+'. Partial overlaps are not full shadowing.</p>'
                if "coverage" in item:
                    detail += '<p>' + e(pretty(item["coverage"])) + ' · ' + e(item["earlier_network"]) + ' / ' + e(item["later_network"]) + ' · counter setting: ' + e(pretty(item["counter_setting"])) + '</p>'
                detail += '<p>Earlier rule</p>' + property_table(item["earlier"]) + '<p>Later rule</p>' + property_table(item["later"])
            if finding["truncated"]:
                detail += '<p class="note">Comparison limit reached; additional relationships may exist.</p>'
            rows.append(tr(e(module_label(finding["module"])), e(finding["identity"]), e(persona_label(finding["persona"])),
                           str(len(finding["locations"])), str(finding["rules"]), str(finding["unsupported_rules"]),
                           str(len(observations)), badge(pretty(finding["status"])),
                           inspect(finding["identity"], detail, "Review rules")))
    panel("rules", "Policy rule review", "Inspect duplicate conditions, differing actions, partial intersections and broader matches within captured ordered policies. Role ACLs also compare literal IPv4 and IPv6 destinations within the same explicit source role and VRF. Unsupported matches and missing order remain unqualified; do not treat these as proven unreachable rules.",
          ("Module", "Policy", "Function", "Locations", "Rules", "Unsupported", "Observations", "Evidence", ""), rows, counts["rules"])
    if selected == "rules":
        sequence_rows = []
        for report in workspace.policy_snapshot(bundle, "sequences"):
            detail = '<p>Observed policy-group order. Cross-policy matches are candidates only; role applicability and resultant device policy remain unverified.</p>'
            detail += '<p>Target context: '+e(pretty(report.get("target_context","unknown")))+'</p>'
            detail += table(("Position", "Referenced policy", "Visibility", "Qualified rules", "Unsupported rules"), [
                tr(str(ref["position"]), e(ref["name"]), badge(pretty(ref["status"])),
                   str(ref.get("qualified_rule_count", "Unknown")), str(ref.get("unsupported_rule_count", "Unknown")))
                for ref in report["references"]])
            for ref in report["references"]:
                if ref.get("individual_conflict"):
                    detail += '<h3>Contradictory policy target: '+e(ref["name"])+'</h3>'+raw(ref["individual_conflict"])
            for finding in report["findings"]:
                detail += '<p>Match relationship: '+e(pretty(finding.get("condition_relationship","unverified")))+'</p>'
                detail += '<h4>' + e(finding["earlier_policy"]) + ' → ' + e(finding["later_policy"]) + '</h4><p>' + e("Same action body" if finding["same_action"] else "Different action bodies") + '</p>'
                detail += '<p>Earlier rule</p>' + property_table(finding["earlier_rule"]) + '<p>Later rule</p>' + property_table(finding["later_rule"])
            if report["truncated"]:
                detail += '<p class="note">Comparison limit reached; more relationships may exist.</p>'
            if report["status"] != "order_observed":
                detail += raw(report["entries"], "Unqualified entries")
            sequence_rows.append(tr(e(report["name"]), e(persona_label(report["persona"])), badge(pretty(report["status"])),
                                    e(pretty(report.get("target_context","unknown"))),
                                    str(len(report["entries"])), str(sum(v["status"] != "rules_observed" for v in report["references"])),
                                    str(sum(v.get("unsupported_rule_count", 0) > 0 for v in report["references"])),
                                    str(len(report["findings"])), inspect("Policy sequence", detail, "Review order")))
        section = '<section><h2>Policy group evaluation order</h2><p>Compare only policy bodies visible in the same captured scope and function. Missing policy definitions or ambiguous order are not interpreted.</p>' + table(("Scope", "Function", "Sequence evidence", "Target context", "Entries", "Unqualified targets", "Targets with unsupported rules", "Cross-policy candidates", ""), sequence_rows, search=True) + '</section>'
        key, label, count, content = panels[-1]
        panels[-1] = (key, label, count, content + section)
    rows = []
    if selected == "duplicates":
        for r in data["library_duplicates"]:
            if selected_group and engineering_group_id("duplicates", r) != selected_group:
                continue
            keep = r["suggested_keep"]
            usage = r["usage"]
            from .retention_review import retention_comparison
            retention = retention_comparison(usage, keep)
            if selected_group:
                comparison = [tr(f'<strong>{e(row["identity"])}</strong>' + ('<small>Suggested retention candidate</small>' if row["suggested"] else ""),
                                 str(row["saved_references"]), e(row["assignments"]), str(row["referencing_objects"]),
                                 str(row["shared_devices"]), str(row["different_devices"]), str(row["unknown_devices"]))
                              for row in retention["rows"]]
                choose_keep = '<label>Profile to retain<select data-keep>' + '<option value="">Choose a profile</option>' + "".join(f'<option value="{e(identity)}"{" selected" if identity == keep else ""}>{e(identity)}</option>' for identity in usage) + '</select></label>'
                from .advanced_review import duplicate_migration_preview
                preview_data = {identity: {"assignments": usage_cells(u)[0], "shared_devices": len(u["shared_devices"]), "referencing_objects": u["reference_count"], "unknown_reads": len(u["unknown_devices"])} for identity, u in usage.items()}
                migration_plans = {identity: duplicate_migration_preview(r["module"], usage, identity, bundle=bundle) for identity in usage}
                unresolved = r["unresolved_reference_count"]
                detail = ('<div class="review-decision"><div><strong>Choose the canonical Library profile</strong><p>Use observed references and assignments to estimate migration work. No profile is proven safe to delete.</p></div></div>'
                          + '<p class="note">' + e(retention["explanation"]) + '</p>'
                          + table(("Profile", "Saved referring objects", "Assignments", "All referring objects", "Shared devices", "Different body", "Unknown reads"), comparison)
                          + f'<div data-duplicate-preview data-usage="{e(json.dumps(preview_data))}" data-migration-plans="{e(json.dumps(migration_plans))}"><h3>Migration preview</h3>{choose_keep}<div data-migration-summary aria-live="polite">Choose a profile to preview the observed migration workload.</div></div>'
                          + (f'<p class="note"><strong>{unresolved} unresolved reference observations in this module.</strong> Their target identities are not established; they may affect this migration.</p>' if unresolved else "")
                          + "".join(f'<details><summary>{e(identity)} · Where it is used</summary>{usage_detail(u, root=root, snapshot=name, module=r["module"])}</details>' for identity, u in usage.items())
                          + '<details><summary>Validation before consolidation</summary><ol><li>Choose the canonical name based on usage and naming standards.</li><li>Move assignments and references to that name.</li><li>Verify effective configuration and complete reverse references before deleting the old profile.</li></ol></details>'
                          + raw(r))
                control = inspect(", ".join(r["identities"]), detail, "Plan consolidation")
                if detail_only:
                    return control.replace("<template>", '<template data-advisor-evidence>', 1)
            else:
                control = review_button("duplicates", r, ", ".join(r["identities"]), "Plan consolidation")
            # One decision per duplicate group. Keep all per-profile usage counts
            # aligned, rather than repeating the same review button for every member.
            group_usage = ('<table class="group-usage"><thead><tr>' + "".join(
                f'<th scope="col">{e(label)}</th>' for label in ("Profile", "Assignments", "Devices", "References", "Unknown reads"))
                + '</tr></thead><tbody>' + "".join(
                    tr(f'<strong>{e(identity)}</strong>' + (' <span class="retain-mark">Suggested</span>' if identity == keep else ""),
                       *usage_cells(u)) for identity, u in usage.items()) + '</tbody></table>')
            rows.append(tr(e(module_label(r["module"])), group_usage,
                           f'<strong>{e(keep) if keep else "Manual choice"}</strong><small>{e(retention["short_reason"])}</small>',
                           control))
    if detail_only:
        raise ValueError("Finding or snapshot changed; reopen the worklist")
    panel("duplicates", "Duplicate Library profiles", "Compare observed usage for each name before choosing which profile to retain. Suggested names are based on observed migration effort, not safe deletion.",
          ("Module", "Profiles and observed usage", "Retention candidate", "Action"), rows, counts["duplicates"])
    for key, label in (("references", "Reference review"), ("resolved", "Observed references")):
        content = ('<section><p class="filter-hint">Observed references are not a complete dependency graph. Not observed does not prove a broken dependency.</p>'
                   + reference_worklist(workspace, root, name, bundle, query, reference_rows[key], key) + '</section>') if selected == key else ""
        panels.append((key, label, counts[key], content))
    tabs = '<nav class="workflow-tabs" aria-label="Engineering workflows">' + "".join(
        f'<a href="{url(root, "advanced", snapshot=name, workflow=k)}"{" aria-current=true" if k == selected else ""}>{e(label)} <span>{n}</span></a>'
        for k, label, n, _ in panels) + '</nav>'
    return page("Engineering review", intro("Engineering review", "Review reusable ports, scope precedence, Library duplication and references.", picker)
                + tabs + next(p[3] for p in panels if p[0] == selected) + '<script>' + DUPLICATE_JS + '</script>', workspace.nav(name))



DUPLICATE_JS = r"""
(()=>{
function update(panel){
 const keep=panel.querySelector('[data-keep]').value;
 const target=panel.querySelector('[data-migration-summary]');
 const usage=JSON.parse(panel.dataset.usage);
 target.replaceChildren();
 const heading=document.createElement('p');
 heading.textContent=keep?'Retain '+keep+'. Review migration from these other names:':'Choose a profile to preview the observed migration workload.';
 target.append(heading);
 if(!keep)return;
 const wrap=document.createElement('div');wrap.className='table-scroll';
 const table=document.createElement('table');
 const head=table.createTHead().insertRow();
 for(const label of ['Migrate from','Assignments','Shared devices','References','Unknown reads']){
  const cell=document.createElement('th');cell.scope='col';cell.textContent=label;head.append(cell);
 }
 const body=table.createTBody();
 for(const [name,u] of Object.entries(usage)){
  if(name===keep)continue;
  const row=body.insertRow();
  for(const value of [name,u.assignments,u.shared_devices,u.referencing_objects,u.unknown_reads])row.insertCell().textContent=String(value);
 }
 wrap.append(table);target.append(wrap);
 const plan=JSON.parse(panel.dataset.migrationPlans)[keep];
 if(!plan)return;
 const heading2=document.createElement('h4');heading2.textContent='Exact observed migration worklist';target.append(heading2);
 function records(title,headers,values){
  const heading=document.createElement('h4');heading.textContent=title+' ('+values.length+')';target.append(heading);
  if(!values.length){const p=document.createElement('p');p.textContent='No records observed; coverage is incomplete.';target.append(p);return;}
  const wrap=document.createElement('div');wrap.className='table-scroll';
  const table=document.createElement('table'),head=table.createTHead().insertRow(),body=table.createTBody();
  for(const label of headers){const cell=document.createElement('th');cell.scope='col';cell.textContent=label;head.append(cell);}
  for(const valuesRow of values){const row=body.insertRow();for(const v of valuesRow)row.insertCell().textContent=String(v??'Unknown');}
  wrap.append(table);target.append(wrap);
 }
 records('Assignment review',['From','To','Scope ID','Function','Action'],plan.assignments.map(a=>[a.from,a.to,a.scope,a.persona,a.action.replaceAll('_',' ')]));
 records('Saved references to review',['From','To','Scope','Module','Profile','Field'],plan.saved_references.map(r=>[r.from,r.to,r.device,r.source_module,r.source,r.path.join('.')]));
 records('Effective reference impact',['From','Device','Module','Profile','Field'],plan.effective_references.map(r=>[r.from,r.device,r.source_module,r.source,r.path.join('.')]));
 const visibility={matching_shared:'Matching shared profile',matching_source_unverified:'Matching settings; source unverified',different_definition:'Conflicting retained-name definition',count_confirmed_absence:'Confirmed absent from captured view',unverified:'Visibility unverified'};
 records('Affected device visibility',['Device','Function','Retained profile','Membership','Why affected'],plan.recipient_review.map(r=>[r.name,r.persona,visibility[r.target_visibility]||r.target_visibility,r.uncertain_membership?'Uncertain':'Observed',r.observations.map(o=>o.from+': '+o.reason).join('; ')]));
 records('Unresolved recipient observations',['Function','Scope','Source profile','Reason'],plan.unresolved_recipient_observations.map(r=>[r.persona,r.scope,r.from,r.reason]));
 const note=document.createElement('p');note.textContent='Review retained-profile visibility on every listed recipient before changing assignments or references. Matching settings alone do not prove the Library source; unresolved recipients prevent complete impact assessment.';target.append(note);
 const button=document.createElement('button');button.type='button';button.textContent='Export private migration preview JSON';
 button.addEventListener('click',()=>{const u=URL.createObjectURL(new Blob([JSON.stringify({schema:1,kind:'library_migration_preview',...plan},null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=u;a.download='library-migration-preview.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);});target.append(button);
}
document.addEventListener('change',event=>{
 if(event.target.matches('[data-keep]'))update(event.target.closest('[data-duplicate-preview]'));
 if(event.target.matches('[data-port-profile]')){
  const review=event.target.closest('[data-port-review]');
  for(const target of review.querySelectorAll('[data-port-target]'))target.textContent=event.target.value||'Not selected';
 }
});
document.addEventListener('workspace-inspector-loaded',()=>{
 for(const panel of document.querySelectorAll('#workspace-inspector-body [data-duplicate-preview]'))update(panel);
});
})();
"""


def keyed_profile_evidence(bundle, persona, scope, module, identity):
    reads = ((bundle.get("keyed_profile_details") or {}).get("profiles", {})
             .get(persona, {}).get(str(scope), {}).get(module, {}).get(identity, {}))
    if not reads:
        return ""
    labels = {"library": "Library", "local": "Saved local", "effective": "Effective"}
    body = '<h3>Individual profile reads</h3><p class="note">Additional evidence from the individual profile endpoint. Source and completeness are not verified; these values do not replace the collection or authorize changes.</p>'
    for kind, evidence in sorted(reads.items()):
        body += '<h4>' + e(labels.get(kind, kind)) + '</h4>' + status(evidence["status"])
        if evidence["status"] == "collection_only_sampled":
            body += '<p class="note">This scope has its own captured collection settings. Individual verification was skipped after two equivalent profiles returned identical details. No detail values were copied from another scope.</p>'
            continue
        if evidence.get("profile") is not None:
            body += property_table(evidence["profile"])
            if evidence.get("differences"):
                body += '<h4>Differences from collection response</h4>' + diff_table(
                    evidence["differences"], "Collection", "Individual read")
        body += raw(evidence, "Individual API evidence")
    return body


def library_profile_detail(bundle, root, name, module, identity, profile, review, usage):
    variants = review.get("local_variants", [])
    detail = '<h3>Profile settings</h3>' + property_table(review.get("profile", profile))
    detail += '<h3>Local instances</h3>' + table(("Scope", "Function", "Comparison", "Action"), [
        tr(e(v["scope_name"]), e(persona_label(v["persona"])), status(v["classification"]),
           f'<a href="{url(root, "report", snapshot=name, persona=v["persona"], scope=v["scope"], module=module, view="all")}">Open configuration</a>') for v in variants], search=True)
    differing = [v for v in variants if v["differences"]]
    if differing:
        detail += '<details><summary>Local configuration differences</summary>' + "".join(
            f'<h3>{e(v["scope_name"])}</h3>' + diff_table(v["differences"], "Local", "Library") for v in differing) + '</details>'
    detail += f'<p><a href="{url(root, "assignments", snapshot=name, module=module, identity=identity)}">Review assignments and recipients</a></p>'
    detail += f'<p><a href="{url(root, "impact", snapshot=name, module=module, identity=identity)}">Trace all observed references to this name</a></p>'
    detail += keyed_profile_evidence(bundle, "Library", "", module, identity)
    detail += '<details><summary>Observed assignments and usage</summary>' + usage_detail(usage) + '</details>'
    return detail + raw({"profile": profile, **review}, "Complete profile evidence")


def library_view(workspace, query):
    from .config_app import library_profile_comparison
    from .advanced_review import advanced_analysis, library_usage
    loaded, empty = load(workspace, query, "Library", "library")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    library = bundle.get("library")
    if not library:
        return page("Library", intro("Library", "This snapshot predates Library collection.", picker)
                    + '<section>Refresh from Central to collect Library evidence.</section>', workspace.nav(name))
    modules = library.get("modules", {})
    module = query.get("module", "")
    if module and module not in modules:
        raise ValueError("Unknown module")
    assignments = library.get("assignments") or {}
    additional = bundle.get("unadapted_profiles") or {}
    rows = []
    for key, view in sorted(modules.items()):
        if module and key != module:
            continue
        link = url(root, "library", snapshot=name, module=key)
        rows.append(tr(f'<a href="{link}">{e(module_label(key))}</a>',
                       str(len(view["profiles"])) if view["status"] == "list_parsed" else "Unavailable",
                       status(view["status"])))
    body = intro("Library", "Shared profiles and their observed assignments.", picker)
    body += f'<p><a class="button" href="{url(root, "assignments", snapshot=name, module=module)}">Review Library assignments</a></p>'
    if not module:
        body += f'<p><a class="button" href="{url(root, "advanced", snapshot=name, workflow="duplicates")}">Review duplicate Library profiles</a></p>'
    if not module:
        for key, evidence in sorted(additional.items()):
            if key in modules:
                continue
            read = evidence.get("library", {})
            link = url(root, "unadapted", snapshot=name, module=key)
            rows.append(tr(f'<a href="{link}">{e(module_label(key))}</a><small>Additional collection</small>',
                           "Unavailable", status(read.get("status", "not_collected"))))
        body += '<section><h2>Profile collections</h2>' + table(("Module", "Parsed profiles", "State"), rows, search=True) + '</section>'
    else:
        body += (f'<div class="collection-nav"><a href="{url(root, "library", snapshot=name)}">← All collections</a>'
                 + f'<form class="auto-select" method="get" action="{root}library"><input type="hidden" name="snapshot" value="{e(name)}">'
                 + select("module", [(k, module_label(k)) for k in sorted(modules)], module, "Collection")
                 + '<noscript><button type="submit">Open</button></noscript></form></div>')
        view = modules[module]
        if module in additional:
            body += f'<p><a href="{url(root, "unadapted", snapshot=name, module=module)}">Inspect supplemental collection evidence</a></p>'
        if view["status"] != "list_parsed":
            body += ('<section><h2>' + e(module_label(module)) + '</h2><p>Profile count unavailable. '
                     'The collection could not be interpreted; this does not mean no profiles exist.</p>'
                     + badge(pretty(view["status"]), "warn") + raw(view, "Captured response") + '</section>')
            from .central_tool import CONFIG_MODULES, observed_profile_candidates
            if module in CONFIG_MODULES:
                candidates = observed_profile_candidates(view, CONFIG_MODULES[module][0])
                if candidates:
                    body += '<section><h2>Observed profiles (incomplete collection)</h2><p>These individual observations do not establish complete Library contents or usage.</p>' + table(("Profile", "Settings"), [
                        tr(e(title_profile(identity, profile)), inspect(identity, property_table(profile) +
                            keyed_profile_evidence(bundle, "Library", "", module, identity)))
                        for identity, profile in sorted(candidates.items())], search=True) + '</section>'
            return page("Library", body, workspace.nav(name))
        from .library_usage_presentation import visibility_filter, usage_summary, STATES
        visibility = query.get("visibility", "all")
        if visibility not in {"all", *(key for key, _ in STATES)}:
            raise ValueError("Unknown Library visibility filter")
        selected_profile = query.get("profile")
        if selected_profile is not None:
            if selected_profile not in view["profiles"]:
                raise ValueError("Unknown Library profile")
            from .library_usage_presentation import device_visibility
            usage = library_usage(bundle, module, [selected_profile], workspace.advanced_snapshot(bundle)["references"])
            comparison = library_profile_comparison(bundle, module, identities=[selected_profile])
            body += '<section><h2>' + e(selected_profile) + ' · Profile review</h2>'
            body += f'<p><a href="{url(root, "library", snapshot=name, module=module, visibility=visibility)}">Back to profile collection</a></p>'
            body += library_profile_detail(bundle, root, name, module, selected_profile,
                                           view["profiles"][selected_profile], comparison.get(selected_profile, {}),
                                           usage[selected_profile])
            body += '</section><section><h2>' + e(selected_profile) + ' · Device visibility</h2>'
            body += device_visibility(usage[selected_profile], root=root, snapshot=name, module=module) + '</section>'
            return page("Library", body, workspace.nav(name))
        comparison = library_profile_comparison(bundle, module)
        usage = library_usage(bundle, module, view["profiles"], workspace.advanced_snapshot(bundle)["references"])
        filtered = visibility_filter(usage, visibility)
        body += usage_summary(root, name, module, usage, visibility)
        rows = []
        for identity, profile in sorted(view["profiles"].items()):
            if identity not in filtered:
                continue
            review = comparison.get(identity, {})
            matches = review.get("assignments", [])
            variants = review.get("local_variants", [])
            conflict = sum(v["classification"] == "different_body" for v in variants)
            href = url(root, "library", snapshot=name, module=module, profile=identity, visibility=visibility)
            rows.append(tr(f'<strong><a href="{href}">{e(title_profile(identity, profile))}</a></strong>',
                           *usage_cells(usage[identity]), str(len(variants)),
                           badge(str(conflict), "warn" if conflict else "neutral"),
                           f'<a href="{href}">Review profile</a>'))
        body += f'<section><h2>{e(module_label(module))} · {len(rows)} of {len(usage)} profiles</h2>' + table(("Profile", "Observed assignments", "Shared devices", "Referencing objects", "Unknown device reads", "Local instances", "Different bodies", ""), rows, search=True) + '</section>'
    body += '<p class="note">Assignments link a Library profile to a scope and device function. A zero count means no assignment was observed in this snapshot, not that the profile is unused.</p>' + raw(assignments, "Assignment capture diagnostics")
    return page("Library", body, workspace.nav(name))


def inventory_view(workspace, query):
    if query.get("mode") == "device":
        from .device_review import device_view
        return device_view(workspace, query)
    loaded, empty = load(workspace, query, "Scopes", "scopes")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    rows = []
    for persona, entry in sorted(bundle["results"].items()):
        totals, qualified_counts = Counter(), Counter()
        for data in entry["modules"].values():
            for view in data["scope_results"]:
                totals[view["scope"]] += 1
                qualified_counts[view["scope"]] += bool(view["review"]["qualified"])
        for s in sorted(entry["scopes"], key=lambda s: (s["kind"] != "device", s["kind"], s.get("name") or s["id"])):
            sid = s["id"]
            qualified = qualified_counts[sid]
            href = url(root, "report", snapshot=name, persona=persona, scope=sid)
            rows.append(tr(f'<strong>{e(s.get("name") or sid)}</strong>', e(pretty(s["kind"])), e(persona_label(persona)),
                           f'{qualified}/{totals[sid]}', ((f'<a href="{url(root, "scopes", snapshot=name, mode="device", persona=persona, device=sid)}">Review device</a> · ' + f'<a href="{url(root, "overrides", snapshot=name, persona=persona, device=sid)}">Compare overrides</a> · ') if s["kind"] == "device" else "") + f'<a href="{href}">Open configuration</a>'))
    return page("Scopes", intro("Inventory", "Browse captured devices and configuration scopes.", picker)
                + '<section>' + table(("Scope / device", "Type", "Function", "Qualified modules", ""), rows, search=True) + '</section>', workspace.nav(name))


def comparison_view(workspace, query):
    if query.get("mode") == "matrix":
        from .comparison_matrix import matrix_view
        return matrix_view(workspace, query)
    from .config_app import compare_devices
    loaded, empty = load(workspace, query, "Compare devices", "compare")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    personas = sorted(bundle["results"])
    if not personas:
        return page("Compare devices", intro("Compare devices", "No device functions captured.", picker), workspace.nav(name))
    persona = query.get("persona", personas[0])
    if persona not in personas:
        raise ValueError("Unknown persona")
    entry = bundle["results"][persona]
    devices = [(s["id"], s.get("name") or s["id"]) for s in entry["scopes"] if s["kind"] == "device"]
    left, right, module = query.get("left", ""), query.get("right", ""), query.get("module", "")
    if module and module not in entry["modules"]:
        raise ValueError("Unknown module")
    controls = scope_filter_form(root, "compare", name, bundle, persona, (
        ("left", "Reference device", left, lambda entry: device_options(entry, "Select device")),
        ("right", "Compare with", right, lambda entry: device_options(entry, "Select device")),
        ("module", "Module", module, lambda entry: module_options(entry, "Reusable modules"))),
        submit="Compare")
    body = intro("Compare devices", "Compare two devices using captured configuration.", picker) + '<section class="filter-section">' + controls + '<p class="filter-hint">Infrastructure modules are excluded unless selected explicitly.</p></section>'
    body += f'<p><a class="button" href="{url(root, "compare", snapshot=name, persona=persona, mode="matrix")}">Compare multiple scopes</a></p>'
    if left and right:
        if left == right:
            body += '<section class="empty">Select two different devices.</section>'
        else:
            result = compare_devices(bundle, persona, left, right, module or None)
            counts = Counter(r["status"] for r in result)
            labels = dict(devices)
            body += metrics([("Different modules", counts["different"], "Exact captured differences"),
                             ("Identical modules", counts["exact_match"], "No captured differences"),
                             ("Not comparable", counts["unqualified"], "Incomplete evidence")])
            rows = []
            for r in result:
                for d in r["differences"]:
                    detail = diff_table(d["fields"], labels[left], labels[right]) if "fields" in d else (
                        '<h3>' + e(labels[left]) + '</h3>' + property_table(d.get("left")) + '<h3>' + e(labels[right]) + '</h3>' + property_table(d.get("right")))
                    if "individual" in d:
                        evidence = d["individual"]
                        detail = '<h3>Collection comparison</h3>' + detail
                        detail += '<h3>Individual profile comparison</h3>'
                        if evidence["fields"] is not None:
                            detail += diff_table(evidence["fields"], labels[left], labels[right])
                        else:
                            detail += '<p class="note">Individual comparison unavailable. A missing or sampled response is not a configuration value.</p>'
                        for side, device in (("left", left), ("right", right)):
                            detail += '<h4>' + e(labels[device]) + '</h4>' + status(evidence[side + "_status"])
                            if evidence[side] is not None:
                                detail += property_table(evidence[side])
                    rows.append(tr(e(module_label(r["module"])), e(d["identity"]), status(d["status"]), inspect(d["identity"], detail + raw(d))))
            body += '<section><h2>Differences</h2>' + table(("Module", "Profile", "Result", ""), rows, search=True) + '</section>'
            body += raw([{k: v for k, v in r.items() if k != "differences"} for r in result], "All module comparison states")
    return page("Compare devices", body, workspace.nav(name))


def collection_gap_rows(bundle):
    """Summarize captured gaps without interpreting failures as missing settings."""
    counts = Counter()
    def record(module, source, view, count_key):
        state = view.get("status", "not_collected")
        error = view.get("http_error")
        if state in ("empty_object", "empty_response"):
            reason = "Unverified empty response"
        elif error is not None:
            reason = "HTTP " + str(error)
        elif state not in ("list_parsed", "response_received"):
            reason = pretty(state)
        elif view.get("pagination_status") not in (None, "complete", "pagination_exhausted"):
            reason = "Pagination unverified: " + pretty(view["pagination_status"])
        elif view.get(count_key) is not True:
            reason = "Record count unverified"
        else:
            return
        counts[module, source, reason] += 1
    for persona, entry in bundle.get("results", {}).items():
        for module, data in entry.get("modules", {}).items():
            for scope in data.get("scope_results", []):
                for side in ("local", "effective"):
                    record(module, persona + " / " + side, scope.get(side + "_view", {}), "count_confirmed")
    for module, view in (bundle.get("library") or {}).get("modules", {}).items():
        record(module, "Library", view, "count_confirmed")
    for module, entry in (bundle.get("unadapted_profiles") or {}).items():
        if not entry.get("library", {}).get("reused_exact_collection"):
            record(module, "Supplemental Library", entry.get("library", {}), "collection_count_verified")
        for scope in entry.get("source_views", []):
            for side in ("committed", "effective"):
                view = scope.get(side, {})
                if not view.get("reused_exact_collection"):
                    record(module, "Supplemental / " + str(scope.get("persona", "unknown")) + " / " + side,
                           view, "collection_count_verified")
        skipped = entry.get("catalog_scope_coverage", {}).get("unfiltered_scopes_not_surveyed")
        if type(skipped) is int and skipped > 0:
            counts[module, "Supplemental scope survey", "Scopes not surveyed"] += skipped
    return [{"module": module, "source": source, "reason": reason, "observations": n}
            for (module, source, reason), n in sorted(counts.items(),
                key=lambda item: (0 if item[0][2].startswith("HTTP ") else 1,
                                  -item[1], item[0]))]


def coverage_view(workspace, query):
    from .config_app import module_coverage
    loaded, empty = load(workspace, query, "Module coverage", "coverage")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    from .coverage_evidence import evidence_link, evidence_view
    from .review_dispositions import snapshot_binding
    binding = snapshot_binding(workspace, name, bundle)
    if "evidence_kind" in query:
        return evidence_view(workspace, query, root, name, bundle, picker, binding)
    def evidence(kind, index, label="Inspect"):
        return evidence_link(root, name, binding, kind, index, label)
    records = module_coverage(bundle)
    counts = Counter(r["status"] for r in records)
    library = bundle.get("library") or {}
    additional = bundle.get("unadapted_profiles") or {}
    discovery = bundle.get("profile_type_discovery") or {}
    tenant_default = set(discovery.get("tenant_default_modules", []))
    unknown = set(discovery.get("unknown_adapter_modules", [])) - tenant_default
    survey = set(discovery.get("survey_modules", []))
    scoped_reads = [s[key + "_view"] for entry in bundle["results"].values()
                    for module in entry["modules"].values() for s in module["scope_results"]
                    for key in ("local", "effective") if key + "_view" in s]
    parsed = sum(v.get("status") == "list_parsed" for v in scoped_reads)
    counted = sum(v.get("status") == "list_parsed" and v.get("count_confirmed") is True for v in scoped_reads)
    body = intro("Coverage", "Identify what was collected, what could be interpreted and what remains unavailable.", picker)
    body += '<section class="review-decision"><div><strong>Full configuration coverage is not verified</strong><p>Parsed responses do not prove that Central returned every setting, profile type or scope. Missing values remain unavailable.</p></div></section>'
    body += metrics([("Scoped reads parsed", f"{parsed}/{len(scoped_reads)}", f"{counted} with explicit count evidence"),
                     ("Qualified modules", f"{counts['qualified']}/{len(records)}", "All requested scopes interpretable"),
                     ("Observed types without adapter", len(unknown), "Raw evidence only"),
                     ("Distinct Library collections", len(set(library.get("modules", {})) | set(additional)), "Structured and supplemental evidence deduplicated")])
    from .coverage_navigation import coverage_navigation, gap_summary, coverage_batch, COVERAGE_CSS
    transport = bundle.get("http_get_transport")
    body += coverage_navigation(bundle, transport, additional)
    if isinstance(transport, dict):
        body += '<section id="coverage-performance"><h2>Collection request performance</h2>' + metrics([
            ("HTTP GET attempts", transport.get("http_get_attempts", "Unavailable"), "Includes retries"),
            ("HTTP GET retries", transport.get("http_get_retries", "Unavailable"), "Additional transport attempts"),
            ("Rate-limit responses", transport.get("http_get_429", "Unavailable"), "HTTP 429"),
            ("Server error responses", transport.get("http_get_5xx", "Unavailable"), "HTTP 5xx"),
            ("Repeated retry sequences avoided", transport.get("custom_500_retry_sequences_suppressed", "Unavailable"), "Custom GET API only"),
        ]) + '<p class="note">Counts cover GET attempts during this audit, including failed attempts. Authentication and troubleshooting POST requests are excluded. A resumed audit counts only this run, not earlier checkpoint requests.</p></section>'
    gaps = collection_gap_rows(bundle)
    reason = query.get("gap_reason", "")
    reason_counts = Counter(g["reason"] for g in gaps)
    if reason and reason not in reason_counts:
        raise ValueError("Unknown collection gap reason")
    body += '<section id="coverage-gaps"><h2>Collection gaps requiring review</h2><p>Failed requests, incomplete counts and unverified empty responses are not evidence of absent configuration. Counts below represent observations, not missing profiles. Reused identical responses are not counted twice.</p>'
    body += gap_summary(root, name, gaps, reason)
    selected_gaps = [g for g in gaps if not reason or g["reason"] == reason]
    gap_batch, gap_controls = coverage_batch(root, name, query, "gaps", selected_gaps,
        lambda g: " ".join((g["module"], module_label(g["module"]), g["source"], g["reason"], str(g["observations"]))))
    gap_rows = []
    for g in gap_batch:
        module, source = g["module"], g["source"]
        if source.startswith("Supplemental"):
            link = url(root, "unadapted", snapshot=name, module=module)
        elif source == "Library":
            link = url(root, "library", snapshot=name, module=module)
        else:
            link = url(root, "report", snapshot=name, persona=source.split(" / ", 1)[0],
                       module=module, view="diagnostics")
        gap_rows.append(tr(e(module_label(module)), e(source), e(g["reason"]),
                           str(g["observations"]), '<a href="' + link + '">Inspect evidence</a>'))
    body += f'<p class="filter-hint">{len(selected_gaps)} matching module/context/reason groups of {len(gaps)}.</p>' + gap_controls
    body += table(("Module", "Collection context", "Coverage gap", "Observations", "Action"), gap_rows, search=True) + '</section>'
    health = bundle.get("configuration_health")
    if health:
        from .central_tool import health_serial
        summary = {health_serial(row): row for row in health.get("devices", []) if health_serial(row)}
        issues = health.get("active_issues", {})
        inventory = {health_serial(record.get("inventory")): record["inventory"]
                     for record in bundle.get("inventory", []) if health_serial(record.get("inventory"))}
        def field(row, key):
            value = row.get(key)
            return e(value) if isinstance(value, (str, int, float, bool)) else "Unavailable"
        health_rows = []
        for index, serial in enumerate(sorted(set(summary) | set(issues) | set(inventory))):
            row = summary.get(serial, {})
            issue = issues.get(serial, {})
            label = row.get("name") or inventory.get(serial, {}).get("deviceName") or serial
            health_rows.append(tr(e(label), e(serial), field(row, "configStatus"),
                field(row, "activeIssues"), field(row, "topPriorityIssue"), field(row, "recommendedAction"),
                status(issue.get("status", "not_collected")),
                evidence("health", index)))
        body += '<section id="coverage-health"><h2>Configuration deployment health</h2>' + metrics([
            ("Device summaries", len(summary), "Count confirmed" if health.get("count_confirmed") else "Count unverified"),
            ("Active issue responses", f"{sum(v.get('status') == 'response_received' for v in issues.values())}/{len(issues)}", "All observed device identifiers"),
            ("Inventory without health summary", len(health.get("inventory_serials_missing_from_summary", [])), "Missing is not healthy"),
            ("Inventory without serial", health.get("inventory_entries_without_serial", "Unavailable"), "Cannot identify device"),
        ]) + '<p>Summary collection: ' + status(health.get("summary_status", "not_collected")) + '</p>'
        body += '<p class="note">Configuration status and issue counts are reported by Central. Missing data does not establish successful deployment. Issue responses have not been semantically qualified.</p>'
        body += table(("Device", "Serial", "Configuration status", "Active issues", "Top issue", "Recommended action", "Issue read", ""), health_rows, search=True)
        body += '<p>' + evidence("health-pages", 0, "Original health summary responses") + "</p>" + '</section>'
    else:
        body += '<section id="coverage-health"><h2>Configuration deployment health</h2><p class="muted">Not collected in this snapshot. Refresh to retrieve Central health evidence.</p></section>'
    assignments = library.get("assignments") or {}
    scope_maps = library.get("scope_maps") or {}
    outcomes = assignments.get("scope_read_outcomes") or {}
    body += '<section id="coverage-assignments"><h2>Discovery and assignments</h2>' + table(("Source", "Status", "Observed records"), [
        tr("Tenant assignments", status(assignments.get("status", "not_collected")) + '<small>' +
           ("Initial count confirmed" if assignments.get("collection_count_verified") else "Initial count unverified") + '</small>',
           str(len(assignments.get("rows", []))) if assignments.get("rows") or assignments.get("status") == "response_received" else "Unavailable"),
        tr("Local scope maps", status(scope_maps.get("status", "not_collected")) + '<small>' +
           ("Count confirmed" if scope_maps.get("collection_count_verified") else "Count unverified") + '</small>',
           str(len(scope_maps.get("rows", []))) if scope_maps.get("rows") or scope_maps.get("status") == "response_received" else "Unavailable"),
        tr("Scoped assignment reads", e(", ".join(f"{pretty(k)}: {v}" for k, v in sorted(outcomes.items())) or "Not collected"), str(sum(outcomes.values()))),
        tr("Additional assignment identities", "Recovered by scoped queries", str(assignments.get("additional_assignments", "Unavailable"))),
        tr("Unqualified device functions", e(", ".join(bundle.get("unqualified_personas", [])) or "None recorded"), str(len(bundle.get("unqualified_personas", []))))])
    body += '<p class="note">Assignment and profile catalog completeness are not verified.</p></section>'
    hierarchy = bundle.get("scope_hierarchy_evidence") or {}
    individual = bundle.get("keyed_assignment_details") or {}
    if hierarchy or individual:
        body += '<section id="coverage-hierarchy"><h2>Direct hierarchy and assignment evidence</h2>'
        body += '<p class="note">Independent reads of discovered scopes and observed assignment identities. They do not establish complete hierarchy or assignment coverage.</p>'
        if hierarchy:
            body += '<h3>Scope hierarchy</h3>' + table(("Scope", "Type", "Status", "Endpoint", "HTTP result", ""), [
                tr(e(r["scope"]), e(r["kind"]), status(r["status"]), e(r.get("endpoint_version", "v1")),
                   e("HTTP " + str(r["http_error"]) if r.get("http_error") else "Response received" if r["status"] == "response_received" else "Unavailable") +
                   (('<small>Alternative: ' + e("HTTP " + str(r["alternate_read"]["http_error"]) if r["alternate_read"].get("http_error") else pretty(r["alternate_read"].get("status", "unknown"))) + '</small>') if r.get("alternate_read") else ""),
                   evidence("hierarchy", index))
                for index, r in enumerate(hierarchy.get("records", []))], search=True)
        if individual:
            body += '<h3>Individual assignments</h3><p>' + e(", ".join(f"{pretty(k)}: {v}" for k, v in sorted(individual.get("outcomes", {}).items()))) + '</p>'
            if individual.get("selector_rejections"):
                body += '<h4>Selectors not queried</h4>' + table(("Reason", "Records"), [
                    tr(e(pretty(k)), str(v)) for k, v in sorted(individual["selector_rejections"].items())])
            assignment_batch, assignment_controls = coverage_batch(root, name, query, "hierarchy",
                list(enumerate(individual.get("records", []))),
                lambda item: " ".join(str(value) for value in (
                    *item[1]["selector"].values(), persona_label(item[1]["selector"]["device-function"]),
                    module_label(item[1]["selector"]["profile-type"]), pretty(item[1]["status"]),
                    "Identical" if item[1].get("body_matches_inventory") is True else
                    "Different" if item[1].get("body_matches_inventory") is False else "Unavailable")))
            body += assignment_controls
            body += table(("Scope", "Device function", "Module", "Profile", "Status", "Body comparison", ""), [
                tr(e(r["selector"]["scope-id"]), e(persona_label(r["selector"]["device-function"])),
                   e(module_label(r["selector"]["profile-type"])), e(r["selector"]["profile-instance"]),
                   status(r["status"]), "Identical" if r.get("body_matches_inventory") is True else
                   "Different" if r.get("body_matches_inventory") is False else "Unavailable",
                   evidence("assignment", index))
                for index, r in assignment_batch], search=True)
        body += '</section>'
    from .library_visibility import visibility_summary
    visibility = visibility_summary(bundle)
    visibility_batch, visibility_controls = coverage_batch(root, name, query, "visibility", visibility,
        lambda v: " ".join((v["module"], module_label(v["module"]), str(v["definitions"]),
                           str(v["observed_assignments"]))), page_size=50)
    body += '<section id="coverage-visibility"><h2>Library definitions and scope visibility</h2><p>Library objects can be assigned or referenced by other profiles. Empty scope responses do not prove they are unused. Review observed assignments and references before any cleanup.</p>'
    body += visibility_controls + table(("Module", "Library profiles", "Profiles with observed assignments", "Observed assignments",
                   "Positive effective views", "Empty-object views", "Assigned identity observed",
                   "Assigned identity absent (count confirmed)", "Assignment visibility unknown", ""), [
        tr(e(module_label(v["module"])), str(v["definitions"]), str(v["definitions_with_observed_assignments"]),
           str(v["observed_assignments"]), str(v["effective_views"].get("positive", 0)),
           str(v["effective_views"].get("empty_object", 0)), str(v["assignment_visibility"].get("identity_observed", 0)),
           str(v["assignment_visibility"].get("count_confirmed_absence", 0)),
           str(v["assignment_visibility"].get("unverified", 0) + v["assignment_visibility"].get("library_definition_unobserved", 0)),
           f'<a href="{url(root, "assignments", snapshot=name, module=v["module"])}">Review assignments</a> · <a href="{url(root, "library", snapshot=name, module=v["module"])}">Library and references</a>')
        for v in visibility_batch], search=True) + '</section>'
    from .nac_authorization import nac_collection
    nac_rows = []
    for module in ("auth-profiles", "authz-policies", "identity-stores", "static-tag"):
        view = nac_collection(bundle, module)
        nac_rows.append(tr(e(module_label(module)), status(view.get("status", "not_collected")),
                           str(len(view.get("profiles", {}))), "Confirmed" if view.get("count_confirmed") is True else "Unverified"))
    macs = bundle.get("nac_registrations") or {}
    nac_rows.append(tr("MAC registrations", status(macs.get("status", "not_collected")),
                       str(len(macs.get("rows", []))), "Confirmed" if macs.get("count_confirmed") is True else "Unverified"))
    body += '<section id="coverage-nac"><h2>Central NAC tenant collection</h2><p>Authentication profiles, authorization policies and identity stores use documented tenant-default parameters. Registration pagination is independent of configuration scope reads.</p>' + table(("Resource", "Read result", "Observed records", "Count evidence"), nac_rows) + f'<p><a href="{url(root, "nac", snapshot=name)}">Review NAC identities and authorization</a></p></section>'
    assets = bundle.get("nac_portal_assets") or {}
    if assets:
        body += '<section id="coverage-assets"><h2>Central NAC portal assets</h2><p>Uploaded image metadata and observed portal references. Binary image contents are not collected.</p>'
        body += metrics([("Images observed", len(assets.get("images", [])), "Count confirmed" if assets.get("count_confirmed") else "Count unverified"),
                         ("Individual metadata reads", len(assets.get("details", {})), "Exact observed image identifiers")])
        body += '<p>Inventory: ' + status(assets.get("status", "not_collected")) + '</p>'
        rows = []
        for image in assets.get("images", []):
            from .nac_assets import image_identity
            identity = image_identity(image)
            detail = assets.get("details", {}).get(identity, {})
            references = image.get("referencedBy")
            rows.append(tr(e(image.get("fileName", identity or "Unresolved identity")), e(image.get("mimeType", "Unavailable")),
                str(len(references)) if isinstance(references, list) else "Unavailable",
                status(detail.get("status", "not_collected")),
                inspect("Image metadata", property_table(image) + raw(detail, "Individual metadata response"), "Inspect")))
        body += table(("Image", "MIME type", "Observed references", "Detail read", ""), rows, search=True)
        body += raw(assets.get("list_read", {}), "Original image inventory response") + '</section>'
    catalog = discovery.get("documented_catalog") or {}
    if catalog:
        surveyed = set(library.get("modules", {})) | set(additional) | set(bundle.get("nac_configuration", {}))
        documented = set(catalog["modules"])
        pending = documented - surveyed - {"ethernet-interfaces"}
        body += '<section id="coverage-catalog"><h2>Vendor API catalog</h2>' + metrics([
            ("Published GET definitions", catalog["get_requests"], f'{catalog["unique_get_paths"]} unique paths'),
            ("Profile collections in catalog", len(documented), f'{len(documented & surveyed)} represented in this capture'),
            ("Catalog categories inspected", f'{catalog["folders_read"]}/{catalog["folders_total"]}', "HPE published collection"),
        ])
        body += '<p class="note">Catalog inclusion does not prove live availability. A deep survey attempts unfiltered reads at every discovered scope for documented unadapted collections; successful attempts do not prove semantic completeness. Non-profile operations, keyed reads and service-specific inventories require their own adapters.</p>'
        if pending:
            body += '<p>Profile collections not captured: ' + e(", ".join(sorted(pending))) + '</p>'
        body += f'<p><a href="{e(catalog["source"])}" target="_blank" rel="noopener noreferrer">HPE published API catalog</a> · Revision {e(catalog["source_updated_at"])}</p></section>'
    keyed = bundle.get("keyed_profile_details")
    if keyed:
        outcomes = keyed.get("outcomes", {})
        body += '<section id="coverage-keyed"><h2>Individual profile evidence</h2>' + metrics([
            ("Supported keyed modules", len(keyed.get("supported_modules", [])), "Documented single-key selectors"),
            ("Individual reads", sum(outcomes.values()), "Includes failed or invalid selectors"),
            ("Collection-only observations", sum(keyed.get("collection_only_by_module", {}).values()), "Adaptive verification; no individual GET"),
            ("Identity observed", outcomes.get("identity_observed", 0), "Source not qualified"),
        ]) + '<p class="note">Open a profile in Library or Configuration to compare individual and collection responses. Library and saved local identities receive individual reads. Adaptive verification reduces repeated individual reads for identical inherited effective device profiles; exhaustive mode verifies every observed identity. Other resource types require separate adapters.</p>'
        body += f'<p><a class="button" href="{url(root, "assessment", snapshot=name, mode="keyed")}">Review individual profile discrepancies</a></p>'
        body += '<p>' + e(", ".join(f"{pretty(k)}: {v}" for k, v in sorted(outcomes.items())) or "No observed profile identities") + '</p></section>'
    else:
        body += '<section id="coverage-keyed"><h2>Individual profile evidence</h2><p class="muted">Not collected. Select Deep catalog collection to retrieve additional individual profile settings.</p></section>'
    ledger = bundle.get("api_read_coverage")
    if ledger:
        operations = ledger.get("operations", [])
        received = sum(bool(r["received"]) for r in operations)
        attempted = sum(bool(r["attempted"]) for r in operations)
        body += '<section id="coverage-operations"><h2>Documented API operation coverage</h2>' + metrics([
            ("Documented GET paths", len(operations), "Includes supplemental release notes"),
            ("Paths attempted", f"{attempted}/{len(operations)}", "Logical GET calls, not retries"),
            ("Paths with responses", f"{received}/{len(operations)}", "Not proof of complete data"),
            ("Paths not attempted", len(operations) - attempted, "Includes intentionally excluded endpoints"),
        ])
        body += '<p class="note">Search by endpoint or category to identify collection gaps. Path parameters and query values are not recorded. A received response may still be empty, partial or uninterpretable. Not attempted includes endpoints outside the collection scope.</p>'
        labels = {"not_attempted": "Not attempted", "no_response": "No successful response",
                  "mixed_outcomes": "Mixed outcomes", "response_received": "Response received"}
        from .coverage_policy import keyed_gap_context, gap_handling
        gap_context = keyed_gap_context(bundle)
        ordered_operations = sorted(operations, key=lambda r: ({"no_response": 0, "mixed_outcomes": 1, "not_attempted": 2,
                                                      "response_received": 3}.get(r["status"], 4), r["path"]))
        operation_batch, operation_controls = coverage_batch(root, name, query, "operations", ordered_operations,
            lambda r: " ".join((*r["groups"], r["path"], labels.get(r["status"], r["status"]),
                str(r["attempted"]), str(r["received"]), " ".join(f"{pretty(k)}: {v}" for k, v in r["outcomes"].items()),
                gap_handling(r, gap_context))))
        body += operation_controls
        operation_rows = []
        for row in operation_batch:
            outcomes = ", ".join(f"{pretty(k)}: {v}" for k, v in sorted(row["outcomes"].items()))
            operation_rows.append(tr(e(", ".join(row["groups"])), e(row["path"]),
                                     e(labels.get(row["status"], row["status"])),
                                     str(row["attempted"]), str(row["received"]), e(outcomes or "None"),
                                     e(gap_handling(row, gap_context))))
        body += table(("Category", "GET path", "Read result", "Attempts", "Responses", "Outcomes", "Current handling / next step"), operation_rows, search=True)
        body += '<p class="note">Current handling describes tool policy, not whether the saved capture attempted or qualified the endpoint. A path selector is not the only possible required parameter.</p>'
        body += '<p>Other or ambiguous GET paths: ' + str(sum(ledger.get("unmatched_get_outcomes", {}).values())) + ' calls. These are not attributed to a documented path.</p></section>'
    else:
        body += '<section id="coverage-operations"><h2>Documented API operation coverage</h2><p class="muted">Not recorded in this snapshot. Collect a fresh audit.</p></section>'
    structured_records = sorted(records, key=lambda r: ({"unqualified": 0, "partial": 1, "qualified": 2}[r["status"]], r["persona"], r["module"]))
    structured_batch, structured_controls = coverage_batch(root, name, query, "structured", structured_records,
        lambda r: " ".join((r["persona"], persona_label(r["persona"]), r["module"], module_label(r["module"]),
                           r["status"], str(r["qualified"]), str(r["total"]))), page_size=50)
    rows = [tr(e(persona_label(r["persona"])), e(module_label(r["module"])), f'{r["qualified"]}/{r["total"]}', status(r["status"]),
               f'<a href="{url(root, "report", snapshot=name, persona=r["persona"], module=r["module"], view="diagnostics")}">View evidence</a>')
            for r in structured_batch]
    body += '<section id="coverage-structured"><h2>Scoped configuration</h2>' + structured_controls + table(("Device function", "Module", "Qualified scopes", "Read status", ""), rows, search=True) + '</section>'
    structured_library = library.get("modules", {})
    library_records = [(m, "structured", v) for m, v in sorted(structured_library.items())]
    library_records += [(m, "raw", additional.get(m, {}).get("library", {}))
                        for m in sorted((unknown | survey | set(additional)) - set(structured_library))]
    library_batch, library_controls = coverage_batch(root, name, query, "library", library_records,
        lambda r: " ".join((r[0], module_label(r[0]), "Adapter available" if r[1] == "structured" else "Raw evidence",
                           "Observed type" if r[0] in unknown else "Documented survey",
                           pretty(r[2].get("status", "not_collected")),
                           "Count confirmed" if r[2].get("count_confirmed" if r[1] == "structured" else "collection_count_verified") else "Count unverified",
                           str(len(r[2].get("profiles", {}))))), page_size=50)
    rows = []
    for m, kind, v in library_batch:
        if kind == "structured":
            rows.append(tr(e(module_label(m)), badge("Adapter available"), status(v.get("status", "not_collected")),
                           str(len(v.get("profiles", {}))) if v.get("status") == "list_parsed" else "Unavailable",
                           e("Count confirmed" if v.get("count_confirmed") else "Count unverified"),
                           f'<a href="{url(root, "library", snapshot=name, module=m)}">Open collection</a>'))
        else:
            source = "Observed type" if m in unknown else "Documented survey"
            rows.append(tr(e(module_label(m)), badge("Raw evidence", "warn") + f'<small>{e(source)}</small>',
                           status(v.get("status", "not_collected")), "Unavailable",
                           e("Count confirmed" if v.get("collection_count_verified") else "Count unverified"),
                           f'<a href="{url(root, "unadapted", snapshot=name, module=m)}">Inspect evidence</a>'))
    body += '<section id="coverage-library"><h2>Distinct Library profile collections</h2><p>Modules with both structured and supplemental reads appear once. Supplemental evidence remains available from the collection or the scoped evidence table.</p>' + library_controls + table(
        ("Profile type", "Interpretation", "Library read", "Parsed profiles", "Collection count", ""), rows, search=True) + '</section>'
    if additional:
        supplemental_records = []
        for m, v in sorted(additional.items()):
            reads = [s[k] for s in v.get("source_views", []) for k in ("committed", "effective")]
            captured = sum(r.get("status") == "response_received" for r in reads)
            counted = sum(r.get("collection_count_verified") is True for r in reads)
            catalog_scope = v.get("catalog_scope_coverage", {})
            gap = catalog_scope.get("unfiltered_scopes_not_surveyed", catalog_scope.get("all_function_scopes_not_surveyed"))
            supplemental_records.append((m, len(v.get("source_views", [])), captured, len(reads), counted, gap))
        supplemental_batch, supplemental_controls = coverage_batch(root, name, query, "supplemental", supplemental_records,
            lambda r: " ".join((r[0], module_label(r[0]), *(str(x) for x in r[1:]))), page_size=50)
        scoped = [tr(e(module_label(m)), str(attempted), f"{captured}/{total}", str(counted),
                     str(gap) if gap is not None else "Unavailable",
                     f'<a href="{url(root, "unadapted", snapshot=name, module=m)}">Inspect settings</a>')
                  for m, attempted, captured, total, counted, gap in supplemental_batch]
        body += '<section id="coverage-supplemental"><h2>Additional scoped configuration</h2><p class="filter-hint">These reads preserve returned data without assuming profile identity or scope applicability. Scopes not surveyed are not verified empty. Fast catalog may miss previously unobserved local-only configuration; use Deep catalog for all supplemental scope surveys. Rejected or incomplete reads remain visible.</p>' + supplemental_controls + table(
            ("Profile type", "Scope views attempted", "Responses captured", "Count-confirmed reads", "Unfiltered scopes not surveyed", ""), scoped, search=True) + '</section>'

    return page("Module coverage", body, workspace.nav(name), extra_css=COVERAGE_CSS)


def explorer_view(workspace, query):
    if query.get("mode") == "entities":
        from .entity_search import entity_search_view
        return entity_search_view(workspace, query)
    if query.get("mode") == "evidence":
        from .configuration_search import evidence_view
        return evidence_view(workspace, query)
    if query.get("mode") == "search":
        from .configuration_search import search_view
        return search_view(workspace, query)
    from .central_tool import config_review_rows, configuration_view_shape
    loaded, empty = load(workspace, query, "Configuration explorer", "report")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    personas = sorted(bundle["results"])
    if not personas:
        return page("Configuration explorer", intro("Configuration", "No configuration captured.", picker), workspace.nav(name))
    persona = query.get("persona", personas[0])
    if persona not in personas:
        raise ValueError("Unknown persona")
    entry = bundle["results"][persona]
    scope = query.get("scope", "")
    modules = sorted(entry["modules"])
    module = query.get("module", "" if scope else ("layer2-vlan" if "layer2-vlan" in modules else modules[0] if modules else ""))
    if module and module not in modules:
        raise ValueError("Unknown module")
    if scope and scope not in {s["id"] for s in entry["scopes"]}:
        raise ValueError("Unknown scope")
    mode = query.get("view", "diagnostics" if query.get("diagnostics") else "all" if scope else "local")
    if mode not in ("all", "local", "diagnostics"):
        raise ValueError("Unknown view")
    identity_filter = query.get("identity")
    if identity_filter is not None and (not module or not scope or mode == "diagnostics"):
        raise ValueError("An exact profile filter requires a scope and module")
    from .review_dispositions import snapshot_binding
    binding = snapshot_binding(workspace, name, bundle)
    detail_only = query.get("detail") == "1"
    if detail_only and (not module or not scope or query.get("binding") != binding
                        or (mode != "diagnostics" and identity_filter is None)):
        raise ValueError("Profile or snapshot changed; reopen the configuration explorer")
    render_details = detail_only or identity_filter is not None or (mode == "diagnostics" and bool(scope and module))
    def control(mod, view, title, identity=None):
        params = dict(snapshot=name, persona=persona, module=mod, scope=view["scope"], view=mode)
        if identity is not None:
            params["identity"] = identity
        href = url(root, "report", **params)
        endpoint = url(root, "report", **params, detail="1", binding=binding)
        return (f'<button type="button" class="quiet inspect-trigger" data-inspect data-inspect-url="{endpoint}">Inspect</button>'
                f'<noscript><a href="{href}">Inspect {e(title)}</a></noscript>')
    def detail_template(title, content):
        return '<template data-advisor-evidence><div class="inspector-title"><h2>' + e(title) + '</h2></div>' + content + '</template>'
    controls = scope_filter_form(root, "report", name, bundle, persona, (
        ("module", "Module", module, module_options),
        ("scope", "Scope", scope, lambda entry: [("", "All scopes")] + sorted(
            [(s["id"], f'{pretty(s["kind"])} / {s.get("name") or s["id"]}') for s in entry["scopes"]],
            key=lambda pair: pair[1].casefold()))),
        submit="Show", extra_fields=(("view", "View", mode, [("local", "Local profiles"), ("all", "All captured profiles"),
                                  ("diagnostics", "Incomplete API results")]),))
    rows = []
    records = [r for r in config_review_rows(bundle) if r[0] == persona and (not module or r[1] == module) and (not scope or r[3]["scope"] == scope)]
    for _, mod, scope_name, view in records:
        review = view["review"]
        if not review["qualified"]:
            if mode == "diagnostics":
                if render_details:
                    content = raw({"local": configuration_view_shape(view["local_view"]),
                                   "effective": configuration_view_shape(view["effective_view"]), "review": review})
                    if detail_only:
                        return detail_template(scope_name, content)
                    action = inspect(scope_name, content)
                else:
                    action = control(mod, view, scope_name)
                rows.append(tr(e(scope_name), e(module_label(mod)), "—", badge("Not qualified"), action))
            elif mode == "all":
                # Show independently parsed bodies even if the other read failed.
                # Do not feed these incomplete views into consolidation.
                from .central_tool import CONFIG_MODULES, observed_profile_candidates, profile_body
                available = {kind: observed_profile_candidates(view[kind + "_view"], CONFIG_MODULES[mod][0])
                             if mod in CONFIG_MODULES else view[kind + "_view"].get("profiles", {})
                             for kind in ("local", "effective")}
                for identity in sorted(set().union(*(p.keys() for p in available.values()))):
                    if identity_filter is not None and identity != identity_filter:
                        continue
                    saved = available.get("local", {}).get(identity)
                    effective = available.get("effective", {}).get(identity)
                    title = title_profile(identity, saved or effective)
                    if render_details:
                        detail = '<p class="note">Only independently retrieved settings are shown. Source and comparison are not verified.</p>'
                        if saved is not None:
                            detail += '<h3>Saved settings</h3>' + property_table(profile_body(saved))
                        if effective is not None:
                            detail += '<h3>Effective settings</h3>' + property_table(profile_body(effective))
                        detail += keyed_profile_evidence(bundle, persona, view["scope"], mod, identity)
                        if detail_only:
                            return detail_template(title, detail)
                        action = inspect(title, detail)
                    else:
                        action = control(mod, view, title, identity)
                    rows.append(tr(e(scope_name), e(module_label(mod)), e(title),
                                   badge("Partial evidence", "warn") + '<small>Source and comparison are not verified.</small>', action))
            continue
        if mode == "diagnostics":
            continue
        for r in review["profiles"]:
            if identity_filter is not None and r["identity"] != identity_filter:
                continue
            if mode == "local" and (r["local"] is None or r["status"] == "default_profile"):
                continue
            title = title_profile(r["identity"], r["local"] or r["effective"])
            if render_details:
                detail = '<h3>Global comparison</h3>' + diff_table(r["global_differences"], "Local", "Global") + '<h3>Effective settings</h3>' + property_table(r["effective"]) + raw(r)
                detail += keyed_profile_evidence(bundle, persona, view["scope"], mod, r["identity"])
                if detail_only:
                    return detail_template(title, detail)
                action = inspect(title, detail)
            else:
                action = control(mod, view, title, r["identity"])
            rows.append(tr(f'<strong>{e(scope_name)}</strong><small>{e(pretty(view["scope_kind"]))}</small>', e(module_label(mod)), e(title),
                           badge(profile_state_label(r["status"]), "good" if r["status"] in ("inherited", "shared", "local_matches_global") else "warn" if r["status"] in ("source_conflict", "local_differs_from_global", "local_effective_mismatch") else "neutral"), action))
    if detail_only:
        raise ValueError("Profile evidence no longer available; reopen the configuration explorer")
    q = sum(v["review"]["qualified"] for _, _, _, v in records)
    body = intro("Configuration", "Inspect captured profiles at a selected scope or module.", picker) + '<section class="filter-section">' + controls + '</section>'
    body += f'<p><a class="button" href="{url(root, "report", snapshot=name, mode="search")}">Search all captured configuration</a></p>'
    body += f'<p><a class="button" href="{url(root, "report", snapshot=name, mode="entities")}">Find devices and profiles</a></p>'
    if identity_filter is not None:
        body += '<p>Exact profile: <strong>' + e(identity_filter) + '</strong> · '
        body += f'<a href="{url(root, "report", snapshot=name, persona=persona, scope=scope, module=module, view=mode)}">Show all profiles at this scope</a></p>'
    body += f'<section><h2>{len(rows)} records</h2><p class="muted">{q}/{len(records)} selected scope views qualified.</p>' + table(("Scope", "Module", "Profile", "Source / state", ""), rows, search=True) + '</section>'
    body += f'<p class="note">For grouped consolidation recommendations, open <a href="{url(root, "advisor", snapshot=name)}">Consolidation</a>. Global comparison does not establish inheritance or safe removal.</p>'
    # Preserve the standalone report and CSV export through a separate optional route.
    body += f'<p><a href="{url(root, "legacy-report", snapshot=name)}">Open full evidence report / CSV export</a></p>'
    return page("Configuration explorer", body, workspace.nav(name))
