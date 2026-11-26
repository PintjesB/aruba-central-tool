"""Task-oriented workspace screens. Analysis and write eligibility are unchanged."""
import json
from collections import Counter
from urllib.parse import urlencode

from workspace_ui import (e, page, intro, metrics, snapshot_picker, module_label,
                          persona_label, pretty, status, badge, raw, table, tr, profile_state_label,
                          inspect, diff_table, property_table)


def load(workspace, query, title, route):
    from config_app import audit_files, read_audit
    from central_tool import refresh_configuration_review
    root = "/" + workspace.token + "/"
    files = audit_files(workspace.directory)
    if not files:
        return None, page(title, intro(title) + '<section class="empty">No snapshots available. Connect from Overview.</section>', workspace.nav())
    name = query.get("snapshot", files[0].name)
    bundle = refresh_configuration_review(read_audit(workspace.directory, name))
    return (root, name, bundle, snapshot_picker(root, route, files, name)), None


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
    "remove_override": ("Matches Global", "Local and Global settings are identical. Check the actual inherited source before removing the local copy.", "Check inheritance, then remove if unchanged."),
    "promote_local": ("Repeated local profiles", "The same profile identity and settings occur at multiple scopes. Consider a common higher scope or a Library assignment.", "Choose where the shared configuration belongs."),
    "reuse_library": ("Matches Library", "An existing Library profile has the same identity and settings. Reuse it instead of maintaining another copy, if assignment and inheritance allow.", "Review assignment and removal of local copies."),
    "create_library": ("Optional Library placement", "A local definition could be reusable, but repeated use has not been established. Keeping it local may be appropriate.", "Leave local unless there is a reason to reuse it."),
    "conflict": ("Different definitions", "The same profile identity has different settings in the captured configuration. The difference may be intentional.", "Compare settings and retain intentional exceptions."),
    "default_review": ("VLAN settings to verify", "The VLAN comparison includes omitted fields, possible defaults or Layer 3 indicators. Equal network behavior is not established.", "Verify the differences before considering removal."),
    "unassigned_library": ("No assignment observed", "The captured assignment records contain no matching entry. This does not prove the profile is unused or safe to delete.", "Check references and intended future use; retain by default."),
}
OPPORTUNITIES = ("remove_override", "promote_local", "reuse_library")
SHORT_REASON = {
    "remove_override": "Exact match with Global",
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
    from central_tool import assess_vlan_reference
    if local is None or reference is None:
        return ""
    saved = local
    if evidence is not None:
        local = evidence['local']
        effective = evidence['comparison']
    # The original saved/reference diff alone hides fields present only in
    # effective or recovered configuration. Include every observed setting,
    # keeping precise nested difference paths where available.
    comparisons = {}
    for body in (saved, local, effective):
        if isinstance(body, dict):
            for d in assess_vlan_reference(body, reference)["differences"]:
                comparisons.setdefault(tuple(d["path"]), d)
    for key in sorted(set().union(*(b.keys() for b in (saved, local, effective, reference) if isinstance(b, dict)))):
        if not any(path and path[0] == key for path in comparisons):
            comparisons[(key,)] = {"path": [key], "assessment": "matching"}
    # Always expose the known VLAN settings, including when every source omits
    # them. An absent value is not a disabled setting or an equality result.
    for key in ("name", "enable", "voice-enable", "igmp", "mld", "dhcpv4-snooping", "dhcpv6-snooping"):
        if not any(path and path[0] == key for path in comparisons):
            comparisons[(key,)] = {"path": [key], "assessment": "unavailable"}
    def has_value(body, path):
        for key in path:
            if isinstance(body, dict) and key in body:
                body = body[key]
            elif isinstance(body, list) and isinstance(key, int) and 0 <= key < len(body):
                body = body[key]
            else:
                return False
        return body is not None
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
            display = json.dumps(value, ensure_ascii=False)
        return e(display) + (f'<small>{e(source)}</small>' if source else '')
    def result_for(d):
        path = d["path"]
        if not has_value(effective, path) or not has_value(reference, path):
            return "unavailable", "Unavailable", "Cannot compare: value unavailable"
        if evidence is not None and evidence["conflicts"]:
            # A conflict on this field is not a verified match. Keep the
            # full conflict list visible separately, without flagging every row.
            field = ".".join(map(str, path))
            if any(v == field or v.endswith("." + field) or ("." + field + ".") in v
                   for v in evidence["conflicts"]):
                return "conflict", "Conflict", "Check conflicting observations"
        def at(body):
            for key in path:
                body = body[key]
            return body
        from central_tool import canonical
        if canonical(at(effective)) == canonical(at(reference)):
            return "matching", "Match", "Observed value matches reference"
        return "different", "Different", "Observed value differs from reference"
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
    counts = Counter()
    priority = {"different": 0, "conflict": 1, "unavailable": 2, "matching": 3}
    ordered = sorted(comparisons.values(), key=lambda d: (
        priority[result_for(d)[0]], list(labels).index(d["path"][0]) if d["path"][0] in labels else len(labels),
        tuple(map(str, d["path"]))))
    for d in ordered:
        kind, label, explanation = result_for(d)
        counts[kind] += 1
        tone = {"matching": "good", "different": "warn", "conflict": "warn", "unavailable": "neutral"}[kind]
        result = f'<span class="tag {tone}" title="{e(explanation)}">{e(label)}</span>'
        rows.append(tr(e(field_label(d["path"])), observed_cell(local, d["path"], "local"),
                       observed_cell(effective, d["path"], "comparison"), observed_cell(reference, d["path"], "reference"),
                       result, attrs=f' data-comparison="{kind}"'))
    summary = '<div class="comparison-summary" aria-label="Comparison summary">' + "".join(
        badge(f"{counts[kind]} {label}", tone) for kind, label, tone in (
            ("different", "different", "warn"), ("conflict", "conflicting", "warn"),
            ("unavailable", "unavailable", "neutral"), ("matching", "matching", "good"))) + '</div>'
    return summary + table(("Setting", "Saved locally", "Effective at source", "Global / reference", "Result"),
                           rows, style="comparison-table") + conflict + '<p class="note">Unavailable: Central did not provide a verified value. Not returned: the saved local field was omitted. A named switch source indicates device evidence; otherwise the value is from Central configuration, not a live switch CLI measurement.</p>'


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
    from central_tool import configuration_operational_vlan
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


def advisor_view(workspace, query):
    from consolidation import profile_recommendations
    loaded, empty = load(workspace, query, "Consolidation advisor", "advisor")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    findings = profile_recommendations(bundle)
    # Exact deep links from the device override inspector preserve the full group.
    scope_filter, identity_filter = query.get("scope"), query.get("identity")
    if scope_filter and identity_filter:
        findings = [f for f in findings if f["action"] == "remove_override"
                    and f["persona"] == query.get("persona") and f["module"] == query.get("module")
                    and f["identity"] == identity_filter and any(s["scope"] == scope_filter for s in f["sources"])]
    short = {key: value[0] for key, value in ACTION_GUIDE.items()}
    counts = Counter(f["action"] for f in findings)
    recommendation_options = [
        ("opportunities", f"Consolidation opportunities ({sum(counts[k] for k in OPPORTUNITIES)})"),
        ("review", f"Settings to review ({counts['conflict'] + counts['default_review']})"),
        ("optional", f"Optional Library review ({counts['create_library'] + counts['unassigned_library']})"),
        ("", f"All findings ({len(findings)})")] + [(k, f"{v[0]} ({counts[k]})") for k, v in ACTION_GUIDE.items()]
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
        placement = e(ACTION_GUIDE[action][2])
        if action == "promote_local":
            choices = [("", "Choose destination for review"), ("library", "Library / exact source scopes")]
            choices += [(p["scope"], f'{pretty(p["kind"])} / {p["name"]} · {len(p["additional_devices"])} extra, {len(p["unknown_membership"])} unknown')
                        for p in f["placement_options"]]
            placement = '<select class="destination" aria-label="Proposed destination">' + "".join(
                f'<option value="{e(key)}">{e(value)}</option>' for key, value in choices) + '</select>'
        source_table = table(("Scope", "Type", "Finding"), [tr(e(s["name"]), e(pretty(s["kind"])), e(profile_state_label(s["status"]))) for s in sources]) if sources else '<p class="muted">Library definition.</p>'
        device_rows = [tr(e(d["name"]), status(k)) for k in ("matching", "different", "absent", "unknown") for d in observed.get(k, [])]
        scope_rows = [tr(e(s["name"]), e(pretty(s["kind"])), status(s["effective"])) for s in f["scope_references"]]
        placement_rows = [tr(e(p["name"]), e(pretty(p["kind"])), str(len(p["intended_devices"])),
                           str(len(p["additional_devices"])), str(len(p["unknown_membership"])), status(p["effective"]))
                          for p in f["placement_options"]]
        reference_label = "Library" if action == "reuse_library" else "Global" if action in ("remove_override", "default_review") else "Reference"
        comparison = ""
        if action == "default_review":
            from central_tool import vlan_comparison_evidence
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
        details = (
            f'<div class="review-decision"><div><strong>{e(ACTION_GUIDE[action][2])}</strong><p>{e(ACTION_GUIDE[action][1])}</p></div></div>'
            + comparison
            + ('<h3>Destination impact</h3>' + table(("Destination", "Type", "Intended", "Additional", "Unknown", "Current"), placement_rows) if placement_rows else "")
            + '<h3>Proposed workflow</h3>' + list_items(f["steps"], ordered=True)
            + '<h3>Validation required</h3>' + list_items(f["blockers"])
            + '<details><summary>Affected scopes and devices</summary>' + source_table
            + ('<h3>Observed device configuration</h3>' + table(("Device", "Profile state"), device_rows) if device_rows else "")
            + ('<h3>Higher-scope configuration</h3>' + table(("Scope", "Type", "Effective body"), scope_rows) if scope_rows else "") + '</details>'
            + '<details><summary>Source evidence</summary>'
            + (vlan_instance_context(bundle, f["persona"], sources, f["identity"]) + operational_vlan_context(bundle, f["persona"], sources, f["identity"]) if f["module"] == "layer2-vlan" else "") + raw(f) + '</details>')
        matching = len(observed.get("matching", []))
        unknown = len(observed.get("unknown", []))
        device_summary = f'<strong>{matching} / {sum(len(v) for v in observed.values())}</strong>' + (f'<small>{unknown} not comparable</small>' if unknown else "") if observed else '<span class="muted">Not assessed</span>'
        # Filter by row metadata; the inspector and plan payload are inert.
        rows.append(tr(
            f'<input type="checkbox" class="choose" aria-label="Select {e(profile)}" data-plan="{e(json.dumps(f, ensure_ascii=False))}"{" disabled" if action not in OPPORTUNITIES else ""}>',
            summary, badge(short[action], "warn" if action in ("conflict", "default_review") else "info" if action in OPPORTUNITIES else "neutral") + f'<small>{e(SHORT_REASON[action])}</small>',
            f'<strong>{len(sources)}</strong><small>{e(names or "Library definition")}</small>', placement, device_summary,
            inspect(profile, details, "Review"),
            attrs=f' data-action="{e(action)}" data-module="{e(f["module"])}" data-persona="{e(f["persona"])}" data-search="{e(profile+" "+str([s["name"] for s in sources]))}"'))
    filters = (
        '<div class="filter-bar advisor-filters">'
        + select("finding-type", recommendation_options, "opportunities", "Recommendation")
        + select("module", [("", "All modules")] + [(m, module_label(m)) for m in sorted({f["module"] for f in findings})], label="Module")
        + select("persona", [("", "All functions")] + [(p, persona_label(p)) for p in sorted({f["persona"] for f in findings})], label="Device function")
        + '<label class="searchbox">Search<input id="search" type="search" placeholder="Profile or scope"></label>'
        '<button id="clear" type="button" class="quiet">Reset</button></div>')
    listing = '<div id="advisor-table">' + table(("Select", "Profile", "Why flagged", "Local copies", "Suggested next step", "Devices with identical settings", ""), rows) + '</div>'
    bar = ('<div class="selection-bar"><div><strong id="selected" aria-live="polite">0 selected</strong>'
           '<small>Preview only · no Central writes</small></div><div class="selection-actions">'
           '<button id="select-visible" type="button">Select all filtered</button><button id="clear-selection" type="button">Clear</button>'
           '<button id="open-preview" type="button" class="primary" disabled>Review selected</button></div></div>')
    dialog = ('<dialog id="plan-dialog" class="inspector" aria-labelledby="plan-title"><div class="inspector-head"><h2 id="plan-title">Selected change preview</h2>'
              '<button id="close-preview" type="button">Close</button></div><div class="plan-content">'
              '<p class="note">These steps are not executable API operations. All writes require separate qualification and approval.</p>'
              '<div id="preview"></div><button id="export-plan" type="button" class="primary" disabled>Export private preview JSON</button>'
              '</div></dialog>')
    return page("Consolidation advisor", intro("Consolidation", "Choose a task, inspect the evidence, and prepare a change preview.", picker)
                + '<section><div id="snapshot-label" hidden data-snapshot="' + e(name) + '"></div>'
                + filters + '<div class="table-toolbar"><span id="visible-count" class="muted" aria-live="polite"></span>'
                '<div><button id="advisor-prev" type="button">Previous</button> <span id="advisor-page" class="muted"></span> '
                '<button id="advisor-next" type="button">Next</button></div></div>'
                + listing + '<p id="advisor-empty" class="empty" hidden>No matching recommendations.</p></section>'
                + bar + dialog + '<script>' + ADVISOR_JS + '</script>', workspace.nav(name), ADVISOR_CSS)


ADVISOR_CSS = """
.advisor-filters{margin-bottom:14px}.advisor-filters select{min-width:135px}.advisor-filters .searchbox{min-width:150px}
#advisor-table td:nth-child(2){min-width:145px}#advisor-table td:nth-child(5){max-width:290px;min-width:160px}
#advisor-table td:nth-child(5) select{width:100%;font-size:12px}
#advisor-table th:first-child{font-size:0;width:38px}.selection-bar{position:sticky;bottom:12px;z-index:3;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:14px 18px;background:var(--surface);border:1px solid var(--line);box-shadow:0 5px 24px #0002;border-radius:10px}
.selection-bar small{display:block}.selection-actions{display:flex;gap:8px;flex-wrap:wrap}.plan-content{flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:22px}.plan-item{padding:14px 0;border-bottom:1px solid var(--line)}.plan-item h3{margin:0 0 5px}.plan-item p{margin:4px 0}.tabs button[aria-pressed=true]{border-bottom-color:var(--accent);color:var(--accent);font-weight:700}
"""
ADVISOR_JS = r"""
(()=>{
'use strict';
const $=id=>document.getElementById(id), rows=Array.from($('advisor-table').querySelectorAll('tbody > tr'));
const checks=rows.map(r=>r.querySelector('.choose'));
const categories={opportunities:['remove_override','promote_local','reuse_library'],review:['conflict','default_review'],optional:['create_library','unassigned_library']};
let page=0, filtered=[];const size=30;
function filter(reset=true){
 if(reset)page=0;
 const q=$('search').value.toLowerCase().trim();
 const action=$('finding-type').value;
 filtered=rows.filter(r=>(!action||(categories[action]?categories[action].includes(r.dataset.action):r.dataset.action===action))&&(!$('module').value||r.dataset.module===$('module').value)&&(!$('persona').value||r.dataset.persona===$('persona').value)&&((r.dataset.search+' '+r.textContent).toLowerCase().includes(q)));
 const pages=Math.max(1,Math.ceil(filtered.length/size));page=Math.min(page,pages-1);
 const visible=new Set(filtered.slice(page*size,(page+1)*size));
 for(const r of rows)r.hidden=!visible.has(r);
 $('visible-count').textContent=filtered.length+' of '+rows.length+' recommendations';
 $('advisor-page').textContent=(page+1)+' / '+pages;$('advisor-prev').disabled=page===0;$('advisor-next').disabled=page+1>=pages;
 $('advisor-empty').hidden=filtered.length>0;
 $('advisor-prev').parentElement.hidden=pages<=1;
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
  }
  return f;
 });
 $('selected').textContent=chosen.length+' selected';
 $('clear-selection').disabled=!chosen.length;
 $('open-preview').disabled=!chosen.length;
 $('export-plan').disabled=!chosen.length||chosen.some(f=>f.action==='promote_local'&&!f.selected_destination);
 return chosen;
}
function el(tag,text){const n=document.createElement(tag);n.textContent=text;return n;}
function preview(){
 const chosen=selection();$('preview').replaceChildren();
 for(const f of chosen){
  const item=document.createElement('div');item.className='plan-item';
  item.append(el('h3',f.module+' / '+f.identity),el('p',({remove_override:'Check matching Global override',promote_local:'Consolidate repeated local profiles',reuse_library:'Reuse matching Library profile'}[f.action]||f.action)+' · '+f.target));
  const steps=document.createElement('ol');for(const s of f.steps)steps.append(el('li',s));item.append(steps);
  const blockers=document.createElement('details');blockers.append(el('summary','Validation required ('+f.blockers.length+')'));
  const ul=document.createElement('ul');for(const b of f.blockers)ul.append(el('li',b));blockers.append(ul);item.append(blockers);$('preview').append(item);
 }
 if(chosen.some(f=>f.action==='promote_local'&&!f.selected_destination))$('preview').append(el('p','Select a destination for each consolidation recommendation before exporting.'));
}
for(const k of ['module','persona','finding-type'])$(k).addEventListener('change',()=>filter());
$('search').addEventListener('input',()=>filter());
$('clear').addEventListener('click',()=>{$('finding-type').value='opportunities';$('module').value='';$('persona').value='';$('search').value='';filter();});
$('advisor-prev').addEventListener('click',()=>{page--;filter(false);});$('advisor-next').addEventListener('click',()=>{page++;filter(false);});
for(const c of checks)c.addEventListener('change',selection);
for(const field of document.querySelectorAll('.destination'))field.addEventListener('change',selection);
$('select-visible').addEventListener('click',()=>{for(const r of filtered){const check=r.querySelector('.choose');if(!check.disabled)check.checked=true;}selection();});
$('clear-selection').addEventListener('click',()=>{for(const c of checks)c.checked=false;selection();});
$('open-preview').addEventListener('click',()=>{preview();$('plan-dialog').showModal();$('plan-dialog').querySelector('.plan-content').scrollTop=0;});
$('close-preview').addEventListener('click',()=>$('plan-dialog').close());
$('export-plan').addEventListener('click',()=>{
 const chosen=selection();if($('export-plan').disabled)return;
 const content=JSON.stringify({schema:1,kind:'consolidation_preview',safe_to_apply:false,snapshot:$('snapshot-label').dataset.snapshot,recommendations:chosen},null,2);
 const u=URL.createObjectURL(new Blob([content],{type:'application/json'})),a=document.createElement('a');a.href=u;a.download='consolidation-preview.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);
});
filter();selection();
})();
"""


def usage_cells(usage):
    assignments = (str(usage["assignment_count"]) if usage["assignment_status"] == "response_received" else "Unknown")
    return (e(assignments), str(len(usage["shared_devices"])), str(usage["reference_count"]),
            str(len(usage["unknown_devices"])))


def usage_detail(usage):
    return ('<h3>Observed usage</h3>'
            + table(("Measure", "Count"), [
                tr("Distinct scope/function assignments", usage_cells(usage)[0]),
                tr("Devices with matching shared profile", usage_cells(usage)[1]),
                tr("Distinct configuration objects referencing this name", usage_cells(usage)[2]),
                tr("Devices with incomplete module reads", usage_cells(usage)[3]),
                tr("Devices with matching settings but unverified Library source", str(len(usage["matching_other_devices"])))])
            + '<h3>Assigned at</h3>' + table(("Scope", "Device function"), [
                tr(e(a.get("scope-name", a.get("scope-id", "Unknown"))), e(persona_label(a.get("device-function", "")))) for a in usage["assignments"]])
            + '<h3>Devices with matching shared configuration</h3>' + list_items([d["name"] for d in usage["shared_devices"]])
            + '<h3>Configuration references</h3>' + table(("Device", "Module", "Object"), [
                tr(e(r["device"]), e(module_label(r["source_module"])), e(r["source"])) for r in usage["references"]])
            + '<p class="note">These are separate observations, not traffic usage. Zero observed references does not prove a profile is unused. Reference coverage is incomplete.</p>')


def engineering_view(workspace, query):
    from advanced_review import advanced_analysis, library_usage, preferred_duplicate
    from central_tool import field_differences
    loaded, empty = load(workspace, query, "Engineering review", "advanced")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    data = advanced_analysis(bundle)
    panels = []
    def panel(key, label, hint, headers, rows, count):
        panels.append((key, label, count, f'<section data-panel="{key}" data-group="engineering"><p class="filter-hint">{e(hint)}</p>'
                       + table(headers, rows, search=True) + '</section>'))
    rows = []
    for i, record in enumerate(data["port_groups"], 1):
        ports = record["ports"]
        matches = record.get("matching_library_profiles", [])
        devices = sorted({p["device"] for p in ports})
        settings = record["portable_settings"]
        match_usage = library_usage(bundle, "sw-port-profiles", [m["identity"] for m in matches], data["references"])
        preferred = preferred_duplicate(match_usage) if len(match_usage) > 1 else next(iter(match_usage), None)
        summary = property_table(settings)
        mapping = table(("Device", "Port", "Description"), [tr(e(p["device"]), e(p["port"]), e(p.get("description") or "")) for p in ports])
        visibility = [tr(e(m["identity"]), e(v["device"]), status(v["status"])) for m in matches for v in m["visibility"]]
        details = ('<h3>Shared settings</h3>' + summary + '<h3>Ports to review</h3>' + mapping
                   + ('<h3>Matching Library profiles</h3>' + table(("Profile", "Device", "Visibility"), visibility) if visibility else '<h3>Placement</h3><p>Review creation of a reusable switch port profile.</p>')
                   + ('<h3>Existing profile usage</h3>' + table(("Profile", "Assignments", "Shared devices", "Referencing objects", "Unknown device reads"), [tr(e(identity), *usage_cells(u)) for identity, u in match_usage.items()]) if match_usage else "")
                   + '<h3>Recommended next step</h3><p>' + e("Review existing profile " + preferred if preferred else "Compare matching profiles and select a canonical name" if matches else "Review creating a reusable port profile") + '. Preserve each port mapping and description.</p>'
                   + '<h3>Validation required</h3>' + list_items(record.get("blockers", [])) + raw(record))
        rows.append(tr(f'<strong>Port group {i}</strong><small>{e(persona_label(record["persona"]))}</small>',
                       str(len(ports)), str(len(devices)), e(preferred or ", ".join(m["identity"] for m in matches) or "New profile candidate") + (f'<small>{len(matches)} matching profiles</small>' if len(matches) > 1 else ""),
                       badge("Unsupported fields" if record["unsupported_fields"] else "Review port mapping", "warn" if record["unsupported_fields"] else "info"),
                       inspect(f"Port group {i}", details)))
    panel("ports", "Port consolidation", "Repeated settings grouped by exact body. Physical mapping and descriptions are preserved.",
          ("Group", "Ports", "Devices", "Existing Library profile", "Next step", ""), rows, len(rows))
    rows = []
    # Group the same winning/higher scope and bodies across devices instead of repeating rows.
    grouped = {}
    from central_tool import canonical
    for rec in data["shadowed"]:
        key = (rec["persona"], rec["module"], rec["identity"], rec["winning_scope_id"], rec["higher_scope_id"],
               canonical(rec["effective"]), canonical(rec["higher_body"]))
        grouped.setdefault(key, []).append(rec)
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
          ("Profile", "Applied from", "Higher-scope definition", "Devices", "Settings compared", "Suggested next step", ""), rows, len(rows))
    rows = []
    for r in data["library_duplicates"]:
        keep = r["suggested_keep"]
        usage = r["usage"]
        comparison = [tr(e(identity), *usage_cells(u),
                         badge("Suggested to keep", "info") if identity == keep else "Review")
                      for identity, u in usage.items()]
        choose_keep = '<label>Profile to retain<select data-keep>' + '<option value="">Choose a profile</option>' + "".join(f'<option value="{e(identity)}"{" selected" if identity == keep else ""}>{e(identity)}</option>' for identity in usage) + '</select></label>'
        preview_data = {identity: {"assignments": usage_cells(u)[0], "shared_devices": len(u["shared_devices"]), "referencing_objects": u["reference_count"], "unknown_reads": len(u["unknown_devices"])} for identity, u in usage.items()}
        detail = ('<h3>Choose the profile to retain</h3>'
                  + '<p>Prefer the profile with more observed referencing objects, then shared device deployments, then scope assignments. This can reduce migration work; it is not permission to delete another profile.</p>'
                  + table(("Profile", "Assignments", "Shared devices", "Referencing objects", "Unknown device reads", "Suggestion"), comparison)
                  + f'<div data-duplicate-preview data-usage="{e(json.dumps(preview_data))}">{choose_keep}<div data-migration-summary aria-live="polite">Choose a profile to preview the observed migration workload.</div><p class="note">Review only. No assignments, references or profiles will be changed.</p></div>'
                  + "".join(f'<details><summary>{e(identity)} · Where it is used</summary>{usage_detail(u)}</details>' for identity, u in usage.items())
                  + '<h3>Before consolidating</h3><ol><li>Choose the canonical name based on usage and naming standards.</li><li>Move assignments and references to that name.</li><li>Verify effective configuration and complete reverse references before deleting the old profile.</li></ol>'
                  + raw(r))
        # One decision per duplicate group. Keep all per-profile usage counts
        # aligned, rather than repeating the same review button for every member.
        cells = [usage_cells(u) for u in usage.values()]
        stack = lambda values: '<div class="usage-stack">' + "".join(f'<div>{v}</div>' for v in values) + '</div>'
        rows.append(tr(e(module_label(r["module"])),
                       stack([f'<strong>{e(identity)}</strong>' + (' <span class="retain-mark">Keep</span>' if identity == keep else "") for identity in usage]),
                       *(stack([values[index] for values in cells]) for index in range(4)),
                       e(keep or "Choose profile"), inspect(", ".join(r["identities"]), detail, "Review group")))
    panel("duplicates", "Duplicate Library profiles", "Each row is a duplicate group. Compare observed usage for each name before choosing which profile to retain.",
          ("Module", "Matching profiles", "Assignments", "Shared devices", "References", "Unknown reads", "Suggested keep", ""), rows, len(rows))
    for key, label, records in (("references", "Reference review", [r for r in data["references"] if r["status"] != "observed"]),
                                ("resolved", "Observed references", [r for r in data["references"] if r["status"] == "observed"])):
        rows = [tr(e(r["device"]), f'{e(module_label(r["source_module"]))}<small>{e(r["source"])}</small>',
                   f'{e(module_label(r["target_module"]))}<small>{e(r["target"] if r["target"] is not None else "Unknown")}</small>',
                   status(r["status"]), e("Keep reference; verify before profile removal" if r["status"] == "observed" else "Verify target profile and scope" if r["status"] == "not_observed" else "Collect or interpret missing reference evidence"), inspect("Reference evidence", property_table(r))) for r in records]
        panel(key, label, "Observed references are not a complete dependency graph. Not observed does not prove a broken dependency.",
              ("Device", "Source", "Target", "State", "Suggested next step", ""), rows, len(rows))
    tabs = '<div class="tabs" data-tabs="engineering">' + "".join(f'<button type="button" data-tab="{k}" aria-selected="false">{e(label)} <span>{n}</span></button>' for k, label, n, _ in panels) + '</div>'
    return page("Engineering review", intro("Engineering review", "Review reusable ports, scope precedence, Library duplication and references.", picker)
                + tabs + "".join(p[3] for p in panels) + '<script>' + DUPLICATE_JS + '</script>', workspace.nav(name))



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
 const list=document.createElement('ul');
 for(const [name,u] of Object.entries(usage)){
  if(name===keep)continue;
  const item=document.createElement('li');
  item.textContent=name+': '+u.assignments+' observed assignments, '+u.shared_devices+' matching shared devices, '+u.referencing_objects+' referencing objects, '+u.unknown_reads+' incomplete device reads.';
  list.append(item);
 }
 target.append(list);
}
document.addEventListener('change',event=>{
 if(event.target.matches('[data-keep]'))update(event.target.closest('[data-duplicate-preview]'));
});
document.addEventListener('click',event=>{
 if(event.target.closest('[data-inspect]'))requestAnimationFrame(()=>{
  for(const panel of document.querySelectorAll('#workspace-inspector-body [data-duplicate-preview]'))update(panel);
 });
});
})();
"""


def library_view(workspace, query):
    from config_app import library_profile_comparison
    from advanced_review import advanced_analysis, library_usage
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
    rows = []
    for key, view in sorted(modules.items()):
        if module and key != module:
            continue
        link = url(root, "library", snapshot=name, module=key)
        rows.append(tr(f'<a href="{link}">{e(module_label(key))}</a>', str(len(view["profiles"])), status(view["status"])))
    body = intro("Library", "Shared profiles and their observed assignments.", picker)
    if not module:
        body += '<section><h2>Profile collections</h2>' + table(("Module", "Profiles", "State"), rows, search=True) + '</section>'
    else:
        body += (f'<div class="collection-nav"><a href="{url(root, "library", snapshot=name)}">← All collections</a>'
                 + f'<form class="auto-select" method="get" action="{root}library"><input type="hidden" name="snapshot" value="{e(name)}">'
                 + select("module", [(k, module_label(k)) for k in sorted(modules)], module, "Collection")
                 + '<noscript><button type="submit">Open</button></noscript></form></div>')
        view = modules[module]
        comparison = library_profile_comparison(bundle, module)
        usage = library_usage(bundle, module, view["profiles"], advanced_analysis(bundle)["references"])
        rows = []
        for identity, profile in sorted(view["profiles"].items()):
            review = comparison.get(identity, {})
            matches = review.get("assignments", [])
            variants = review.get("local_variants", [])
            conflict = sum(v["classification"] == "different_body" for v in variants)
            detail = '<h3>Profile settings</h3>' + property_table(review.get("profile", profile))
            detail += '<h3>Local instances</h3>' + table(("Scope", "Function", "Comparison"), [tr(e(v["scope_name"]), e(persona_label(v["persona"])), status(v["classification"])) for v in variants])
            differing = [v for v in variants if v["differences"]]
            if differing:
                detail += '<details><summary>Local configuration differences</summary>' + "".join(
                    f'<h3>{e(v["scope_name"])}</h3>' + diff_table(v["differences"], "Local", "Library") for v in differing) + '</details>'
            detail += '<details><summary>Observed assignments and usage</summary>' + usage_detail(usage[identity]) + '</details>' + raw({"profile": profile, **review})
            rows.append(tr(f'<strong>{e(title_profile(identity, profile))}</strong>', *usage_cells(usage[identity]), str(len(variants)),
                           badge(str(conflict), "warn" if conflict else "neutral"), inspect(identity, detail)))
        body += f'<section><h2>{e(module_label(module))} · {len(rows)} profiles</h2>' + table(("Profile", "Observed assignments", "Shared devices", "Referencing objects", "Unknown device reads", "Local instances", "Different bodies", ""), rows, search=True) + '</section>'
    body += '<p class="note">Assignments link a Library profile to a scope and device function. A zero count means no assignment was observed in this snapshot, not that the profile is unused.</p>' + raw(assignments, "Assignment capture diagnostics")
    return page("Library", body, workspace.nav(name))


def inventory_view(workspace, query):
    loaded, empty = load(workspace, query, "Scopes", "scopes")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    rows = []
    for persona, entry in sorted(bundle["results"].items()):
        for s in sorted(entry["scopes"], key=lambda s: (s["kind"] != "device", s["kind"], s.get("name") or s["id"])):
            sid = s["id"]
            views = [v for m in entry["modules"].values() for v in m["scope_results"] if v["scope"] == sid]
            qualified = sum(v["review"]["qualified"] for v in views)
            href = url(root, "report", snapshot=name, persona=persona, scope=sid)
            rows.append(tr(f'<strong>{e(s.get("name") or sid)}</strong>', e(pretty(s["kind"])), e(persona_label(persona)),
                           f'{qualified}/{len(views)}', (f'<a href="{url(root, "overrides", snapshot=name, persona=persona, device=sid)}">Compare overrides</a> · ' if s["kind"] == "device" else "") + f'<a href="{href}">Open configuration</a>'))
    return page("Scopes", intro("Inventory", "Browse captured devices and configuration scopes.", picker)
                + '<section>' + table(("Scope / device", "Type", "Function", "Qualified modules", ""), rows, search=True) + '</section>', workspace.nav(name))


def comparison_view(workspace, query):
    from config_app import compare_devices
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
                    rows.append(tr(e(module_label(r["module"])), e(d["identity"]), status(d["status"]), inspect(d["identity"], detail + raw(d))))
            body += '<section><h2>Differences</h2>' + table(("Module", "Profile", "Result", ""), rows, search=True) + '</section>'
            body += raw([{k: v for k, v in r.items() if k != "differences"} for r in result], "All module comparison states")
    return page("Compare devices", body, workspace.nav(name))


def coverage_view(workspace, query):
    from config_app import module_coverage
    loaded, empty = load(workspace, query, "Module coverage", "coverage")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    records = module_coverage(bundle)
    counts = Counter(r["status"] for r in records)
    body = intro("Coverage", "Shows whether Central returned interpretable configuration. Incomplete reads do not mean configuration is absent.", picker)
    body += metrics([("Complete module reads", counts["qualified"], "All requested scopes could be interpreted"), ("Partial module reads", counts["partial"], "Some scopes could be interpreted"), ("Unverified module reads", counts["unqualified"], "No scope evidence qualified")])
    rows = [tr(e(persona_label(r["persona"])), e(module_label(r["module"])), f'{r["qualified"]}/{r["total"]}', status(r["status"]),
               f'<a href="{url(root, "report", snapshot=name, persona=r["persona"], module=r["module"], diagnostics="1")}">View evidence</a>')
            for r in sorted(records, key=lambda r: ({"qualified": 0, "partial": 1, "unqualified": 2}[r["status"]], r["persona"], r["module"]))]
    body += '<section><h2>Module qualification</h2>' + table(("Device function", "Module", "Qualified scopes", "Read status", ""), rows, search=True) + '</section>'
    discovery = bundle.get("profile_type_discovery")
    if discovery:
        unknown = set(discovery["unknown_adapter_modules"])
        rows = [tr(e(module_label(m)), e(", ".join(persona_label(p) for p in ps)), badge("Adapter needed", "warn") if m in unknown else badge("Adapter available"),
                   f'<a href="{url(root, "unadapted", snapshot=name, module=m)}">Raw evidence</a>' if m in unknown else "")
                for m, ps in discovery["modules"].items()]
        body += f'<section><h2>Discovered profile types · {len(unknown)} without adapters</h2>' + table(("Profile type", "Observed device functions", "Adapter", ""), rows, search=True) + '</section>'
    return page("Module coverage", body, workspace.nav(name))


def explorer_view(workspace, query):
    from central_tool import config_review_rows, configuration_view_shape
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
                rows.append(tr(e(scope_name), e(module_label(mod)), "—", badge("Not qualified"), inspect(scope_name, raw({"local": configuration_view_shape(view["local_view"]), "effective": configuration_view_shape(view["effective_view"]), "review": review}))))
            elif mode == "all":
                # Show independently parsed bodies even if the other read failed.
                # Do not feed these incomplete views into consolidation.
                available = {kind: view[kind + "_view"].get("profiles", {})
                             for kind in ("local", "effective")
                             if view[kind + "_view"].get("status") == "list_parsed"}
                from central_tool import profile_body
                for identity in sorted(set().union(*(p.keys() for p in available.values()))):
                    saved = available.get("local", {}).get(identity)
                    effective = available.get("effective", {}).get(identity)
                    title = title_profile(identity, saved or effective)
                    detail = '<p class="note">Only independently retrieved settings are shown. Source and comparison are not verified.</p>'
                    if saved is not None:
                        detail += '<h3>Saved settings</h3>' + property_table(profile_body(saved))
                    if effective is not None:
                        detail += '<h3>Effective settings</h3>' + property_table(profile_body(effective))
                    rows.append(tr(e(scope_name), e(module_label(mod)), e(title),
                                   badge("Partial evidence", "warn"), inspect(title, detail)))
            continue
        if mode == "diagnostics":
            continue
        for r in review["profiles"]:
            if mode == "local" and (r["local"] is None or r["status"] == "default_profile"):
                continue
            title = title_profile(r["identity"], r["local"] or r["effective"])
            detail = '<h3>Global comparison</h3>' + diff_table(r["global_differences"], "Local", "Global") + '<h3>Effective settings</h3>' + property_table(r["effective"]) + raw(r)
            rows.append(tr(f'<strong>{e(scope_name)}</strong><small>{e(pretty(view["scope_kind"]))}</small>', e(module_label(mod)), e(title),
                           badge(profile_state_label(r["status"]), "good" if r["status"] in ("inherited", "shared", "local_matches_global") else "warn" if r["status"] in ("source_conflict", "local_differs_from_global", "local_effective_mismatch") else "neutral"), inspect(title, detail)))
    q = sum(v["review"]["qualified"] for _, _, _, v in records)
    body = intro("Configuration", "Inspect captured profiles at a selected scope or module.", picker) + '<section class="filter-section">' + controls + '</section>'
    body += f'<section><h2>{len(rows)} records</h2><p class="muted">{q}/{len(records)} selected scope views qualified.</p>' + table(("Scope", "Module", "Profile", "Source / state", ""), rows, search=True) + '</section>'
    body += f'<p class="note">For grouped consolidation recommendations, open <a href="{url(root, "advisor", snapshot=name)}">Consolidation</a>. Global comparison does not establish inheritance or safe removal.</p>'
    # Preserve the standalone report and CSV export through a separate optional route.
    body += f'<p><a href="{url(root, "legacy-report", snapshot=name)}">Open full evidence report / CSV export</a></p>'
    return page("Configuration explorer", body, workspace.nav(name))
