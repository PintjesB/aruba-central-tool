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
    from central_tool import comparison_fields
    from workspace_ui import setting_value
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
        placement = e(f["target"] if action == "remove_override" else ACTION_GUIDE[action][2])
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
        reference_label = "Library" if action == "reuse_library" else "Nearest inherited" if action == "remove_override" and f["preview_selectable"] else "Global" if action in ("remove_override", "default_review") else "Reference"
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
        fallback_html = ""
        if f["fallbacks"]:
            fallback_html = '<h3>Expected inherited definition for each source</h3>' + table(("Source", "Nearest observed scope", "Result", "Blockers"), [tr(e(x["name"]), e((x.get("source") or {}).get("name", "Unavailable")), e(pretty(x["status"])), list_items(x["blockers"])) for x in f["fallbacks"]])
            for x in f["fallbacks"]:
                if x.get("source"):
                    fallback_html += '<h4>' + e(x["name"]) + '</h4>' + diff_table(x.get("differences"), "Local", "Nearest higher scope")
        details = (
            f'<div class="review-decision"><div><strong>{e(f["target"] if action == "remove_override" else ACTION_GUIDE[action][2])}</strong><p>{e(ACTION_GUIDE[action][1])}</p></div></div>'
            + fallback_html + comparison
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
            f'<input type="checkbox" class="choose" aria-label="Select {e(profile)}" data-plan="{e(json.dumps(f, ensure_ascii=False))}"{" disabled" if action not in OPPORTUNITIES or not f["preview_selectable"] else ""}>',
            summary, badge(short[action], "warn" if action in ("conflict", "default_review") else "info" if action in OPPORTUNITIES else "neutral") + f'<small>{e(SHORT_REASON[action])}</small>',
            f'<strong>{len(sources)}</strong><small>{e(names or "Library definition")}</small>', placement, device_summary,
            inspect(profile, details, "Review"),
            attrs=f' data-action="{e(action)}" data-module="{e(f["module"])}" data-persona="{e(f["persona"])}" data-search="{e(profile+" "+str([s["name"] for s in sources]))}"'))
    filters = (
        '<div class="filter-bar advisor-filters">'
        + select("finding-type", recommendation_options, selected_recommendation, "Recommendation")
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
const $=id=>document.getElementById(id), rows=Array.from($('advisor-table').querySelectorAll(':scope > .data-grid > .table-scroll > table > tbody > tr'));
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
  item.append(el('h3',f.module+' / '+f.identity),el('p',({remove_override:'Review matching nearest inheritance',promote_local:'Consolidate repeated local profiles',reuse_library:'Reuse matching Library profile'}[f.action]||f.action)+' · '+f.target));
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
            + '<h3>Configuration references</h3>' + table(("Source scope", "Module", "Object"), [
                tr(e(r["device"]), e(module_label(r["source_module"])), e(r["source"])) for r in usage["references"]])
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
    for record in sorted(data["port_groups"], key=lambda r: (-len(r["ports"]), r["persona"])):
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
        visibility = []
        for match in matches:
            counts = Counter(v["status"] for v in match["visibility"])
            visibility.append(tr(e(match["identity"]), *usage_cells(match_usage[match["identity"]]),
                                 e(f'{counts["matching"]}/{len(devices)} matching; {counts["unknown"]} unknown')))
        device_summary = Counter(p["device"] for p in ports)
        mapping = table(("Device", "Port", "Description", "Proposed profile"), [
            tr(e(p["device"]), e(p["port"]), e(p.get("description") or "—"),
               '<span data-port-target>' + e(preferred or "Not selected") + '</span>') for p in ports], search=len(ports) > 30)
        chooser = ""
        if matches:
            chooser = ('<label>Profile to review<select data-port-profile aria-label="Profile to review">'
                       + '<option value="">Choose matching profile</option>' + "".join(
                           f'<option value="{e(m["identity"])}"{" selected" if m["identity"] == preferred else ""}>{e(m["identity"])}</option>'
                           for m in matches) + '</select></label>')
        action = ("Review unsupported settings first" if record["unsupported_fields"] else
                  "Resolve dependency evidence" if unresolved else
                  "Review existing profile assignment" if matches else
                  "Review a new reusable profile" if library_available else "Retrieve Library definitions first")
        details = ('<div class="review-decision"><div><strong>' + e(action) + '</strong><p>Preserve every port identity and description. This is a review preview, not an executable change.</p></div></div>'
                   + '<div class="comparison-summary">' + badge(f"{len(ports)} ports", "info") + badge(f"{len(devices)} devices", "neutral")
                   + (badge(f"{unresolved} unresolved dependencies", "warn") if unresolved else badge(f"{len(dependencies)} observed dependencies", "neutral")) + '</div>'
                   + '<h3>Shared configuration</h3>' + property_table(settings)
                   + ('<h3>Matching Library profiles</h3>' + table(("Profile", "Assignments", "Shared devices", "References", "Unknown reads", "Visibility on affected devices"), visibility) if matches else
                      '<p class="note">' + e("No exact Library match in captured profiles." if library_available else "Library coverage unavailable; an existing profile may be present.") + '</p>')
                   + '<div data-port-review><h3>Proposed port mapping</h3>' + chooser + mapping + '</div>'
                   + ('<h3>Unsupported fields</h3>' + list_items(record["unsupported_fields"]) if record["unsupported_fields"] else "")
                   + ('<details' + (' open' if unresolved else '') + '><summary>Port dependencies</summary>' +
                      table(("Device", "Port", "Target", "Evidence"), [tr(e(r["device"]), e(r["source"]),
                          e(module_label(r["target_module"]) + " / " + str(r["target"] if r["target"] is not None else "Unresolved")), status(r["status"]))
                          for r in sorted(dependencies, key=lambda r: r["status"] == "observed")], search=len(dependencies) > 30) + '</details>' if dependencies else '<p class="note">No dependencies observed; reference coverage is incomplete.</p>')
                   + '<details><summary>Validation required</summary>' + list_items(record.get("blockers", [])) + '</details>' + raw(record))
        device_names = ", ".join(f"{dev} ({device_summary[dev]})" for dev in devices[:2])
        if len(devices) > 2:
            device_names += f" +{len(devices)-2} more"
        rows.append(tr(f'<strong>{e(label)}</strong><small>{e(persona_label(record["persona"]))}</small>',
                       f'<strong>{len(ports)} ports</strong><small>{e(device_names)}</small>',
                       f'<strong>{e(target)}</strong>' + (f'<small>{len(matches)} matching Library profiles</small>' if matches else ""),
                       badge(action, "warn" if record["unsupported_fields"] or unresolved or not library_available else "info"),
                       inspect(label, details, "Review mapping")))
    panel("ports", "Port consolidation", "Review shared settings, choose a reusable profile and verify port mappings and dependencies.",
          ("Shared configuration", "Affected ports", "Proposed target", "Next step", ""), rows, len(rows))
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
        unresolved = r["unresolved_reference_count"]
        detail = ('<div class="review-decision"><div><strong>Choose the canonical Library profile</strong><p>Use observed references and assignments to estimate migration work. No profile is proven safe to delete.</p></div></div>'
                  + table(("Profile", "Assignments", "Shared devices", "Referencing objects", "Unknown device reads", "Suggestion"), comparison)
                  + f'<div data-duplicate-preview data-usage="{e(json.dumps(preview_data))}"><h3>Migration preview</h3>{choose_keep}<div data-migration-summary aria-live="polite">Choose a profile to preview the observed migration workload.</div></div>'
                  + (f'<p class="note"><strong>{unresolved} unresolved reference observations in this module.</strong> Their target identities are not established; they may affect this migration.</p>' if unresolved else "")
                  + "".join(f'<details><summary>{e(identity)} · Where it is used</summary>{usage_detail(u)}</details>' for identity, u in usage.items())
                  + '<details><summary>Validation before consolidation</summary><ol><li>Choose the canonical name based on usage and naming standards.</li><li>Move assignments and references to that name.</li><li>Verify effective configuration and complete reverse references before deleting the old profile.</li></ol></details>'
                  + raw(r))
        # One decision per duplicate group. Keep all per-profile usage counts
        # aligned, rather than repeating the same review button for every member.
        group_usage = ('<table class="group-usage"><thead><tr>' + "".join(
            f'<th scope="col">{e(label)}</th>' for label in ("Profile", "Assignments", "Devices", "References", "Unknown reads"))
            + '</tr></thead><tbody>' + "".join(
                tr(f'<strong>{e(identity)}</strong>' + (' <span class="retain-mark">Keep</span>' if identity == keep else ""),
                   *usage_cells(u)) for identity, u in usage.items()) + '</tbody></table>')
        rows.append(tr(e(module_label(r["module"])), group_usage,
                       inspect(", ".join(r["identities"]), detail, "Plan consolidation")))
    panel("duplicates", "Duplicate Library profiles", "Compare observed usage for each name before choosing which profile to retain. Suggested names are based on observed migration effort, not safe deletion.",
          ("Module", "Profiles and observed usage", ""), rows, len(rows))
    for key, label, records in (("references", "Reference review", [r for r in data["references"] if r["status"] not in ("observed", "definition_observed")]),
                                ("resolved", "Observed references", [r for r in data["references"] if r["status"] in ("observed", "definition_observed")])):
        rows = [tr(e(r["device"]), f'{e(module_label(r["source_module"]))}<small>{e(r["source"])}</small>',
                   f'{e(module_label(r["target_module"]))}<small>{e(r["target"] if r["target"] is not None else "Unknown")}</small>',
                   status(r["status"]), e("Keep reference; verify before profile removal" if r["status"] in ("observed", "definition_observed") else "Verify target profile and scope" if r["status"] == "not_observed" else "Collect or interpret missing reference evidence"), inspect("Reference evidence", property_table(r))) for r in records]
        panel(key, label, "Observed references are not a complete dependency graph. Not observed does not prove a broken dependency.",
              ("Source scope", "Source", "Target", "State", "Suggested next step", ""), rows, len(rows))
    selected = query.get("workflow", "")
    if selected not in {p[0] for p in panels}:
        selected = next((key for key in ("duplicates", "ports", "shadow", "references") if any(p[0] == key and p[2] for p in panels)), "ports")
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
}
document.addEventListener('change',event=>{
 if(event.target.matches('[data-keep]'))update(event.target.closest('[data-duplicate-preview]'));
 if(event.target.matches('[data-port-profile]')){
  const review=event.target.closest('[data-port-review]');
  for(const target of review.querySelectorAll('[data-port-target]'))target.textContent=event.target.value||'Not selected';
 }
});
document.addEventListener('click',event=>{
 if(event.target.closest('[data-inspect]'))requestAnimationFrame(()=>{
  for(const panel of document.querySelectorAll('#workspace-inspector-body [data-duplicate-preview]'))update(panel);
 });
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
        if evidence.get("profile") is not None:
            body += property_table(evidence["profile"])
            if evidence.get("differences"):
                body += '<h4>Differences from collection response</h4>' + diff_table(
                    evidence["differences"], "Collection", "Individual read")
        body += raw(evidence, "Individual API evidence")
    return body


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
        rows.append(tr(f'<a href="{link}">{e(module_label(key))}</a>',
                       str(len(view["profiles"])) if view["status"] == "list_parsed" else "Unavailable",
                       status(view["status"])))
    body = intro("Library", "Shared profiles and their observed assignments.", picker)
    if not module:
        body += f'<p><a class="button" href="{url(root, "advanced", snapshot=name, workflow="duplicates")}">Review duplicate Library profiles</a></p>'
    if not module:
        for key, evidence in sorted((bundle.get("unadapted_profiles") or {}).items()):
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
        if view["status"] != "list_parsed":
            body += ('<section><h2>' + e(module_label(module)) + '</h2><p>Profile count unavailable. '
                     'The collection could not be interpreted; this does not mean no profiles exist.</p>'
                     + badge(pretty(view["status"]), "warn") + raw(view, "Captured response") + '</section>')
            return page("Library", body, workspace.nav(name))
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
            detail += keyed_profile_evidence(bundle, "Library", "", module, identity)
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
    library = bundle.get("library") or {}
    additional = bundle.get("unadapted_profiles") or {}
    discovery = bundle.get("profile_type_discovery") or {}
    unknown = set(discovery.get("unknown_adapter_modules", []))
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
                     ("Library collections attempted", len(library.get("modules", {})) + len(additional), "Includes additional raw reads")])
    health = bundle.get("configuration_health")
    if health:
        from central_tool import health_serial
        summary = {health_serial(row): row for row in health.get("devices", []) if health_serial(row)}
        issues = health.get("active_issues", {})
        inventory = {health_serial(record.get("inventory")): record["inventory"]
                     for record in bundle.get("inventory", []) if health_serial(record.get("inventory"))}
        def field(row, key):
            value = row.get(key)
            return e(value) if isinstance(value, (str, int, float, bool)) else "Unavailable"
        health_rows = []
        for serial in sorted(set(summary) | set(issues) | set(inventory)):
            row = summary.get(serial, {})
            issue = issues.get(serial, {})
            label = row.get("name") or inventory.get(serial, {}).get("deviceName") or serial
            health_rows.append(tr(e(label), e(serial), field(row, "configStatus"),
                field(row, "activeIssues"), field(row, "topPriorityIssue"), field(row, "recommendedAction"),
                status(issue.get("status", "not_collected")),
                inspect(label, raw(row, "Configuration health summary") + raw(issue, "Active issue response"), "Inspect")))
        body += '<section><h2>Configuration deployment health</h2>' + metrics([
            ("Device summaries", len(summary), "Count confirmed" if health.get("count_confirmed") else "Count unverified"),
            ("Active issue responses", f"{sum(v.get('status') == 'response_received' for v in issues.values())}/{len(issues)}", "All observed device identifiers"),
            ("Inventory without health summary", len(health.get("inventory_serials_missing_from_summary", [])), "Missing is not healthy"),
            ("Inventory without serial", health.get("inventory_entries_without_serial", "Unavailable"), "Cannot identify device"),
        ]) + '<p>Summary collection: ' + status(health.get("summary_status", "not_collected")) + '</p>'
        body += '<p class="note">Configuration status and issue counts are reported by Central. Missing data does not establish successful deployment. Issue responses have not been semantically qualified.</p>'
        body += table(("Device", "Serial", "Configuration status", "Active issues", "Top issue", "Recommended action", "Issue read", ""), health_rows, search=True)
        body += raw(health.get("summary_pages", []), "Original health summary responses") + '</section>'
    else:
        body += '<section><h2>Configuration deployment health</h2><p class="muted">Not collected in this snapshot. Refresh to retrieve Central health evidence.</p></section>'
    assignments = library.get("assignments") or {}
    scope_maps = library.get("scope_maps") or {}
    outcomes = assignments.get("scope_read_outcomes") or {}
    body += '<section><h2>Discovery and assignments</h2>' + table(("Source", "Status", "Observed records"), [
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
    catalog = discovery.get("documented_catalog") or {}
    if catalog:
        surveyed = set(library.get("modules", {})) | set(additional)
        documented = set(catalog["modules"])
        pending = documented - surveyed - {"ethernet-interfaces"}
        body += '<section><h2>Vendor API catalog</h2>' + metrics([
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
        body += '<section><h2>Individual profile evidence</h2>' + metrics([
            ("Supported keyed modules", len(keyed.get("supported_modules", [])), "Documented single-key selectors"),
            ("Individual reads", sum(outcomes.values()), "Includes failed or invalid selectors"),
            ("Identity observed", outcomes.get("identity_observed", 0), "Source not qualified"),
        ]) + '<p class="note">Open a profile in Library or Configuration to compare individual and collection responses. Only observed Library and saved local identities are queried; inherited-only and other resource types remain outstanding.</p>'
        body += '<p>' + e(", ".join(f"{pretty(k)}: {v}" for k, v in sorted(outcomes.items())) or "No observed profile identities") + '</p></section>'
    else:
        body += '<section><h2>Individual profile evidence</h2><p class="muted">Not collected. Select Deep catalog collection to retrieve additional individual profile settings.</p></section>'
    ledger = bundle.get("api_read_coverage")
    if ledger:
        operations = ledger.get("operations", [])
        received = sum(bool(r["received"]) for r in operations)
        attempted = sum(bool(r["attempted"]) for r in operations)
        body += '<section><h2>Documented API operation coverage</h2>' + metrics([
            ("Documented GET paths", len(operations), "Includes supplemental release notes"),
            ("Paths attempted", f"{attempted}/{len(operations)}", "Logical GET calls, not retries"),
            ("Paths with responses", f"{received}/{len(operations)}", "Not proof of complete data"),
            ("Paths not attempted", len(operations) - attempted, "Includes intentionally excluded endpoints"),
        ])
        body += '<p class="note">Search by endpoint or category to identify collection gaps. Path parameters and query values are not recorded. A received response may still be empty, partial or uninterpretable. Not attempted includes endpoints outside the collection scope.</p>'
        labels = {"not_attempted": "Not attempted", "no_response": "No successful response",
                  "mixed_outcomes": "Mixed outcomes", "response_received": "Response received"}
        operation_rows = []
        for row in sorted(operations, key=lambda r: ({"no_response": 0, "mixed_outcomes": 1, "not_attempted": 2,
                                                      "response_received": 3}.get(r["status"], 4), r["path"])):
            outcomes = ", ".join(f"{pretty(k)}: {v}" for k, v in sorted(row["outcomes"].items()))
            operation_rows.append(tr(e(", ".join(row["groups"])), e(row["path"]),
                                     e(labels.get(row["status"], row["status"])),
                                     str(row["attempted"]), str(row["received"]), e(outcomes or "None")))
        body += table(("Category", "GET path", "Read result", "Attempts", "Responses", "Outcomes"), operation_rows, search=True)
        body += '<p>Other or ambiguous GET paths: ' + str(sum(ledger.get("unmatched_get_outcomes", {}).values())) + ' calls. These are not attributed to a documented path.</p></section>'
    else:
        body += '<section><h2>Documented API operation coverage</h2><p class="muted">Not recorded in this snapshot. Collect a fresh audit.</p></section>'
    rows = [tr(e(persona_label(r["persona"])), e(module_label(r["module"])), f'{r["qualified"]}/{r["total"]}', status(r["status"]),
               f'<a href="{url(root, "report", snapshot=name, persona=r["persona"], module=r["module"], view="diagnostics")}">View evidence</a>')
            for r in sorted(records, key=lambda r: ({"unqualified": 0, "partial": 1, "qualified": 2}[r["status"]], r["persona"], r["module"]))]
    body += '<section><h2>Scoped configuration</h2>' + table(("Device function", "Module", "Qualified scopes", "Read status", ""), rows, search=True) + '</section>'
    rows = []
    for m, v in sorted(library.get("modules", {}).items()):
        rows.append(tr(e(module_label(m)), badge("Adapter available"), status(v.get("status", "not_collected")),
                       str(len(v.get("profiles", {}))) if v.get("status") == "list_parsed" else "Unavailable",
                       e("Count confirmed" if v.get("count_confirmed") else "Count unverified"),
                       f'<a href="{url(root, "library", snapshot=name, module=m)}">Open collection</a>'))
    for m in sorted(unknown | survey | set(additional)):
        v = additional.get(m, {})
        read = v.get("library", {})
        source = "Observed type" if m in unknown else "Documented survey"
        rows.append(tr(e(module_label(m)), badge("Raw evidence", "warn") + f'<small>{e(source)}</small>',
                       status(read.get("status", "not_collected")), "Unavailable",
                       e("Count confirmed" if read.get("collection_count_verified") else "Count unverified"),
                       f'<a href="{url(root, "unadapted", snapshot=name, module=m)}">Inspect evidence</a>'))
    body += '<section><h2>Library and additional profile collections</h2>' + table(
        ("Profile type", "Interpretation", "Library read", "Parsed profiles", "Collection count", ""), rows, search=True) + '</section>'
    if additional:
        scoped = []
        for m, v in sorted(additional.items()):
            reads = [s[k] for s in v.get("source_views", []) for k in ("committed", "effective")]
            captured = sum(r.get("status") == "response_received" for r in reads)
            counted = sum(r.get("collection_count_verified") is True for r in reads)
            catalog_scope = v.get("catalog_scope_coverage", {})
            gap = catalog_scope.get("unfiltered_scopes_not_surveyed", catalog_scope.get("all_function_scopes_not_surveyed"))
            scoped.append(tr(e(module_label(m)), str(len(v.get("source_views", []))),
                             f"{captured}/{len(reads)}", str(counted),
                             str(gap) if gap is not None else "Unavailable",
                             f'<a href="{url(root, "unadapted", snapshot=name, module=m)}">Inspect settings</a>'))
        body += '<section><h2>Additional scoped configuration</h2><p class="filter-hint">These reads preserve returned data without assuming profile identity or scope applicability. Remaining unfiltered surveys are not necessarily missing configuration; targeted reads may already exist. Rejected or incomplete reads remain visible.</p>' + table(
            ("Profile type", "Scope views attempted", "Responses captured", "Count-confirmed reads", "Unfiltered scopes not surveyed", ""), scoped, search=True) + '</section>'

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
                    detail += keyed_profile_evidence(bundle, persona, view["scope"], mod, identity)
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
            detail += keyed_profile_evidence(bundle, persona, view["scope"], mod, r["identity"])
            rows.append(tr(f'<strong>{e(scope_name)}</strong><small>{e(pretty(view["scope_kind"]))}</small>', e(module_label(mod)), e(title),
                           badge(profile_state_label(r["status"]), "good" if r["status"] in ("inherited", "shared", "local_matches_global") else "warn" if r["status"] in ("source_conflict", "local_differs_from_global", "local_effective_mismatch") else "neutral"), inspect(title, detail)))
    q = sum(v["review"]["qualified"] for _, _, _, v in records)
    body = intro("Configuration", "Inspect captured profiles at a selected scope or module.", picker) + '<section class="filter-section">' + controls + '</section>'
    body += f'<section><h2>{len(rows)} records</h2><p class="muted">{q}/{len(records)} selected scope views qualified.</p>' + table(("Scope", "Module", "Profile", "Source / state", ""), rows, search=True) + '</section>'
    body += f'<p class="note">For grouped consolidation recommendations, open <a href="{url(root, "advisor", snapshot=name)}">Consolidation</a>. Global comparison does not establish inheritance or safe removal.</p>'
    # Preserve the standalone report and CSV export through a separate optional route.
    body += f'<p><a href="{url(root, "legacy-report", snapshot=name)}">Open full evidence report / CSV export</a></p>'
    return page("Configuration explorer", body, workspace.nav(name))
