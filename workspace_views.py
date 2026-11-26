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


def vlan_explanation(local, reference, effective=None):
    from central_tool import assess_vlan_reference
    if local is None or reference is None:
        return ""
    assessment = assess_vlan_reference(local, reference)
    if not assessment["differences"]:
        return ""
    def cell(d, key):
        return e(json.dumps(d[key], ensure_ascii=False)) if key in d else '<span class="muted">Not returned</span>'
    def effective_cell(path):
        value = effective
        for key in path:
            if isinstance(value, dict) and key in value:
                value = value[key]
            elif isinstance(value, list) and isinstance(key, int) and 0 <= key < len(value):
                value = value[key]
            else:
                return '<span class="muted">Not returned</span>' if effective is not None else '<span class="muted">Not captured</span>'
        return e(json.dumps(value, ensure_ascii=False))
    return '<h3>Why these VLAN settings differ</h3>' + table(
        ("Setting", "Saved locally", "Effective at source", "Global / reference", "Meaning"),
        [tr(e(".".join(map(str, d["path"]))), cell(d, "local_value"), effective_cell(d["path"]), cell(d, "reference_value"),
            e(ASSESSMENT_LABELS.get(d["assessment"], pretty(d["assessment"]))))
         for d in assessment["differences"]]) + '<p class="note">Not returned does not mean disabled or equal to the default. Effective is the Central configuration view, not a live switch CLI or traffic measurement.</p>'


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
    group_counts = [("opportunities", "Consolidation opportunities", sum(counts[k] for k in OPPORTUNITIES)),
                    ("review", "Settings to review", counts["conflict"] + counts["default_review"]),
                    ("optional", "Optional Library review", counts["create_library"] + counts["unassigned_library"]),
                    ("", "All findings", len(findings))]
    tabs = '<div class="tabs" id="action-tabs" aria-label="Recommendation type">' + "".join(
        f'<button type="button" data-action="{e(key)}" aria-pressed="false">{e(label)} <span>{count}</span></button>'
        for key, label, count in group_counts) + "</div>"
    category_help = '<p id="category-help" class="note" aria-live="polite">Start with identical Global or Library profiles and repeated local definitions. All changes still require verification.</p>'
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
        comparison = (vlan_explanation(f["local"], f["reference"], f["local"]) if action == "default_review" else "")
        if not comparison:
            comparison = '<h3>Configuration comparison</h3>' + diff_table(f["differences"], "Local", reference_label)
        details = (
            f'<h3>Why this appears</h3><p>{e(ACTION_GUIDE[action][1])}</p>'
            f'<h3>What to do</h3><p>{e(ACTION_GUIDE[action][2])}</p>'
            + comparison +
            '<h3>Local scopes</h3>' + source_table +
            ('<h3>Observed device configuration</h3>' + table(("Device", "Profile state"), device_rows) if device_rows else "") +
            ('<h3>Higher-scope configuration</h3>' + table(("Scope", "Type", "Effective body"), scope_rows) if scope_rows else "") +
            ('<h3>Destination impact</h3>' + table(("Destination", "Type", "Intended", "Additional", "Unknown", "Current"), placement_rows) if placement_rows else "") +
            '<h3>Proposed workflow</h3>' + list_items(f["steps"], ordered=True) +
            '<h3>Validation required</h3>' + list_items(f["blockers"]) + raw(f))
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
        '<div class="toolbar advisor-filters">'
        + select("module", [("", "All modules")] + [(m, module_label(m)) for m in sorted({f["module"] for f in findings})], label="Module")
        + select("persona", [("", "All functions")] + [(p, persona_label(p)) for p in sorted({f["persona"] for f in findings})], label="Device function")
        + select("finding-type", [("", "All types")] + [(k, v[0]) for k, v in ACTION_GUIDE.items()], label="Finding type")
        + '<label class="searchbox">Search<input id="search" type="search" placeholder="Profile or scope"></label>'
        '<button id="clear" type="button" class="quiet">Reset</button></div>')
    listing = '<div id="advisor-table">' + table(("Select", "Profile", "Why flagged", "Local copies", "Suggested next step", "Devices with identical settings", ""), rows) + '</div>'
    bar = ('<div class="selection-bar"><div><strong id="selected" aria-live="polite">0 selected</strong>'
           '<small>Preview only · no Central writes</small></div><div class="selection-actions">'
           '<button id="select-visible" type="button">Select filtered</button><button id="clear-selection" type="button">Clear</button>'
           '<button id="open-preview" type="button" class="primary" disabled>Review selected</button></div></div>')
    dialog = ('<dialog id="plan-dialog" class="inspector"><div class="inspector-head"><strong>Selected change preview</strong>'
              '<button id="close-preview" type="button">Close</button></div><div class="plan-content">'
              '<p class="note">These steps are not executable API operations. All writes require separate qualification and approval.</p>'
              '<div id="preview"></div><button id="export-plan" type="button" class="primary" disabled>Export private preview JSON</button>'
              '</div></dialog>')
    return page("Consolidation advisor", intro("Consolidation", "Choose a task, inspect the evidence, and prepare a change preview.", picker)
                + f'<p><a href="{url(root, "overrides", snapshot=name)}">Compare device overrides with Global →</a></p>'
                + '<section><div id="snapshot-label" hidden data-snapshot="' + e(name) + '"></div>'
                + tabs + category_help + filters + '<div class="table-toolbar"><span id="visible-count" class="muted" aria-live="polite"></span>'
                '<div><button id="advisor-prev" type="button">Previous</button> <span id="advisor-page" class="muted"></span> '
                '<button id="advisor-next" type="button">Next</button></div></div>'
                + listing + '<p id="advisor-empty" class="empty" hidden>No matching recommendations.</p></section>'
                + bar + dialog + '<script>' + ADVISOR_JS + '</script>', workspace.nav(name), ADVISOR_CSS)


ADVISOR_CSS = """
.advisor-filters{margin-bottom:14px}.advisor-filters select{min-width:135px}.advisor-filters .searchbox{min-width:150px}
#advisor-table td:nth-child(2){min-width:145px}#advisor-table td:nth-child(5){max-width:290px;min-width:160px}
#advisor-table td:nth-child(5) select{width:100%;font-size:12px}
#advisor-table th:first-child{font-size:0;width:38px}.selection-bar{position:sticky;bottom:12px;z-index:3;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;padding:14px 18px;background:var(--surface);border:1px solid var(--line);box-shadow:0 5px 24px #0002;border-radius:10px}
.selection-bar small{display:block}.selection-actions{display:flex;gap:8px;flex-wrap:wrap}.plan-content{padding:22px}.plan-item{padding:14px 0;border-bottom:1px solid var(--line)}.plan-item h3{margin:0 0 5px}.plan-item p{margin:4px 0}.tabs button[aria-pressed=true]{border-bottom-color:var(--accent);color:var(--accent);font-weight:700}
"""
ADVISOR_JS = r"""
(()=>{
'use strict';
const $=id=>document.getElementById(id), rows=Array.from($('advisor-table').querySelectorAll('tbody > tr'));
const checks=rows.map(r=>r.querySelector('.choose')), actions=Array.from($('action-tabs').querySelectorAll('[data-action]'));
const categories={opportunities:['remove_override','promote_local','reuse_library'],review:['conflict','default_review'],optional:['create_library','unassigned_library']};
const explanations={opportunities:'Start here: exact matches and repeated local profiles. Verify inheritance and destination impact before changing anything.',review:'These differences need interpretation. They are not necessarily errors or redundant settings.',optional:'Housekeeping only. Keep local profiles and Library definitions unless reuse or cleanup is justified.','':'All captured findings, including optional housekeeping and differences.'};
let action='opportunities', page=0, filtered=[];const size=30;
function filter(reset=true){
 if(reset)page=0;
 const q=$('search').value.toLowerCase().trim();
 filtered=rows.filter(r=>(!action||categories[action].includes(r.dataset.action))&&(!$('finding-type').value||r.dataset.action===$('finding-type').value)&&(!$('module').value||r.dataset.module===$('module').value)&&(!$('persona').value||r.dataset.persona===$('persona').value)&&((r.dataset.search+' '+r.textContent).toLowerCase().includes(q)));
 const pages=Math.max(1,Math.ceil(filtered.length/size));page=Math.min(page,pages-1);
 const visible=new Set(filtered.slice(page*size,(page+1)*size));
 for(const r of rows)r.hidden=!visible.has(r);
 $('visible-count').textContent=filtered.length+' of '+rows.length+' recommendations';
 $('advisor-page').textContent=(page+1)+' / '+pages;$('advisor-prev').disabled=page===0;$('advisor-next').disabled=page+1>=pages;
 $('advisor-empty').hidden=filtered.length>0;
 $('category-help').textContent=explanations[action];
 for(const b of actions)b.setAttribute('aria-pressed',String(b.dataset.action===action));
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
for(const b of actions)b.addEventListener('click',()=>{action=b.dataset.action;$('finding-type').value='';filter();});
for(const k of ['module','persona','finding-type'])$(k).addEventListener('change',()=>filter());
$('search').addEventListener('input',()=>filter());
$('clear').addEventListener('click',()=>{action='opportunities';$('finding-type').value='';$('module').value='';$('persona').value='';$('search').value='';filter();});
$('advisor-prev').addEventListener('click',()=>{page--;filter(false);});$('advisor-next').addEventListener('click',()=>{page++;filter(false);});
for(const c of checks)c.addEventListener('change',selection);
for(const field of document.querySelectorAll('.destination'))field.addEventListener('change',selection);
$('select-visible').addEventListener('click',()=>{for(const r of filtered){const check=r.querySelector('.choose');if(!check.disabled)check.checked=true;}selection();});
$('clear-selection').addEventListener('click',()=>{for(const c of checks)c.checked=false;selection();});
$('open-preview').addEventListener('click',()=>{preview();$('plan-dialog').showModal();});
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
        panels.append((key, label, count, f'<section data-panel="{key}" data-group="engineering"><h2>{e(label)}</h2><p class="muted">{e(hint)}</p>'
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
        for identity, u in usage.items():
            rows.append(tr(e(module_label(r["module"])), f'<strong>{e(identity)}</strong><small>Matches {e(", ".join(i for i in r["identities"] if i != identity))}</small>',
                           *usage_cells(u), badge("Suggested to keep", "info") if identity == keep else "Review",
                           inspect(", ".join(r["identities"]), detail, "Compare usage")))
    panel("duplicates", "Duplicate Library profiles", "Compare each matching profile name separately. Choose which to retain based on observed assignments, shared device deployments and referencing configuration objects. Counts are not complete usage evidence.",
          ("Module", "Profile", "Assignments", "Shared devices", "Referencing objects", "Unknown device reads", "Suggested action", ""), rows, len(rows))
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
    body += (f'<section><form method="get" action="{root}library"><input type="hidden" name="snapshot" value="{e(name)}">'
             + select("module", [("", "All collections")] + [(k, module_label(k)) for k in sorted(modules)], module, "Profile collection")
             + '<button type="submit" class="quiet">Open collection</button></form></section>')
    if not module:
        body += '<section><h2>Profile collections</h2>' + table(("Module", "Profiles", "State"), rows, search=True) + '</section>'
    else:
        view = modules[module]
        comparison = library_profile_comparison(bundle, module)
        usage = library_usage(bundle, module, view["profiles"], advanced_analysis(bundle)["references"])
        rows = []
        for identity, profile in sorted(view["profiles"].items()):
            review = comparison.get(identity, {})
            matches = review.get("assignments", [])
            variants = review.get("local_variants", [])
            conflict = sum(v["classification"] == "different_body" for v in variants)
            detail = '<h3>Profile settings</h3>' + property_table(review.get("profile", profile)) + '<h3>Observed assignments</h3>' + table(("Scope", "Function"), [tr(e(a.get("scope-name", a.get("scope-id", ""))), e(persona_label(a.get("device-function", "")))) for a in matches])
            detail += '<h3>Local instances</h3>' + table(("Scope", "Function", "Comparison"), [tr(e(v["scope_name"]), e(persona_label(v["persona"])), status(v["classification"])) for v in variants])
            for v in variants:
                if v["differences"]:
                    detail += f'<h3>{e(v["scope_name"])} differences</h3>' + diff_table(v["differences"], "Local", "Library")
            detail += usage_detail(usage[identity]) + raw({"profile": profile, **review})
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
    choose = f'<form method="get" action="{root}compare"><input type="hidden" name="snapshot" value="{e(name)}">' + select("persona", [(p, persona_label(p)) for p in personas], persona, "Device function") + '<button type="submit" class="quiet">Load devices</button></form>'
    controls = f'<form method="get" action="{root}compare"><input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="persona" value="{e(persona)}">' + select("left", [("", "Select device")] + devices, left, "Reference device") + select("right", [("", "Select device")] + devices, right, "Compare with") + select("module", [("", "Reusable modules")] + [(m, module_label(m)) for m in sorted(entry["modules"])], module, "Module") + '<button type="submit">Compare</button></form>'
    body = intro("Compare devices", "Show configuration differences, not identical settings.", picker) + '<section>' + choose + '<hr>' + controls + '<p class="note">Infrastructure is excluded unless a specific module is selected.</p></section>'
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
    scope_names = [(s["id"], f'{pretty(s["kind"])} / {s.get("name") or s["id"]}') for s in entry["scopes"]]
    controls = f'<form method="get" action="{root}report"><input type="hidden" name="snapshot" value="{e(name)}">' + select("persona", [(p, persona_label(p)) for p in personas], persona, "Function") + '<button type="submit" class="quiet">Load function</button></form><hr>'
    controls += f'<form method="get" action="{root}report"><input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="persona" value="{e(persona)}">' + select("module", [("", "All modules")] + [(m, module_label(m)) for m in modules], module, "Module") + select("scope", [("", "All scopes")] + scope_names, scope, "Scope") + select("view", [("local", "Local profiles"), ("all", "All qualified profiles"), ("diagnostics", "Incomplete API results")], mode, "Configuration to show") + '<button type="submit">Show</button></form>'
    rows = []
    records = [r for r in config_review_rows(bundle) if r[0] == persona and (not module or r[1] == module) and (not scope or r[3]["scope"] == scope)]
    for _, mod, scope_name, view in records:
        review = view["review"]
        if not review["qualified"]:
            if mode == "diagnostics":
                rows.append(tr(e(scope_name), e(module_label(mod)), "—", badge("Not qualified"), inspect(scope_name, raw({"local": configuration_view_shape(view["local_view"]), "effective": configuration_view_shape(view["effective_view"]), "review": review}))))
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
    body = intro("Configuration", "Inspect captured profiles at a selected scope or module.", picker) + '<section>' + controls + '</section>'
    body += f'<section><h2>{len(rows)} records</h2><p class="muted">{q}/{len(records)} selected scope views qualified.</p>' + table(("Scope", "Module", "Profile", "Source / state", ""), rows, search=True) + '</section>'
    body += f'<p class="note">For grouped consolidation recommendations, open <a href="{url(root, "advisor", snapshot=name)}">Consolidation</a>. Global comparison does not establish inheritance or safe removal.</p>'
    # Preserve the standalone report and CSV export through a separate optional route.
    body += f'<p><a href="{url(root, "legacy-report", snapshot=name)}">Open full evidence report / CSV export</a></p>'
    return page("Configuration explorer", body, workspace.nav(name))
