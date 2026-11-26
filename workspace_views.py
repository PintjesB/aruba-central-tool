"""Task-oriented workspace screens. Analysis and write eligibility are unchanged."""
import json
from collections import Counter
from urllib.parse import urlencode

from workspace_ui import (e, page, intro, metrics, snapshot_picker, module_label,
                          persona_label, pretty, status, badge, raw, table, tr,
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


def advisor_view(workspace, query):
    from consolidation import LABELS, profile_recommendations
    loaded, empty = load(workspace, query, "Consolidation advisor", "advisor")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    findings = profile_recommendations(bundle)
    # Short, task-oriented labels. Keep the full recommendation in the inspector.
    groups = [
        ("remove_override", "Remove override"),
        ("promote_local", "Consolidate"),
        ("reuse_library", "Reuse Library"),
        ("create_library", "Create Library"),
        ("conflict", "Conflicts"),
        ("default_review", "Default differences"),
        ("unassigned_library", "Unassigned Library"),
    ]
    short = dict(groups)
    counts = Counter(f["action"] for f in findings)
    tabs = '<div class="tabs" id="action-tabs" aria-label="Recommendation type">' + "".join(
        f'<button type="button" data-action="{e(key)}" aria-pressed="false">{e(label)} <span>{count}</span></button>'
        for key, label, count in [("", "All", len(findings))] + [(k, v, counts[k]) for k, v in groups]) + "</div>"
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
        placement = e(f["target"])
        if action == "promote_local":
            choices = [("", "Choose destination for review"), ("library", "Library / exact source scopes")]
            choices += [(p["scope"], f'{pretty(p["kind"])} / {p["name"]} · {len(p["additional_devices"])} extra, {len(p["unknown_membership"])} unknown')
                        for p in f["placement_options"]]
            placement = '<select class="destination" aria-label="Proposed destination">' + "".join(
                f'<option value="{e(key)}">{e(value)}</option>' for key, value in choices) + '</select>'
        source_table = table(("Scope", "Type", "Finding"), [tr(e(s["name"]), e(pretty(s["kind"])), e(pretty(s["status"]))) for s in sources]) if sources else '<p class="muted">Library definition.</p>'
        device_rows = [tr(e(d["name"]), status(k)) for k in ("matching", "different", "absent", "unknown") for d in observed.get(k, [])]
        scope_rows = [tr(e(s["name"]), e(pretty(s["kind"])), status(s["effective"])) for s in f["scope_references"]]
        placement_rows = [tr(e(p["name"]), e(pretty(p["kind"])), str(len(p["intended_devices"])),
                           str(len(p["additional_devices"])), str(len(p["unknown_membership"])), status(p["effective"]))
                          for p in f["placement_options"]]
        details = (
            f'<p>{e(LABELS[action])}</p><p class="note">Review only. This recommendation is not approved for execution.</p>'
            '<h3>Configuration comparison</h3>' + diff_table(f["differences"]) +
            '<h3>Local scopes</h3>' + source_table +
            ('<h3>Observed device configuration</h3>' + table(("Device", "Profile state"), device_rows) if device_rows else "") +
            ('<h3>Higher-scope configuration</h3>' + table(("Scope", "Type", "Effective body"), scope_rows) if scope_rows else "") +
            ('<h3>Destination impact</h3>' + table(("Destination", "Type", "Intended", "Additional", "Unknown", "Current"), placement_rows) if placement_rows else "") +
            '<h3>Proposed workflow</h3>' + list_items(f["steps"], ordered=True) +
            '<h3>Validation required</h3>' + list_items(f["blockers"]) + raw(f))
        matching = len(observed.get("matching", []))
        unknown = len(observed.get("unknown", []))
        device_summary = f'<strong>{matching}</strong><small>{unknown} unknown</small>' if observed else '<span class="muted">Not assessed</span>'
        # Filter by row metadata; the inspector and plan payload are inert.
        rows.append(tr(
            f'<input type="checkbox" class="choose" aria-label="Select {e(profile)}" data-plan="{e(json.dumps(f, ensure_ascii=False))}">',
            summary, badge(short[action], "warn" if action in ("conflict", "default_review") else "info"),
            f'<strong>{len(sources)}</strong><small>{e(names or "Library")}</small>', placement, device_summary,
            inspect(profile, details, "Review"),
            attrs=f' data-action="{e(action)}" data-module="{e(f["module"])}" data-persona="{e(f["persona"])}" data-search="{e(profile+" "+str([s["name"] for s in sources]))}"'))
    filters = (
        '<div class="toolbar advisor-filters">'
        + select("module", [("", "All modules")] + [(m, module_label(m)) for m in sorted({f["module"] for f in findings})], label="Module")
        + select("persona", [("", "All functions")] + [(p, persona_label(p)) for p in sorted({f["persona"] for f in findings})], label="Device function")
        + '<label class="searchbox">Search<input id="search" type="search" placeholder="Profile or scope"></label>'
        '<button id="clear" type="button" class="quiet">Reset</button></div>')
    listing = '<div id="advisor-table">' + table(("Select", "Profile", "Action", "Local scopes", "Destination", "Matching devices", ""), rows) + '</div>'
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
                + '<section><div id="snapshot-label" hidden data-snapshot="' + e(name) + '"></div>'
                + tabs + filters + '<div class="table-toolbar"><span id="visible-count" class="muted" aria-live="polite"></span>'
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
let action='', page=0, filtered=[];const size=30;
function filter(reset=true){
 if(reset)page=0;
 const q=$('search').value.toLowerCase().trim();
 filtered=rows.filter(r=>(!action||r.dataset.action===action)&&(!$('module').value||r.dataset.module===$('module').value)&&(!$('persona').value||r.dataset.persona===$('persona').value)&&((r.dataset.search+' '+r.textContent).toLowerCase().includes(q)));
 const pages=Math.max(1,Math.ceil(filtered.length/size));page=Math.min(page,pages-1);
 const visible=new Set(filtered.slice(page*size,(page+1)*size));
 for(const r of rows)r.hidden=!visible.has(r);
 $('visible-count').textContent=filtered.length+' of '+rows.length+' recommendations';
 $('advisor-page').textContent=(page+1)+' / '+pages;$('advisor-prev').disabled=page===0;$('advisor-next').disabled=page+1>=pages;
 $('advisor-empty').hidden=filtered.length>0;
 for(const b of actions)b.setAttribute('aria-pressed',String(b.dataset.action===action));
}
function selection(){
 const chosen=checks.filter(c=>c.checked).map(c=>{
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
  item.append(el('h3',f.module+' / '+f.identity),el('p',f.action.replaceAll('_',' ')+' · '+f.target));
  const steps=document.createElement('ol');for(const s of f.steps)steps.append(el('li',s));item.append(steps);
  const blockers=document.createElement('details');blockers.append(el('summary','Validation required ('+f.blockers.length+')'));
  const ul=document.createElement('ul');for(const b of f.blockers)ul.append(el('li',b));blockers.append(ul);item.append(blockers);$('preview').append(item);
 }
 if(chosen.some(f=>f.action==='promote_local'&&!f.selected_destination))$('preview').append(el('p','Select a destination for each consolidation recommendation before exporting.'));
}
for(const b of actions)b.addEventListener('click',()=>{action=b.dataset.action;filter();});
for(const k of ['module','persona'])$(k).addEventListener('change',()=>filter());
$('search').addEventListener('input',()=>filter());
$('clear').addEventListener('click',()=>{action='';$('module').value='';$('persona').value='';$('search').value='';filter();});
$('advisor-prev').addEventListener('click',()=>{page--;filter(false);});$('advisor-next').addEventListener('click',()=>{page++;filter(false);});
for(const c of checks)c.addEventListener('change',selection);
for(const field of document.querySelectorAll('.destination'))field.addEventListener('change',selection);
$('select-visible').addEventListener('click',()=>{for(const r of filtered)r.querySelector('.choose').checked=true;selection();});
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


def engineering_view(workspace, query):
    from advanced_review import advanced_analysis
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
        summary = property_table(settings)
        mapping = table(("Device", "Port", "Description"), [tr(e(p["device"]), e(p["port"]), e(p.get("description") or "")) for p in ports])
        visibility = [tr(e(m["identity"]), e(v["device"]), status(v["status"])) for m in matches for v in m["visibility"]]
        details = ('<h3>Shared settings</h3>' + summary + '<h3>Ports to review</h3>' + mapping
                   + ('<h3>Matching Library profiles</h3>' + table(("Profile", "Device", "Visibility"), visibility) if visibility else '<h3>Placement</h3><p>Review creation of a reusable switch port profile.</p>')
                   + '<h3>Validation required</h3>' + list_items(record.get("blockers", [])) + raw(record))
        rows.append(tr(f'<strong>Port group {i}</strong><small>{e(persona_label(record["persona"]))}</small>',
                       str(len(ports)), str(len(devices)), e(", ".join(m["identity"] for m in matches) or "New profile candidate"),
                       badge("Unsupported fields" if record["unsupported_fields"] else "Review mapping", "warn" if record["unsupported_fields"] else "info"),
                       inspect(f"Port group {i}", details)))
    panel("ports", "Port consolidation", "Repeated settings grouped by exact body. Physical mapping and descriptions are preserved.",
          ("Group", "Ports", "Devices", "Library match", "Review", ""), rows, len(rows))
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
        details = '<h3>Winning vs higher-scope settings</h3>' + diff_table(field_differences(r["effective"], r["higher_body"]), "Winning", "Higher scope") + '<h3>Affected devices</h3>' + list_items([v["device"] for v in members]) + raw(members)
        rows.append(tr(f'<strong>{e(title_profile(r["identity"], r["effective"]))}</strong><small>{e(module_label(r["module"]))}</small>',
                       e(r["winning_scope"]), e(r["higher_scope"]), str(len({v["scope"] for v in members})),
                       badge("Same body" if r["relationship"] == "same_body" else "Different body", "good" if r["relationship"] == "same_body" else "warn"),
                       inspect(r["identity"], details)))
    panel("shadow", "Shadowed configuration", "Known member scopes and observed winning sources. A shadowed profile may still serve other devices.",
          ("Profile", "Winning scope", "Shadowed scope", "Devices", "Comparison", ""), rows, len(rows))
    rows = []
    for r in data["library_duplicates"]:
        refs = r.get("observed_references", [])
        detail = '<h3>Matching definitions</h3>' + list_items(r["identities"]) + '<h3>Observed references</h3>' + table(("Device", "Source", "Target"), [tr(e(v["device"]), e(v["source"]), e(v["target"])) for v in refs]) + '<p class="note">Identity semantics and complete reverse references must be verified before merging.</p>' + raw(r)
        rows.append(tr(e(module_label(r["module"])), e(", ".join(r["identities"])), str(len(r["assignments"])), str(len(refs)),
                       str(r.get("unresolved_reference_count", 0)), inspect(", ".join(r["identities"]), detail)))
    panel("duplicates", "Duplicate Library profiles", "Matching bodies after excluding the identity field; not proof that names are interchangeable.",
          ("Module", "Identities", "Assignments", "References", "Unresolved", ""), rows, len(rows))
    for key, label, records in (("references", "Reference review", [r for r in data["references"] if r["status"] != "observed"]),
                                ("resolved", "Observed references", [r for r in data["references"] if r["status"] == "observed"])):
        rows = [tr(e(r["device"]), f'{e(module_label(r["source_module"]))}<small>{e(r["source"])}</small>',
                   f'{e(module_label(r["target_module"]))}<small>{e(r["target"] if r["target"] is not None else "Unknown")}</small>',
                   status(r["status"]), inspect("Reference evidence", property_table(r))) for r in records]
        panel(key, label, "Observed references are not a complete dependency graph. Not observed does not prove a broken dependency.",
              ("Device", "Source", "Target", "State", ""), rows, len(rows))
    tabs = '<div class="tabs" data-tabs="engineering">' + "".join(f'<button type="button" data-tab="{k}" aria-selected="false">{e(label)} <span>{n}</span></button>' for k, label, n, _ in panels) + '</div>'
    return page("Engineering review", intro("Engineering review", "Review reusable ports, scope precedence, Library duplication and references.", picker)
                + tabs + "".join(p[3] for p in panels), workspace.nav(name))


def library_view(workspace, query):
    from config_app import library_profile_comparison
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
    body += '<div class="toolbar"><a class="button" href="' + url(root, "library", snapshot=name) + '">All modules</a>' + ''.join(
        f'<a class="button{" primary" if k == module else ""}" href="{url(root, "library", snapshot=name, module=k)}">{e(module_label(k))}</a>'
        for k, v in sorted(modules.items()) if v["status"] == "list_parsed" and v["profiles"]) + '</div>'
    if not module:
        body += '<section><h2>Profile collections</h2>' + table(("Module", "Profiles", "State"), rows, search=True) + '</section>'
    else:
        view = modules[module]
        comparison = library_profile_comparison(bundle, module)
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
            detail += raw({"profile": profile, **review})
            rows.append(tr(f'<strong>{e(title_profile(identity, profile))}</strong>', str(len(matches)), str(len(variants)),
                           badge(str(conflict), "warn" if conflict else "neutral"), inspect(identity, detail)))
        body += f'<section><h2>{e(module_label(module))} · {len(rows)} profiles</h2>' + table(("Profile", "Observed assignments", "Local instances", "Different bodies", ""), rows, search=True) + '</section>'
    body += '<p class="note">Assignment completeness is not verified. Zero observed assignments is not proof that a profile is unused.</p>' + raw(assignments, "Assignment capture diagnostics")
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
                           f'{qualified}/{len(views)}', f'<a href="{href}">Open configuration</a>'))
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
    body = intro("Coverage", "Collection diagnostics are separate from engineering recommendations.", picker)
    body += metrics([("Qualified", counts["qualified"], "All captured scopes qualified"), ("Partial", counts["partial"], "Some qualified scopes"), ("Unqualified", counts["unqualified"], "Evidence incomplete")])
    rows = [tr(e(persona_label(r["persona"])), e(module_label(r["module"])), f'{r["qualified"]}/{r["total"]}', status(r["status"]),
               f'<a href="{url(root, "report", snapshot=name, persona=r["persona"], module=r["module"], diagnostics="1")}">View evidence</a>')
            for r in sorted(records, key=lambda r: ({"qualified": 0, "partial": 1, "unqualified": 2}[r["status"]], r["persona"], r["module"]))]
    body += '<section><h2>Module qualification</h2>' + table(("Device function", "Module", "Qualified scopes", "State", ""), rows, search=True) + '</section>'
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
    from config_dashboard import LABELS
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
    mode = query.get("view", "all" if scope or query.get("diagnostics") else "local")
    if mode not in ("all", "local", "diagnostics"):
        raise ValueError("Unknown view")
    scope_names = [(s["id"], f'{pretty(s["kind"])} / {s.get("name") or s["id"]}') for s in entry["scopes"]]
    controls = f'<form method="get" action="{root}report"><input type="hidden" name="snapshot" value="{e(name)}">' + select("persona", [(p, persona_label(p)) for p in personas], persona, "Function") + '<button type="submit" class="quiet">Load function</button></form><hr>'
    controls += f'<form method="get" action="{root}report"><input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="persona" value="{e(persona)}">' + select("module", [("", "All modules")] + [(m, module_label(m)) for m in modules], module, "Module") + select("scope", [("", "All scopes")] + scope_names, scope, "Scope") + select("view", [("local", "Local profiles"), ("all", "All qualified profiles"), ("diagnostics", "Unqualified scopes")], mode, "View") + '<button type="submit">Show</button></form>'
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
                           badge(LABELS.get(r["status"], pretty(r["status"])), "good" if r["status"] in ("inherited", "shared", "local_matches_global") else "warn" if r["status"] in ("source_conflict", "local_differs_from_global", "local_effective_mismatch") else "neutral"), inspect(title, detail)))
    q = sum(v["review"]["qualified"] for _, _, _, v in records)
    body = intro("Configuration", "Inspect captured profiles at a selected scope or module.", picker) + '<section>' + controls + '</section>'
    body += f'<section><h2>{len(rows)} records</h2><p class="muted">{q}/{len(records)} selected scope views qualified.</p>' + table(("Scope", "Module", "Profile", "Source / state", ""), rows, search=True) + '</section>'
    body += f'<p class="note">For grouped consolidation recommendations, open <a href="{url(root, "advisor", snapshot=name)}">Consolidation</a>. Global comparison does not establish inheritance or safe removal.</p>'
    # Preserve the standalone report and CSV export through a separate optional route.
    body += f'<p><a href="{url(root, "legacy-report", snapshot=name)}">Open full evidence report / CSV export</a></p>'
    return page("Configuration explorer", body, workspace.nav(name))
