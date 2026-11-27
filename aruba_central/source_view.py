"""Configuration source and conflict inspection."""
from .workspace_ui import e, page, intro, badge, table, tr, inspect, raw, diff_table, property_table, module_label, persona_label, pretty
from .workspace_views import load, scope_filter_form, device_options, module_options, url
from .source_review import source_trace


def source_view(workspace, query):
    loaded, empty = load(workspace, query, "Configuration sources", "sources")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    personas = sorted(bundle["results"])
    body = intro("Configuration sources", "Trace one effective profile across all applicable configuration scopes and compare conflicting definitions.", picker)
    if not personas:
        return page("Configuration sources", body, workspace.nav(name), extra_css=SOURCE_CSS)
    persona = query.get("persona", personas[0])
    if persona not in personas:
        raise ValueError("Unknown device function")
    device, module, identity = (query.get(k, "") for k in ("device", "module", "identity"))
    fields = scope_filter_form(root, "sources", name, bundle, persona, (
        ("device", "Device", device, device_options),
        ("module", "Module", module, module_options)), submit="Choose device and module")
    body += '<section>' + fields + '</section>'
    if not device or not module:
        return page("Configuration sources", body, workspace.nav(name), extra_css=SOURCE_CSS)
    entry = bundle["results"][persona]
    data = entry["modules"].get(module)
    if data is None:
        raise ValueError("Unknown module")
    view = next((r.get("effective_view", {}) for r in data["scope_results"] if r["scope"] == device), {})
    profiles = view.get("profiles", {}) if view.get("status") == "list_parsed" else {}
    from .workspace_views import select
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "sources")}">'
             + "".join(f'<input type="hidden" name="{e(k)}" value="{e(v)}">' for k, v in
                       {"snapshot": name, "persona": persona, "device": device, "module": module}.items())
             + select("identity", [("", "Choose effective profile")] + [(p, p) for p in sorted(profiles)], identity, "Profile")
             + '<button type="submit">Trace configuration</button></form></section>')
    if identity:
        if identity not in profiles:
            raise ValueError("Unknown effective profile")
        result = source_trace(bundle, persona, device, module, identity)
        winner = next((r["name"] for r in result["chain"] if r["scope"] == result["observed_source_scope"] and r["scope"] is not None), "Not established")
        body += '<section><h2>Observed source: ' + e(winner) + '</h2><p>Higher precedence is listed first. Conflicting bodies may be intentional; a matching body alone does not establish source identity.</p>'
        body += inheritance_path(result, root, name, persona)
        body += '<h3>Detailed scope evidence</h3>'
        rows = []
        for row in result["chain"]:
            details = ""
            for key in ("local", "effective"):
                obs = row.get(key, {})
                details += '<h3>' + e(pretty(key)) + '</h3><p>' + e(pretty(obs.get("state", "unavailable"))) + '</p>'
                if "body" in obs:
                    details += property_table(obs["body"]) + raw(obs.get("annotations"))
            if row.get("differences"):
                details += '<h3>Effective device versus scope</h3>' + diff_table(row["differences"], "Device", "Scope")
            rows.append(tr(e(pretty(row["kind"])), e(row["name"]), e(row.get("identity", "")),
                           badge(SOURCE_LABELS.get(row["status"], pretty(row["status"]))), inspect("Scope evidence", details, "Compare")))
        body += table(("Precedence", "Scope", "Identity", "Observed relationship", ""), rows)
        body += '<h3>Uncertainty and restrictions</h3>' + ("<ul>" + "".join("<li>" + e(b) + "</li>" for b in result["blockers"]) + "</ul>" if result["blockers"] else "<p>No contradiction in the captured qualified chain. Coverage is not exhaustive.</p>") + '</section>'
        body += '<section><h2>Library evidence</h2><p>' + e(pretty(result["library"]["state"])) + '</p>' + property_table(result["library"].get("body")) + '<h3>Observed assignments on the chain</h3>' + raw(result["observed_assignments"]) + '</section>'
        body += f'<section><a href="{url(root, "impact", snapshot=name, persona=persona, scope=device, module=module, identity=identity)}">Trace references on this device</a></section>'
    return page("Configuration sources", body, workspace.nav(name), extra_css=SOURCE_CSS)


SOURCE_LABELS = {
    "direct_match": "Direct definition matches device",
    "direct_difference": "Direct definition differs",
    "inherited_match": "Inherited settings match device",
    "inherited_difference": "Inherited settings differ",
    "membership_unknown": "Membership not established",
    "source_unverified": "Profile source unverified",
    "unavailable": "Read unavailable",
    "absent": "Profile absent (count confirmed)",
    "absence_unverified": "Profile absence unverified",
}


def inheritance_path(result, root, snapshot, persona):
    """Present existing observed precedence evidence without resolving new sources."""
    nodes = []
    for row in result["chain"]:
        scope = row["scope"]
        winner = scope is not None and scope == result["observed_source_scope"]
        status = row["status"]
        tone = "source-winner" if winner else "source-gap" if status in ("membership_unknown", "source_unverified", "unavailable", "absence_unverified") else ""
        local = row.get("local", {}).get("state", "unavailable")
        effective = row.get("effective", {}).get("state", "unavailable")
        fields = row.get("differences", [])
        label = SOURCE_LABELS.get(status, pretty(status))
        action = ""
        if scope is not None:
            action = f'<a href="{url(root, "report", snapshot=snapshot, persona=persona, scope=scope, module=result["module"], view="all")}">Open scope configuration</a>'
        nodes.append(f'<li class="{tone}"><div class="source-node-head"><small>{e(pretty(row["kind"]))}</small>'
                     f'<strong>{e(row["name"])}</strong></div><div class="source-node-body">'
                     + (badge("Observed source", "good") if winner else "")
                     + f'<span>{e(label)}</span><small>Saved: {e(pretty(local))} · Effective: {e(pretty(effective))}</small>'
                     + (f'<small>{len(fields)} differing fields</small>' if fields else "")
                     + '</div>' + action + '</li>')
    explanation = ("The marked source is established by the captured qualified chain." if result["observed_source_scope"] is not None
                   else "No unique source is established. Review the uncertain steps before changing configuration.")
    return '<p class="source-path-caption">' + e(explanation) + '</p><ol class="source-path" aria-label="Observed configuration precedence">' + "".join(nodes) + '</ol>'


SOURCE_CSS = """
.source-path { list-style:none; padding:0; margin:12px 0 24px; display:grid; gap:10px; }
.source-path li { position:relative; display:grid; grid-template-columns:minmax(130px,1fr) minmax(170px,2fr) auto; align-items:start; gap:12px; border:1px solid var(--line); border-radius:9px; padding:13px; background:var(--surface); }
.source-path li:not(:last-child)::after { content:""; position:absolute; width:2px; height:10px; bottom:-11px; left:24px; background:var(--line); }
.source-path .source-winner { border-color:var(--accent); background:var(--soft); }
.source-path .source-gap { border-left:3px solid var(--warn); }
.source-node-head,.source-node-body { display:flex; flex-direction:column; gap:4px; min-width:0; overflow-wrap:anywhere; }
.source-node-body .tag { align-self:start; }
.source-path small { color:var(--muted); }
@media(max-width:720px) { .source-path li { grid-template-columns:1fr; gap:6px; } }
"""
