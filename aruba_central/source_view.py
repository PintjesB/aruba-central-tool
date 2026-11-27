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
        return page("Configuration sources", body, workspace.nav(name))
    persona = query.get("persona", personas[0])
    if persona not in personas:
        raise ValueError("Unknown device function")
    device, module, identity = (query.get(k, "") for k in ("device", "module", "identity"))
    fields = scope_filter_form(root, "sources", name, bundle, persona, (
        ("device", "Device", device, device_options),
        ("module", "Module", module, module_options)), submit="Choose device and module")
    body += '<section>' + fields + '</section>'
    if not device or not module:
        return page("Configuration sources", body, workspace.nav(name))
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
                           badge(pretty(row["status"])), inspect("Scope evidence", details, "Compare")))
        body += table(("Precedence", "Scope", "Identity", "Observed relationship", ""), rows)
        body += '<h3>Uncertainty and restrictions</h3>' + ("<ul>" + "".join("<li>" + e(b) + "</li>" for b in result["blockers"]) + "</ul>" if result["blockers"] else "<p>No contradiction in the captured qualified chain. Coverage is not exhaustive.</p>") + '</section>'
        body += '<section><h2>Library evidence</h2><p>' + e(pretty(result["library"]["state"])) + '</p>' + property_table(result["library"].get("body")) + '<h3>Observed assignments on the chain</h3>' + raw(result["observed_assignments"]) + '</section>'
        body += f'<section><a href="{url(root, "impact", snapshot=name, persona=persona, scope=device, module=module, identity=identity)}">Trace references on this device</a></section>'
    return page("Configuration sources", body, workspace.nav(name))
