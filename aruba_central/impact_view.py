"""Read-only worklist for investigating a profile before changing it."""
from collections import Counter
from .dependency_impact import dependency_impact
from .workspace_ui import e, page, intro, metrics, badge, table, tr, inspect, raw, module_label, persona_label, pretty
from .workspace_views import load, select, url


def impact_view(workspace, query):
    loaded, empty = load(workspace, query, "Dependency impact", "impact")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    module, identity = query.get("module", ""), query.get("identity", "")
    persona, scope = query.get("persona", ""), query.get("scope", "")
    modules = sorted({m for entry in bundle["results"].values() for m in entry["modules"]}
                     | set((bundle.get("library") or {}).get("modules", {})))
    data = workspace.advanced_snapshot(bundle)
    refs = data["references"]
    modules = sorted(set(modules) | {r["target_module"] for r in refs} | {r["source_module"] for r in refs})
    functions = sorted(set(bundle["results"]) | {r["persona"] for r in refs if r["persona"]!="Library"})
    body = intro("Dependency impact", "Find what uses a profile and what it depends on, before changing or removing it.", picker)
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "impact")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}">'
             + select("module", [("", "Select a module")] + [(m, module_label(m)) for m in modules], module, "Profile module")
             + f'<label>Exact profile name or ID<input name="identity" value="{e(identity)}" required maxlength="512"></label>'
             + select("persona", [("", "All functions"), ("Library", "Library")] + [(p, persona_label(p)) for p in functions], persona, "Device function")
             + f'<label>Scope ID (optional)<input name="scope" value="{e(scope)}" maxlength="128"></label>'
             + '<button type="submit">Trace dependencies</button></form>'
             + '<p class="note">All matching names are reviewed separately per scope and function. A matching name is not proof of a shared Library source.</p></section>')
    if module and identity:
        if module not in modules or persona not in ("", "Library", *functions):
            raise ValueError("Invalid dependency selection")
        result = dependency_impact(refs, module, identity, persona=persona, scope=scope)
        from .review_dispositions import snapshot_binding
        from .history_view import private_export
        binding=snapshot_binding(workspace,name,bundle)
        params={"snapshot":name,"module":module,"identity":identity,"persona":persona,"scope":scope}
        if query.get("export")=="1":
            if query.get("binding")!=binding:
                raise ValueError("Snapshot changed; reopen dependency review")
            return page("Dependency impact",intro("Private dependency report","Complete observed impact for the selected context, subject to traversal limits.",picker)
                        +private_export("dependency-impact",{"selection":params,"report":result}),workspace.nav(name))
        paths = result["paths"]
        direct = result["direct"]
        counts = Counter(p["direction"] for p in paths)
        body += metrics([("Direct reference observations", len(direct), "Saved, Library and effective evidence"),
                         ("Reachable consumers", counts["consumers"], "Per resolved context"),
                         ("Reachable dependencies", counts["dependencies"], "Per resolved context"),
                         ("Unresolved target observations", len(result["unresolved_target_observations"]), "Could affect this module")])
        direction = query.get("direction", "")
        if direction not in ("", "consumers", "dependencies"):
            raise ValueError("Unknown reference direction")
        body += direction_panel(root, name, module, identity, persona, scope, counts, direction, result["truncated"])
        rows = []
        for p in sorted(paths, key=lambda v: (v["direction"], v["depth"], v["persona"], v["scope"], v["module"], v["identity"])):
            if direction and p["direction"] != direction:
                continue
            chain = []
            for ref in p["edges"]:
                chain.append(tr(e(module_label(ref["source_module"]) + " / " + ref["source"]),
                                e(".".join(map(str, ref["path"]))),
                                e(module_label(ref["target_module"]) + " / " + str(ref["target"]))))
            details = reference_path(p) + table(("Source", "Reference field", "Target"), chain) + raw(p)
            rows.append(tr(e(pretty(p["direction"])), e(p["edges"][0]["device"]), e(persona_label(p["persona"])),
                           e(pretty(p["view"])), e(module_label(p["module"])), e(p["identity"]),
                           str(p["depth"]), inspect("Reference chain", details)))
        body += '<section><h2>Resolved reference chains</h2>' + (table(("Direction", "Scope", "Function", "View", "Module", "Profile", "Hops", ""), rows, search=True) if rows else '<p>No resolved paths observed for this selection.</p>')
        if result["truncated"]:
            body += '<p class="note">Path limit reached. Narrow the selection to a device function or scope.</p>'
        body += '<p class="note">Chains follow resolved observations within a single device effective view or the Library. They do not establish deployment, behavioral impact or complete reference coverage.</p></section>'
        def reference_rows(records):
            return [tr(e(r["device"]), e(persona_label(r["persona"])), e(pretty(r.get("source_view", "effective"))),
                       e(module_label(r["source_module"]) + " / " + r["source"]),
                       e(module_label(r["target_module"]) + " / " + (str(r["target"]) if r["target"] is not None else "Unknown")),
                       badge(pretty(r["status"])), inspect("Reference evidence", raw(r))) for r in records]
        headers = ("Scope", "Function", "View", "Source", "Target", "Result", "")
        boundaries=result["unqualified_boundaries"]
        boundary_rows=[]
        for item in boundaries:
            ref=item["unqualified_edge"]
            detail='<p>Resolved prefix ends at this profile. The next reference is not qualified and is not traversed.</p>'+raw(item)
            boundary_rows.append(tr(e(pretty(item["direction"])),e(ref["device"]),e(persona_label(item["persona"])),
                e(item["module"]+" / "+item["identity"]),str(item["depth"]),
                e(ref["source_module"]+" / "+str(ref["source"])),e(ref["target_module"]+" / "+str(ref["target"] or "Unknown")),
                badge(pretty(ref["status"])),inspect("Dependency boundary",detail)))
        body += '<section><h2>Unqualified dependency boundaries</h2><p>These observations stop an otherwise resolved chain. They may affect indirect impact, but do not establish a further reachable profile.</p>'+table(("Direction","Scope","Function","Last resolved profile","Resolved hops","Source","Target","Evidence",""),boundary_rows,search=True)
        if result["boundary_truncated"] or result["truncated"]:
            body += '<p class="note">Traversal or boundary limit reached; additional unresolved observations may exist.</p>'
        body += '</section>'
        body += '<section><h2>Direct references</h2>' + table(headers, reference_rows(direct), search=True) + '</section>'
        body += '<section><h2>Conditional tenant enforcement observations</h2><p>These NAC policy observations are independent of the selected device function or scope. They may refer to this profile or an unresolved identity in its module. No device recipient or client authorization is inferred.</p>'
        tenant=result["conditional_tenant_observations"]
        body += table(("Policy","Module","Target","Attribute evidence","Policy state","Rule state",""),[
            tr(e(r["device"]),e(r["target_module"]),e(str(r["target"]) if r["target"] is not None else "Unknown"),
               badge(pretty(r.get("attribute_status",r["status"]))),e(str(r.get("policy_enabled"))),e(str(r.get("rule_enabled"))),
               inspect("Conditional enforcement evidence",raw(r))) for r in tenant],search=True)+'</section>'
        body += '<section><h2>Unresolved target identities in this module</h2>' + table(headers, reference_rows(result["unresolved_target_observations"]), search=True) + '<p class="note">These references may point elsewhere; do not assign them to the selected identity without more evidence.</p></section>'
        body += f'<p><a class="button" href="{url(root,"impact",**params,export="1",binding=binding)}">Export private dependency report JSON</a></p>'
    return page("Dependency impact", body, workspace.nav(name), extra_css=IMPACT_CSS)


def direction_panel(root, snapshot, module, identity, persona, scope, counts, selected, truncated):
    params = {"snapshot": snapshot, "module": module, "identity": identity, "persona": persona, "scope": scope}
    def tile(direction, title, description, count):
        href = url(root, "impact", **params, direction=direction)
        return (f'<a class="impact-direction" href="{href}"' + (' aria-current="true"' if direction == selected else "") + '>'
                f'<strong>{count}</strong><span>{e(title)}</span><small>{e(description)}</small></a>')
    return ('<section><h2>Reference direction</h2><div class="impact-flow">'
            + tile("consumers", "Consumers", "Objects referring to this profile, directly or through a resolved chain", counts["consumers"])
            + '<div class="impact-focus"><small>Selected profile</small><strong>' + e(identity) + '</strong><span>' + e(module_label(module)) + '</span></div>'
            + tile("dependencies", "Dependencies", "Objects this profile refers to, directly or through a resolved chain", counts["dependencies"])
            + '</div><p><a href="' + url(root, "impact", **params) + '">Show both directions</a></p>'
            + '<p class="note">Counts represent reachable paths per captured context, not unique devices or complete impact.'
            + (' Path limit reached; narrow the scope for more detail.' if truncated else '') + '</p></section>')


def reference_path(path):
    edges = path["edges"]
    if not edges:
        return ""
    # Traversal order for reverse paths is not necessarily edge direction.
    # Display each edge separately, retaining its actual source and target.
    return '<ol class="impact-path">' + "".join(
        '<li><strong>' + e(module_label(edge["source_module"]) + " / " + edge["source"]) + '</strong>'
        '<small>references ' + e(".".join(map(str, edge["path"]))) + '</small><strong>'
        + e(module_label(edge["target_module"]) + " / " + str(edge["target"])) + '</strong></li>'
        for edge in edges) + '</ol>'


IMPACT_CSS = """
.impact-flow { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr) minmax(0,1fr); gap:12px; }
.impact-direction,.impact-focus { display:flex; flex-direction:column; gap:6px; border:1px solid var(--line); border-radius:9px; padding:15px; color:var(--text); overflow-wrap:anywhere; }
.impact-direction { text-decoration:none; }
.impact-direction:hover,.impact-direction[aria-current=true] { border-color:var(--accent); background:var(--soft); text-decoration:none; }
.impact-direction strong { font-size:26px; }
.impact-focus { background:var(--bg); justify-content:center; text-align:center; }
.impact-flow small { color:var(--muted); }
.impact-path { padding-left:22px; }
.impact-path li { margin:8px 0; }
.impact-path small { display:block; color:var(--muted); margin:3px 0; }
@media(max-width:720px) { .impact-flow { grid-template-columns:1fr; } }
"""
