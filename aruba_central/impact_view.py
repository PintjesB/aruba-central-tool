"""Read-only worklist for investigating a profile before changing it."""
from collections import Counter
from .advanced_review import advanced_analysis
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
    data = advanced_analysis(bundle)
    refs = data["references"]
    modules = sorted(set(modules) | {r["target_module"] for r in refs})
    body = intro("Dependency impact", "Find what uses a profile and what it depends on, before changing or removing it.", picker)
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "impact")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}">'
             + select("module", [("", "Select a module")] + [(m, module_label(m)) for m in modules], module, "Profile module")
             + f'<label>Exact profile name or ID<input name="identity" value="{e(identity)}" required maxlength="512"></label>'
             + select("persona", [("", "All functions"), ("Library", "Library")] + [(p, persona_label(p)) for p in sorted(bundle["results"])], persona, "Device function")
             + f'<label>Scope ID (optional)<input name="scope" value="{e(scope)}" maxlength="128"></label>'
             + '<button type="submit">Trace dependencies</button></form>'
             + '<p class="note">All matching names are reviewed separately per scope and function. A matching name is not proof of a shared Library source.</p></section>')
    if module and identity:
        if module not in modules or persona not in ("", "Library", *bundle["results"]):
            raise ValueError("Invalid dependency selection")
        result = dependency_impact(refs, module, identity, persona=persona, scope=scope)
        paths = result["paths"]
        direct = result["direct"]
        counts = Counter(p["direction"] for p in paths)
        body += metrics([("Direct reference observations", len(direct), "Saved, Library and effective evidence"),
                         ("Reachable consumers", counts["consumers"], "Per resolved context"),
                         ("Reachable dependencies", counts["dependencies"], "Per resolved context"),
                         ("Unresolved target observations", len(result["unresolved_target_observations"]), "Could affect this module")])
        rows = []
        for p in sorted(paths, key=lambda v: (v["direction"], v["depth"], v["persona"], v["scope"], v["module"], v["identity"])):
            chain = []
            for ref in p["edges"]:
                chain.append(tr(e(module_label(ref["source_module"]) + " / " + ref["source"]),
                                e(".".join(map(str, ref["path"]))),
                                e(module_label(ref["target_module"]) + " / " + str(ref["target"]))))
            details = table(("Source", "Reference field", "Target"), chain) + raw(p)
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
        body += '<section><h2>Direct references</h2>' + table(headers, reference_rows(direct), search=True) + '</section>'
        body += '<section><h2>Unresolved target identities in this module</h2>' + table(headers, reference_rows(result["unresolved_target_observations"]), search=True) + '<p class="note">These references may point elsewhere; do not assign them to the selected identity without more evidence.</p></section>'
    return page("Dependency impact", body, workspace.nav(name))
