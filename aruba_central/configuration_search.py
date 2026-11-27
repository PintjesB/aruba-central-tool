"""Local search of captured configuration evidence, without inferring profile presence."""
from .workspace_ui import e, page, intro, table, tr, setting_value, badge
from .workspace_views import load, select, url
from .central_tool import canonical


def leaves(value, path=()):
    if isinstance(value, dict) and value:
        for key, item in value.items():
            yield from leaves(item, (*path, str(key)))
    elif isinstance(value, list) and value:
        for index, item in enumerate(value):
            yield from leaves(item, (*path, str(index)))
    else:
        yield path, value


def configuration_sources(bundle):
    names = {(persona, str(s["id"])): s.get("name") or s["id"]
             for persona, entry in bundle["results"].items() for s in entry["scopes"]}
    def emit(persona, module, scope, side, identity, value, source, state):
        return {"persona": persona, "module": module, "scope": str(scope), "name": names.get((persona, str(scope)), str(scope)),
                "view": side, "identity": identity, "body": value, "source": source, "state": state}
    def structured(persona, module, scope, side, view):
        if view.get("status") == "list_parsed":
            for identity, body in view.get("profiles", {}).items():
                yield emit(persona, module, scope, side, identity, body, "structured", view["status"])
        elif "raw" in view:
            yield emit(persona, module, scope, side, "", view["raw"], "structured_raw", view.get("status", "unknown"))
        if "alternate_raw" in view:
            yield emit(persona, module, scope, side, "", view["alternate_raw"], "structured_alternate", view.get("status", "unknown"))
    for persona, entry in bundle["results"].items():
        for module, data in entry["modules"].items():
            for scope in data["scope_results"]:
                for side in ("local", "effective"):
                    yield from structured(persona, module, scope["scope"], side, scope.get(side + "_view", {}))
    for module, view in (bundle.get("library") or {}).get("modules", {}).items():
        yield from structured("Library", module, "", "library", view)
    for module, data in (bundle.get("unadapted_profiles") or {}).items():
        for scope in data.get("source_views", []):
            for side in ("committed", "effective"):
                view = scope.get(side, {})
                if "raw" in view:
                    yield emit(scope.get("persona", ""), module, scope.get("scope", ""), side, "", view["raw"], "supplemental", view.get("status", "unknown"))
        view = data.get("library", {})
        if "raw" in view:
            yield emit("Library", module, "", "library", "", view["raw"], "supplemental", view.get("status", "unknown"))
    for persona, scopes in (bundle.get("keyed_profile_details") or {}).get("profiles", {}).items():
        for scope, modules in scopes.items():
            for module, profiles in modules.items():
                for identity, views in profiles.items():
                    for side, view in views.items():
                        if view.get("status") == "identity_observed" and isinstance(view.get("profile"), dict):
                            yield emit(persona, module, scope, side, identity, view["profile"], "individual", view["status"])


def search_configuration(bundle, query, *, module="", persona="", limit=300):
    terms = query.casefold().split()
    if not terms or len(query) > 200 or not 1 <= limit <= 1000:
        raise ValueError("Invalid search")
    rows, total, scanned = [], 0, 0
    for record in configuration_sources(bundle):
        if (module and module != record["module"]) or (persona and persona != record["persona"]):
            continue
        scanned += 1
        context = " ".join(str(record[k]) for k in ("persona", "module", "name", "scope", "identity", "view")).casefold()
        for path, value in leaves(record["body"]):
            haystack = context + " " + ".".join(path).casefold() + " " + canonical(value).casefold()
            if not all(term in haystack for term in terms):
                continue
            total += 1
            if len(rows) < limit:
                rows.append({**{k: v for k, v in record.items() if k != "body"}, "path": list(path), "value": value})
    return {"matches": rows, "total": total, "sources_searched": scanned, "truncated": total > len(rows), "complete": False}


def search_view(workspace, query):
    loaded, empty = load(workspace, query, "Configuration explorer", "report")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    text, module, persona = (query.get(k, "") for k in ("q", "module", "persona"))
    modules = sorted({m for entry in bundle["results"].values() for m in entry["modules"]}
                     | set((bundle.get("library") or {}).get("modules", {})) | set(bundle.get("unadapted_profiles") or {}))
    personas = sorted(set(bundle["results"]) | {"Library"})
    if (module and module not in modules) or (persona and persona not in personas):
        raise ValueError("Unknown search filter")
    body = intro("Configuration search", "Find captured profile names, scope names, field paths and values across the tenant.", picker)
    body += f'<p><a href="{url(root, "report", snapshot=name)}">Return to configuration explorer</a></p>'
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "report")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="mode" value="search">'
             f'<label>Search terms<input name="q" type="search" value="{e(text)}" maxlength="200" required></label>'
             + select("module", [("", "All modules")] + [(m, m) for m in modules], module, "Module")
             + select("persona", [("", "All functions")] + [(p, p) for p in personas], persona, "Device function")
             + '<button type="submit">Search configuration</button></form>'
             '<p class="note">Search is local and includes parsed structured profiles, unparsed structured responses, supplemental raw responses and directly observed individual profiles. Sampled markers, operational telemetry and uncaptured configuration are not searched. Repeated observations may appear independently.</p></section>')
    if text.strip():
        result = search_configuration(bundle, text, module=module, persona=persona)
        rows = []
        for row in result["matches"]:
            if row["source"] == "supplemental":
                params = {"module": row["module"]}
                if row["persona"] != "Library":
                    params.update(persona=row["persona"], scope=row["scope"])
                link = url(root, "unadapted", snapshot=name, **params)
            elif row["persona"] == "Library":
                route = "library" if row["module"] in (bundle.get("library") or {}).get("modules", {}) else "unadapted"
                link = url(root, route, snapshot=name, module=row["module"])
            elif row["module"] in bundle["results"].get(row["persona"], {}).get("modules", {}):
                link = url(root, "report", snapshot=name, persona=row["persona"], scope=row["scope"], module=row["module"], view="all")
            else:
                link = url(root, "unadapted", snapshot=name, module=row["module"])
            rows.append(tr(e(row["name"] or "Library"), e(row["persona"]), e(row["module"]), e(row["identity"] or "Raw response"),
                           e(row["view"]), e(".".join(row["path"]) or "(root)"), setting_value(row["value"]),
                           badge(row["source"].replace("_", " ")), f'<a href="{link}">Inspect source</a>'))
        body += f'<section><h2>{result["total"]} matching fields</h2><p>{result["sources_searched"]} captured sources searched. Showing {len(rows)} results.</p>'
        if result["truncated"]:
            body += '<p class="note">Result limit reached; narrow the search to a module, function or more specific terms.</p>'
        body += table(("Scope", "Function", "Module", "Profile", "View", "Field path", "Captured value", "Evidence", ""), rows, search=True) + '</section>'
    return page("Configuration explorer", body, workspace.nav(name))
