"""Local search of captured configuration evidence, without inferring profile presence."""
from .workspace_ui import e, page, intro, table, tr, setting_value, badge, property_table, raw
from .workspace_views import load, select, url
from .central_tool import canonical
import hashlib


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


def evidence_id(record):
    # Bind the evidence link to the exact captured source, not a guessed identity.
    selector = [record[k] for k in ("persona", "module", "scope", "view", "identity", "source", "state")]
    return hashlib.sha256(canonical([selector, record["body"]]).encode()).hexdigest()


def search_configuration(bundle, query, *, module="", persona="", limit=300, offset=0):
    terms = query.casefold().split()
    if not terms or len(query) > 200 or not 1 <= limit <= 1000 or type(offset) is not int or offset < 0:
        raise ValueError("Invalid search")
    rows, total, scanned = [], 0, 0
    for record in configuration_sources(bundle):
        if (module and module != record["module"]) or (persona and persona != record["persona"]):
            continue
        scanned += 1
        context = " ".join(str(record[k]) for k in ("persona", "module", "name", "scope", "identity", "view")).casefold()
        source_id = None
        for path, value in leaves(record["body"]):
            haystack = context + " " + ".".join(path).casefold() + " " + canonical(value).casefold()
            if not all(term in haystack for term in terms):
                continue
            total += 1
            if offset < total <= offset + limit:
                if source_id is None:
                    source_id = evidence_id(record)
                rows.append({**{k: v for k, v in record.items() if k != "body"}, "path": list(path), "value": value, "evidence_id": source_id})
    return {"matches": rows, "total": total, "sources_searched": scanned, "truncated": total > offset + len(rows), "complete": False}


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
        try:
            offset = int(query.get("offset", "0"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid search offset") from exc
        result = search_configuration(bundle, text, module=module, persona=persona, offset=offset)
        rows = []
        for row in result["matches"]:
            link = url(root, "report", snapshot=name, mode="evidence", persona=row["persona"],
                       module=row["module"], scope=row["scope"], evidence=row["evidence_id"])
            rows.append(tr(e(row["name"] or "Library"), e(row["persona"]), e(row["module"]), e(row["identity"] or "Raw response"),
                           e(row["view"]), e(".".join(row["path"]) or "(root)"), setting_value(row["value"]),
                           badge(row["source"].replace("_", " ")), f'<a href="{link}">Inspect source</a>'))
        first = offset + 1 if rows else 0
        last = offset + len(rows) if rows else 0
        body += f'<section><h2>{result["total"]} matching fields</h2><p>{result["sources_searched"]} captured sources searched. Showing {first}–{last}.</p>'
        params = {"snapshot": name, "mode": "search", "q": text, "module": module, "persona": persona}
        if offset:
            body += f'<a class="button" href="{url(root, "report", **params, offset=max(0, offset - 300))}">Previous result batch</a> '
        if result["truncated"]:
            body += f'<a class="button" href="{url(root, "report", **params, offset=offset + 300)}">Next result batch</a>'
        if offset >= result["total"] and offset:
            body += f'<p><a href="{url(root, "report", **params)}">Return to first result batch</a></p>'
        body += '<p class="note">Search results are shown in batches of up to 300. Table filters and CSV export apply to the loaded batch only.</p>'
        body += table(("Scope", "Function", "Module", "Profile", "View", "Field path", "Captured value", "Evidence", ""), rows, search=True) + '</section>'
    return page("Configuration explorer", body, workspace.nav(name))


def evidence_view(workspace, query):
    loaded, empty = load(workspace, query, "Configuration explorer", "report")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    persona, module, scope = (query.get(k, "") for k in ("persona", "module", "scope"))
    identity = query.get("evidence", "")
    if len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
        raise ValueError("Invalid evidence identity")
    record = next((r for r in configuration_sources(bundle) if
                   (r["persona"], r["module"], r["scope"]) == (persona, module, scope)
                   and evidence_id(r) == identity), None)
    if record is None:
        raise ValueError("Captured evidence no longer available")
    body = intro("Captured configuration evidence", "Exact observation selected from configuration search.", picker)
    body += f'<p><a href="{url(root, "report", snapshot=name, mode="search", module=module, persona=persona)}">Search this module again</a></p>'
    body += '<section><h2>' + e(record["identity"] or "Raw response") + '</h2>'
    body += property_table({k: v for k, v in record.items() if k != "body"})
    body += '<h3>Captured settings</h3>' + setting_value(record["body"]) + raw(record["body"], "Complete captured value") + '</section>'
    body += '<p class="note">This is a captured observation, not proof of configuration completeness, inheritance or deployment.</p>'
    return page("Configuration explorer", body, workspace.nav(name))
