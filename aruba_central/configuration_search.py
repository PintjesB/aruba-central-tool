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


def configuration_sources(bundle, *, persona="", module="", scope=None):
    selected_persona, selected_module, selected_scope = persona, module, scope
    def accepts(function, mod=None, sid=None):
        return ((not selected_persona or function == selected_persona)
                and (mod is None or not selected_module or mod == selected_module)
                and (sid is None or selected_scope is None or str(sid) == selected_scope))
    names = {(function, str(s["id"])): s.get("name") or s["id"]
             for function, entry in bundle["results"].items() if accepts(function)
             for s in entry["scopes"] if accepts(function, sid=s["id"])}
    def emit(persona, module, scope, side, identity, value, source, state):
        return {"persona": persona, "module": module, "scope": str(scope), "name": names.get((persona, str(scope)), str(scope)),
                "view": side, "identity": identity, "body": value, "source": source, "state": state}
    def partial_pages(persona, module, scope, side, view, source):
        # A complete merged collection already represents its successful pages.
        # For incomplete collections, later pages can contain otherwise invisible settings.
        if view.get("pagination_status") not in (None, "complete"):
            for index, payload in enumerate(view.get("raw_pages") or [], 1):
                yield emit(persona, module, scope, side, "", payload, source, view.get("status", "unknown"))
    def structured(persona, module, scope, side, view):
        if view.get("status") == "list_parsed":
            for identity, body in view.get("profiles", {}).items():
                yield emit(persona, module, scope, side, identity, body, "structured", view["status"])
        elif "raw" in view:
            yield emit(persona, module, scope, side, "", view["raw"], "structured_raw", view.get("status", "unknown"))
        yield from partial_pages(persona, module, scope, side, view, "structured_page")
        if "alternate_raw" in view:
            yield emit(persona, module, scope, side, "", view["alternate_raw"], "structured_alternate", view.get("status", "unknown"))
    for persona, entry in bundle["results"].items():
        if not accepts(persona):
            continue
        for module, data in entry["modules"].items():
            if not accepts(persona, module):
                continue
            for scope in data["scope_results"]:
                if not accepts(persona, module, scope["scope"]):
                    continue
                for side in ("local", "effective"):
                    yield from structured(persona, module, scope["scope"], side, scope.get(side + "_view", {}))
    if accepts("Library", sid=""):
        for module, view in (bundle.get("library") or {}).get("modules", {}).items():
            if accepts("Library", module, ""):
                yield from structured("Library", module, "", "library", view)
    if accepts("NAC", sid=""):
        for module, view in (bundle.get("nac_configuration") or {}).items():
            if accepts("NAC", module, ""):
                yield from structured("NAC", module, "", "tenant", view)
    for module, data in (bundle.get("unadapted_profiles") or {}).items():
        if selected_module and module != selected_module:
            continue
        for scope in data.get("source_views", []):
            if not accepts(scope.get("persona", ""), module, scope.get("scope", "")):
                continue
            for side in ("committed", "effective"):
                view = scope.get(side, {})
                if "raw" in view:
                    yield emit(scope.get("persona", ""), module, scope.get("scope", ""), side, "", view["raw"], "supplemental", view.get("status", "unknown"))
                yield from partial_pages(scope.get("persona", ""), module, scope.get("scope", ""), side, view, "supplemental_page")
        view = data.get("library", {})
        if accepts("Library", module, "") and "raw" in view:
            yield emit("Library", module, "", "library", "", view["raw"], "supplemental", view.get("status", "unknown"))
        if accepts("Library", module, ""):
            yield from partial_pages("Library", module, "", "library", view, "supplemental_page")
    for persona, scopes in (bundle.get("keyed_profile_details") or {}).get("profiles", {}).items():
        if not accepts(persona):
            continue
        for scope, modules in scopes.items():
            if not accepts(persona, sid=scope):
                continue
            for module, profiles in modules.items():
                if not accepts(persona, module, scope):
                    continue
                for identity, views in profiles.items():
                    for side, view in views.items():
                        if view.get("status") == "identity_observed" and isinstance(view.get("profile"), dict):
                            yield emit(persona, module, scope, side, identity, view["profile"], "individual", view["status"])
                        elif view.get("status") != "collection_only_sampled" and "raw" in view:
                            yield emit(persona, module, scope, side, identity, view["raw"], "individual_raw", view.get("status", "unknown"))


def evidence_id(record):
    # Bind the evidence link to the exact captured source, not a guessed identity.
    selector = [record[k] for k in ("persona", "module", "scope", "view", "identity", "source", "state")]
    return hashlib.sha256(canonical([selector, record["body"]]).encode()).hexdigest()


def matching_fields(bundle, query, *, module="", persona=""):
    terms = query.casefold().split()
    if not terms or len(query) > 200:
        raise ValueError("Invalid search")
    for record in configuration_sources(bundle, module=module, persona=persona):
        context = " ".join(str(record[k]) for k in ("persona", "module", "name", "scope", "identity", "view")).casefold()
        def matches(body, context):
            for path, value in leaves(body):
                haystack = context + " " + ".".join(path).casefold() + " " + canonical(value).casefold()
                if all(term in haystack for term in terms):
                    yield path, value
        yield record, matches(record["body"], context)


def field_group(record, path, value):
    # Preserve capture view and source type: local, effective and raw evidence
    # must not be conflated even when their displayed values are identical.
    return [record["persona"], record["module"], record["view"], record["source"], list(path), value]


def group_id(group):
    return hashlib.sha256(canonical(group).encode()).hexdigest()


def grouped_search(bundle, query, *, module="", persona="", offset=0, limit=300):
    if type(offset) is not int or offset < 0 or not 1 <= limit <= 1000:
        raise ValueError("Invalid search bounds")
    device_scopes = {(p, str(s["id"])) for p, entry in bundle["results"].items() for s in entry["scopes"] if s["kind"] == "device"}
    groups = {}
    total = 0
    for record, matches in matching_fields(bundle, query, module=module, persona=persona):
        for path, value in matches:
            total += 1
            selector = field_group(record, path, value)
            key = canonical(selector)
            if key not in groups:
                groups[key] = {"selector": selector, "observations": 0, "scopes": set(), "devices": set()}
            group = groups[key]
            group["observations"] += 1
            scope = (record["persona"], record["scope"])
            if record["scope"]:
                group["scopes"].add(scope)
            if scope in device_scopes:
                group["devices"].add(scope)
    ordered = sorted(groups.values(), key=lambda g: (-len(g["devices"]), -g["observations"], canonical(g["selector"])))
    rows = []
    for group in ordered[offset:offset + limit]:
        rows.append({"selector": group["selector"], "id": group_id(group["selector"]),
                     "observations": group["observations"], "scopes": len(group["scopes"]), "devices": len(group["devices"])})
    return {"groups": rows, "total_groups": len(groups), "total": total, "truncated": len(groups) > offset + len(rows)}


def search_configuration(bundle, query, *, module="", persona="", limit=300, offset=0, group=""):
    if not 1 <= limit <= 1000 or type(offset) is not int or offset < 0:
        raise ValueError("Invalid search")
    if group and (len(group) != 64 or any(c not in "0123456789abcdef" for c in group)):
        raise ValueError("Invalid group identity")
    rows, total, scanned = [], 0, 0
    for record, matches in matching_fields(bundle, query, module=module, persona=persona):
        scanned += 1
        source_id = None
        for path, value in matches:
            if group and group_id(field_group(record, path, value)) != group:
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
    raw_modules = bundle.get("unadapted_profiles") or {}
    keyed = (bundle.get("keyed_profile_details") or {}).get("profiles") or {}
    modules = sorted({m for entry in bundle["results"].values() for m in entry["modules"]}
                     | set((bundle.get("library") or {}).get("modules", {})) | set(raw_modules)
                     | set(bundle.get("nac_configuration") or {})
                     | {m for scopes in keyed.values() for data in scopes.values() for m in data})
    personas = sorted(set(bundle["results"]) | {"Library"} | set(keyed)
                      | ({"NAC"} if bundle.get("nac_configuration") else set())
                      | {v.get("persona") for data in raw_modules.values() for v in data.get("source_views", [])
                         if isinstance(v.get("persona"), str) and v["persona"]})
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
             '<p class="note">Search is local and includes parsed structured profiles, unparsed structured responses, supplemental raw responses, incomplete collection pages, NAC configuration and individual responses (including unresolved raw evidence). Sampled markers, NAC registrations, operational telemetry and uncaptured configuration are not searched. Repeated observations may appear independently.</p></section>')
    presentation = query.get("presentation", "fields")
    group = query.get("group", "")
    if presentation not in ("fields", "grouped"):
        raise ValueError("Unknown search presentation")
    if text.strip():
        common = {"snapshot": name, "mode": "search", "q": text, "module": module, "persona": persona}
        body += f'<p><a class="button" href="{url(root, "report", **common, presentation="grouped")}">Group identical values</a> <a class="button" href="{url(root, "report", **common)}">All individual matches</a></p>'
        try:
            offset = int(query.get("offset", "0"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid search offset") from exc
        if presentation == "grouped":
            result = grouped_search(bundle, text, module=module, persona=persona, offset=offset)
            rows = []
            for row in result["groups"]:
                function, mod, view, source, path, value = row["selector"]
                link = url(root, "report", **common, group=row["id"])
                rows.append(tr(e(function), e(mod), e(view), e(source.replace("_", " ")), e(".".join(path) or "(root)"),
                               setting_value(value), str(row["devices"]), str(row["scopes"]), str(row["observations"]),
                               f'<a href="{link}">Inspect matching observations</a>'))
            body += f'<section><h2>{result["total_groups"]} distinct field/value groups</h2><p>{result["total"]} matching observations. Counts are observed device/function pairs, not an inferred deployment impact. Higher-scope observations are not expanded into recipients.</p>'
            if offset:
                body += f'<a class="button" href="{url(root, "report", **common, presentation="grouped", offset=max(0, offset - 300))}">Previous group batch</a> '
            if result["truncated"]:
                body += f'<a class="button" href="{url(root, "report", **common, presentation="grouped", offset=offset + 300)}">Next group batch</a>'
            body += table(("Function", "Module", "View", "Source", "Field path", "Value", "Observed devices", "Observed scopes", "Observations", ""), rows, search=True) + '</section>'
            return page("Configuration explorer", body, workspace.nav(name))
        result = search_configuration(bundle, text, module=module, persona=persona, offset=offset, group=group)
        if group:
            body += '<p class="note">Showing only the selected exact field/value group.</p>'
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
        params = {**common, **({"group": group} if group else {})}
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
    record = next((r for r in configuration_sources(bundle, persona=persona, module=module, scope=scope) if
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
