"""Find captured devices, scopes and named profiles without scanning every field."""
from collections import Counter
import re
from .central_tool import CONFIG_MODULES, observed_profile_candidates
from .workspace_ui import e, page, intro, table, tr, badge, module_label, persona_label, pretty
from .workspace_views import load, url, select, title_profile
from .nac_authorization import nac_collection

CATEGORIES = {"device": "Devices", "scope": "Higher scopes", "library": "Library profiles",
              "profile": "Scoped profiles", "tag": "NAC tags"}


def entities(bundle):
    for persona, entry in sorted(bundle.get("results", {}).items()):
        scopes = {str(s["id"]): s for s in entry["scopes"]}
        for sid, scope in sorted(scopes.items()):
            kind = "device" if scope["kind"] == "device" else "scope"
            yield {"category": kind, "label": scope.get("name") or sid,
                   "identity": sid, "persona": persona, "module": "", "scope": sid,
                   "scope_name": scope.get("name") or sid, "state": pretty(scope["kind"])}
    for module, view in sorted((bundle.get("library") or {}).get("modules", {}).items()):
        if view.get("status") != "list_parsed":
            continue
        for identity, profile in sorted(view.get("profiles", {}).items()):
            yield {"category": "library", "label": title_profile(identity, profile), "identity": identity,
                   "persona": "Library", "module": module, "scope": "", "scope_name": "Library", "state": "Captured definition"}
    tags = nac_collection(bundle, "static-tag")
    if tags.get("status") == "list_parsed":
        for identity, profile in sorted(tags.get("profiles", {}).items()):
            yield {"category": "tag", "label": title_profile(identity, profile), "identity": identity,
                   "persona": "NAC", "module": "static-tag", "scope": "", "scope_name": "Tenant", "state": "Captured tag"}
    for persona, entry in sorted(bundle.get("results", {}).items()):
        names = {str(s["id"]): s.get("name") or s["id"] for s in entry["scopes"]}
        for module, data in sorted(entry["modules"].items()):
            for record in data["scope_results"]:
                sid = str(record["scope"])
                if sid not in names:
                    continue
                def profiles(side):
                    view = record.get(side + "_view", {})
                    if module in CONFIG_MODULES:
                        return observed_profile_candidates(view, CONFIG_MODULES[module][0])
                    return view.get("profiles", {}) if view.get("status") == "list_parsed" else {}
                local, effective = profiles("local"), profiles("effective")
                for identity in sorted(local.keys() | effective.keys()):
                    profile = local.get(identity) or effective.get(identity)
                    alternate = title_profile(identity, effective.get(identity)) if identity in local and identity in effective else ""
                    label = title_profile(identity, profile)
                    state = "Saved and effective observed" if identity in local and identity in effective else "Saved observed" if identity in local else "Effective observed"
                    if not record.get("review", {}).get("qualified"):
                        state += "; comparison unqualified"
                    yield {"category": "profile", "label": label, "alternate_label": alternate if alternate != label else "", "identity": identity,
                           "persona": persona, "module": module, "scope": sid, "scope_name": names[sid], "state": state}


def find_entities(bundle, text, *, category="", offset=0, limit=150):
    if not isinstance(text, str) or len(text) > 200 or category not in ("", *CATEGORIES):
        raise ValueError("Invalid entity search")
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("Invalid entity search batch")
    terms = [match.group(1) or match.group(2) for match in re.finditer(r'"([^"]+)"|(\S+)', text.casefold())]
    counts, rows, total = Counter(), [], 0
    if terms:
        for item in entities(bundle):
            haystack = " ".join(str(v) for v in (item["label"], item.get("alternate_label", ""), item["identity"], item["scope_name"], item["scope"],
                                item["persona"], persona_label(item["persona"]), item["module"], module_label(item["module"]))).casefold()
            if not all(term in haystack for term in terms):
                continue
            counts[item["category"]] += 1
            if category and item["category"] != category:
                continue
            if offset <= total < offset + limit:
                rows.append(item)
            total += 1
    return {"rows": rows, "total": total, "counts": dict(counts)}


def entity_url(root, snapshot, item):
    kind, persona, module, identity, scope = (item[k] for k in ("category", "persona", "module", "identity", "scope"))
    if kind == "device":
        return url(root, "scopes", snapshot=snapshot, mode="device", persona=persona, device=scope)
    if kind == "scope":
        return url(root, "report", snapshot=snapshot, persona=persona, scope=scope, view="all")
    if kind == "library":
        return url(root, "library", snapshot=snapshot, module=module, profile=identity)
    if kind == "tag":
        return url(root, "nac", snapshot=snapshot, tag=identity)
    return url(root, "report", snapshot=snapshot, persona=persona, module=module, scope=scope, identity=identity, view="all")


def entity_search_view(workspace, query):
    loaded, empty = load(workspace, query, "Find devices and profiles", "report")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    text, category = query.get("q", ""), query.get("entity_category", "")
    try:
        offset = int(query.get("offset", 0))
    except (TypeError, ValueError):
        raise ValueError("Invalid search offset") from None
    result = find_entities(bundle, text, category=category, offset=offset)
    body = intro("Find devices and profiles", "Find named captured objects and open their exact review context.", picker)
    body += (f'<section><form class="filter-bar" method="get" action="{e(root+"report")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="mode" value="entities">'
             f'<label>Name, ID or scope<input name="q" type="search" maxlength="200" value="{e(text)}" placeholder="Device, VLAN, role or tag"></label>'
             + select("entity_category", [("", "All object types")] + list(CATEGORIES.items()), category, "Object type")
             + '<button type="submit">Find</button></form>'
             + f'<p><a href="{url(root, "report", snapshot=name, mode="search", q=text)}">Search configuration field values instead</a></p>'
             '<p class="note">Use double quotes for an exact phrase. Searches captured inventory, parsed Library definitions, scoped profile identities and NAC tags. It does not search registration records, uncaptured objects or arbitrary raw field values.</p></section>')
    if text.strip():
        params = {"snapshot": name, "mode": "entities", "q": text}
        body += '<section><h2>Matching object types</h2><div class="filter-bar">'
        for key, label in [("", "All")] + list(CATEGORIES.items()):
            count = result["counts"].get(key, 0) if key else sum(result["counts"].values())
            body += f'<a class="button" href="{url(root, "report", **params, entity_category=key)}">{e(label)} ({count})</a> '
        body += '</div></section>'
        rows = []
        for item in result["rows"]:
            link = entity_url(root, name, item)
            rows.append(tr(f'<a href="{link}"><strong>{e(item["label"])}</strong></a>' + (f'<small>Effective: {e(item["alternate_label"])}</small>' if item.get("alternate_label") else ""),
                           e(CATEGORIES[item["category"]]), e(persona_label(item["persona"])),
                           e(module_label(item["module"])) if item["module"] else "Not applicable",
                           e(item["scope_name"]), badge(item["state"]), f'<a href="{link}">Open evidence</a>'))
        body += f'<section><h2>{result["total"]} matching objects</h2><p>Table search and CSV apply to the loaded batch only.</p>'
        if offset:
            body += f'<a class="button" href="{url(root, "report", **params, entity_category=category, offset=max(0, offset-150))}">Previous batch</a> '
        if offset + len(rows) < result["total"]:
            body += f'<a class="button" href="{url(root, "report", **params, entity_category=category, offset=offset+150)}">Next batch</a>'
        body += table(("Object", "Type", "Function", "Module", "Scope", "Observed evidence", "Action"), rows, search=True) + '</section>'
    return page("Find devices and profiles", body, workspace.nav(name))
