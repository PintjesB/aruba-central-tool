"""Review independently captured individual profile evidence without treating it as truth."""
from collections import Counter
from .keyed_qualification import (difference_category, identity_relationship,
                                  case_candidate_evidence, server_count_relationship)
from .workspace_ui import e, page, intro, metrics, table, tr, badge, inspect, diff_table, raw, module_label, persona_label
from .workspace_views import load, select, url


def keyed_observations(bundle):
    names = {(p, str(s["id"])): s.get("name") or s["id"]
             for p, entry in bundle.get("results", {}).items() for s in entry.get("scopes", [])}
    for persona, scopes in sorted(((bundle.get("keyed_profile_details") or {}).get("profiles") or {}).items()):
        for scope, modules in sorted(scopes.items()):
            for module, profiles in sorted(modules.items()):
                for identity, views in sorted(profiles.items()):
                    for side, read in sorted(views.items()):
                        status = read.get("status", "unknown")
                        differences = read.get("differences")
                        if status == "collection_only_sampled":
                            category = "sampled"
                        elif status != "identity_observed":
                            category = "unqualified"
                        elif not isinstance(differences, list):
                            category = "not_compared"
                        elif not differences:
                            category = "identical"
                        elif all(isinstance(d, dict) and difference_category(d) == "order_only" for d in differences):
                            category = "order_only"
                        else:
                            category = "different"
                        yield {"persona": persona, "scope": str(scope), "name": names.get((persona, str(scope)), str(scope) or persona),
                               "module": module, "identity": identity, "view": side, "category": category, "read": read}


CATEGORIES = {"unqualified": "Unqualified individual response", "order_only": "List order differs",
              "different": "Other field differences", "not_compared": "No collection comparison",
              "identical": "Exact body match", "sampled": "Collection-only sampled observation"}


def keyed_view(workspace, query):
    loaded, empty = load(workspace, query, "Configuration assessment", "assessment")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    from .review_dispositions import snapshot_binding
    binding = snapshot_binding(workspace, name, bundle)
    if query.get("detail") == "1":
        if query.get("binding") != binding:
            raise ValueError("Evidence or snapshot changed; reopen the worklist")
        fields = ("persona", "scope", "module", "identity", "view")
        if not all(query.get(k) for k in fields if k != "scope"):
            raise ValueError("Incomplete individual evidence selector")
        persona, scope, module, identity, view = (query.get(k, "") for k in fields)
        read = (bundle.get("keyed_profile_details") or {}).get("profiles", {}).get(persona, {}).get(scope, {}).get(module, {}).get(identity, {}).get(view)
        if not isinstance(read, dict):
            raise ValueError("Unknown individual evidence")
        return '<template data-advisor-evidence><div class="inspector-title"><h2>' + e(identity) + '</h2></div>' + individual_detail(read, context=(bundle, persona, scope, module, identity, view)) + '</template>'
    category = query.get("category", "attention")
    module = query.get("module", "")
    persona = query.get("persona", "")
    scope = query.get("scope", "")
    if category not in ("attention", "all", *CATEGORIES):
        raise ValueError("Unknown individual evidence category")
    try:
        offset = int(query.get("offset", 0))
    except (TypeError, ValueError):
        raise ValueError("Invalid offset")
    if offset < 0:
        raise ValueError("Invalid offset")
    counts, modules, personas = Counter(), set(), set()
    selected = []
    total = 0
    for row in keyed_observations(bundle):
        modules.add(row["module"])
        personas.add(row["persona"])
        if (module and row["module"] != module) or (persona and row["persona"] != persona) or (scope and row["scope"] != scope):
            continue
        counts[row["category"]] += 1
        if category == "attention":
            if row["category"] not in ("unqualified", "different", "order_only", "not_compared"):
                continue
        elif category != "all" and row["category"] != category:
            continue
        if offset <= total < offset + 200:
            selected.append(row)
        total += 1
    if module and module not in modules:
        raise ValueError("Unknown individual evidence module")
    if persona and persona not in personas:
        raise ValueError("Unknown individual evidence function")
    body = intro("Individual profile evidence", "Investigate collection versus individual GET discrepancies and unresolved responses.", picker)
    body += f'<p><a href="{url(root, "assessment", snapshot=name)}">Back to configuration assessment</a></p>'
    if scope:
        body += '<p class="note">Exact scope filter: ' + e(scope) + '</p>'
    body += metrics([("Unqualified", counts["unqualified"], "Individual read could not be qualified"),
                     ("Differing bodies", counts["different"] + counts["order_only"], "Exact field comparisons"),
                     ("Order-only", counts["order_only"], "Order may be significant"),
                     ("Collection-only", counts["sampled"], "No individual read at this selector")])
    if not bundle.get("keyed_profile_details"):
        body += '<p class="note">Individual profile evidence was not collected in this snapshot.</p>'
    body += (f'<section><form class="filter-bar" method="get" action="{e(root+"assessment")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="mode" value="keyed">'
             + select("category", [("attention", "Requires review"), ("all", "All observations")] + list(CATEGORIES.items()), category, "Evidence")
             + (f'<input type="hidden" name="scope" value="{e(scope)}">' if scope else "")
             + select("persona", [("", "All functions")] + [(p, persona_label(p)) for p in sorted(personas)], persona, "Function")
             + select("module", [("", "All modules")] + [(m, module_label(m)) for m in sorted(modules)], module, "Module")
             + '<button type="submit">Filter evidence</button></form>'
             '<p class="note">Collection and individual reads are independent observations. Neither is automatically authoritative. Order-only differences remain differences; no removal or migration is authorized.</p></section>')
    rows = []
    for row in selected:
        read = row["read"]
        category_name = row["category"]
        endpoint = url(root, "assessment", snapshot=name, mode="keyed", persona=row["persona"], scope=row["scope"],
                       module=row["module"], identity=row["identity"], view=row["view"], detail="1", binding=binding)
        control = f'<button type="button" class="quiet inspect-trigger" data-inspect data-inspect-url="{endpoint}">Inspect evidence</button>'
        rows.append(tr(e(row["name"]), e(persona_label(row["persona"])), e(module_label(row["module"])),
                       e(row["identity"]), e(row["view"]), badge(CATEGORIES[category_name]),
                       str(len(read["differences"])) if isinstance(read.get("differences"), list) else "Unknown",
                       control))
    params = {"snapshot": name, "mode": "keyed", "category": category, "module": module, "persona": persona, "scope": scope}
    body += f'<section><h2>{total} matching observations</h2><p>Showing {offset + 1 if selected else 0}–{offset + len(selected) if selected else 0}. Table search and CSV cover this batch only.</p>'
    if offset:
        body += f'<a class="button" href="{url(root, "assessment", **params, offset=max(0, offset-200))}">Previous batch</a> '
    if offset + len(selected) < total:
        body += f'<a class="button" href="{url(root, "assessment", **params, offset=offset+200)}">Next batch</a>'
    body += table(("Scope", "Function", "Module", "Profile", "View", "Evidence", "Differences", ""), rows, search=True) + '</section>'
    return page("Configuration assessment", body, workspace.nav(name))


def qualification_explanation(bundle, persona, scope, module, identity, view, read):
    """Explain observed relationships without changing exact comparison status."""
    notes = []
    if module in ("roles", "role-gpids") and read.get("status") == "schema_unresolved":
        raw_response = read.get("raw")
        if identity_relationship(raw_response, "name", str(identity)) == "case_only":
            notes.append("Requested and returned names differ only by case.")
            outcome = case_candidate_evidence(bundle, persona, scope, module, str(identity), view, raw_response)
            labels = {
                "observed_case_collision": "Multiple distinct case-equivalent names are observed in this exact collection context. Do not merge or normalize these identities.",
                "requested_collection_identity_unobserved": "The requested exact name was not observed in the captured collection.",
                "conflicting_collection_bodies": "Conflicting bodies were observed for the requested exact name.",
                "body_matches_except_name": "The observed body matches except for the name; this does not establish identity equivalence.",
                "body_differs_beyond_name": "The observed body also differs beyond the name.",
            }
            notes.append(labels[outcome])
    if module == "server-groups" and read.get("status") == "identity_observed":
        labels = {
            "equals_observed_server_count": "The missing integer equals the length of the observed individual server list.",
            "differs_from_observed_server_count": "The missing integer differs from the length of the observed individual server list.",
            "server_list_unavailable": "No individual server list is available for the integer comparison.",
        }
        for diff in read.get("differences") or []:
            if not isinstance(diff, dict):
                continue
            relationship = server_count_relationship(read, diff)
            if relationship is not None:
                notes.append(str(diff["path"][0]) + ": " + labels[relationship])
        if notes:
            notes.append("A count correlation does not establish a derived field or authorize ignoring differences. Server list order remains significant until qualified.")
    if not notes:
        return ""
    return '<h3>Qualification findings</h3><ul>' + "".join("<li>" + e(note) + "</li>" for note in notes) + '</ul><p class="note">Evidence remains unqualified for automatic equivalence or migration.</p>'


def individual_detail(read, *, context=None):
    detail = '<p>Individual read status: ' + e(read.get("status", "unknown")) + '</p>'
    if read.get("http_error") is not None:
        detail += '<p>HTTP ' + e(read["http_error"]) + '</p>'
    if isinstance(read.get("differences"), list):
        detail += '<h3>Exact comparison</h3>' + diff_table(read["differences"], "Collection profile", "Individual profile")
    else:
        detail += '<p>No qualified exact comparison available.</p>'
    if context is not None:
        detail += qualification_explanation(*context, read)
    if "raw" in read:
        detail += raw(read["raw"], "Original individual response (private)")
    if "profile" in read:
        detail += raw(read["profile"], "Parsed individual body")
    return detail
