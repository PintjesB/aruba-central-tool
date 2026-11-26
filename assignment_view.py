"""Bulk Library assignment review with recipient-level evidence."""
from collections import Counter
from assignment_review import assignment_review
from workspace_ui import e, page, intro, metrics, badge, table, tr, inspect, raw, diff_table, pretty, module_label, persona_label
from workspace_views import load, select, url
from history_view import private_export


def assignments_view(workspace, query):
    loaded, empty = load(workspace, query, "Library assignments", "assignments")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    library = bundle.get("library") or {}
    modules = set(library.get("modules", {}))
    modules.update(str(a["profile-type"]) for a in (library.get("assignments") or {}).get("rows", []) if a.get("profile-type"))
    module, persona, identity = (query.get(k, "") for k in ("module", "persona", "identity"))
    result = assignment_review(bundle, module, persona, identity)
    rows = result["rows"]
    body = intro("Library assignments", "Inspect observed assignment scopes, known recipients, retained profile visibility and overlapping assignments.", picker)
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "assignments")}"><input type="hidden" name="snapshot" value="{e(name)}">'
             + select("module", [("", "All modules")] + [(m, module_label(m)) for m in sorted(modules)], module, "Module")
             + select("persona", [("", "All functions")] + [(p, persona_label(p)) for p in sorted(bundle["results"])], persona, "Device function")
             + f'<label>Exact profile name<input name="identity" value="{e(identity)}" maxlength="512"></label>'
             + '<button type="submit">Review assignments</button></form></section>')
    body += metrics([("Observed assignments", len(rows), "Distinct profile/scope/function tuples"),
                     ("Unresolved assignment scopes", sum(not row["scope_resolved"] for row in rows), "Review scope identity"),
                     ("Overlapping assignments", len(result["overlaps"]), "Known recipient/module combinations"),
                     ("Invalid assignment records", len(result["invalid_rows"]), "Identity incomplete")])
    listing = []
    for row in rows:
        counts = Counter(d["status"] for d in row["recipients"])
        detail = table(("Device", "Result", ""), [
            tr(e(d["device"]), badge(pretty(d["status"])),
               inspect(d["device"], diff_table(d["differences"], "Library", "Effective device") + raw(d), "Compare"))
            for d in row["recipients"]], search=True)
        detail += '<p>Library definition captured: ' + e(str(row["library_present"])) + '</p>' + raw(row)
        listing.append(tr(e(module_label(row["module"])), e(row["identity"]), e(persona_label(row["persona"])),
                          e(row["scope_name"]), e(pretty(row["scope_kind"])), str(row["known_count"]), str(row["unknown_count"]),
                          str(counts["matching_shared"]), str(counts["different_body"]), str(counts["not_visible"]),
                          str(counts["unverified"] + counts["matching_source_unverified"]), inspect(row["identity"], detail, "Review")))
    body += '<section><h2>Assignment worklist</h2>' + table(("Module", "Profile", "Function", "Scope", "Type", "Known recipients", "Unknown membership", "Shared matches", "Different", "Not visible", "Unverified", ""), listing, search=True) + '</section>'
    body += '<section><h2>Overlapping assignment observations</h2><p>Assignments to overlapping scopes can be intentional. Atomic modules are grouped by module rather than name; overlap does not establish a conflict or prove precedence.</p>'
    body += table(("Function", "Device", "Module", "Identity", "Assignments", ""), [
        tr(e(persona_label(row["persona"])), e(row["device"]), e(module_label(row["module"])), e(row["identity"]),
           str(len(row["assignments"])), inspect("Overlapping assignments", raw(row), "Review"))
        for row in result["overlaps"]], search=True) + '</section>'
    body += '<section><h2>Capture limitations</h2><p>Assignment capture: ' + e(pretty(result["capture_status"])) + '. Counts are observed lower bounds. Unknown membership is not non-membership.</p>' + raw(result["invalid_rows"]) + private_export("library-assignment-review", {"snapshot": name, "report": result}) + '</section>'
    return page("Library assignments", body, workspace.nav(name))
