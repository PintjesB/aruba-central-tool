"""Bulk Library assignment review with recipient-level evidence."""
from collections import Counter
from .assignment_review import filter_assignment_review, ASSIGNMENT_FILTERS
from .workspace_ui import e, page, intro, metrics, badge, table, tr, inspect, raw, diff_table, pretty, module_label, persona_label
from .workspace_views import load, select, url
from .history_view import private_export


def assignments_view(workspace, query):
    loaded, empty = load(workspace, query, "Library assignments", "assignments")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    library = bundle.get("library") or {}
    modules = set(library.get("modules", {}))
    modules.update(str(a["profile-type"]) for a in (library.get("assignments") or {}).get("rows", []) if a.get("profile-type"))
    module, persona, identity = (query.get(k, "") for k in ("module", "persona", "identity"))
    state = query.get("state", "all")
    result = filter_assignment_review(workspace.assignment_snapshot(bundle), module, persona, identity, state)
    rows = result["rows"]
    from .review_dispositions import snapshot_binding
    binding = snapshot_binding(workspace, name, bundle)
    if query.get("detail") or query.get("export") or query.get("evidence"):
        if query.get("binding") != binding:
            raise ValueError("Assignment evidence or snapshot changed; reopen the worklist")
        if query.get("export") == "1":
            body = intro("Export private assignment review", "Full filtered captured assignment evidence. Keep this data private.", picker)
            body += private_export("library-assignment-review", {"snapshot": name, "report": result})
            return page("Library assignments", body, workspace.nav(name))
        kind = query.get("detail") or query.get("evidence")
        if kind not in ("assignment", "overlap"):
            raise ValueError("Unknown assignment evidence type")
        try:
            index = int(query.get("index", ""))
        except (TypeError, ValueError):
            raise ValueError("Invalid assignment evidence selector") from None
        records = rows if kind == "assignment" else result["overlaps"]
        if not 0 <= index < len(records):
            raise ValueError("Unknown assignment evidence")
        row = records[index]
        content = assignment_detail(row) if kind == "assignment" else raw(row)
        if query.get("evidence"):
            return page("Assignment evidence", intro("Assignment evidence", row["identity"], picker) + content, workspace.nav(name))
        return '<template data-advisor-evidence><div class="inspector-title"><h2>' + e(row["identity"]) + '</h2></div>' + content + '</template>'
    common = {"snapshot": name, "module": module, "persona": persona, "identity": identity, "state": state, "binding": binding}
    def control(kind, index):
        endpoint = url(root, "assignments", **common, detail=kind, index=index)
        href = url(root, "assignments", **common, evidence=kind, index=index)
        return (f'<button type="button" class="quiet inspect-trigger" data-inspect data-inspect-url="{endpoint}">Review</button>'
                f'<noscript><a href="{href}">Review</a></noscript>')
    body = intro("Library assignments", "Inspect observed assignment scopes, known recipients, retained profile visibility and overlapping assignments.", picker)
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "assignments")}"><input type="hidden" name="snapshot" value="{e(name)}">'
             + select("module", [("", "All modules")] + [(m, module_label(m)) for m in sorted(modules)], module, "Module")
             + select("persona", [("", "All functions")] + [(p, persona_label(p)) for p in sorted(bundle["results"])], persona, "Device function")
             + f'<label>Exact profile name<input name="identity" value="{e(identity)}" maxlength="512"></label>'
             + select("state", list(ASSIGNMENT_FILTERS.items()), state, "Evidence")
             + '<button type="submit">Review assignments</button></form></section>')
    body += metrics([("Observed assignments", len(rows), "Distinct profile/scope/function tuples"),
                     ("Unresolved assignment scopes", sum(not row["scope_resolved"] for row in rows), "Review scope identity"),
                     ("Overlapping assignments", len(result["overlaps"]), "Known recipient/module combinations"),
                     ("Invalid assignment records", len(result["invalid_rows"]), "Whole capture; identity incomplete")])
    listing = []
    for index, row in enumerate(rows):
        counts = Counter(d["status"] for d in row["recipients"])
        profile = e(row["identity"]) + '<small>' + badge("Library observed" if row["library_present"] else "Library unverified",
                    "neutral" if row["library_present"] else "warn") + '</small>'
        scope_label = e(row["scope_name"]) + '<small>' + badge("Scope resolved" if row["scope_resolved"] else "Scope unresolved",
                    "neutral" if row["scope_resolved"] else "warn") + '</small>'
        listing.append(tr(e(module_label(row["module"])), profile, e(persona_label(row["persona"])),
                          scope_label, e(pretty(row["scope_kind"])), str(row["known_count"]), str(row["unknown_count"]),
                          str(counts["matching_shared"]), str(counts["different_body"]), str(counts["not_visible"]),
                          str(counts["unverified"] + counts["matching_source_unverified"]), control("assignment", index)))
    body += '<section><h2>Assignment worklist</h2>' + table(("Module", "Profile", "Function", "Scope", "Type", "Known recipients", "Unknown membership", "Shared matches", "Different", "Not visible", "Unverified", ""), listing, search=True) + '</section>'
    body += '<section><h2>Overlapping assignment observations</h2><p>Complete overlap groups involving the selected assignments are shown, including other profile names outside the current filter. Assignments to overlapping scopes can be intentional. Atomic modules are grouped by module rather than name; overlap does not establish a conflict or prove precedence.</p>'
    body += table(("Function", "Device", "Module", "Identity", "Assignments", ""), [
        tr(e(persona_label(row["persona"])), e(row["device"]), e(module_label(row["module"])), e(row["identity"]),
           str(len(row["assignments"])), control("overlap", index))
        for index, row in enumerate(result["overlaps"])], search=True) + '</section>'
    body += '<section><h2>Capture limitations</h2><p>Assignment capture: ' + e(pretty(result["capture_status"])) + '. Counts are observed lower bounds. Unknown membership is not non-membership. Invalid records are capture-wide because their selectors are incomplete.</p>' + raw(result["invalid_rows"]) + f'<p><a class="button" href="{url(root, "assignments", **common, export="1")}">Export private report JSON</a></p></section>'
    return page("Library assignments", body, workspace.nav(name))


def assignment_detail(row):
    detail = table(("Device", "Result", ""), [
        tr(e(d["device"]), badge(pretty(d["status"])),
           inspect(d["device"], diff_table(d["differences"], "Library", "Effective device") + raw(d), "Compare"))
        for d in row["recipients"]], search=True)
    return detail + '<p>Library definition captured: ' + e(str(row["library_present"])) + '</p>' + raw(row)
