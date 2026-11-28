"""Bulk Library assignment review with recipient-level evidence."""
from collections import Counter, defaultdict
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
    modules.update(str(a["profile-type"]) for a in (library.get("assignments") or {}).get("rows", []) if isinstance(a, dict) and a.get("profile-type"))
    functions = set(bundle["results"])
    functions.update(str(a["device-function"]) for a in (library.get("assignments") or {}).get("rows", [])
                     if isinstance(a, dict) and type(a.get("device-function")) in (str, int) and str(a["device-function"]))
    module, persona, identity = (query.get(k, "") for k in ("module", "persona", "identity"))
    state = query.get("state", "all")
    scope = query.get("scope", "")
    result = filter_assignment_review(workspace.assignment_snapshot(bundle), module, persona, identity, state, scope=scope)
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
    common = {"snapshot": name, "module": module, "persona": persona, "identity": identity, "state": state, "scope": scope, "binding": binding}
    def control(kind, index):
        endpoint = url(root, "assignments", **common, detail=kind, index=index)
        href = url(root, "assignments", **common, evidence=kind, index=index)
        return (f'<button type="button" class="quiet inspect-trigger" data-inspect data-inspect-url="{endpoint}">Review</button>'
                f'<noscript><a href="{href}">Review</a></noscript>')
    body = intro("Library assignments", "Inspect observed assignment scopes, known recipients, retained profile visibility and overlapping assignments.", picker)
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "assignments")}"><input type="hidden" name="snapshot" value="{e(name)}">'
             + select("module", [("", "All modules")] + [(m, module_label(m)) for m in sorted(modules)], module, "Module")
             + select("persona", [("", "All functions")] + [(p, persona_label(p)) for p in sorted(functions)], persona, "Device function")
             + f'<label>Exact profile name<input name="identity" value="{e(identity)}" maxlength="512"></label>'
             + f'<label>Exact scope ID<input name="scope" value="{e(scope)}" maxlength="128"></label>'
             + select("state", list(ASSIGNMENT_FILTERS.items()), state, "Evidence")
             + '<button type="submit">Review assignments</button></form></section>')
    conflict_count = sum(bool(r.get("library_individual_conflict") or any(d.get("individual_conflict") for d in r["recipients"])) for r in rows)
    body += metrics([("Observed assignments", len(rows), "Distinct profile/scope/function tuples"),
                     ("Unresolved assignment scopes", sum(not row["scope_resolved"] for row in rows), "Review scope identity"),
                     ("Overlapping assignments", len(result["overlaps"]), "Known recipient/module combinations"),
                     ("Invalid assignment records", len(result["invalid_rows"]), "Whole capture; identity incomplete"),
                     ("Individual evidence conflicts", conflict_count, "Assignments requiring review")])
    scope_counts=Counter(r["scope_resolution"] for r in rows if not r["scope_resolved"])
    if scope_counts:
        body += '<section><h2>Why assignment scopes are unresolved</h2><p>Exact scope IDs in another function are diagnostic evidence only. They do not establish recipients in the requested function.</p>'+table(("Reason","Assignments"),[
            tr(f'<a href="{url(root, "assignments", snapshot=name, module=module, persona=persona, identity=identity, scope=scope, state=reason)}">{e(pretty(reason))}</a>',str(count)) for reason,count in sorted(scope_counts.items())])+'</section>'
    if scope_counts:
        groups = defaultdict(list)
        for row in rows:
            if not row["scope_resolved"]:
                groups[(row["persona"], row["scope"])].append(row)
        group_rows = []
        for (function, sid), members in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
            states = Counter(r.get("assignment_evidence_state", "not_collected") for r in members)
            exact = states["identity_observed"] + states["body_difference_observed"]
            contexts = sorted({c["persona"] for r in members for c in r.get("other_scope_contexts", [])})
            link = url(root, "assignments", snapshot=name, module=module, persona=function, identity=identity, scope=sid, state=state)
            group_rows.append(tr(e(persona_label(function)), e(sid), e(pretty(members[0]["scope_resolution"])) + '<small>' + e(pretty(members[0].get("function_context","unknown"))) + '</small>',
                str(len(members)), str(len({r["module"] for r in members})), str(exact),
                e(", ".join(persona_label(p) for p in contexts) or "None observed"), f'<a href="{link}">Inspect assignments</a>'))
        body += '<section><h2>Unresolved scope groups</h2><p>'+str(len(groups))+' distinct function/scope pairs. An exact individual identity confirms an assignment observation, not the device recipients.</p>'+table(("Function","Scope ID","Reason","Assignments","Modules","Exact individual identities","Other observed functions",""), group_rows, search=True)+'</section>'
    # Search the complete filtered assignment set before bounding rendered rows.
    # Inspector indices remain relative to the original filtered result so
    # paging and searching cannot rebind an evidence link to another profile.
    keyword=query.get("assignment_q","")
    if len(keyword)>200:
        raise ValueError("Invalid assignment search")
    terms=keyword.casefold().split()
    selected=[(index,row) for index,row in enumerate(rows)
              if all(term in " ".join(str(row.get(k,"")) for k in ("module","identity","persona","scope","scope_name","scope_kind","scope_resolution","function_context","assignment_evidence_state")).casefold() for term in terms)]
    try:
        offset=int(query.get("assignment_offset","0"))
    except (TypeError,ValueError):
        raise ValueError("Invalid assignment page") from None
    if offset<0 or offset%50 or (offset and offset>=len(selected)):
        raise ValueError("Invalid assignment page")
    controls=(f'<form class="filter-bar" method="get" action="{e(root+"assignments")}">'
              +"".join(f'<input type="hidden" name="{e(k)}" value="{e(v)}">' for k,v in common.items() if k!="binding")
              +f'<label>Search all filtered assignments<input name="assignment_q" maxlength="200" value="{e(keyword)}"></label>'
              +'<button type="submit">Search</button></form>'
              +f'<p>Showing {offset+1 if selected else 0}–{min(offset+50,len(selected))} of {len(selected)} matching assignments. Summary and private export cover the complete scope filters. ')
    for label,position in (("Previous",offset-50),("Next",offset+50)):
        if 0<=position<len(selected):
            controls+=f'<a class="button" href="{url(root,"assignments",**common,assignment_q=keyword,assignment_offset=position)}">{label}</a> '
    controls+='</p>'
    listing = []
    for index, row in selected[offset:offset+50]:
        counts = Counter(d["status"] for d in row["recipients"])
        profile = e(row["identity"]) + '<small>' + badge("Library observed" if row["library_present"] else "Library unverified",
                    "neutral" if row["library_present"] else "warn") + '</small>'
        profile += '<small>Individual assignment: '+e(pretty(row.get("assignment_evidence_state", "not_collected")))+'</small>'
        if row.get("library_individual_conflict") or any(d.get("individual_conflict") for d in row["recipients"]):
            profile += '<small>' + badge("Individual evidence conflict", "warn") + '</small>'
        scope_label = e(row["scope_name"]) + '<small>' + badge("Scope resolved" if row["scope_resolved"] else "Scope unresolved",
                    "neutral" if row["scope_resolved"] else "warn") + '</small>'
        if not row["scope_resolved"]:
            scope_label += '<small>'+e(pretty(row["scope_resolution"]))+'</small>'
        listing.append(tr(e(module_label(row["module"])), profile, e(persona_label(row["persona"])),
                          scope_label, e(pretty(row["scope_kind"])), str(row["known_count"]) if row["scope_resolved"] else "Unknown",
                          str(row["unknown_count"]) if row["scope_resolved"] else "Unknown",
                          str(counts["matching_shared"]) if row["scope_resolved"] else "Unknown",
                          str(counts["different_body"]) if row["scope_resolved"] else "Unknown",
                          str(counts["not_visible"]) if row["scope_resolved"] else "Unknown",
                          str(counts["unverified"] + counts["matching_source_unverified"] + counts["individual_evidence_conflict"]) if row["scope_resolved"] else "Unknown", control("assignment", index)))
    body += '<section><h2>Assignment worklist</h2>' + controls + table(("Module", "Profile", "Function", "Scope", "Type", "Known recipients", "Unknown membership", "Shared matches", "Different", "Not visible", "Unverified", ""), listing, search=True) + '</section>'
    body += '<section><h2>Overlapping assignment observations</h2><p>Complete overlap groups involving the selected assignments are shown, including other profile names outside the current filter. Assignments to overlapping scopes can be intentional. Atomic modules are grouped by module rather than name; overlap does not establish a conflict or prove precedence.</p>'
    body += table(("Function", "Device", "Module", "Identity", "Assignments", ""), [
        tr(e(persona_label(row["persona"])), e(row["device"]), e(module_label(row["module"])), e(row["identity"]),
           str(len(row["assignments"])), control("overlap", index))
        for index, row in enumerate(result["overlaps"])], search=True) + '</section>'
    body += '<section><h2>Capture limitations</h2><p>Assignment capture: ' + e(pretty(result["capture_status"])) + '. Counts are observed lower bounds. Unknown membership is not non-membership. Invalid records are capture-wide because their selectors are incomplete.</p>' + raw(result["invalid_rows"]) + f'<p><a class="button" href="{url(root, "assignments", **common, export="1")}">Export private report JSON</a></p></section>'
    return page("Library assignments", body, workspace.nav(name))


def assignment_detail(row):
    detail = '<h3>Individual assignment evidence</h3><p>'+e(pretty(row.get("assignment_evidence_state", "not_collected")))+'</p><p>Exact assignment identity does not establish device membership. A body difference is a recorded discrepancy, not proof of changed deployment.</p>'
    if row.get("individual_assignment_observations"):
        detail += raw(row["individual_assignment_observations"])
    if not row["scope_resolved"]:
        detail += '<p>Scope resolution: '+e(pretty(row["scope_resolution"]))+'</p><p>Function context: '+e(pretty(row.get("function_context","unknown")))+'</p><p>Missing inventory observations do not establish absence of devices or assignments.</p>'
        if row["other_scope_contexts"]:
            detail += '<h3>Other function observations for this exact scope ID</h3><p>Not verified assignment recipients.</p>'+table(("Function","Type","Scope"),[
                tr(e(persona_label(c["persona"])),e(pretty(c["kind"])),e(c["name"])) for c in row["other_scope_contexts"]])
    if row.get("library_individual_conflict"):
        detail += '<h3>Conflicting Library evidence</h3>' + raw(row["library_individual_conflict"])
    detail += table(("Device", "Result", ""), [
        tr(e(d["device"]), badge(pretty(d["status"])) + (('<small>' + badge("Individual evidence conflict", "warn") + '</small>') if d.get("individual_conflict") else ""),
           inspect(d["device"], diff_table(d["differences"], "Library", "Effective device") + raw(d), "Compare"))
        for d in row["recipients"]], search=True)
    return detail + '<p>Library definition captured: ' + e(str(row["library_present"])) + '</p>' + raw(row)
