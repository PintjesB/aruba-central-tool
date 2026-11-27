"""Aggregate Library definition visibility without confusing no assignments with no use."""
from collections import Counter, defaultdict


def visibility_summary(bundle):
    library = bundle.get("library") or {}
    modules = library.get("modules") or {}
    assignment_view = library.get("assignments") or {}
    entries = bundle.get("results") or {}
    assigned = defaultdict(set)
    for row in assignment_view.get("rows", []):
        if not isinstance(row, dict):
            continue
        module, identity, persona, scope = (row.get(k) for k in
            ("profile-type", "profile-instance", "device-function", "scope-id"))
        if (not isinstance(module, str) or type(identity) not in (str, int)
                or not isinstance(persona, str) or type(scope) not in (str, int)):
            continue
        assigned[module].add((str(identity), persona, str(scope)))
    results = []
    for module, view in sorted(modules.items()):
        if view.get("status") != "list_parsed" or not view.get("profiles"):
            continue
        definitions = set(view["profiles"])
        records = assigned[module]
        views = {}
        counts = Counter()
        for persona, entry in entries.items():
            for row in entry.get("modules", {}).get(module, {}).get("scope_results", []):
                effective = row.get("effective_view") or {}
                views[(persona, str(row["scope"]))] = effective
                if effective.get("status") == "empty_object":
                    counts["empty_object"] += 1
                elif effective.get("status") != "list_parsed":
                    counts["unqualified"] += 1
                elif not effective.get("profiles"):
                    counts["confirmed_empty" if effective.get("count_confirmed") is True else "unconfirmed_empty"] += 1
                else:
                    counts["positive"] += 1
        visibility = Counter()
        for identity, persona, scope in records:
            if identity not in definitions:
                visibility["library_definition_unobserved"] += 1
                continue
            effective = views.get((persona, scope), {})
            if effective.get("status") != "list_parsed":
                visibility["unverified"] += 1
            elif identity in effective.get("profiles", {}):
                visibility["identity_observed"] += 1
            elif effective.get("count_confirmed") is True:
                visibility["count_confirmed_absence"] += 1
            else:
                visibility["unverified"] += 1
        results.append({"module": module, "definitions": len(definitions),
                        "definitions_with_observed_assignments": len(definitions & {i for i, _, _ in records}),
                        "observed_assignments": len(records),
                        "assignment_capture_status": assignment_view.get("status", "not_collected"),
                        "effective_views": dict(counts), "assignment_visibility": dict(visibility),
                        "complete": False})
    return results
