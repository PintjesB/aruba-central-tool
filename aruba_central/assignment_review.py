"""Review captured Library assignment recipients and conflicting scope definitions."""
from collections import defaultdict
from .central_tool import canonical, profile_body, field_differences
from .consolidation import scope_memberships
from .inheritance_review import ATOMIC


def assignment_review(bundle, module_filter="", persona_filter="", identity_filter=""):
    library = bundle.get("library") or {}
    collections = library.get("modules", {})
    assignment_view = library.get("assignments") or {}
    entries = bundle["results"]
    direct = (bundle.get("keyed_profile_details") or {}).get("profiles", {})
    def contradiction(view, body, persona, sid, module, identity, kind):
        if view.get("status") != "list_parsed":
            return None
        read = direct.get(persona, {}).get(str(sid), {}).get(module, {}).get(identity, {}).get(kind, {})
        if read.get("status") != "identity_observed" or not isinstance(read.get("profile"), dict):
            return None
        individual = profile_body(read["profile"])
        if body is not None and canonical(body) != canonical(individual):
            return {"collection_state": "present", "collection_body": body, "individual_body": individual,
                    "differences": field_differences(body, individual)}
        if body is None and view.get("count_confirmed") is True:
            return {"collection_state": "count_confirmed_absent", "individual_body": individual}
        return None
    scopes, memberships, views = {}, {}, {}
    def index_persona(persona):
        if persona in scopes or persona not in entries:
            return
        entry = entries[persona]
        scopes[persona] = {s["id"]: s for s in entry["scopes"]}
        known, unknown = defaultdict(list), defaultdict(list)
        for device, membership in scope_memberships(entry["scopes"]).items():
            known["device", device].append(device)
            for kind, ancestor in membership.items():
                if ancestor is None:
                    unknown[kind].append(device)
                else:
                    known[kind, ancestor].append(device)
        memberships[persona] = (known, unknown)
    seen = set()
    rows = []
    invalid = []
    overlaps = {}
    for a in assignment_view.get("rows", []):
        keys = ("profile-type", "profile-instance", "device-function", "scope-id")
        if not isinstance(a, dict) or not all(type(a.get(k)) in (str, int) and str(a[k]) for k in keys):
            invalid.append(a)
            continue
        module, identity, persona, sid = (str(a[k]) for k in keys)
        if module_filter and module != module_filter or persona_filter and persona != persona_filter or identity_filter and identity != identity_filter:
            continue
        key = (module, identity, persona, sid)
        if key in seen:
            continue
        seen.add(key)
        index_persona(persona)
        source = scopes.get(persona, {}).get(sid)
        lib = collections.get(module, {})
        expected = lib.get("profiles", {}).get(identity) if lib.get("status") == "list_parsed" else None
        known, unknown = [], []
        if source:
            kind = source["kind"]
            by_scope, by_unknown = memberships[persona]
            known = by_scope.get((kind, sid), [])
            unknown = by_unknown.get(kind, [])
        view_key = (persona, module)
        if view_key not in views:
            data = entries.get(persona, {}).get("modules", {}).get(module, {})
            views[view_key] = {s["scope"]: s.get("effective_view", {}) for s in data.get("scope_results", [])}
        expected_body = profile_body(expected) if expected is not None else None
        expected_signature = canonical(expected_body) if expected is not None else None
        library_conflict = contradiction(lib, expected_body, "Library", "", module, identity, "library")
        known_set, unknown_set = set(known), set(unknown)
        recipients = []
        for device in known + unknown:
            view = views[view_key].get(device, {})
            actual = view.get("profiles", {}).get(identity) if view.get("status") == "list_parsed" else None
            actual_body = profile_body(actual) if actual is not None else None
            comparable = expected is not None and actual is not None
            # The exact canonical comparison already establishes whether
            # recursive field comparison can return a non-empty result.
            same_body = comparable and canonical(actual_body) == expected_signature
            direct_conflict = contradiction(view, actual_body, persona, device, module, identity, "effective")
            if device in unknown_set:
                state = "membership_unverified"
            elif library_conflict or direct_conflict:
                state = "individual_evidence_conflict"
            elif expected is None or view.get("status") != "list_parsed":
                state = "unverified"
            elif actual is None:
                state = "not_visible" if view.get("count_confirmed") is True else "unverified"
            elif not same_body:
                state = "different_body"
            elif isinstance(actual.get("@"), dict) and actual["@"].get("aruba-annotation:object_type") == "SHARED":
                state = "matching_shared"
            else:
                state = "matching_source_unverified"
            recipient = {"scope": device, "device": scopes[persona][device].get("name") or device,
                         "status": state, "differences": field_differences(expected_body, actual_body)
                         if comparable and not same_body else []}
            if direct_conflict:
                recipient["individual_conflict"] = direct_conflict
            recipients.append(recipient)
            if device in known_set:
                overlap_key = (persona, device, module, "*" if module in ATOMIC else identity)
                overlaps.setdefault(overlap_key, []).append({"scope": sid, "identity": identity})
        row = {"module": module, "identity": identity, "persona": persona, "scope": sid,
                     "scope_name": source.get("name") or sid if source else sid, "scope_kind": source["kind"] if source else "unknown",
                     "library_present": expected is not None, "scope_resolved": source is not None,
                     "recipients": recipients, "known_count": len(known), "unknown_count": len(unknown)}
        if library_conflict:
            row["library_individual_conflict"] = library_conflict
        rows.append(row)
    collisions = [{"persona": p, "device": d, "module": m, "identity": i, "assignments": a}
                  for (p, d, m, i), a in overlaps.items() if len(a) > 1]
    return {"rows": rows, "overlaps": collisions, "invalid_rows": invalid,
            "capture_status": assignment_view.get("status", "not_collected"), "complete": False, "safe_to_apply": False}


ASSIGNMENT_FILTERS = {
    "all": "All assignments", "attention": "Requires review",
    "scope_unresolved": "Unresolved assignment scope",
    "overlap": "Overlapping assignments",
    "library_unobserved": "Library definition not observed",
    "different_body": "Different effective settings",
    "individual_evidence_conflict": "Contradictory individual evidence",
    "not_visible": "Count-confirmed profile absence",
    "membership_unverified": "Unknown recipient membership",
    "unverified": "Unverified effective evidence",
    "matching_source_unverified": "Matching body, source unverified",
    "matching_shared": "Matching shared profile observed",
    "no_recipients": "No known or uncertain recipients",
}


def filter_assignment_review(report, module="", persona="", identity="", state="all"):
    """Filter cached review rows without discarding their overlap context.

    An atomic module may overlap across different profile names. Retain the
    complete collision when any selected assignment participates.
    """
    if state not in ASSIGNMENT_FILTERS:
        raise ValueError("Unknown assignment evidence filter")
    def key(row):
        return (row["persona"], row["module"], row["identity"], row["scope"])
    def participants(collision):
        return {(collision["persona"], collision["module"], item["identity"], item["scope"])
                for item in collision["assignments"]}
    overlap_keys = set().union(*(participants(c) for c in report["overlaps"]))
    def matches(row):
        if ((module and row["module"] != module) or (persona and row["persona"] != persona)
                or (identity and row["identity"] != identity)):
            return False
        states = {r["status"] for r in row["recipients"]}
        unresolved = not row["scope_resolved"]
        overlap = key(row) in overlap_keys
        no_recipients = not row["recipients"]
        if state == "all":
            return True
        conflict = bool(row.get("library_individual_conflict") or any(r.get("individual_conflict") for r in row["recipients"]))
        if state == "attention":
            return (unresolved or overlap or not row["library_present"] or no_recipients
                    or conflict or bool(states - {"matching_shared"}))
        if state == "individual_evidence_conflict":
            return conflict
        if state == "scope_unresolved":
            return unresolved
        if state == "overlap":
            return overlap
        if state == "library_unobserved":
            return not row["library_present"]
        if state == "no_recipients":
            return no_recipients
        return state in states
    rows = [row for row in report["rows"] if matches(row)]
    selected = {key(row) for row in rows}
    return {**report, "rows": rows, "overlaps": [c for c in report["overlaps"] if participants(c) & selected]}
