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
        if not all(type(a.get(k)) in (str, int) and str(a[k]) for k in keys):
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
        known_set, unknown_set = set(known), set(unknown)
        recipients = []
        for device in known + unknown:
            view = views[view_key].get(device, {})
            actual = view.get("profiles", {}).get(identity) if view.get("status") == "list_parsed" else None
            actual_body = profile_body(actual) if actual is not None else None
            if device in unknown_set:
                state = "membership_unverified"
            elif expected is None or view.get("status") != "list_parsed":
                state = "unverified"
            elif actual is None:
                state = "not_visible" if view.get("count_confirmed") is True else "unverified"
            elif canonical(actual_body) != expected_signature:
                state = "different_body"
            elif isinstance(actual.get("@"), dict) and actual["@"].get("aruba-annotation:object_type") == "SHARED":
                state = "matching_shared"
            else:
                state = "matching_source_unverified"
            recipients.append({"scope": device, "device": scopes[persona][device].get("name") or device,
                               "status": state, "differences": field_differences(expected_body, actual_body)
                               if expected is not None and actual is not None else []})
            if device in known_set:
                overlap_key = (persona, device, module, "*" if module in ATOMIC else identity)
                overlaps.setdefault(overlap_key, []).append({"scope": sid, "identity": identity})
        rows.append({"module": module, "identity": identity, "persona": persona, "scope": sid,
                     "scope_name": source.get("name") or sid if source else sid, "scope_kind": source["kind"] if source else "unknown",
                     "library_present": expected is not None, "scope_resolved": source is not None,
                     "recipients": recipients, "known_count": len(known), "unknown_count": len(unknown)})
    collisions = [{"persona": p, "device": d, "module": m, "identity": i, "assignments": a}
                  for (p, d, m, i), a in overlaps.items() if len(a) > 1]
    return {"rows": rows, "overlaps": collisions, "invalid_rows": invalid,
            "capture_status": assignment_view.get("status", "not_collected"), "complete": False, "safe_to_apply": False}
