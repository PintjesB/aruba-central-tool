"""Review captured Library assignment recipients and conflicting scope definitions."""
from .central_tool import canonical, profile_body, field_differences
from .consolidation import scope_memberships
from .inheritance_review import ATOMIC


def assignment_review(bundle, module_filter="", persona_filter="", identity_filter=""):
    library = bundle.get("library") or {}
    collections = library.get("modules", {})
    assignment_view = library.get("assignments") or {}
    entries = bundle["results"]
    scopes = {p: {s["id"]: s for s in e["scopes"]} for p, e in entries.items()}
    members = {p: scope_memberships(e["scopes"]) for p, e in entries.items()}
    views = {p: {m: {s["scope"]: s.get("effective_view", {}) for s in d["scope_results"]}
                 for m, d in e["modules"].items()} for p, e in entries.items()}
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
        source = scopes.get(persona, {}).get(sid)
        lib = collections.get(module, {})
        expected = lib.get("profiles", {}).get(identity) if lib.get("status") == "list_parsed" else None
        known, unknown = [], []
        if source:
            kind = source["kind"]
            for device, membership in members[persona].items():
                if kind == "device":
                    if sid == device:
                        known.append(device)
                elif kind in membership:
                    if membership[kind] == sid:
                        known.append(device)
                    elif membership[kind] is None:
                        unknown.append(device)
        recipients = []
        for device in known + unknown:
            view = views.get(persona, {}).get(module, {}).get(device, {})
            actual = view.get("profiles", {}).get(identity) if view.get("status") == "list_parsed" else None
            if device in unknown:
                state = "membership_unverified"
            elif expected is None or view.get("status") != "list_parsed":
                state = "unverified"
            elif actual is None:
                state = "not_visible" if view.get("count_confirmed") is True else "unverified"
            elif canonical(profile_body(actual)) != canonical(profile_body(expected)):
                state = "different_body"
            elif isinstance(actual.get("@"), dict) and actual["@"].get("aruba-annotation:object_type") == "SHARED":
                state = "matching_shared"
            else:
                state = "matching_source_unverified"
            recipients.append({"scope": device, "device": scopes[persona][device].get("name") or device,
                               "status": state, "differences": field_differences(profile_body(expected), profile_body(actual))
                               if expected is not None and actual is not None else []})
            if device in known:
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
