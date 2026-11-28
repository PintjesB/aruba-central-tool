"""Trace observed profile provenance without assuming a unique winning source."""
from .central_tool import canonical, profile_body, field_differences
from .consolidation import scope_memberships
from .standard_evidence import conflicting_profiles
from .inheritance_review import PRECEDENCE, ADDITIVE, ATOMIC, TOPOLOGY_REVIEW


def source_trace(bundle, persona, device, module, identity):
    entry = bundle["results"][persona]
    scopes = {s["id"]: s for s in entry["scopes"]}
    members = scope_memberships(entry["scopes"])
    if device not in members or module not in entry["modules"]:
        raise ValueError("Choose a captured device and module")
    views = {s["scope"]: s for s in entry["modules"][module]["scope_results"]}
    def observe(view, name, sid, side, function=persona):
        if view.get("status") != "list_parsed":
            return {"state": "unavailable", "read_status": view.get("status", "not_collected")}
        raw = view["profiles"].get(name)
        conflicts = conflicting_profiles(bundle, function, module, sid, view, {name}, side=side)
        if name in conflicts:
            return {"state": "individual_evidence_conflict", "individual_conflict": conflicts[name]}
        if raw is None:
            return {"state": "absent" if view.get("count_confirmed") is True else "absence_unverified"}
        return {"state": "present", "body": profile_body(raw), "annotations": raw.get("@")}
    actual = observe(views.get(device, {}).get("effective_view", {}), identity, device, "effective")
    chain = [("device", device)] + [(kind, members[device][kind]) for kind in PRECEDENCE]
    rows = []
    blockers = ["Device effective profile contradicts individual evidence"] if actual["state"] == "individual_evidence_conflict" else []
    matching_sources = []
    winner = None
    atomic = module in ATOMIC
    qualified = module in ADDITIVE or atomic
    for kind, sid in chain:
        if sid is None:
            rows.append({"kind": kind, "scope": None, "name": kind, "status": "membership_unknown"})
            if winner is None:
                blockers.append(kind + " membership unknown")
            continue
        record = views.get(sid, {})
        effective = record.get("effective_view", {})
        name = identity
        if atomic and effective.get("status") == "list_parsed" and effective.get("count_confirmed") is True and len(effective["profiles"]) == 1:
            name = next(iter(effective["profiles"]))
        local = observe(record.get("local_view", {}), name, sid, "local")
        observed = observe(effective, name, sid, "effective")
        ann = observed.get("annotations")
        direct = isinstance(ann, dict) and ann.get("aruba-annotation:inherited") is False and ann.get("aruba-annotation:object_type") in ("LOCAL", "SHARED") and ann.get("aruba-annotation:is_default") is not True
        inherited = isinstance(ann, dict) and ann.get("aruba-annotation:inherited") is True
        match = observed["state"] == actual["state"] == "present" and canonical(observed["body"]) == canonical(actual["body"])
        status = ("direct_match" if match else "direct_difference") if direct else ("inherited_match" if match else "inherited_difference") if inherited else observed["state"] if observed["state"] != "present" else "source_unverified"
        if local["state"] == "individual_evidence_conflict" or observed["state"] == "individual_evidence_conflict":
            status = "individual_evidence_conflict"
        if direct and match and status != "individual_evidence_conflict":
            matching_sources.append(sid)
        if winner is None:
            if atomic and (effective.get("count_confirmed") is not True or len(effective.get("profiles", {})) > 1):
                blockers.append(kind + " atomic cardinality unverified")
            if status == "direct_match" and qualified and not blockers:
                winner = sid
            elif status not in ("absent", "inherited_match"):
                blockers.append(kind + ": " + status)
        if status == "individual_evidence_conflict" and winner is not None:
            blockers.append(kind + ": contradictory individual evidence outside the observed winning chain")
        rows.append({"kind": kind, "scope": sid, "name": scopes[sid].get("name") or sid,
                     "identity": name, "status": status, "local": local, "effective": observed,
                     "differences": field_differences(actual["body"], observed["body"]) if actual["state"] == observed["state"] == "present" else []})
    library_data = bundle.get("library") or {}
    library = observe(library_data.get("modules", {}).get(module, {}), identity, "", "library", "Library")
    if library["state"] == "individual_evidence_conflict":
        blockers.append("Library definition contradicts individual evidence")
    assignments = [a for a in (library_data.get("assignments") or {}).get("rows", [])
                   if isinstance(a, dict) and a.get("profile-type") == module and str(a.get("profile-instance")) == identity
                   and a.get("device-function") == persona and str(a.get("scope-id")) in {sid for _, sid in chain if sid is not None}]
    if not qualified:
        blockers.append("Module precedence semantics not qualified")
    if module in TOPOLOGY_REVIEW:
        blockers.append("Topology-sensitive comparison; operational behavior not verified")
    return {"device": device, "module": module, "identity": identity, "effective": actual,
            "chain": rows, "observed_source_scope": winner, "matching_direct_scopes": matching_sources,
            "library": library, "observed_assignments": assignments, "blockers": blockers,
            "safe_to_apply": False, "complete": False}
