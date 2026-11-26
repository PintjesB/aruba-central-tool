"""Read-only before/after checks for an observed consolidation candidate."""
from datetime import datetime
from central_tool import canonical, health_serial, profile_body, field_differences
from configuration_history import snapshot_identity_checks
from consolidation import profile_recommendations
from advanced_review import advanced_analysis, duplicate_migration_preview


def comparable(before, after, confirmed):
    if any(bundle.get("collection_checkpoint", {}).get("mixed_capture_times") for bundle in (before, after)):
        raise ValueError("Remediation verification requires fresh captures without resumed scope evidence")
    if not confirmed:
        raise ValueError("Confirm that both snapshots belong to the same tenant")
    result = snapshot_identity_checks(before, after)
    try:
        older = datetime.fromisoformat(before["captured_at"])
        newer = datetime.fromisoformat(after["captured_at"])
        if older.tzinfo is None or newer.tzinfo is None or newer <= older:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ValueError("A strictly newer timestamped capture is required") from None
    return result


def scope_meta(bundle, persona, sid):
    return next((s for s in bundle["results"].get(persona, {}).get("scopes", [])
                 if s["id"] == sid), {})


def same_device(before, after, persona, sid):
    a, b = scope_meta(before, persona, sid), scope_meta(after, persona, sid)
    serial = health_serial(a.get("metadata"))
    return bool(a.get("kind") == b.get("kind") == "device" and serial
                and serial == health_serial(b.get("metadata")))


def scoped_view(bundle, persona, module, sid, kind):
    rows = bundle["results"].get(persona, {}).get("modules", {}).get(module, {}).get("scope_results", [])
    return next((s.get(kind + "_view", {}) for s in rows if s["scope"] == sid), {})


def observation(view, identity):
    if view.get("status") != "list_parsed":
        return {"state": "unavailable"}
    raw = view.get("profiles", {}).get(identity)
    if raw is None:
        return {"state": "absent" if view.get("count_confirmed") is True else "absence_unverified"}
    return {"state": "present", "body": profile_body(raw), "annotations": raw.get("@")}


def override_candidates(bundle):
    return [f for f in profile_recommendations(bundle)
            if f["action"] == "remove_override" and f["preview_selectable"]
            and f["sources"] and all(s["kind"] == "device" for s in f["sources"])]


def verify_override(before, after, candidate_id, *, confirmed=False):
    identity_checks = comparable(before, after, confirmed)
    candidate = next((f for f in override_candidates(before) if f["id"] == candidate_id), None)
    if candidate is None:
        raise ValueError("Unknown or unqualified prior override candidate")
    persona, module, identity = (candidate[k] for k in ("persona", "module", "identity"))
    rows = []
    for source in candidate["sources"]:
        sid = source["scope"]
        old_local = observation(scoped_view(before, persona, module, sid, "local"), identity)
        old_effective = observation(scoped_view(before, persona, module, sid, "effective"), identity)
        new_local = observation(scoped_view(after, persona, module, sid, "local"), identity)
        new_effective = observation(scoped_view(after, persona, module, sid, "effective"), identity)
        if not same_device(before, after, persona, sid):
            status = "device_identity_unverified"
        elif new_local["state"] == "present":
            status = "local_override_still_present"
        elif new_local["state"] != "absent" or new_effective["state"] != "present":
            status = "verification_required"
        elif canonical(old_effective.get("body")) != canonical(new_effective["body"]):
            status = "effective_configuration_changed"
        elif not isinstance(new_effective.get("annotations"), dict) or new_effective["annotations"].get("aruba-annotation:inherited") is not True:
            status = "inheritance_unverified"
        else:
            status = "observed_goal_met"
        rows.append({"scope": sid, "device": source["name"], "status": status,
                     "before_local": old_local, "before_effective": old_effective,
                     "after_local": new_local, "after_effective": new_effective,
                     "rollback_review": {"saved_body": old_local.get("body"), "prior_effective": old_effective.get("body"),
                                         "instruction": "Review prior saved definition and assignments; do not restore blindly."}})
    return {"workflow": "override_removal", "candidate": candidate, "rows": rows, "identity_checks": identity_checks,
            "complete": False, "safe_to_apply": False}


def duplicate_candidates(bundle):
    return advanced_analysis(bundle)["library_duplicates"]


def verify_library_migration(before, after, module, keep, *, confirmed=False):
    identity_checks = comparable(before, after, confirmed)
    matches = [d for d in duplicate_candidates(before) if d["module"] == module and keep in d["identities"]]
    if len(matches) != 1:
        raise ValueError("Choose a retained identity from an observed duplicate group")
    group = matches[0]
    old_names = set(group["identities"]) - {keep}
    plan = duplicate_migration_preview(module, group["usage"], keep, bundle=before)
    old_library = before.get("library", {}).get("modules", {}).get(module, {})
    new_library = after.get("library", {}).get("modules", {}).get(module, {})
    expected = observation(old_library, keep)
    retained = observation(new_library, keep)
    library_matches = retained["state"] == "present" and canonical(retained["body"]) == canonical(expected.get("body"))
    rows = []
    for recipient in plan["recipient_review"]:
        persona, sid = recipient["persona"], recipient["scope"]
        old_view = scoped_view(before, persona, module, sid, "effective")
        new_view = scoped_view(after, persona, module, sid, "effective")
        new_keep = observation(new_view, keep)
        previous = {identity: observation(old_view, identity) for identity in sorted(old_names | {keep})}
        current = {identity: observation(new_view, identity) for identity in sorted(old_names | {keep})}
        if not same_device(before, after, persona, sid):
            status = "device_identity_unverified"
        elif recipient["uncertain_membership"] or not library_matches or new_keep["state"] != "present":
            status = "verification_required"
        elif canonical(new_keep["body"]) != canonical(expected.get("body")):
            status = "retained_definition_differs"
        elif any(current[n]["state"] == "present" for n in old_names):
            status = "old_identity_still_visible"
        elif any(current[n]["state"] != "absent" for n in old_names):
            status = "verification_required"
        else:
            status = "observed_profiles_match_goal"
        rows.append({**recipient, "device": recipient["name"], "status": status,
                     "before_effective": previous, "after_effective": current})
    after_analysis = advanced_analysis(after)
    remaining_references = [r for r in after_analysis["references"] if r["target_module"] == module and r["target"] in old_names]
    assignment_view = after.get("library", {}).get("assignments", {})
    remaining_assignments = [a for a in assignment_view.get("rows", []) if a.get("profile-type") == module
                             and str(a.get("profile-instance")) in old_names]
    return {"workflow": "library_migration", "module": module, "retain": keep, "old_names": sorted(old_names),
            "identity_checks": identity_checks, "rows": rows, "retained_library_matches": library_matches,
            "remaining_references": remaining_references, "remaining_assignments": remaining_assignments,
            "unresolved_recipients": plan["unresolved_recipient_observations"],
            "rollback_review": {"prior_library": {n: observation(old_library, n) for n in sorted(old_names | {keep})},
                                "current_library": {n: observation(new_library, n) for n in sorted(old_names | {keep})},
                                "prior_assignments": plan["assignments"], "prior_saved_references": plan["saved_references"]},
            "complete": False, "safe_to_apply": False}
