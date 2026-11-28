"""Compare a proposed local-profile promotion against a newer private capture.

Review captured evidence only. Never infer deployment or authorize a change.
"""
from .central_tool import canonical
from .consolidation import profile_recommendations
from .bulk_review import source_recipient_evidence
from .remediation_review import comparable, observation, scoped_view, scope_meta, same_device


def promotion_candidates(bundle):
    return [f for f in profile_recommendations(bundle)
            if f["action"] == "promote_local" and f["preview_selectable"] and f["sources"]]


def verify_promotion(before, after, candidate_id, destination, *, confirmed=False):
    identity_checks = comparable(before, after, confirmed)
    candidate = next((f for f in promotion_candidates(before) if f["id"] == candidate_id), None)
    if candidate is None:
        raise ValueError("Unknown or unqualified prior promotion")
    persona, module, identity = (candidate[k] for k in ("persona", "module", "identity"))
    sources = candidate["sources"]
    expected = canonical(candidate["local"])

    def matches(obs):
        return obs["state"] == "present" and canonical(obs["body"]) == expected

    def source_observation(bundle, sid, kind):
        return observation(scoped_view(bundle, persona, module, sid, kind), identity)

    def members(bundle, selected):
        entry = bundle["results"].get(persona, {"scopes": []})
        observed = source_recipient_evidence(entry, selected)
        return ({r["scope"] for r in observed["known"]},
                {r["scope"] for r in observed["unknown"]})

    intended, uncertain = members(before, sources)
    new_intended, new_uncertain = members(after, sources)
    if destination == "library":
        old_dest = observation((before.get("library") or {}).get("modules", {}).get(module, {}), identity)
        new_dest = observation((after.get("library") or {}).get("modules", {}).get(module, {}), identity)
        old_recipients, old_unknown = intended, uncertain
        new_recipients, dest_unknown = new_intended, new_uncertain
        assignment_view = (after.get("library") or {}).get("assignments") or {}
        assignments = {(str(a.get("profile-type")), str(a.get("profile-instance")),
                        str(a.get("device-function")), str(a.get("scope-id")))
                       for a in assignment_view.get("rows", []) if isinstance(a, dict)}
        assignment_rows = [{"scope": r["scope"], "observed": assignment_view.get("status") == "response_received"
                            and (module, identity, persona, r["scope"]) in assignments} for r in sources]
        target_matches = matches(new_dest) and all(a["observed"] for a in assignment_rows)
    else:
        options = [p for p in candidate["placement_options"] if p["scope"] == destination]
        if len(options) != 1:
            raise ValueError("Destination not observed in prior promotion")
        option = options[0]
        target = [{"scope": destination, "kind": option["kind"]}]
        old_recipients, old_unknown = members(before, target)
        new_recipients, dest_unknown = members(after, target)
        old_dest = source_observation(before, destination, "local")
        new_dest = source_observation(after, destination, "local")
        target_matches = (scope_meta(after, persona, destination).get("kind") == option["kind"] and matches(new_dest))
        assignment_rows = []

    source_rows = []
    for source in sources:
        sid = source["scope"]
        old = source_observation(before, sid, "local")
        new = source_observation(after, sid, "local")
        scope_stable = (scope_meta(before, persona, sid).get("kind") == source["kind"]
                        == scope_meta(after, persona, sid).get("kind"))
        if source["kind"] == "device":
            scope_stable = scope_stable and same_device(before, after, persona, sid)
        if not scope_stable or not matches(old):
            status = "source_identity_or_baseline_unverified"
        elif destination != "library" and sid == destination:
            status = "destination_retained" if matches(new) else "source_removal_unverified"
        elif new["state"] == "absent":
            status = "observed_local_removal"
        elif new["state"] == "present":
            status = "local_override_still_present"
        else:
            status = "source_removal_unverified"
        source_rows.append({"scope": sid, "name": source["name"], "status": status,
                            "before_local": old, "after_local": new})

    def devices(bundle):
        return {s["id"]: s.get("name") or s["id"] for s in
                bundle["results"].get(persona, {}).get("scopes", []) if s["kind"] == "device"}

    a, b = devices(before), devices(after)
    rows = []
    for sid in sorted(a.keys() | b.keys()):
        old, new = (source_observation(bundle, sid, "effective") for bundle in (before, after))
        intended_recipient = sid in intended
        membership_unknown = sid in uncertain | new_uncertain | old_unknown | dest_unknown
        membership_changed = ((sid in intended) != (sid in new_intended)
                              or (sid in old_recipients) != (sid in new_recipients))
        if not same_device(before, after, persona, sid):
            status = "device_identity_unverified"
        elif membership_unknown or membership_changed:
            status = "recipient_membership_unverified"
        elif intended_recipient:
            if sid not in new_recipients or not matches(old):
                status = "verification_required"
            elif new["state"] != "present":
                status = "verification_required"
            elif not matches(new):
                status = "effective_configuration_changed"
            else:
                status = "observed_intended_effective_match"
        elif old["state"] == new["state"] == "absent":
            status = "observed_outside_unchanged"
        elif old["state"] == new["state"] == "present":
            status = ("observed_outside_unchanged" if canonical(old["body"]) == canonical(new["body"])
                      else "outside_effective_changed")
        elif {old["state"], new["state"]} == {"present", "absent"}:
            status = "outside_effective_changed"
        else:
            status = "verification_required"
        rows.append({"scope": sid, "device": b.get(sid, a.get(sid)),
                     "intended": intended_recipient, "destination_recipient": sid in new_recipients,
                     "status": status, "before_effective": old, "after_effective": new})

    return {"workflow": "local_promotion", "candidate": candidate, "destination": destination,
            "identity_checks": identity_checks, "destination_definition_matches": matches(new_dest),
            "destination_and_assignments_observed": target_matches,
            "before_destination": old_dest, "after_destination": new_dest,
            "assignment_observations": assignment_rows, "source_rows": source_rows, "rows": rows,
            "complete": False, "safe_to_apply": False}
