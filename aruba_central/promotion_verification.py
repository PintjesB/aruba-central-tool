"""Compare a proposed local-profile promotion against a newer private capture.

Review captured evidence only. Never infer deployment or authorize a change.
"""
from .central_tool import canonical
from .consolidation import profile_recommendations
from .bulk_review import source_recipient_evidence
from .remediation_review import comparable, captured_observation, contradictory, scope_meta, same_device


def promotion_candidates(bundle):
    return [f for f in profile_recommendations(bundle)
            if f["action"] in ("promote_local", "reuse_library") and f["preview_selectable"] and f["sources"]]


def verify_promotion(before, after, candidate_id, destination, *, confirmed=False):
    identity_checks = comparable(before, after, confirmed)
    candidate = next((f for f in promotion_candidates(before) if f["id"] == candidate_id), None)
    if candidate is None:
        raise ValueError("Unknown or unqualified prior promotion")
    persona, module, identity = (candidate[k] for k in ("persona", "module", "identity"))
    sources = candidate["sources"]
    reuse = candidate.get("action") == "reuse_library"
    if any(d["destination"] == destination for d in candidate.get("blocked_destinations", [])):
        raise ValueError("Destination blocked by contradictory individual evidence")
    if reuse and destination != "library":
        raise ValueError("Existing Library reuse has no other destination")
    expected = canonical(candidate["local"])

    def matches(obs):
        return obs["state"] == "present" and canonical(obs["body"]) == expected

    def source_observation(bundle, sid, kind):
        return captured_observation(bundle, persona, module, sid, kind, identity)

    def members(bundle, selected):
        entry = bundle["results"].get(persona, {"scopes": []})
        observed = source_recipient_evidence(entry, selected)
        return ({r["scope"] for r in observed["known"]},
                {r["scope"] for r in observed["unknown"]})

    assignment_comparison = None
    intended, uncertain = members(before, sources)
    new_intended, new_uncertain = members(after, sources)
    if destination == "library":
        old_dest = captured_observation(before, "Library", module, "", "library", identity)
        new_dest = captured_observation(after, "Library", module, "", "library", identity)
        old_recipients, old_unknown = intended, uncertain
        new_recipients, dest_unknown = new_intended, new_uncertain
        def assigned(bundle):
            view = (bundle.get("library") or {}).get("assignments") or {}
            keys = set()
            for row in view.get("rows", []):
                if (isinstance(row, dict) and row.get("profile-type") == module
                        and type(row.get("profile-instance")) in (str, int)
                        and str(row["profile-instance"]) == identity
                        and isinstance(row.get("device-function"), str)
                        and type(row.get("scope-id")) in (str, int)):
                    keys.add((row["device-function"], str(row["scope-id"])))
            return view, keys
        prior_assignment_view, prior_assignments = assigned(before)
        assignment_view, assignments = assigned(after)
        expected_scopes = {(persona, str(r["scope"])) for r in sources}
        assignment_rows = [{"scope": r["scope"], "observed": assignment_view.get("status") == "response_received"
                            and (persona, str(r["scope"])) in assignments} for r in sources]
        assignment_comparison = {
            "before_capture_status": prior_assignment_view.get("status", "not_collected"),
            "after_capture_status": assignment_view.get("status", "not_collected"),
            "rows": [{"persona": function, "scope": sid,
                      "selected_source_scope": (function, sid) in expected_scopes,
                      "before_observed": (function, sid) in prior_assignments,
                      "after_observed": (function, sid) in assignments,
                      "status": ("observed_in_both" if (function, sid) in prior_assignments and (function, sid) in assignments
                                 else "newly_observed" if (function, sid) in assignments
                                 else "no_longer_observed" if (function, sid) in prior_assignments
                                 else "not_observed")}
                     for function, sid in sorted(prior_assignments | assignments | expected_scopes)]}
        # Source-scope assignment checks do not establish the complete set
        # of destinations. Expose all observed assignments independently,
        # including other functions and scopes, without inferring removal.
        target_matches = matches(new_dest) and (not reuse or matches(old_dest)) and all(a["observed"] for a in assignment_rows)
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

    if contradictory(old_dest, new_dest):
        target_matches = False

    source_rows = []
    for source in sources:
        sid = source["scope"]
        old = source_observation(before, sid, "local")
        new = source_observation(after, sid, "local")
        scope_stable = (scope_meta(before, persona, sid).get("kind") == source["kind"]
                        == scope_meta(after, persona, sid).get("kind"))
        if source["kind"] == "device":
            scope_stable = scope_stable and same_device(before, after, persona, sid)
        if contradictory(old, new):
            status = "individual_evidence_conflict"
        elif not scope_stable or not matches(old):
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
        elif contradictory(old, new):
            status = "individual_evidence_conflict"
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

    from .remediation_collateral import collateral_review
    collateral = collateral_review(before, after, module, {(persona, r["scope"]): {identity} for r in rows})
    return {"collateral": collateral, "workflow": "library_reuse" if reuse else "local_promotion", "candidate": candidate, "destination": destination,
            "identity_checks": identity_checks, "destination_definition_matches": matches(new_dest),
            "destination_and_assignments_observed": target_matches,
            "before_destination": old_dest, "after_destination": new_dest,
            "assignment_observations": assignment_rows, "assignment_comparison": assignment_comparison,
            "source_rows": source_rows, "rows": rows,
            "complete": False, "safe_to_apply": False}
