"""Determine observed migration recipients and retained-profile visibility."""
from collections import defaultdict
from .consolidation import scope_memberships


def migration_recipient_review(bundle, usage, keep, assignments, definitions, impacts):
    entries = (bundle or {}).get("results", {})
    inventory = {}
    membership = {}
    for persona, entry in entries.items():
        inventory[persona] = {s["id"]: s for s in entry["scopes"]}
        membership[persona] = scope_memberships(entry["scopes"])
    recipients = {}
    unresolved = []
    def add(persona, sid, reason, identity, name=None, uncertain=False):
        record = recipients.setdefault((persona, sid), {"persona": persona, "scope": sid,
            "name": name or inventory.get(persona, {}).get(sid, {}).get("name") or sid,
            "observations": [], "uncertain_membership": False})
        evidence = {"from": identity, "reason": reason}
        if evidence not in record["observations"]:
            record["observations"].append(evidence)
        record["uncertain_membership"] |= uncertain
    def expand(persona, sid, identity, reason):
        meta = inventory.get(persona, {}).get(sid)
        if not meta:
            unresolved.append({"persona": persona, "scope": sid, "from": identity, "reason": reason + ": scope unavailable"})
            return
        kind = meta["kind"]
        if kind == "device":
            add(persona, sid, reason, identity)
        elif kind in ("global", "group", "site", "collection"):
            for device, memberships in membership[persona].items():
                member = memberships.get(kind)
                if member == sid or member is None:
                    add(persona, device, reason, identity, uncertain=member is None)
        else:
            unresolved.append({"persona": persona, "scope": sid, "from": identity, "reason": reason + ": unsupported scope"})
    for assignment in assignments:
        expand(assignment["persona"], assignment["scope"], assignment["from"], "Observed assignment")
    for ref in definitions + impacts:
        if ref.get("source_evidence") == "nac_enforcement":
            unresolved.append({"persona":ref["persona"],"scope":ref["scope"],"from":ref["from"],
                               "reason":"NAC enforcement candidate; policy applicability and client location unverified"})
        elif ref.get("source_view") == "library":
            unresolved.append({"persona": ref["persona"], "scope": ref["scope"], "from": ref["from"],
                               "reason": "Library reference deployment not established"})
        elif ref.get("source_scope_kind", "device") == "device":
            add(ref["persona"], ref["scope"], "Observed reference", ref["from"], ref.get("device"))
        else:
            expand(ref["persona"], ref["scope"], ref["from"], "Saved higher-scope reference")
    for identity, value in usage.items():
        if identity == keep:
            continue
        for field, reason in (("shared_devices", "Matching shared source profile"),
                              ("matching_other_devices", "Matching source name; Library source unverified"),
                              ("different_devices", "Different definition under source name"),
                              ("individual_conflict_devices", "Contradictory individual profile evidence")):
            for record in value.get(field, []):
                add(record["persona"], record["scope"], reason, identity, record.get("name"))
        for row in value.get("assignments", []):
            if type(row.get("scope-id")) not in (str, int) or not row.get("device-function"):
                unresolved.append({"persona": row.get("device-function"), "scope": row.get("scope-id"),
                                   "from": identity, "reason": "Assignment identity incomplete"})
    visibility = {}
    for field, status in (("shared_devices", "matching_shared"), ("matching_other_devices", "matching_source_unverified"),
                          ("different_devices", "different_definition"), ("absent_devices", "count_confirmed_absence"),
                          ("unknown_devices", "unverified"), ("individual_conflict_devices", "individual_evidence_conflict")):
        for record in usage[keep].get(field, []):
            visibility[(record["persona"], record["scope"])] = status
    for key, record in recipients.items():
        record["target_visibility"] = visibility.get(key, "unverified")
    return {"recipient_review": sorted(recipients.values(), key=lambda x: (x["persona"], x["scope"])),
            "unresolved_recipient_observations": unresolved}
