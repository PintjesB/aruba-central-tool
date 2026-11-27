"""Recipient evidence for non-executable consolidation worklists."""
from .consolidation import scope_memberships


def source_recipient_evidence(entry, sources):
    members = scope_memberships(entry["scopes"])
    scopes = {s["id"]: s for s in entry["scopes"]}
    known, unknown = set(), set()
    for source in sources:
        sid = source["scope"]
        kind = source["kind"]
        if kind == "device" and sid in members:
            known.add(sid)
        elif kind in ("global", "group", "site", "collection") and sid in scopes:
            known.update(d for d, membership in members.items() if membership[kind] == sid)
            unknown.update(d for d, membership in members.items() if membership[kind] is None)
        else:
            unknown.update(members)
    def describe(ids):
        return [{"scope": sid, "name": scopes[sid].get("name") or sid} for sid in sorted(ids)]
    # Unknown membership of one source must not disappear just because another
    # selected source already identifies the same device.
    return {"known": describe(known), "unknown": describe(unknown)}
