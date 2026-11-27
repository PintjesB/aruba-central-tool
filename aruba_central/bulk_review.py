"""Recipient evidence for non-executable consolidation worklists."""
from collections import defaultdict
from .consolidation import scope_memberships


def source_recipient_index(entry):
    members = scope_memberships(entry["scopes"])
    scopes = {s["id"]: s for s in entry["scopes"]}
    known, unknown = defaultdict(set), defaultdict(set)
    for device, membership in members.items():
        for kind, sid in membership.items():
            if sid is None:
                unknown[kind].add(device)
            else:
                known[kind, sid].add(device)
    return members, scopes, known, unknown


def source_recipient_evidence(entry, sources, *, index=None):
    members, scopes, by_scope, by_unknown = source_recipient_index(entry) if index is None else index
    known, unknown = set(), set()
    for source in sources:
        sid = source["scope"]
        kind = source["kind"]
        if kind == "device" and sid in members:
            known.add(sid)
        elif kind in ("global", "group", "site", "collection") and sid in scopes:
            known.update(by_scope.get((kind, sid), ()))
            unknown.update(by_unknown.get(kind, ()))
        else:
            unknown.update(members)
    def describe(ids):
        return [{"scope": sid, "name": scopes[sid].get("name") or sid} for sid in sorted(ids)]
    # Unknown membership of one source must not disappear just because another
    # selected source already identifies the same device.
    return {"known": describe(known), "unknown": describe(unknown)}
