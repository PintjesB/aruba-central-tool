"""Group matching observed drift transitions without inferring change causality."""
from collections import defaultdict
from central_tool import canonical


PROFILE_STATES = {"changed", "added", "removed", "source_changed"}


def drift_groups(records, current):
    """Group exact profile transitions; keep every scope and view as evidence.

    Equal transitions do not establish that one source change caused another
    change. Scope/function pairs are counted separately from Library and saved
    definitions. Missing/null fields remain evidence gaps.
    """
    kinds = {(persona, str(s["id"])): s["kind"]
             for persona, entry in current["results"].items()
             for s in entry["scopes"]}
    groups = defaultdict(list)
    for record in records:
        if (record.get("view") not in ("local", "effective", "library")
                or record.get("status") not in PROFILE_STATES or not record.get("identity")):
            continue
        state = record["status"]
        key = (record["module"], record["identity"], state,
               canonical(record.get("before")), canonical(record.get("after")),
               canonical(record.get("source_fields", [])) if state == "source_changed" else "")
        groups[key].append(record)
    results = []
    for (module, identity, state, *_), members in groups.items():
        devices = {(r["persona"], str(r["scope"])) for r in members
                   if r["view"] == "effective" and kinds.get((r["persona"], str(r["scope"]))) == "device"}
        saved = {(r["persona"], str(r["scope"])) for r in members if r["view"] == "local"}
        higher = {(r["persona"], str(r["scope"])) for r in members
                  if r["view"] == "effective" and kinds.get((r["persona"], str(r["scope"]))) in
                  ("global", "site", "group", "collection")}
        gaps = any(d["kind"] in ("missing_local", "missing_reference", "null_vs_value")
                   for r in members for d in r.get("fields", []) + r.get("source_fields", []))
        results.append({"module": module, "identity": identity, "status": state,
                        "effective_device_count": len(devices), "saved_scope_count": len(saved),
                        "higher_effective_count": len(higher),
                        "library_count": sum(r["view"] == "library" for r in members),
                        "has_field_gaps": gaps, "observations": members,
                        "safe_to_apply": False})
    return sorted(results, key=lambda g: (-g["effective_device_count"], -len(g["observations"]),
                                          g["module"], g["identity"], g["status"]))
