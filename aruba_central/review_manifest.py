"""Re-derive exported consolidation selections from a private saved snapshot.

This validates review-plan selection and export gates, not deployment or
execution. Client-supplied proposal bodies, counts and order are not trusted.
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path
from .config_app import Workspace
from .review_dispositions import snapshot_binding
from .optimization_dependencies import attach_dependency_review
from .bulk_review import source_recipient_evidence, source_recipient_index

ACTIONS = {"remove_override", "promote_local", "reuse_library"}


def validate_selection(workspace, manifest):
    if (not isinstance(manifest, dict)
            or set(manifest) != {"schema", "kind", "snapshot", "snapshot_binding", "selections"}
            or type(manifest["schema"]) is not int or manifest["schema"] != 1
            or manifest["kind"] != "consolidation_selection"
            or not isinstance(manifest["snapshot"], str)):
        raise ValueError("Invalid or unsupported selection manifest")
    selections = manifest["selections"]
    if not isinstance(selections, list) or not selections:
        raise ValueError("Select at least one review proposal")
    if any(not isinstance(s, dict) or set(s) != {"id", "destination"} or not isinstance(s["id"], str)
           or (s["destination"] is not None and not isinstance(s["destination"], str)) for s in selections):
        raise ValueError("Invalid proposal selection")
    ids = [s["id"] for s in selections]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate proposal selection")
    name = manifest["snapshot"]
    bundle = workspace.reviewed_snapshot(name)
    binding = snapshot_binding(workspace, name, bundle)
    if binding != manifest["snapshot_binding"]:
        raise ValueError("Snapshot changed or manifest belongs to another workspace")
    by_id = {f["id"]: f for f in workspace.consolidation_snapshot(bundle)}
    if any(i not in by_id or by_id[i]["action"] not in ACTIONS or not by_id[i]["preview_selectable"] for i in ids):
        raise ValueError("Unknown, changed or blocked proposal")
    chosen = [dict(by_id[i]) for i in ids]
    attach_dependency_review(chosen, workspace.advanced_snapshot(bundle)["references"])
    indexes = {}
    known, unknown = set(), set()
    touched, promotions = defaultdict(set), defaultdict(set)
    reuses, fallbacks = [], []
    missing = 0
    for f, selection in zip(chosen, selections):
        fid, persona, module, identity = (f[k] for k in ("id", "persona", "module", "identity"))
        entry = bundle["results"][persona]
        if persona not in indexes:
            indexes[persona] = source_recipient_index(entry)
        recipients = source_recipient_evidence(entry, f["sources"], index=indexes[persona])
        def add_recipient(target, rows):
            target.update((persona, d["scope"]) for d in rows)
        add_recipient(known, recipients["known"])
        add_recipient(unknown, recipients["unknown"])
        def key(sid):
            return (persona, module, identity, sid)
        for source in f["sources"]:
            touched[key(source["scope"])].add(fid)
        destination = selection["destination"]
        if f["action"] == "promote_local":
            if destination is None:
                missing += 1
            elif destination == "library":
                promotions[module, identity].add(fid)
            else:
                options = [p for p in f["placement_options"] if p["scope"] == destination]
                if len(options) != 1:
                    raise ValueError("Destination not observed in this proposal")
                p = options[0]
                touched[key(destination)].add(fid)
                add_recipient(known, p["intended_devices"])
                add_recipient(known, p["additional_devices"])
                add_recipient(unknown, p["unknown_membership"])
        elif destination is not None:
            raise ValueError("Unexpected destination on non-promotion proposal")
        elif f["action"] == "reuse_library":
            reuses.append(((module, identity), fid))
        for fallback in f.get("fallbacks", []):
            if fallback.get("source"):
                fallbacks.append((key(fallback["source"]["scope"]), fid))
    collision_pairs = set()
    def collision(a, b, reason):
        if a != b:
            collision_pairs.add((*sorted((a, b)), reason))
    from itertools import combinations
    for group in touched.values():
        for a, b in combinations(group, 2):
            collision(a, b, "scope_overlap")
    for group in promotions.values():
        for a, b in combinations(group, 2):
            collision(a, b, "library_promotion_overlap")
    for key, fid in reuses:
        for other in promotions.get(key, ()):
            collision(fid, other, "library_reuse_overlap")
    for key, fid in fallbacks:
        for other in touched.get(key, ()):
            collision(fid, other, "fallback_overlap")
    outgoing = {i: set() for i in ids}
    incoming = {i: 0 for i in ids}
    for consumer in chosen:
        for ref in consumer["dependency_review"]["dependencies"]:
            if (ref.get("status") not in ("observed", "definition_observed")
                    or ref.get("target") is None or ref.get("source_view") not in ("effective", "library")
                    or ref["source_module"] != consumer["module"] or ref["source"] != consumer["identity"]):
                continue
            for prereq in chosen:
                a, b = prereq["id"], consumer["id"]
                if (a != b and prereq["module"] == ref["target_module"] and prereq["identity"] == ref["target"]
                        and (prereq["persona"] == ref["persona"] or ref["persona"] == "Library")
                        and b not in outgoing[a]):
                    outgoing[a].add(b)
                    incoming[b] += 1
    ready = [i for i in ids if incoming[i] == 0]
    ordered = []
    while ready:
        fid = ready.pop(0)
        ordered.append(fid)
        for other in sorted(outgoing[fid]):
            incoming[other] -= 1
            if incoming[other] == 0:
                ready.append(other)
    if snapshot_binding(workspace, name, bundle) != binding:
        raise ValueError("Snapshot changed during validation")
    blocked = len(ids) - len(ordered)
    return {"schema": 1, "kind": "offline_selection_validation",
            "proposal_count": len(ids), "observed_recipient_pairs": len(known),
            "uncertain_recipient_pairs": len(unknown), "missing_destinations": missing,
            "overlapping_proposal_conflicts": len(collision_pairs), "dependency_order_blocked": blocked,
            "review_export_gates_passed": not (missing or collision_pairs or blocked),
            "complete": False, "safe_to_apply": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--preview", required=True, type=Path)
    args = parser.parse_args()
    try:
        payload = json.loads(args.preview.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Invalid preview")
        manifest = payload.get("selection_manifest")
        if manifest is None:
            raise ValueError("Preview has no snapshot-bound selection manifest; export again")
        report = validate_selection(Workspace(args.directory), manifest)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Do not print a raw body, snapshot identifier or path in diagnostics.
        parser.error("Selection validation failed: " + (str(exc) if type(exc) is ValueError and not isinstance(exc, json.JSONDecodeError) else "invalid or unavailable local evidence"))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["review_export_gates_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
