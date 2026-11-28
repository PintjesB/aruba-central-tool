"""Anonymous offline qualification of actual consolidation review choices."""
from collections import Counter

from .config_app import Workspace
from .review_dispositions import snapshot_binding
from .review_manifest import validate_selection, reconstruct_selection, ACTIONS

KNOWN_ACTIONS = ACTIONS | {"conflict", "default_review", "create_library", "unassigned_library"}
DESTINATIONS = {"library", "global", "site", "group", "collection", "device", "not_applicable"}


def planner_qualification(directory, snapshot, *, max_validations=200, max_pair_validations=50):
    if any(type(value) is not int or value < 0 for value in (max_validations, max_pair_validations)):
        raise ValueError("Invalid validation budget")
    workspace = Workspace(directory)
    bundle = workspace.reviewed_snapshot(snapshot)
    binding = snapshot_binding(workspace, snapshot, bundle)
    findings = workspace.consolidation_snapshot(bundle)
    actions, options = {}, {}
    candidates = []
    for finding in findings:
        action = finding["action"]
        row = actions.setdefault(action if action in KNOWN_ACTIONS else "other", Counter())
        row["findings"] += 1
        row["local_source_observations"] += len(finding["sources"])
        if action not in ACTIONS or not finding["preview_selectable"]:
            row["not_selectable"] += 1
            continue
        row["selectable"] += 1
        if action != "promote_local":
            candidates.append((finding, None, "not_applicable"))
            continue
        candidates.append((finding, "library", "library"))
        for option in finding["placement_options"]:
            kind = option["kind"] if option["kind"] in DESTINATIONS else "other"
            stats = options.setdefault(kind, Counter())
            stats["options"] += 1
            stats["exact_observed_recipient_set"] += option["membership_status"] == "exact_observed_recipient_set"
            stats["additional_recipients"] += len(option["additional_devices"])
            stats["additional_not_confirmed_matching"] += len(option["additional_not_confirmed_matching"])
            stats["uncertain_recipients"] += len(option["unknown_membership"])
            candidates.append((finding, option["scope"], kind))
    # Interleave action/destination categories so a large population does not
    # consume the entire budget before another workflow is exercised.
    buckets = {}
    for candidate in candidates:
        f, _, kind = candidate
        buckets.setdefault((f["action"], kind), []).append(candidate)
    from collections import deque
    queues = {key: deque(rows) for key, rows in sorted(buckets.items())}
    checks = {}
    attempted = 0
    while queues and attempted < max_validations:
        for key in list(queues):
            if attempted >= max_validations:
                break
            finding, destination, _ = queues[key].popleft()
            if not queues[key]:
                del queues[key]
            row = checks.setdefault(key, Counter())
            row["attempted"] += 1
            attempted += 1
            manifest = {"schema": 1, "kind": "consolidation_selection", "snapshot": snapshot,
                        "snapshot_binding": binding,
                        "selections": [{"id": finding["id"], "destination": destination}]}
            # A mismatch between an advertised choice and the independent
            # validator is a failed qualification, not a silently skipped row.
            try:
                result = validate_selection(workspace, manifest)
            except ValueError:
                row["rejected"] += 1
            else:
                row["passed" if result["review_export_gates_passed"] else "rejected"] += 1
    pair_checks = qualify_pairs(workspace, snapshot, binding, candidates, max_pair_validations)
    if snapshot_binding(workspace, snapshot, bundle) != binding:
        raise ValueError("Snapshot changed during planner qualification")
    rejected = sum(r["rejected"] for r in checks.values())
    return {"schema": 1, "kind": "anonymous_planner_qualification",
            "actions": [{"action": k, **dict(v)} for k, v in sorted(actions.items())],
            "scope_destination_options": [{"kind": k, **dict(v)} for k, v in sorted(options.items())],
            "individual_choice_checks": [{"action": a, "destination_kind": k, **dict(v)}
                                         for (a, k), v in sorted(checks.items())],
            "candidate_choices": len(candidates), "validated_choices": attempted,
            "rejected_choices": rejected, "all_choices_checked": attempted == len(candidates),
            "review_choice_validation_passed": bool(candidates) and attempted == len(candidates) and rejected == 0,
            "combined_choice_checks": pair_checks,
            "complete": False, "safe_to_apply": False}


def qualify_pairs(workspace, snapshot, binding, candidates, budget):
    """Exercise distinct proposals, not alternative destinations of one proposal.

    Count all possible pairs without materializing their Cartesian product.
    A blocked combination is a valid review-gate outcome, not a failed test.
    """
    from itertools import combinations, product, islice
    groups = {}
    for finding, destination, _ in candidates:
        groups.setdefault(finding["id"], []).append({"id": finding["id"], "destination": destination})
    choices = [groups[key] for key in sorted(groups)]
    sizes = [len(group) for group in choices]
    total = (sum(sizes) ** 2 - sum(n * n for n in sizes)) // 2
    pairs = (pair for left, right in combinations(choices, 2) for pair in product(left, right))
    counts = Counter()
    for first, second in islice(pairs, budget):
        counts["attempted"] += 1
        manifest = {"schema": 1, "kind": "consolidation_selection", "snapshot": snapshot,
                    "snapshot_binding": binding, "selections": [first, second]}
        reverse = {**manifest, "selections": [second, first]}
        try:
            report = validate_selection(workspace, manifest)
            other = validate_selection(workspace, reverse)
            if report != other:
                counts["order_mismatch"] += 1
                continue
            if not report["review_export_gates_passed"]:
                counts["blocked"] += 1
                if report["overlapping_proposal_conflicts"]:
                    counts["blocked_by_overlap"] += 1
                if report["dependency_order_blocked"]:
                    counts["blocked_by_dependency_order"] += 1
                if report["missing_destinations"]:
                    counts["blocked_by_missing_destination"] += 1
                continue
            plan = reconstruct_selection(workspace, manifest)
            if plan != reconstruct_selection(workspace, reverse) or plan["validation"] != report:
                counts["reconstruction_mismatch"] += 1
                continue
            counts["passed_and_reconstructed"] += 1
        except ValueError:
            counts["validation_error"] += 1
    errors = sum(counts[k] for k in ("order_mismatch", "reconstruction_mismatch", "validation_error"))
    return {"candidate_pairs": total, "attempted": counts["attempted"],
            "all_pairs_checked": counts["attempted"] == total,
            "passed_and_reconstructed": counts["passed_and_reconstructed"],
            "blocked": counts["blocked"], "blocked_by_overlap": counts["blocked_by_overlap"],
            "blocked_by_dependency_order": counts["blocked_by_dependency_order"],
            "blocked_by_missing_destination": counts["blocked_by_missing_destination"],
            "order_mismatch": counts["order_mismatch"], "reconstruction_mismatch": counts["reconstruction_mismatch"],
            "validation_error": counts["validation_error"],
            "pair_checks_passed": bool(total) and counts["attempted"] == total and not errors,
            "safe_to_apply": False}
