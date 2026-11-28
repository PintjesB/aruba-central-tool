"""Verify a previously selected consolidation review against a newer private capture.

Use the original selection manifest only. This is not a replay, transaction
log, causal analysis or deployment approval. No Central API access.
"""
import argparse
import json
from collections import Counter
from pathlib import Path

from .config_app import Workspace
from .review_dispositions import snapshot_binding
from .review_manifest import reconstruct_selection
from .remediation_review import comparable, verify_override
from .promotion_verification import verify_promotion
from .central_tool import write_private


def verify_plan(workspace, manifest, after_name, *, confirmed=False):
    if not confirmed:
        raise ValueError("Confirm both captures belong to the same tenant")
    # Independent reconstruction rejects tampered, changed or blocked choices.
    plan = reconstruct_selection(workspace, manifest)
    before_name = plan["selection_manifest"]["snapshot"]
    if after_name == before_name:
        raise ValueError("Choose a newer capture")
    before = workspace.reviewed_snapshot(before_name)
    before_binding = snapshot_binding(workspace, before_name, before)
    if before_binding != plan["selection_manifest"]["snapshot_binding"]:
        raise ValueError("Before snapshot changed")
    # Use a separate workspace so both exact capture bindings remain verifiable
    # without switching the active cache and reparsing either capture.
    after_workspace = Workspace(workspace.directory)
    after = after_workspace.reviewed_snapshot(after_name)
    after_binding = snapshot_binding(after_workspace, after_name, after)
    identity_checks = comparable(before, after, confirmed)
    destinations = {s["id"]: s["destination"] for s in plan["selection_manifest"]["selections"]}
    reports = []
    counts = Counter()
    for proposal in plan["recommendations"]:
        fid, action = proposal["id"], proposal["action"]
        if action == "remove_override":
            report = verify_override(before, after, fid, confirmed=True)
        elif action in ("reuse_library", "promote_local"):
            destination = "library" if action == "reuse_library" else destinations[fid]
            report = verify_promotion(before, after, fid, destination, confirmed=True)
        else:
            raise ValueError("Unsupported review workflow")
        counts[action] += 1
        reports.append({"id": fid, "action": action, "report": report})
    if (snapshot_binding(workspace, before_name, before) != before_binding or
            snapshot_binding(after_workspace, after_name, after) != after_binding):
        raise ValueError("Snapshot changed during plan verification")
    return {"schema": 1, "kind": "private_plan_verification", "selection_manifest": plan["selection_manifest"],
            "after_snapshot": after_name, "after_binding": after_binding, "identity_checks": identity_checks,
            "proposal_counts": dict(counts), "reports": reports, "review_order": plan["review_order"],
            "complete": False, "safe_to_apply": False,
            "limitations": ["Each proposal is compared separately; collateral observations may include other selected proposals.",
                            "Captured settings do not establish causation, intermediate state, deployment or recovery."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--preview", type=Path, required=True)
    parser.add_argument("--after", required=True, help="Exact newer saved snapshot filename")
    parser.add_argument("--confirm-same-tenant", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output already exists; choose a new filename")
    try:
        payload = json.loads(args.preview.read_text(encoding="utf-8"))
        report = verify_plan(Workspace(args.directory), payload["selection_manifest"], args.after,
                             confirmed=args.confirm_same_tenant)
        write_private(args.output, report)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        parser.error("Plan verification failed; check the original selection manifest and both unchanged captures")
    print("Private plan verification saved; no deployment qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
