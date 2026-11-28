"""Revalidate a private exported review against a newer saved capture.

This is an offline evidence comparison, not a live write preflight, approval,
deployment simulation or proof of operational equivalence.
"""
import argparse
import json
from pathlib import Path

from .config_app import Workspace
from .review_manifest import reconstruct_selection
from .review_dispositions import snapshot_binding
from .remediation_review import comparable, same_device, scope_meta
from .central_tool import canonical, write_private


def assignment_evidence(bundle, module, identity):
    view = (bundle.get("library") or {}).get("assignments") or {}
    rows = [row for row in view.get("rows",[]) if isinstance(row,dict)
            and row.get("profile-type") == module and str(row.get("profile-instance")) == identity]
    return view.get("status","not_collected"), sorted({canonical(row) for row in rows})


def revalidate_plan(workspace, manifest, current_name, *, confirmed=False):
    if not confirmed:
        raise ValueError("Confirm both captures belong to the same tenant")
    plan = reconstruct_selection(workspace,manifest)
    previous = plan["selection_manifest"]["snapshot"]
    if previous == current_name:
        raise ValueError("Choose a newer capture")
    before = workspace.reviewed_snapshot(previous)
    before_binding = snapshot_binding(workspace,previous,before)
    if before_binding != plan["selection_manifest"]["snapshot_binding"]:
        raise ValueError("Original snapshot changed")
    current_workspace = Workspace(workspace.directory)
    after = current_workspace.reviewed_snapshot(current_name)
    current_binding = snapshot_binding(current_workspace,current_name,after)
    identity_checks = comparable(before,after,confirmed)
    current_by_id = {f["id"]:f for f in current_workspace.consolidation_snapshot(after)}
    combined_reasons = []
    rows = []
    current_manifest = {**plan["selection_manifest"],"snapshot":current_name,"snapshot_binding":current_binding}
    current_plan = None
    if all(s["id"] in current_by_id and current_by_id[s["id"]]["preview_selectable"] for s in current_manifest["selections"]):
        try:
            current_plan = reconstruct_selection(current_workspace,current_manifest)
        except ValueError:
            combined_reasons.append("combined_review_selection_no_longer_passes")
    else:
        combined_reasons.append("one_or_more_prior_proposals_changed_or_missing")
    rebuilt = {f["id"]:f for f in current_plan["recommendations"]} if current_plan is not None else {}
    for proposal in plan["recommendations"]:
        fid,persona,module,identity = (proposal[k] for k in ("id","persona","module","identity"))
        reasons = []
        current = current_by_id.get(fid)
        if not current or not current["preview_selectable"]:
            reasons.append("proposal_evidence_changed_or_missing")
        if current_plan is not None:
            if proposal["dependency_review"] != rebuilt[fid]["dependency_review"]:
                reasons.append("dependency_evidence_changed")
            if proposal["recipient_evidence"] != rebuilt[fid]["recipient_evidence"]:
                reasons.append("recipient_evidence_changed")
            if proposal["selected_destination"] != rebuilt[fid]["selected_destination"]:
                reasons.append("destination_evidence_changed")
        destination = proposal.get("selected_destination") or {}
        # Check all device observations, including outside recipients; a
        # matching scope ID alone cannot establish device continuity.
        device_ids = {str(row["scope"]) for values in proposal.get("observed_devices",{}).values() for row in values}
        device_ids.update(str(row["scope"]) for values in proposal["recipient_evidence"].values() for row in values)
        for key in ("intended_devices","additional_devices","unknown_membership"):
            device_ids.update(str(row["scope"]) for row in destination.get(key,[]))
        source_scopes = {str(row["scope"]):row["kind"] for row in proposal["sources"]}
        if destination.get("kind") not in (None,"library"):
            source_scopes[str(destination["scope"])] = destination["kind"]
        if any(scope_meta(before,persona,sid).get("kind") != kind or scope_meta(after,persona,sid).get("kind") != kind
               for sid,kind in source_scopes.items()):
            reasons.append("source_or_destination_scope_unverified")
        device_ids.update(sid for sid,kind in source_scopes.items() if kind == "device")
        unverified = sum(not same_device(before,after,persona,sid) for sid in device_ids)
        if unverified:
            reasons.append("device_identity_unverified")
        if destination.get("kind") == "library" or proposal["action"] == "reuse_library":
            old_assignments = assignment_evidence(before,module,identity)
            new_assignments = assignment_evidence(after,module,identity)
            if old_assignments != new_assignments:
                reasons.append("library_assignment_evidence_changed")
        if current_plan is None and not reasons:
            reasons.append("combined_review_not_reconstructed")
        rows.append({"id":fid,"action":proposal["action"],"persona":persona,"module":module,"identity":identity,
                     "status":"review_required" if reasons else "observed_evidence_unchanged",
                     "reasons":reasons,"device_pairs_checked":len(device_ids),"unverified_device_pairs":unverified})
    if current_plan is not None and (current_plan["review_order"] != plan["review_order"] or current_plan["validation"] != plan["validation"]):
        combined_reasons.append("combined_review_order_or_gate_evidence_changed")
    if (snapshot_binding(workspace,previous,before) != before_binding or
            snapshot_binding(current_workspace,current_name,after) != current_binding):
        raise ValueError("Snapshot changed during revalidation")
    return {"schema":1,"kind":"private_plan_preflight","selection_manifest":plan["selection_manifest"],
            "current_snapshot":current_name,"current_binding":current_binding,"identity_checks":identity_checks,
            "rows":rows,"combined_reasons":combined_reasons,
            "observed_review_matches": bool(current_plan is not None and not combined_reasons and all(not r["reasons"] for r in rows)),
            "complete":False,"safe_to_apply":False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory",type=Path,required=True)
    parser.add_argument("--preview",type=Path,required=True)
    parser.add_argument("--current",required=True)
    parser.add_argument("--confirm-same-tenant",action="store_true",required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output already exists; choose a new filename")
    try:
        payload=json.loads(args.preview.read_text(encoding="utf-8"))
        report=revalidate_plan(Workspace(args.directory),payload["selection_manifest"],args.current,
                               confirmed=args.confirm_same_tenant)
        write_private(args.output,report)
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        parser.error("Plan revalidation failed; check the original manifest and both unchanged captures")
    print("Private captured-plan revalidation saved; no deployment qualification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
