"""Historical assessments of a frozen local standard; no retrospective approvals."""
from collections import Counter
from datetime import datetime, date, timezone
from .config_app import read_audit
from .local_standards import evaluate_standard, exception_candidates, apply_approvals, records


def capture_time(value):
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.tzinfo is None:
            return None
        return stamp.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def historical_approvals(approvals, revocations, standard_id, candidates, stamp):
    revoked = {row.get("exception") for row in revocations
               if row.get("standard") == standard_id and capture_time(row.get("created_at")) is not None
               and capture_time(row["created_at"]) <= stamp}
    active = {}
    for row in approvals:
        try:
            created = capture_time(row.get("created_at"))
            if (row["standard"] == standard_id and row["candidate"] in candidates and row["id"] not in revoked
                    and created is not None and created <= stamp and date.fromisoformat(row["expiry"]) >= stamp.date()):
                active.setdefault(row["candidate"], []).append(row)
        except (KeyError, ValueError, TypeError):
            continue
    return active


def compliance_trends(directory, standard, snapshots, *, confirmed=False):
    if not confirmed:
        raise ValueError("Confirm selected captures belong to the same tenant")
    if len(snapshots) > 20:
        raise ValueError("Select at most 20 captures")
    approvals = records(directory, "exception")
    revocations = records(directory, "exception-revocation")
    entries = []
    skipped = []
    for name in snapshots:
        try:
            stamp = capture_time(read_audit(directory, name).get("captured_at"))
            if stamp is None:
                raise ValueError("Capture timestamp unavailable")
            bundle, result = evaluate_standard(directory, standard, name, confirmed=True)
            candidates = exception_candidates(bundle, standard, result, include_legacy=True)
            active = historical_approvals(approvals, revocations, standard["id"], candidates, stamp)
            apply_approvals(result, candidates, active)
            counts = Counter(row["status"] for row in result["findings"])
            entries.append({"snapshot": name, "captured_at": stamp.isoformat(), "counts": dict(counts),
                            "known_recipients": result["target_count"], "unknown_membership": result["unknown_membership"],
                            "devices_with_evidence_gaps": sum(bool(row.get("has_gaps")) or row["status"] == "membership_unverified" for row in result["findings"]),
                            "active_approval_count": len(active), "findings": result["findings"]})
        except (ValueError, KeyError, TypeError, OSError):
            skipped.append({"snapshot": name, "reason": "Timestamp, tenant, baseline, target identity or evidence could not be verified"})
    entries.sort(key=lambda row: (row["captured_at"], row["snapshot"]))
    return {"standard_id": standard["id"], "entries": entries, "skipped": skipped,
            "approval_policy": "Approvals and revocations effective at capture time (UTC expiry date)", "safe_to_apply": False}
