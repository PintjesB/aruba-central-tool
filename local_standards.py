"""Immutable, private local standards and exact observed exception approvals."""
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

from central_tool import canonical, health_serial, refresh_configuration_review
from configuration_history import reference_compliance

ID = re.compile(r"[a-f0-9]{32}")
KINDS = {"standard", "exception", "exception-revocation"}


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def read_record(directory, kind, identity):
    if kind not in KINDS or not ID.fullmatch(identity):
        raise ValueError("Invalid record identity")
    path = Path(directory) / f"{kind}-{identity}.json"
    if not path.is_file() or path.is_symlink():
        raise ValueError("Unknown local record")
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("schema") != 1 or record.get("kind") != kind or record.get("id") != identity:
        raise ValueError("Invalid local record")
    return record


def records(directory, kind):
    if kind not in KINDS:
        raise ValueError("Invalid record kind")
    result = []
    for path in sorted(Path(directory).glob(f"{kind}-*.json")):
        try:
            result.append(read_record(directory, kind, path.stem[len(kind)+1:]))
        except (ValueError, OSError, TypeError, AttributeError):
            continue
    return result


def save_record(directory, kind, payload):
    identity = uuid.uuid4().hex
    if kind not in KINDS:
        raise ValueError("Invalid record kind")
    record = {**payload, "schema": 1, "kind": kind, "id": identity,
              "created_at": datetime.now(timezone.utc).isoformat()}
    path = Path(directory) / f"{kind}-{identity}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return record


def checked_text(value, limit):
    value = value.strip()
    if not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError("Enter a nonempty single-line value")
    return value


def scope_identity(bundle, persona, target):
    scope = next((s for s in bundle["results"][persona]["scopes"] if s["id"] == target), None)
    if scope is None:
        raise ValueError("Target scope unavailable")
    metadata = scope.get("metadata") or {}
    serial = health_serial(metadata) if scope["kind"] == "device" else None
    if scope["kind"] == "device" and not serial:
        raise ValueError("Target device serial unavailable")
    return {"kind": scope["kind"], "name": scope.get("name"), "entity_id": metadata.get("id"), "serial": serial}


def create_standard(directory, *, name, snapshot, baseline_name, persona, reference, module, target, confirmed):
    from config_app import read_audit
    raw_current = read_audit(directory, snapshot)
    raw_baseline = read_audit(directory, baseline_name)
    current = refresh_configuration_review(raw_current)
    baseline_hash = digest(raw_baseline) if snapshot != baseline_name else digest(read_audit(directory, baseline_name))
    baseline = current if snapshot == baseline_name else refresh_configuration_review(raw_baseline)
    result = reference_compliance(current, persona, module, reference, target,
                                  baseline=baseline, confirmed=confirmed, include_reference=True)
    return save_record(directory, "standard", {
        "name": checked_text(name, 120), "baseline": baseline_name, "baseline_hash": baseline_hash,
        "persona": persona, "reference": reference, "module": module, "modules": result["modules"],
        "target": target, "target_identity": scope_identity(current, persona, target)})


def evaluate_standard(directory, standard, snapshot, *, confirmed):
    from config_app import read_audit
    raw_baseline = read_audit(directory, standard["baseline"])
    if digest(raw_baseline) != standard["baseline_hash"]:
        raise ValueError("Baseline snapshot changed; create a new standard version")
    current = refresh_configuration_review(read_audit(directory, snapshot))
    baseline = current if snapshot == standard["baseline"] else refresh_configuration_review(raw_baseline)
    persona, target = standard["persona"], standard["target"]
    if scope_identity(current, persona, target) != standard["target_identity"]:
        raise ValueError("Target scope identity changed; create a new standard version")
    result = reference_compliance(current, persona, standard["module"], standard["reference"], target,
                                  baseline=baseline, confirmed=confirmed, selected_modules=standard["modules"],
                                  include_reference=True)
    return current, result


def exception_candidates(bundle, standard, result):
    """Only complete explicit profile deviations qualify; never approve coverage gaps."""
    persona = standard["persona"]
    serials = {s["id"]: health_serial(s.get("metadata")) for s in bundle["results"][persona]["scopes"]
               if s["kind"] == "device"}
    candidates = {}
    for finding in result["findings"]:
        serial = serials.get(finding["scope"])
        if not serial:
            continue
        for row in finding["differences"]:
            module = finding.get("module_results", {}).get(row["module"], {})
            if row["status"] not in ("added", "removed", "changed") or module.get("has_gaps") is not False:
                continue
            key = digest({"standard": standard["id"], "serial": serial, "module": row["module"],
                          "profile": row["identity"], "status": row["status"],
                          "before": row.get("before"), "after": row.get("after")})
            candidates[key] = {"serial": serial, "scope": finding["scope"], "device": finding["device"],
                               "module": row["module"], "profile": row["identity"], "observation": row}
    return candidates


def approve_exception(directory, standard_id, snapshot, candidate, reason, expiry, *, confirmed):
    standard = read_record(directory, "standard", standard_id)
    bundle, result = evaluate_standard(directory, standard, snapshot, confirmed=confirmed)
    observation = exception_candidates(bundle, standard, result).get(candidate)
    if not observation:
        raise ValueError("Deviation is no longer eligible for approval")
    end = date.fromisoformat(expiry)
    if end < date.today():
        raise ValueError("Exception expiry must not be in the past")
    return save_record(directory, "exception", {"standard": standard_id, "candidate": candidate,
                       "reason": checked_text(reason, 500), "expiry": end.isoformat(),
                       **observation})


def revoke_exception(directory, standard_id, exception_id, reason):
    standard = read_record(directory, "standard", standard_id)
    approval = read_record(directory, "exception", exception_id)
    if approval["standard"] != standard["id"]:
        raise ValueError("Exception belongs to a different standard")
    return save_record(directory, "exception-revocation", {
        "standard": standard_id, "exception": exception_id, "reason": checked_text(reason, 500)})


def exception_history(directory, standard_id, candidates, today=None):
    today = today or date.today()
    revoked = {}
    for record in records(directory, "exception-revocation"):
        if record.get("standard") == standard_id and isinstance(record.get("exception"), str):
            revoked.setdefault(record["exception"], []).append(record)
    history = []
    for record in records(directory, "exception"):
        try:
            if record["standard"] != standard_id:
                continue
            state = ("revoked" if record["id"] in revoked else
                     "expired" if date.fromisoformat(record["expiry"]) < today else
                     "not_observed" if record["candidate"] not in candidates else "active")
            history.append({**record, "state": state, "revocations": revoked.get(record["id"], [])})
        except (KeyError, ValueError, TypeError):
            continue
    return history


def active_exceptions(directory, standard_id, candidates, today=None):
    active = {}
    for record in exception_history(directory, standard_id, candidates, today):
        if record["state"] == "active":
            # Preserve the original approval payload for existing report consumers.
            active.setdefault(record["candidate"], []).append({k: v for k, v in record.items()
                                                               if k not in ("state", "revocations")})
    return active
