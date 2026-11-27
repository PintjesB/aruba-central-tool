"""Private snapshot-bound review dispositions. These are not approvals."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from datetime import datetime, timezone

from .central_tool import canonical
from .config_app import audit_files

STATES = {"open": "Open", "reviewed": "Reviewed", "intentional": "Intentional",
          "deferred": "Deferred", "investigate": "Investigate"}
ID = re.compile(r"[0-9a-f]{64}")


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def snapshot_binding(workspace, name, bundle):
    path = next((p for p in audit_files(workspace.directory) if p.name == name), None)
    if path is None:
        raise ValueError("Unknown snapshot")
    def fingerprint():
        if path.is_symlink():
            raise ValueError("Unknown snapshot")
        stat = path.stat()
        return [name, stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]
    before = fingerprint()
    if workspace.reviewed_snapshot(name) is not bundle or fingerprint() != before:
        raise ValueError("Snapshot changed; reopen the worklist")
    return digest(before)


def finding_key(binding, row):
    return digest([binding, row])


def record_path(directory, key):
    if not ID.fullmatch(key):
        raise ValueError("Invalid review identity")
    return Path(directory) / f"review-disposition-{key}.json"


def read_disposition(directory, key):
    path = record_path(directory, key)
    if not path.is_file() or path.is_symlink():
        return {"state": "open", "note": ""}
    record = json.loads(path.read_text(encoding="utf-8"))
    if (record.get("schema") != 1 or record.get("key") != key or record.get("state") not in STATES
            or not isinstance(record.get("note"), str)):
        raise ValueError("Invalid review disposition")
    return record


def save_disposition(directory, key, state, note):
    path = record_path(directory, key)
    if state not in STATES or not isinstance(note, str) or len(note) > 500 or any(ord(c) < 32 for c in note):
        raise ValueError("Invalid review disposition")
    payload = {"schema": 1, "key": key, "state": state, "note": note,
               "updated_at": datetime.now(timezone.utc).isoformat(), "safe_to_apply": False}
    temp = path.with_name(path.name + "." + secrets.token_hex(8) + ".partial")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    return payload


def update_disposition(workspace, snapshot, key, state, note):
    from .consolidation import profile_recommendations
    from .optimization_worklist import optimization_worklist
    if not ID.fullmatch(key):
        raise ValueError("Invalid review identity")
    bundle = workspace.reviewed_snapshot(snapshot)
    binding = snapshot_binding(workspace, snapshot, bundle)
    rows = optimization_worklist(bundle, profile_recommendations(bundle), workspace.advanced_snapshot(bundle))
    if key not in {finding_key(binding, row) for row in rows}:
        raise ValueError("Finding changed or unavailable")
    if snapshot_binding(workspace, snapshot, bundle) != binding:
        raise ValueError("Snapshot changed")
    return save_disposition(workspace.directory, key, state, note)
