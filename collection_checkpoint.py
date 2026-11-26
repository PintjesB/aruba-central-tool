"""Explicit, bounded resume of qualified configuration scope read pairs."""
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path


def fingerprint(value):
    from central_tool import canonical
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def qualification_manifest(region, plans, inventory, revision):
    from central_tool import health_serial
    serials = sorted({s for record in inventory if (s := health_serial(record.get("inventory")))})
    globals_ = sorted({str(scope["id"]) for _, _, scopes in plans for scope in scopes if scope["kind"] == "global"})
    if not serials or len(globals_) != 1:
        raise ValueError("Cannot qualify resume: missing inventory serials or unique Global identity")
    # Include actual scope identity and membership, adapter keys and catalog.
    # No credentials, access tokens or customer names are written in the manifest.
    topology = [(persona, sorted((m, spec[0], spec[2]) for m, spec in modules.items()),
                 sorted((str(s["id"]), s["kind"], fingerprint(s.get("metadata") or {})) for s in scopes))
                for persona, modules, scopes in plans]
    return fingerprint({"region": region, "global": globals_, "serials": serials,
                        "topology": topology, "revision": revision, "schema": 1})


class ScopeCheckpoint:
    """Use only explicitly requested checkpoints for one interrupted audit.

    Successful pairs are immutable within the run. Failed/incomplete pairs are
    reread. Discovery and other collection phases always run live.
    """
    def __init__(self, path, manifest, *, resume=False, now=None):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.created = self.now().isoformat()
        self.manifest = manifest
        self.pairs = 0
        self.reused = 0
        if self.path.is_symlink():
            raise ValueError("Checkpoint must not be a symlink")
        if self.path.exists():
            if not resume or not self.path.is_file():
                raise ValueError("Checkpoint already exists; explicitly resume or choose a new path")
        else:
            if resume:
                raise ValueError("No checkpoint found to resume")
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        with self._connect() as db:
            if not resume:
                db.execute("CREATE TABLE manifest (payload TEXT NOT NULL)")
                db.execute("CREATE TABLE pairs (key TEXT PRIMARY KEY, payload TEXT NOT NULL)")
                db.execute("INSERT INTO manifest VALUES (?)", (json.dumps({"schema": 1, "manifest": manifest,
                           "created_at": self.created, "complete": False}),))
            else:
                data = json.loads(db.execute("SELECT payload FROM manifest").fetchone()[0])
                if data.get("schema") != 1 or data.get("manifest") != manifest or data.get("complete") is not False:
                    raise ValueError("Checkpoint does not match current discovered inventory or is complete")
                created = datetime.fromisoformat(data["created_at"])
                if created.tzinfo is None or not timedelta(0) <= self.now() - created <= timedelta(hours=24):
                    raise ValueError("Checkpoint expired; start a fresh audit")
                self.created = data["created_at"]
                self.pairs = db.execute("SELECT COUNT(*) FROM pairs").fetchone()[0]

    def _connect(self):
        from contextlib import contextmanager
        @contextmanager
        def connection():
            if self.path.is_symlink():
                raise ValueError("Checkpoint changed to a symlink")
            db = sqlite3.connect(self.path)
            try:
                with db:
                    yield db
            finally:
                db.close()
        return connection()

    @staticmethod
    def qualified(local, effective):
        return all(v.get("status") == "list_parsed" and v.get("count_confirmed") is True
                   and isinstance(v.get("profiles"), dict) for v in (local, effective))

    def get(self, persona, module, scope):
        key = fingerprint([persona, module, str(scope)])
        with self.lock, self._connect() as db:
            record = db.execute("SELECT payload FROM pairs WHERE key = ?", (key,)).fetchone()
            row = json.loads(record[0]) if record else None
            if row and self.qualified(row["local"], row["effective"]):
                self.reused += 1
                return row
        return None

    def save(self, persona, module, scope, local, effective):
        if not self.qualified(local, effective):
            return
        key = fingerprint([persona, module, str(scope)])
        row = {"local": local, "effective": effective, "captured_at": self.now().isoformat()}
        with self.lock, self._connect() as db:
            cursor = db.execute("INSERT OR IGNORE INTO pairs VALUES (?, ?)",
                                (key, json.dumps(row, allow_nan=False)))
            self.pairs += cursor.rowcount

    def evidence(self):
        return {"enabled": True, "started_at": self.created, "qualified_pairs_saved": self.pairs,
                "reused_pairs": self.reused, "mixed_capture_times": self.reused > 0,
                "scope_pairs_only": True, "max_age_hours": 24}

def mark_complete(path):
    """Seal the checkpoint only after the completed snapshot is published."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Checkpoint unavailable")
    db = sqlite3.connect(path)
    try:
        with db:
            data = json.loads(db.execute("SELECT payload FROM manifest").fetchone()[0])
            data["complete"] = True
            db.execute("UPDATE manifest SET payload = ?", (json.dumps(data),))
    finally:
        db.close()
