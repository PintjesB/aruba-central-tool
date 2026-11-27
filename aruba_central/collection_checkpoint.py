"""Explicit, bounded resume of qualified configuration scope read pairs."""
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path


def fingerprint(value):
    from .central_tool import canonical
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def qualification_manifest(region, plans, inventory, revision, *, legacy=False):
    from .central_tool import health_serial, device_identity
    serials = sorted({s for record in inventory if (s := health_serial(record.get("inventory")))})
    globals_ = sorted({str(scope["id"]) for _, _, scopes in plans for scope in scopes if scope["kind"] == "global"})
    if not serials or len(globals_) != 1:
        raise ValueError("Cannot qualify resume: missing inventory serials or unique Global identity")
    # Bind the relevant identity, membership and model/firmware data, not
    # changing operational timestamps, counters or connection state.
    def stable_identity(row):
        row = row or {}
        keys = ("id", "scopeId", "scopeID", "siteId", "deviceGroupId", "collectionId",
                "serial", "serialNumber", "conductorSerialNumber", "deviceFunction",
                "device-function", "persona", "model", "modelName", "deviceModel",
                "firmwareVersion", "softwareVersion", "firmware")
        return {key: row[key] for key in keys if key in row}
    topology = [(persona, sorted((m, spec[0], spec[2]) for m, spec in modules.items()),
                 sorted((str(s["id"]), s["kind"], fingerprint((s.get("metadata") or {}) if legacy else stable_identity(s.get("metadata")))) for s in scopes))
                for persona, modules, scopes in plans]
    payload = {"region": region, "global": globals_, "serials": serials,
               "topology": topology, "revision": revision, "schema": 1 if legacy else 2}
    if not legacy:
        # Include unadapted inventory identities as well as adapted scopes.
        payload["inventory"] = sorted(fingerprint({"identity": stable_identity(record.get("inventory")),
                                      "capabilities": device_identity(record.get("inventory") or {})}) for record in inventory)
    return fingerprint(payload)


class ScopeCheckpoint:
    """Use only explicitly requested checkpoints for one interrupted audit.

    Successful pairs are immutable within the run. Failed/incomplete pairs are
    reread. Discovery and other collection phases always run live.
    """
    def __init__(self, path, manifest, *, resume=False, now=None, compatible_manifests=()):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.created = self.now().isoformat()
        self.manifest = manifest
        self.pairs = 0
        self.reused = 0
        self.extra_reused = {}
        self.extra_saved = {}
        # Fresh runs own an initially empty checkpoint. Avoid opening SQLite
        # to look up keys that this run has not yet saved. Resumed runs still
        # consult durable evidence for every requested key.
        self._fresh_pairs = None if resume else set()
        self._fresh_observations = None if resume else set()
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
                if data.get("schema") != 1 or data.get("manifest") not in (manifest, *compatible_manifests) or data.get("complete") is not False:
                    raise ValueError("Checkpoint does not match current discovered inventory or is complete")
                created = datetime.fromisoformat(data["created_at"])
                if created.tzinfo is None or not timedelta(0) <= self.now() - created <= timedelta(hours=24):
                    raise ValueError("Checkpoint expired; start a fresh audit")
                self.created = data["created_at"]
                self.manifest = data["manifest"]
                self.pairs = db.execute("SELECT COUNT(*) FROM pairs").fetchone()[0]
            db.execute("CREATE TABLE IF NOT EXISTS observations (key TEXT PRIMARY KEY, phase TEXT NOT NULL, payload TEXT NOT NULL)")
            self.extra_saved = dict(db.execute("SELECT phase, COUNT(*) FROM observations GROUP BY phase"))

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
        with self.lock:
            if self._fresh_pairs is not None and key not in self._fresh_pairs:
                return None
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
        payload = json.dumps(row, allow_nan=False, separators=(",", ":"))
        with self.lock:
            with self._connect() as db:
                cursor = db.execute("INSERT OR IGNORE INTO pairs VALUES (?, ?)", (key, payload))
                inserted = cursor.rowcount
            self.pairs += inserted
            if self._fresh_pairs is not None:
                self._fresh_pairs.add(key)

    def observe(self, phase, selector, read, qualified):
        """Resume one independently qualified configuration observation.

        The caller supplies a selector including all relevant inputs and the
        phase-specific qualification predicate. No unsuccessful read is reused.
        """
        key = fingerprint([phase, selector])
        with self.lock:
            if self._fresh_observations is None or key in self._fresh_observations:
                with self._connect() as db:
                    record = db.execute("SELECT payload FROM observations WHERE key = ?", (key,)).fetchone()
                if record:
                    payload = json.loads(record[0])["evidence"]
                    if qualified(payload):
                        self.extra_reused[phase] = self.extra_reused.get(phase, 0) + 1
                        return payload
        payload = read()
        if qualified(payload):
            encoded = json.dumps({"captured_at": self.now().isoformat(), "evidence": payload},
                                 allow_nan=False, separators=(",", ":"))
            with self.lock:
                with self._connect() as db:
                    cursor = db.execute("INSERT OR IGNORE INTO observations VALUES (?, ?, ?)", (key, phase, encoded))
                    inserted = cursor.rowcount
                self.extra_saved[phase] = self.extra_saved.get(phase, 0) + inserted
                if self._fresh_observations is not None:
                    self._fresh_observations.add(key)
        return payload

    def evidence(self):
        return {"enabled": True, "started_at": self.created, "qualified_pairs_saved": self.pairs,
                "reused_pairs": self.reused, "mixed_capture_times": self.reused > 0 or any(self.extra_reused.values()),
                "scope_pairs_only": False, "additional_observations_saved": dict(self.extra_saved),
                "additional_observations_reused": dict(self.extra_reused), "max_age_hours": 24}

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

def available_checkpoints(directory, now=None):
    """List only locally created, unsealed, nonexpired checkpoint filenames."""
    import re
    now = now or datetime.now(timezone.utc)
    result = []
    for path in Path(directory).glob("collection-*.db"):
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r"collection-[a-f0-9]{32}\.db", path.name):
            continue
        try:
            db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
            try:
                manifest = json.loads(db.execute("SELECT payload FROM manifest").fetchone()[0])
                created = datetime.fromisoformat(manifest["created_at"])
                if (manifest.get("schema") == 1 and manifest.get("complete") is False
                        and created.tzinfo is not None and timedelta(0) <= now - created <= timedelta(hours=24)):
                    result.append({"name": path.name, "created_at": created.isoformat(),
                                   "pairs": db.execute("SELECT COUNT(*) FROM pairs").fetchone()[0]})
            finally:
                db.close()
        except (sqlite3.Error, OSError, ValueError, KeyError, TypeError, AttributeError):
            continue
    return sorted(result, key=lambda row: row["created_at"], reverse=True)
