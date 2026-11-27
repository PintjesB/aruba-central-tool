"""Loopback-only configuration workspace backed by private audit files."""
import json
import hashlib
import os
import re
import secrets
import threading
import time
import unicodedata
import webbrowser
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit


CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'")


def e(value):
    return escape(str(value), quote=True)


def tenant_label(value):
    """Optional operator-supplied display label, not an authenticated tenant ID."""
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > 100 or any(not c.isprintable() for c in value):
        raise ValueError("Invalid tenant name")
    return value.strip()


def snapshot_filename(stamp, name):
    # Never use untrusted labels directly as filesystem paths.
    name = tenant_label(name)
    slug = re.sub(r"[^A-Za-z0-9]+", "-", unicodedata.normalize("NFKD", name)
                  .encode("ascii", "ignore").decode()).strip("-")[:64].rstrip("-")
    if name and not slug:
        slug = "tenant-" + hashlib.sha256(name.encode()).hexdigest()[:10]
    return f"config-audit-{slug + '-' if slug else ''}{stamp}.json"


def audit_files(directory):
    """Use only direct, non-symlink audit files in the selected workspace."""
    return sorted((p for p in directory.glob("config-audit-*.json")
                   if p.is_file() and not p.is_symlink()
                   and re.fullmatch(r"config-audit-[A-Za-z0-9-]+\.json", p.name)),
                  key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)


def read_audit(directory, name):
    path = next((p for p in audit_files(directory) if p.name == name), None)
    if path is None:
        raise ValueError("Unknown snapshot")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or data.get("kind") != "configuration_audit":
        raise ValueError("Not a configuration audit")
    return data


class WorkspaceIdentityError(ValueError):
    """A refresh could not establish continuity with the workspace."""


def verify_workspace_identity(directory, incoming):
    """Require positive continuity with the newest existing capture.

    This is a conservative guard, not an authoritative Central tenant ID.
    An empty workspace accepts its first capture; a different customer needs
    a separate workspace directory. Legacy evidence without the required
    identifiers cannot establish continuity.
    """
    from .configuration_history import snapshot_identity_checks
    files = audit_files(directory)
    if not files:
        return
    try:
        previous = read_audit(directory, files[0].name)
        snapshot_identity_checks(previous, incoming)
        # Return the label from the exact capture that established continuity.
        # Callers that only verify identity need not use the return value.
        return previous.get("tenant_name")
    except (ValueError, KeyError, TypeError, OSError, AttributeError) as exc:
        raise WorkspaceIdentityError("Workspace identity not established; use a separate customer directory") from exc


from .workspace_ui import page, navigation, intro, snapshot_picker, metrics


def options(items, selected=None):
    return "".join(f'<option value="{e(key)}"{" selected" if key == selected else ""}>{e(label)}</option>'
                   for key, label in items)


def module_coverage(bundle):
    """Count actual qualified scopes, not merely successful API requests."""
    result = []
    for persona, entry in sorted(bundle["results"].items()):
        for module, data in sorted(entry["modules"].items()):
            scopes = data["scope_results"]
            qualified = sum(s.get("review", {}).get("qualified") is True for s in scopes)
            result.append({"persona": persona, "module": module, "qualified": qualified,
                           "total": len(scopes), "status": "qualified" if scopes and qualified == len(scopes)
                           else "partial" if qualified else "unqualified"})
    return result


def credential_refresh(client_id, client_secret, region, *, deep_catalog=False, exhaustive_details=False, targeted_catalog=False, checkpoint_path=None, resume=False, identity_guard=None):
    """One-shot credentials captured in a worker closure, not a workspace or file."""
    from .central_tool import Central, EU_REGIONS, detect_region, configuration_audit, audit_progress
    if region and region not in EU_REGIONS:
        raise ValueError("Choose an official EU region")
    if not client_id.strip() or not client_secret or len(client_id) > 1024 or len(client_secret) > 4096:
        raise ValueError("Invalid credentials")
    client = Central(region or EU_REGIONS[0], None, client_id, client_secret)
    def run(progress=None, module_completed=None):
        try:
            audit_progress(progress, "Connection", 0, 0, "Authenticating and detecting region")
            detect_region(client, region or None)
            return configuration_audit(client, progress=progress, deep_catalog=deep_catalog, exhaustive_details=exhaustive_details, targeted_catalog=targeted_catalog,
                                       checkpoint_path=checkpoint_path, resume=resume, identity_guard=identity_guard,
                                       module_completed=module_completed)
        finally:
            client.client_id = None
            client.client_secret = None
            client.token = None
    run.supports_module_preview = True
    run.collection_strategy = "targeted" if targeted_catalog else "deep" if deep_catalog else "standard"
    run.exhaustive_details = exhaustive_details
    run.resumed = resume
    return run


# Phases are ordered, but some are conditional. A phase position is not a
# percentage of work: the duration of individual phases varies considerably.
AUDIT_PHASES = (
    "Connection", "Discovery", "Assignment coverage", "Configuration scopes",
    "Library", "Additional profile types", "NAC configuration", "NAC registrations",
    "NAC portal assets", "Configuration health", "Profile details",
    "Profile detail expansion", "Scope hierarchy", "Individual assignments",
    "VLAN details", "Operational VLANs", "Switch VLAN verification",
    "Switch VLAN features", "Saving snapshot",
)
DEEP_ONLY_PHASES = {"NAC portal assets", "Profile details", "Profile detail expansion",
                    "Scope hierarchy", "Individual assignments"}


def performance_record(bundle):
    """Small private summary; never use it as configuration evidence."""
    from .central_tool import canonical, health_serial
    topology = {
        "region": bundle.get("region"),
        "serials": sorted({serial for r in bundle.get("inventory", [])
                           if (serial := health_serial(r.get("inventory")))}),
        "scopes": sorted((p, str(s["id"]), s["kind"])
                         for p, entry in bundle.get("results", {}).items()
                         for s in entry.get("scopes", [])),
        "plan": sorted((p, module, sorted(str(s["scope"]) for s in data.get("scope_results", [])))
                       for p, entry in bundle.get("results", {}).items()
                       for module, data in entry.get("modules", {}).items()),
    }
    timing = bundle.get("collection_timing") or {}
    phases = []
    for row in timing.get("phases", []):
        seconds = row.get("seconds")
        if row.get("phase") in AUDIT_PHASES and type(seconds) in (int, float) and 0 <= seconds <= 864000:
            phases.append({"phase": row["phase"], "seconds": seconds})
    elapsed = timing.get("elapsed_before_save_seconds")
    transport = bundle.get("http_get_transport") or {}
    details = bundle.get("keyed_profile_details") or {}
    def number(value):
        return value if type(value) is int and value >= 0 else None
    return {"strategy": bundle.get("collection_strategy"), "detail_strategy": details.get("detail_strategy"),
            "mixed_capture_times": bool((bundle.get("collection_checkpoint") or {}).get("mixed_capture_times")),
            "elapsed": elapsed if type(elapsed) in (int, float) and 0 < elapsed <= 864000 else None,
            "phases": phases, "attempts": number(transport.get("http_get_attempts")),
            "retries": number(transport.get("http_get_retries")),
            "rate_limits": number(transport.get("http_get_429")),
            "detail_reads": number(details.get("actual_reads")),
            "scope_pairs": sum(len(data.get("scope_results", [])) for entry in bundle.get("results", {}).values()
                               for data in entry.get("modules", {}).values()),
            "topology": hashlib.sha256(canonical(topology).encode()).hexdigest()
                        if topology["region"] and topology["serials"] and topology["scopes"] else None}


def performance_fingerprint(path):
    stat = path.stat()
    return [stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]


def cache_performance(path, record):
    from .central_tool import write_private
    destination = path.with_suffix(".performance.json")
    if destination.is_symlink():
        return
    temporary = destination.with_name(destination.name + "." + secrets.token_hex(8) + ".partial")
    try:
        write_private(temporary, {"schema": 1, "fingerprint": performance_fingerprint(path), "record": record}, compact=True)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def read_performance(path):
    """Use a validated small cache or rebuild from the completed local snapshot."""
    destination = path.with_suffix(".performance.json")
    before = performance_fingerprint(path)
    try:
        if not destination.is_symlink() and destination.stat().st_size <= 65536:
            cached = json.loads(destination.read_text(encoding="utf-8"))
            if cached.get("schema") == 1 and cached.get("fingerprint") == before and isinstance(cached.get("record"), dict):
                return cached["record"]
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    record = performance_record(read_audit(path.parent, path.name))
    if before != performance_fingerprint(path):
        raise ValueError("Snapshot changed while reading performance")
    try:
        cache_performance(path, record)
    except (OSError, ValueError, TypeError):
        pass
    return record


def historical_phase_times(directory, strategy, exhaustive=False):
    """Use a completed comparable fresh capture in this workspace, if available."""
    if strategy not in ("standard", "deep", "targeted"):
        return {}
    files = audit_files(directory)
    if not files:
        return {}
    try:
        previous = read_performance(files[0])
        if (previous.get("strategy") != strategy
                or previous.get("mixed_capture_times")
                or (strategy != "standard" and previous.get("detail_strategy")
                    != ("exhaustive" if exhaustive else "adaptive"))):
            return {}
        times = {}
        for row in previous.get("phases", []):
            phase, seconds = row.get("phase"), row.get("seconds")
            if phase in AUDIT_PHASES and type(seconds) in (float, int) and 0 <= seconds <= 864000:
                times[phase] = times.get(phase, 0) + seconds
        required = {"Configuration scopes", "Additional profile types"}
        if strategy != "standard":
            required.add("Profile details")
        return times if required <= times.keys() and sum(times.values()) > 0 else {}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {}


def overall_audit_progress(phase, strategy, history, elapsed, phase_elapsed, done, total, phase_eta):
    phases = [p for p in AUDIT_PHASES if strategy != "standard" or p not in DEEP_ONLY_PHASES]
    position = phases.index(phase) if phase in phases else None
    result = {"stage": position + 1 if position is not None else None,
              "stages": len(phases), "overall_percent": None, "overall_eta_seconds": None,
              "estimate_basis": None}
    if position is None or not history or phase not in history:
        return result
    # Use observed throughput in the active phase where available, not its
    # historical duration. Later phases are estimated from the prior capture.
    remaining_here = (phase_eta if phase_eta is not None else
                      0 if total > 0 and done >= total else
                      max(0, history[phase] - phase_elapsed))
    future = sum(history.get(p, 0) for p in phases[position + 1:])
    remaining = remaining_here + future
    if phase != "Saving snapshot":
        remaining = max(1, remaining)
    if elapsed + remaining > 0:
        result.update(overall_percent=min(99.0, round(100 * elapsed / (elapsed + remaining), 1)),
                      overall_eta_seconds=round(remaining),
                      estimate_basis="Previous comparable capture and current phase progress")
    return result


def library_profile_comparison(bundle, module):
    """Join only exact profile identities; absence of assignments proves nothing."""
    from .central_tool import canonical, field_differences, profile_body
    library = bundle.get("library", {})
    view = library.get("modules", {}).get(module, {})
    if view.get("status") != "list_parsed":
        return {}
    assignments = library.get("assignments", {})
    by_identity = {}
    for identity, profile in view["profiles"].items():
        matches = [r for r in assignments.get("rows", [])
                   if r.get("profile-type") == module and type(r.get("profile-instance")) in (str, int)
                   and str(r["profile-instance"]) == identity]
        by_identity[identity] = {"profile": profile_body(profile), "assignments": matches,
                                 "assignment_completeness_verified": False, "local_variants": []}
    for persona, data in bundle["results"].items():
        scope_names = {s["id"]: s.get("name") or s["id"] for s in data["scopes"]}
        for scope in data["modules"].get(module, {}).get("scope_results", []):
            if not scope["review"]["qualified"]:
                continue
            for row in scope["review"]["profiles"]:
                identity = row["identity"]
                if identity not in by_identity or row.get("local") is None:
                    continue
                target = by_identity[identity]
                differences = field_differences(row["local"], target["profile"])
                target["local_variants"].append({"persona": persona, "scope": scope["scope"],
                                                 "scope_name": scope_names.get(scope["scope"], scope["scope"]),
                                                 "classification": "exact_match" if canonical(row["local"]) == canonical(target["profile"])
                                                 else "different_body", "differences": differences})
    return by_identity


def individual_effective_comparison(bundle, persona, left, right, module, identity):
    """Compare direct individual evidence separately, never copy sampled values."""
    from .central_tool import field_differences
    profiles = (bundle.get("keyed_profile_details") or {}).get("profiles", {}).get(persona, {})
    def read(scope):
        evidence = profiles.get(str(scope), {}).get(module, {}).get(identity, {}).get("effective", {})
        body = evidence.get("profile")
        return evidence.get("status", "not_collected"), body if (
            evidence.get("status") == "identity_observed" and isinstance(body, dict)) else None
    left_status, left_body = read(left)
    right_status, right_body = read(right)
    return {"left_status": left_status, "right_status": right_status,
            "left": left_body, "right": right_body,
            "fields": field_differences(left_body, right_body)
                      if left_body is not None and right_body is not None else None}


def compare_devices(bundle, persona, left, right, module=None):
    """Compare collection bodies and independent individual evidence within one capture."""
    from .central_tool import field_differences, profile_body
    entry = bundle["results"].get(persona)
    if entry is None or left == right:
        raise ValueError("Select two distinct devices of the same function")
    devices = {s["id"] for s in entry["scopes"] if s["kind"] == "device"}
    if left not in devices or right not in devices:
        raise ValueError("Unknown device")
    results = []
    for name, data in sorted(entry["modules"].items()):
        if module and name != module:
            continue
        # Port IDs are device-specific. Expose them only on explicit selection.
        if not module and name in {"ethernet-interfaces", "vlan-interfaces", "portchannels"}:
            continue
        by_scope = {s["scope"]: s["effective_view"] for s in data["scope_results"]}
        a, b = by_scope.get(left, {}), by_scope.get(right, {})
        if a.get("status") != "list_parsed" or b.get("status") != "list_parsed":
            results.append({"module": name, "status": "unqualified", "differences": []})
            continue
        pa, pb = a["profiles"], b["profiles"]
        diffs = []
        for identity in sorted(pa.keys() | pb.keys()):
            if identity not in pa or identity not in pb:
                diffs.append({"identity": identity, "status": "left_only" if identity in pa else "right_only",
                              "left": profile_body(pa[identity]) if identity in pa else None,
                              "right": profile_body(pb[identity]) if identity in pb else None})
                continue
            fields = field_differences(profile_body(pa[identity]), profile_body(pb[identity]))
            detail = individual_effective_comparison(bundle, persona, left, right, name, identity)
            if fields or detail["fields"]:
                result = {"identity": identity, "status": "different" if fields else "individual_detail_difference",
                          "fields": fields}
                if detail["left_status"] != "not_collected" or detail["right_status"] != "not_collected":
                    result["individual"] = detail
                diffs.append(result)
            elif (detail["fields"] is None
                  and (detail["left_status"] == "identity_observed" or detail["right_status"] == "identity_observed")):
                # Show one-sided detail only when it adds evidence not already
                # present in that scope's collection. Do not call it a difference.
                if ((detail["left"] is not None and field_differences(profile_body(pa[identity]), detail["left"]))
                        or (detail["right"] is not None and field_differences(profile_body(pb[identity]), detail["right"]))):
                    diffs.append({"identity": identity, "status": "individual_comparison_unavailable",
                                  "fields": fields, "individual": detail})
        comparison_status = ("different" if any(d["status"] != "individual_comparison_unavailable" for d in diffs)
                             else "unqualified" if diffs else "exact_match")
        results.append({"module": name, "status": comparison_status, "differences": diffs})
    return results


class Workspace:
    def __init__(self, directory, refresh=None):
        self.directory = Path(directory).resolve(strict=True)
        if not self.directory.is_dir():
            raise ValueError("Workspace must be a directory")
        self.token = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.refresh = refresh
        self.lock = threading.Lock()
        # Keep at most one reviewed snapshot per local workspace. Separate
        # this lock from progress reporting so expensive parsing never blocks
        # the collection status endpoint.
        self.snapshot_lock = threading.Lock()
        self._reviewed_snapshot = None
        self._overview_snapshot = None
        self.state = "idle"
        self.phase = ""
        self.detail = ""
        self.done = 0
        self.total = 0
        self.started = None
        self.phase_started = None
        self.phase_start_count = 0
        self.phase_history = []
        self.finished = None
        self.snapshot = None
        self.collection_strategy = None
        self.historical_times = {}
        self.live_modules = {}

    def publish_module_preview(self, persona, module, data, scopes):
        """Retain read-only structured evidence only for the active capture."""
        with self.lock:
            if self.state == "running":
                self.live_modules[(persona, module)] = (data, scopes)

    def update_progress(self, phase, done, total, detail):
        with self.lock:
            now = time.monotonic()
            if phase != self.phase or done < self.done or (self.total != total and self.total > 0):
                if self.phase_started is not None:
                    self.phase_history.append({"phase": self.phase, "done": self.done,
                                               "total": self.total, "seconds": round(now - self.phase_started, 1)})
                self.phase_started = now
                self.phase_start_count = done
            elif self.phase_started is None:
                self.phase_started = now
                self.phase_start_count = done
            self.phase = phase
            self.done = done
            self.total = total
            self.detail = detail

    def status(self):
        with self.lock:
            now = self.finished if self.finished is not None else time.monotonic()
            elapsed = now - self.started if self.started is not None else 0
            phase_elapsed = now - self.phase_started if self.phase_started is not None else 0
            completed = max(0, self.done - self.phase_start_count)
            rate = completed / phase_elapsed if phase_elapsed > 0 and completed > 0 else None
            eta = round((self.total - self.done) / rate) if (self.state == "running" and rate
                    and completed >= 10 and phase_elapsed >= 10 and self.total > self.done) else None
            overall = overall_audit_progress(self.phase, self.collection_strategy, self.historical_times,
                                             elapsed, phase_elapsed, self.done, self.total, eta)
            if self.state == "complete":
                overall.update(overall_percent=100, overall_eta_seconds=0)
            return {**overall, "phase_elapsed": int(phase_elapsed), "phase_items_per_second": round(rate, 2) if rate else None,
                    "phase_eta_seconds": eta, "phase_history": list(self.phase_history),
                    "state": "failed" if self.state.startswith("failed") else self.state,
                    "message": self.state, "phase": self.phase, "detail": self.detail,
                    "done": self.done, "total": self.total, "elapsed": int(elapsed),
                    "snapshot": self.snapshot, "live_module_count": len(self.live_modules)}

    def start_refresh(self, one_shot=None, *, checkpoint_path=None, tenant_name=None):
        label = tenant_label(tenant_name)
        with self.lock:
            refresh = one_shot if one_shot is not None else self.refresh
            if refresh is None or self.state == "running":
                return False
            self.state = "running"
            self.phase = "Connection"
            self.detail = "Starting read-only audit"
            self.done = self.total = 0
            self.started = time.monotonic()
            self.phase_started = self.started
            self.phase_start_count = 0
            self.phase_history = []
            self.finished = None
            self.snapshot = None
            self.collection_strategy = getattr(refresh, "collection_strategy", None)
            self.historical_times = {}
            self.live_modules = {}
        def run():
            try:
                from .central_tool import write_private
                if not getattr(refresh, "resumed", False):
                    times = historical_phase_times(self.directory, self.collection_strategy,
                                                   getattr(refresh, "exhaustive_details", False))
                    with self.lock:
                        self.historical_times = times
                kwargs = {"progress": self.update_progress}
                if getattr(refresh, "supports_module_preview", False):
                    kwargs["module_completed"] = self.publish_module_preview
                bundle = refresh(**kwargs)
                verified_label = verify_workspace_identity(self.directory, bundle)
                # Use the same verified capture, not a second filesystem
                # lookup that might resolve a different snapshot.
                saved_label = tenant_label(verified_label) if tenant_name is None else label
                if saved_label:
                    bundle["tenant_name"] = saved_label
                    bundle["tenant_name_source"] = "operator_label"
                self.update_progress("Saving snapshot", 0, 0, "Publishing the completed audit")
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
                target = self.directory / snapshot_filename(stamp, saved_label)
                temporary = target.with_suffix(".partial")
                try:
                    with self.lock:
                        bundle["collection_timing"] = {
                            "elapsed_before_save_seconds": round(time.monotonic() - self.started, 1),
                            "phases": list(self.phase_history)}
                    write_private(temporary, bundle, compact=True)
                    os.replace(temporary, target)
                    try:
                        cache_performance(target, performance_record(bundle))
                    except (OSError, ValueError, TypeError, KeyError, AttributeError):
                        pass  # Optional index must not invalidate the capture.
                finally:
                    temporary.unlink(missing_ok=True)
                if checkpoint_path is not None:
                    from .collection_checkpoint import mark_complete
                    mark_complete(checkpoint_path)
                state = "complete"
                snapshot = target.name
            except Exception as exc:
                snapshot = None
                # Expose only a known HTTP status, never arbitrary exception data.
                from .central_tool import APIError
                if isinstance(exc, WorkspaceIdentityError):
                    state = "failed; workspace identity not established; use a separate customer directory"
                elif isinstance(exc, APIError):
                    stage = "OAuth" if str(exc).startswith("OAuth:") else "Central API"
                    state = f"failed; {stage} returned HTTP {exc.status}"
                else:
                    state = "failed; check local configuration and API access"
            with self.lock:
                self.state = state
                self.live_modules = {}
                self.finished = time.monotonic()
                if self.phase_started is not None:
                    self.phase_history.append({"phase": self.phase, "done": self.done, "total": self.total,
                                               "seconds": round(self.finished - self.phase_started, 1)})
                self.phase_started = self.finished
                self.phase_start_count = 0
                self.snapshot = snapshot
                self.phase = "Complete" if state == "complete" else "Failed"
                self.detail = "Snapshot saved" if state == "complete" else state
                self.done = self.total = 0
        threading.Thread(target=run, daemon=True).start()
        return True

    def reviewed_snapshot(self, name):
        """Load and review one unchanged private capture per workspace.

        Returned bundles are shared read-only by the rendering functions.
        Never cache failed loads or reuse evidence after a file replacement.
        """
        from .central_tool import refresh_configuration_review
        with self.snapshot_lock:
            path = next((p for p in audit_files(self.directory) if p.name == name), None)
            if path is None:
                raise ValueError("Unknown snapshot")

            def fingerprint():
                if path.is_symlink():
                    raise ValueError("Unknown snapshot")
                stat = path.stat()
                return (path.name, stat.st_dev, stat.st_ino, stat.st_size,
                        stat.st_mtime_ns, stat.st_ctime_ns)

            before = fingerprint()
            if self._reviewed_snapshot is not None and self._reviewed_snapshot[0] == before:
                return self._reviewed_snapshot[1]
            # Release the previous large bundle before parsing another file.
            self._reviewed_snapshot = None
            bundle = refresh_configuration_review(read_audit(self.directory, name))
            if before != fingerprint():
                raise ValueError("Snapshot changed while loading; open it again")
            self._reviewed_snapshot = (before, bundle)
            return bundle

    def nav(self, snapshot=None):
        return navigation("/" + self.token + "/", snapshot)

    def snapshot_overview(self, name):
        """Cache only the small dashboard summary, never another full capture."""
        from .consolidation import profile_recommendations
        from collections import Counter
        from .central_tool import refresh_configuration_review
        with self.snapshot_lock:
            path = next((p for p in audit_files(self.directory) if p.name == name), None)
            if path is None:
                raise ValueError("Unknown snapshot")
            def fingerprint():
                if path.is_symlink():
                    raise ValueError("Unknown snapshot")
                stat = path.stat()
                return (path.name, stat.st_dev, stat.st_ino, stat.st_size,
                        stat.st_mtime_ns, stat.st_ctime_ns)
            before = fingerprint()
            if self._overview_snapshot is not None and self._overview_snapshot[0] == before:
                return self._overview_snapshot[1]
            self._overview_snapshot = None
            bundle = read_audit(self.directory, name)
            coverage = module_coverage(bundle)
            devices = {s["id"] for entry in bundle["results"].values() for s in entry["scopes"] if s["kind"] == "device"}
            scopes = {s["id"] for entry in bundle["results"].values() for s in entry["scopes"] if s["kind"] != "device"}
            library = (bundle.get("library") or {}).get("modules", {})
            complete_structure = all(
                {"scope_kind", "local_view", "effective_view"} <= scope.keys()
                for entry in bundle["results"].values() for data in entry["modules"].values()
                for scope in data["scope_results"])
            # Coverage and inventory are based on the saved evidence, as before.
            # Only the recommendation calculation reparses adapter evidence.
            summary = {"device_count": len(devices), "scope_count": len(scopes),
                       "library_count": sum(len(v["profiles"]) for v in library.values() if v["status"] == "list_parsed"),
                       "coverage_count": len(coverage),
                       "qualified_count": sum(r["status"] == "qualified" for r in coverage),
                       "tenant_name": bundle.get("tenant_name"),
                       "captured_at": bundle.get("captured_at", "unknown"),
                       "findings_available": complete_structure, "counts": {}}
            if complete_structure:
                reviewed = (self._reviewed_snapshot[1] if self._reviewed_snapshot is not None
                            and self._reviewed_snapshot[0] == before else refresh_configuration_review(bundle))
                summary["counts"] = dict(Counter(f["action"] for f in profile_recommendations(reviewed)))
            if before != fingerprint():
                raise ValueError("Snapshot changed while loading; open it again")
            self._overview_snapshot = (before, summary)
            return summary

    def home(self, query=None):
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        name = (query or {}).get("snapshot", files[0].name if files else None)
        bundle = self.snapshot_overview(name) if name else None
        status = self.status()
        state = status["state"]
        from .central_tool import EU_REGIONS
        disabled = " disabled" if state == "running" else ""
        name_label = tenant_label(bundle.get("tenant_name")) if bundle else ""
        hidden = f'<input type="hidden" name="csrf" value="{e(self.csrf)}">'
        from .collection_checkpoint import available_checkpoints
        checkpoints = available_checkpoints(self.directory) if state != "running" else []
        checkpoint_options = options([("", "New collection (resumable)") , ("fresh", "New collection without checkpoint")] + [(v["name"], "Resume " + v["created_at"] + " (" + str(v["pairs"]) + " saved scope pairs)") for v in checkpoints])
        refresh = (f'<form class="connection-form" method="post" action="{root}credentials" autocomplete="off">' + hidden +
                   '<label>API region<select name="region">'
                   + options([("", "Detect EU region")] + [(r, urlsplit(r).hostname.split(".")[0].upper()) for r in EU_REGIONS])
                   + '</select></label><label>Client ID<input name="client_id" type="text" required maxlength="1024" autocomplete="off"></label>'
                   '<label>Client secret<input name="client_secret" type="password" required maxlength="4096" autocomplete="new-password"></label>'
                   f'<label>Tenant name (optional)<input name="tenant_name" type="text" maxlength="100" value="{e(name_label)}" placeholder="Customer or tenant name"></label>'
                   '<label>Collection depth<select name="depth"><option value="deep">Deep catalog (optimized individual verification)</option><option value="fast">Fast catalog (observed modules; limited discovery)</option><option value="exhaustive">Deep catalog (exhaustive individual verification)</option><option value="standard">Standard (observed functions and Global)</option></select></label>'
                   '<label>Collection recovery<select name="checkpoint">' + checkpoint_options + '</select></label>'
                   f'<button type="submit"{disabled}>Connect and refresh</button></form>'
                   '<p><small>Deep collection can take substantially longer on large tenants. API coverage gaps and rejected reads remain visible.</small></p>'
                   '<p><small>Resume only an interrupted collection with the same tenant, depth and inventory. Resumed evidence has mixed capture times; use a fresh collection for change verification.</small></p>'
                   '<p><small>Use a separate directory per customer. Existing captures require matching region, Global scope and overlapping device serial evidence before collecting configuration.</small></p>'
                   '<p><small>Credentials are used only for this audit, in process memory. '
                   'They are not saved or returned by the application. Decline browser password-saving prompts.</small></p>')
        if self.refresh is not None:
            refresh += (f'<form method="post" action="{root}refresh">' + hidden + '<button type="submit"'
                       + (" disabled" if state == "running" else "")
                       + ">Refresh using environment credentials</button></form>")
        title = {"idle": "Ready to connect", "running": "Audit in progress",
                 "complete": "Audit complete", "failed": "Audit failed"}[state]
        snapshot_link = ""
        if status["snapshot"]:
            href = root + "report?" + urlencode({"snapshot": status["snapshot"]})
            advisor = root + "advisor?" + urlencode({"snapshot": status["snapshot"]})
            snapshot_link = f'<p><a href="{e(advisor)}">Review consolidation recommendations</a> · <a href="{e(href)}">Open new configuration snapshot</a></p>'
        progress_html = (
            f'<div class="audit-state" id="audit-state" data-state="{e(state)}" data-status-url="{root}status">'
            f'<h3 id="audit-title" role="status">{e(title)}</h3>'
            '<div id="audit-overall" hidden><h4>Overall audit progress</h4>'
            '<progress id="audit-overall-progress" max="100"></progress>'
            '<p id="audit-overall-count"></p><p id="audit-overall-estimate" class="muted"></p></div>'
            '<h4>Current phase</h4>'
            f'<p id="audit-detail">{e(status["phase"])} {e(status["detail"])}</p>'
            f'<progress id="audit-progress" max="{max(1, status["total"])}"'
            + (f' value="{status["done"]}"' if status["total"] else "")
            + ("" if state == "running" else " hidden")
            + f'></progress><p id="audit-count">{status["done"]}/{status["total"]} · {status["elapsed"]}s total elapsed</p>'
            + f'<p id="audit-live-preview"{" hidden" if not status["live_module_count"] else ""}><a href="{root}live">Browse collected modules</a> <span id="audit-live-count">{status["live_module_count"]} ready</span></p>'
            + '<p id="audit-rate" class="muted"></p><details id="audit-history"><summary>Completed phases</summary><ul id="audit-phases"></ul></details>'
            + snapshot_link + f'<p><a href="{root}performance">Collection performance history</a></p></div>')
        script = """
<script>
const panel=document.getElementById('audit-state');
const title=document.getElementById('audit-title');
const detail=document.getElementById('audit-detail');
const bar=document.getElementById('audit-progress');
const count=document.getElementById('audit-count');
const rate=document.getElementById('audit-rate');
const history=document.getElementById('audit-phases');
const overall=document.getElementById('audit-overall');
const overallBar=document.getElementById('audit-overall-progress');
const overallCount=document.getElementById('audit-overall-count');
const overallEstimate=document.getElementById('audit-overall-estimate');
const livePreview=document.getElementById('audit-live-preview');
const liveCount=document.getElementById('audit-live-count');
function duration(seconds){
  const s=Math.max(0,Math.round(seconds));
  return (s>=3600?Math.floor(s/3600)+'h ':'')+(s>=60?Math.floor((s%3600)/60)+'m ':'')+(s%60)+'s';
}
for(const form of document.querySelectorAll('form[method=post]')){
  form.addEventListener('submit',()=>{
    title.textContent='Connecting to Central…';
    detail.textContent='Starting audit. Please keep the local application open.';
    panel.dataset.state='running';
    bar.hidden=false;bar.removeAttribute('value');
    for(const button of document.querySelectorAll('form[method=post] button'))button.disabled=true;
  });
}
async function poll(){
  try {
    const response=await fetch(panel.dataset.statusUrl,{cache:'no-store',credentials:'same-origin'});
    if(!response.ok)throw Error('Status unavailable');
    const state=await response.json();
    if(state.state!=='running'){location.reload();return;}
    title.textContent='Audit in progress';
    detail.textContent=[state.phase,state.detail].filter(Boolean).join(' · ');
    overall.hidden=false;
    livePreview.hidden=state.live_module_count===0;
    liveCount.textContent=state.live_module_count+' ready';
    if(state.overall_percent!==null){
      overallBar.value=state.overall_percent;
      overallCount.textContent='Approximately '+state.overall_percent.toFixed(1)+'% · '+duration(state.elapsed)+' elapsed · '+duration(state.overall_eta_seconds)+' remaining';
      overallEstimate.textContent=state.estimate_basis+'. Conditional phases and changing API latency may alter the estimate.';
    }else{
      overallBar.removeAttribute('value');
      overallCount.textContent=duration(state.elapsed)+' elapsed';
      overallEstimate.textContent='Overall time estimate unavailable until a comparable completed capture is available. Current phase progress is shown below.';
    }
    if(state.stage!==null)overallEstimate.textContent+=' · Stage '+state.stage+' of '+state.stages+' (some stages are conditional)';
    bar.hidden=false;
    if(state.total>0){bar.max=state.total;bar.value=state.done;}
    else{bar.removeAttribute('value');}
    count.textContent=(state.total>0?state.done.toLocaleString()+'/'+state.total.toLocaleString()+' · '+(100*state.done/state.total).toFixed(1)+'% · ':'')+duration(state.elapsed)+' total elapsed';
    rate.textContent=duration(state.phase_elapsed)+' in this phase'+
      (state.phase_items_per_second!==null?' · '+state.phase_items_per_second.toFixed(2)+' items/s':'')+
      (state.phase_eta_seconds!==null?' · approximately '+duration(state.phase_eta_seconds)+' remaining in this phase':'');
    history.replaceChildren(...state.phase_history.map(p=>{
      const li=document.createElement('li');li.textContent=p.phase+' · '+duration(p.seconds)+(p.total?' · '+p.done+'/'+p.total:'');return li;
    }));
  } catch(error) {
    detail.textContent='Unable to reach the local status endpoint. Retrying…';
  }
  setTimeout(poll,1000);
}
if(panel.dataset.state==='running')poll();
</script>"""
        summary = ""
        if bundle:
            coverage_count = bundle["coverage_count"]
            qualified = bundle["qualified_count"]
            summary = metrics([("Devices", bundle["device_count"], "Captured inventory"),
                               ("Configuration scopes", bundle["scope_count"], "Non-device scopes"),
                               ("Library profiles", bundle["library_count"], "Observed definitions")])
            from collections import Counter
            counts = Counter(bundle["counts"])
            opportunities = counts["remove_override"] + counts["promote_local"] + counts["reuse_library"]
            advisor_href = root + "advisor?" + urlencode({"snapshot": name})
            overrides_href = root + "overrides?" + urlencode({"snapshot": name})
            coverage_href = root + "coverage?" + urlencode({"snapshot": name})
            if not bundle["findings_available"]:
                summary += '<section><h2>Consolidation analysis unavailable</h2><p>This snapshot lacks the saved configuration evidence needed for review. Collect a new snapshot to calculate recommendations.</p></section>'
            else:
                from .workspace_ui import icon
                categories = (("remove_override", "Matching Global profiles", "Review lower-scope copies"),
                              ("promote_local", "Repeated local profiles", "Consolidate repeated definitions"),
                              ("reuse_library", "Matching Library profiles", "Reuse an existing definition"))
                breakdown = "".join(
                    f'<a class="opportunity-row" href="{e(advisor_href + "&finding=" + key)}">'
                    f'<div><strong>{e(label)}</strong><small>{e(description)}</small></div>'
                    f'<div class="opportunity-meter"><span style="width:{100 * counts[key] / max(1, opportunities):.2f}%"></span></div>'
                    f'<b>{counts[key]}</b>{icon("chevron")}</a>'
                    for key, label, description in categories)
                gap = coverage_count - qualified
                summary = (f'<div class="overview-layout"><section class="overview-focus"><div class="focus-lead">'
                           '<div class="focus-kicker">' + icon("advisor") + ' Consolidation opportunities</div>'
                           f'<div class="focus-number">{opportunities}</div>'
                           '<h2>Reduce configuration duplication.</h2>'
                           '<p>Review the captured evidence and prepare a change preview. No changes are sent to Central.</p>'
                           f'<a class="button primary" href="{e(advisor_href)}">Review opportunities {icon("arrow")}</a></div>'
                           '<div class="overview-breakdown"><h3>Review by recommendation</h3>' + breakdown + '</div></section>'
                           '<section class="coverage-focus"><div class="focus-kicker">' + icon("coverage") + ' Data readiness</div>'
                           f'<div class="coverage-number">{qualified}<small> / {coverage_count}</small></div>'
                           '<h3>Fully qualified module reads</h3>'
                           f'<div class="coverage-meter" role="img" aria-label="{qualified} of {coverage_count} module reads fully qualified">'
                           f'<span style="width:{100 * qualified / max(1, coverage_count):.2f}%"></span></div>'
                           f'<p>{gap} incomplete or unavailable module reads.</p><a href="{e(coverage_href)}">Inspect coverage {icon("arrow")}</a></section></div>'
                           + summary
                           + '<section class="overview-links"><div><h3>Review device overrides</h3><p>Inspect the actual differences between a device and Global before removing local definitions.</p>'
                           f'<a href="{e(overrides_href + "&result=cleanup")}">Review potential cleanup {icon("arrow")}</a></div>'
                           '<div><h3>Library engineering</h3><p>Find duplicate definitions, compare individual usage and inspect configuration dependencies.</p>'
                           f'<a href="{e(root + "advanced?" + urlencode({"snapshot": name}))}">Review engineering {icon("arrow")}</a></div></section>')
        else:
            summary = '<section><h2>Saved snapshots</h2><p>No snapshots yet. Connect to Central to start a read-only configuration audit.</p></section>'
        picker = snapshot_picker(root, "", files, name) if files else ""
        capture_note = (f'<p class="muted">Captured: {e(bundle.get("captured_at", "unknown"))} · Saved snapshots: {len(files)}</p>' if bundle else "")
        # The connection form is secondary once an audit is available. Keep
        # active/failed progress visible and never store credentials.
        connection = (f'<section><details class="connection-details"{" open" if not bundle or state in ("running", "failed", "complete") else ""}>'
                      f'<summary>Collect a new snapshot</summary>{progress_html}{refresh}'
                      '<p class="note">Use a separate workspace directory for each customer. Tenant identity is not independently verified.</p></details></section>')
        return page("Snapshots", intro("Overview", "Review captured configuration and plan improvements.", picker)
                    + capture_note + summary + connection + script, self.nav(name))

    def overrides(self, query):
        from .override_view import overrides_view
        return overrides_view(self, query)

    def advisor(self, query):
        from .workspace_views import advisor_view
        return advisor_view(self, query)

    def advanced(self, query):
        from .workspace_views import engineering_view
        return engineering_view(self, query)

    def library(self, query):
        from .workspace_views import library_view
        return library_view(self, query)

    def unadapted(self, query):
        from .workspace_ui import property_table, table, tr, status, raw, module_label, persona_label, badge, diff_table
        from .central_tool import qualify_observed_identities, keyed_profile_contracts, observed_profile_candidates, field_differences, profile_body
        root = "/" + self.token + "/"
        name, module = query["snapshot"], query["module"]
        bundle = self.reviewed_snapshot(name)
        evidence = bundle.get("unadapted_profiles", {}).get(module)
        if evidence is None:
            return page("Profile evidence", "<p>No captured evidence for this profile type. Collect a fresh audit.</p>", self.nav(name))
        def link(**params):
            return e(root + "unadapted?" + urlencode({"snapshot": name, "module": module, **params}))
        def individual(persona, scope):
            from .workspace_views import keyed_profile_evidence
            records = ((bundle.get("keyed_profile_details") or {}).get("profiles", {})
                       .get(persona, {}).get(str(scope), {}).get(module, {}))
            if not records:
                return ""
            return '<section><h3>Individual profile evidence</h3>' + "".join(
                '<details><summary>' + e(identity) + '</summary>' +
                keyed_profile_evidence(bundle, persona, scope, module, identity) + '</details>'
                for identity in sorted(records)) + '</section>'
        def settings(read):
            payload = read.get("raw")
            if isinstance(payload, dict):
                fields = {k: v for k, v in payload.items() if k != "metadata"}
                display = property_table(fields) if fields else '<p class="empty">No configuration values returned.</p>'
            else:
                display = '<p class="empty">Structured settings unavailable.</p>'
            return status(read["status"]) + display + raw(read, "Complete captured response")
        identity_key = keyed_profile_contracts(include_raw=True).get(module)
        selected_identity = query.get("profile")
        def profile_table(reads, persona=None, scope=None):
            if not identity_key:
                return ""
            candidates = {label: observed_profile_candidates(read, identity_key)
                          for label, read in reads.items()}
            identities = sorted(set().union(*(set(rows) for rows in candidates.values())))
            if not identities:
                return ""
            params = {} if persona is None else {"persona": persona, "scope": scope}
            def comparison(identity):
                if len(candidates) != 2:
                    return "Observed"
                left, right = (rows.get(identity) for rows in candidates.values())
                if left is None or right is None:
                    return "One view observed; other unverified"
                return "Identical observed settings" if profile_body(left) == profile_body(right) else "Different observed settings"
            html = '<section><h3>Observed profiles</h3><p>Positive identities from the documented key. Missing records are not proof of absence; source and completeness remain unverified.</p>'
            if selected_identity is not None:
                if selected_identity not in identities:
                    raise ValueError("Unknown observed profile")
                html += '<p><a href="' + link(**params) + '">Back to observed profiles</a></p><h4>' + e(selected_identity) + '</h4>'
                for label, rows in candidates.items():
                    html += '<h4>' + e(label) + '</h4>'
                    if selected_identity in rows:
                        html += property_table(profile_body(rows[selected_identity]))
                    else:
                        html += '<p class="note">No independently qualified record observed.</p>'
                if len(candidates) == 2:
                    left, right = (rows.get(selected_identity) for rows in candidates.values())
                    if left is not None and right is not None:
                        html += diff_table(field_differences(profile_body(left), profile_body(right)),
                                           *candidates.keys())
                return html + '</section>'
            return html + table(("Profile", *candidates.keys(), "Comparison", ""), [
                tr(e(identity), *("Observed" if identity in rows else "Unverified" for rows in candidates.values()),
                   e(comparison(identity)), '<a href="' + link(**params, profile=identity) + '">Inspect profile</a>')
                for identity in identities], search=True) + '</section>'
        names = {(persona, str(s["id"])): s.get("name") or s["id"]
                 for persona, entry in bundle["results"].items() for s in entry["scopes"]}
        identities = qualify_observed_identities(evidence)
        selected_persona, selected_scope = query.get("persona"), query.get("scope")
        body = intro(module_label(module), "System configuration and captured evidence." if "singleton_library" in evidence else
                     "Supplemental captured configuration evidence." if evidence.get("status") == "supplemental_raw" else
                     "Captured configuration without a qualified comparison adapter.")
        body += f'<div class="collection-nav"><a href="{e(root + "coverage?" + urlencode({"snapshot": name}))}">← Collection coverage</a></div>'
        body += '<p class="note">Read-only evidence. A captured value does not establish profile identity, source precedence or safe removal.</p>'
        if selected_persona is not None or selected_scope is not None:
            matches = [v for v in evidence["source_views"] if v["persona"] == selected_persona and v["scope"] == selected_scope]
            if len(matches) != 1:
                raise ValueError("Unknown source scope")
            view = matches[0]
            label = names.get((selected_persona, selected_scope), selected_scope)
            body += f'<section><a href="{link()}">← All captured scopes</a><h2>{e(label)} · {e(persona_label(selected_persona))}</h2>'
            review = view.get("singleton_review")
            if review:
                body += '<h3>System settings comparison</h3>'
                differences = review.get("differences")
                if differences is None:
                    body += '<p class="note">Comparison unavailable. Both configuration objects must be observed.</p>'
                else:
                    body += '<p>Identical observed settings.</p>' if not differences else property_table({"Differences": differences})
                for side in ("committed", "effective"):
                    item = review[side]
                    body += f'<h4>{e(side.title())} settings</h4>' + status(item["status"])
                    if item.get("settings") is not None:
                        body += property_table(item["settings"])
            body += profile_table({"Committed": view["committed"], "Effective": view["effective"]},
                                  selected_persona, selected_scope)
            body += '<details><summary>Committed configuration (complete response)</summary>' + settings(view["committed"]) + '</details>'
            body += '<details><summary>Effective configuration (complete response)</summary>' + settings(view["effective"]) + '</details></section>'
            body += individual(selected_persona, selected_scope)
        else:
            library = evidence["library"]
            body += '<section><h2>Library</h2>'
            if evidence.get("singleton_library", {}).get("settings") is not None:
                body += property_table(evidence["singleton_library"]["settings"])
            body += profile_table({"Library": library})
            body += '<details><summary>Complete Library response</summary>' + settings(library) + '</details></section>'
            body += individual("Library", "")
            views = evidence["source_views"]
            if identities:
                body += '<section><h2>Identity evidence</h2>' + table(("Device function", "Identity field", "Comparable observed source scopes"),
                    [tr(e(persona_label(p)), e(v.get("identity_field", "Unavailable")),
                        f'{v.get("comparable_source_scopes", 0)}/{v["source_scopes"]}')
                     for p, v in identities.items()]) + '</section>'
            body += '<section><h2>Captured scopes</h2>' + table(("Device function", "Scope", "Committed", "Effective", ""),
                    [tr(e(persona_label(v["persona"])), e(names.get((v["persona"], v["scope"]), v["scope"])),
                        status(v["committed"]["status"]), status(v["effective"]["status"]),
                        f'<a href="{link(persona=v["persona"], scope=v["scope"])}">Inspect settings</a>')
                     for v in views], search=True) + '</section>'
        return page("Profile evidence", body, self.nav(name))

    def coverage(self, query):
        from .workspace_views import coverage_view
        return coverage_view(self, query)

    def performance_history(self):
        root = "/" + self.token + "/"
        rows = []
        records = []
        for path in audit_files(self.directory)[:5]:
            try:
                records.append((path.name, read_performance(path)))
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                continue
        baseline = records[0][1] if records else {}
        def display(value):
            return e(value) if value is not None else "Unavailable"
        for name, record in records:
            comparable = bool(record.get("topology") and record.get("topology") == baseline.get("topology")
                              and record.get("strategy") == baseline.get("strategy")
                              and record.get("detail_strategy") == baseline.get("detail_strategy")
                              and not record.get("mixed_capture_times") and not baseline.get("mixed_capture_times"))
            elapsed = record.get("elapsed")
            attempts = record.get("attempts")
            duration = f"{elapsed / 60:.1f} min" if type(elapsed) in (int, float) and elapsed > 0 else None
            throughput = f"{attempts / elapsed:.2f}" if type(attempts) is int and type(elapsed) in (int, float) and elapsed > 0 else None
            rows.append('<tr>' + ''.join(f'<td>{display(value)}</td>' for value in (
                name, record.get("strategy"), record.get("detail_strategy"), duration, attempts, throughput,
                record.get("scope_pairs"), record.get("detail_reads"), record.get("rate_limits"),
                "Same scope/module plan" if comparable else "Different or unverified workload")) + '</tr>')
        body = (f'<p><a href="{root}">Back to workspace</a></p>'
                '<p>Latest five completed captures. Timing excludes final snapshot serialization. Matching topology and mode '
                'do not guarantee identical configuration content. Resumed captures are not comparable.</p>'
                '<table><thead><tr><th>Capture</th><th>Mode</th><th>Detail strategy</th><th>Duration</th>'
                '<th>GET attempts</th><th>GET/s</th><th>Scope pairs</th><th>Detail reads</th><th>429s</th>'
                '<th>Compared with latest</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table>')
        return page("Collection performance history", body, self.nav())

    def live_preview(self, query):
        """Separate live inspection route; never treated as a snapshot or plan."""
        root = "/" + self.token + "/"
        with self.lock:
            modules = dict(self.live_modules)
            running = self.state == "running"
            snapshot = self.snapshot
        intro = ('<p><a href="' + root + '">Back to audit progress</a></p>'
                 '<p>Partial read-only evidence from the current audit. Library, individual profile reads, '
                 'dependencies and operational verification may still be pending. No recommendations or changes '
                 'are authorized from this preview.</p>')
        if not running:
            link = (f'<p><a href="{root}report?{e(urlencode({"snapshot": snapshot}))}">Open completed snapshot</a></p>'
                    if snapshot else "")
            return page("Live collection preview", intro + '<p>No audit is running.</p>' + link, self.nav())
        links = []
        for (persona, module), (data, scopes) in sorted(modules.items()):
            total = len(data["scope_results"])
            qualified = sum(row["review"]["qualified"] is True for row in data["scope_results"])
            href = root + "live?" + urlencode({"persona": persona, "module": module})
            links.append(f'<tr><td>{e(persona)}</td><td><a href="{e(href)}">{e(module)}</a></td>'
                         f'<td>{qualified}/{total}</td></tr>')
        body = intro + f'<p>{len(modules)} structured modules available. <a href="{root}live">Refresh list</a></p>'
        selected = (query.get("persona"), query.get("module"))
        if selected != (None, None):
            if selected not in modules:
                raise ValueError("Module not yet collected")
            data, scopes = modules[selected]
            names = {str(scope["id"]): scope.get("name") or str(scope["id"]) for scope in scopes}
            body += f'<h2>{e(selected[0])} / {e(selected[1])}</h2>'
            rows = []
            chosen = query.get("scope")
            selected_scope = None
            for scope in data["scope_results"]:
                sid = str(scope["scope"])
                href = root + "live?" + urlencode({"persona": selected[0], "module": selected[1], "scope": sid})
                local = scope["local_view"]
                effective = scope["effective_view"]
                rows.append(f'<tr><td><a href="{e(href)}">{e(names.get(sid, sid))}</a></td>'
                            f'<td>{e(scope["scope_kind"])}</td><td>{e(local["status"])} ({len(local.get("profiles", {}))})</td>'
                            f'<td>{e(effective["status"])} ({len(effective.get("profiles", {}))})</td></tr>')
                if sid == chosen:
                    selected_scope = scope
            if chosen is not None and selected_scope is None:
                raise ValueError("Unknown collected scope")
            if selected_scope is not None:
                body += f'<h3>{e(names.get(chosen, chosen))}</h3>'
                for label, key in (("Committed local", "local_view"), ("Effective", "effective_view")):
                    body += f'<details open><summary>{label} evidence</summary><pre>{e(json.dumps(selected_scope[key], indent=2, ensure_ascii=False))}</pre></details>'
            body += '<table><thead><tr><th>Scope</th><th>Level</th><th>Local status</th><th>Effective status</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table>'
        body += '<h2>Available modules</h2><table><thead><tr><th>Device function</th><th>Module</th><th>Qualified scopes</th></tr></thead><tbody>' + ''.join(links) + '</tbody></table>'
        return page("Live collection preview", body, self.nav())

    def report(self, query):
        from .workspace_views import explorer_view
        return explorer_view(self, query)

    def scopes(self, query):
        from .workspace_views import inventory_view
        return inventory_view(self, query)

    def nac(self, query):
        from .nac_view import nac_view
        return nac_view(self, query)

    def assessment(self, query):
        from .assessment_view import assessment_view
        return assessment_view(self, query)

    def assignments(self, query):
        from .assignment_view import assignments_view
        return assignments_view(self, query)

    def sources(self, query):
        from .source_view import source_view
        return source_view(self, query)

    def impact(self, query):
        from .impact_view import impact_view
        return impact_view(self, query)

    def comparison(self, query):
        from .workspace_views import comparison_view
        return comparison_view(self, query)

    def drift(self, query):
        from .history_view import drift_view
        return drift_view(self, query)

    def remediation(self, query):
        from .remediation_view import remediation_view
        return remediation_view(self, query)

    def trends(self, query):
        from .trends_view import trends_view
        return trends_view(self, query)

    def standards(self, query):
        from .history_view import standards_view
        return standards_view(self, query)


def handler_for(workspace):
    root = "/" + workspace.token + "/"
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def valid_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def reply(self, body, status=200, content_type="text/html; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            # no-referrer can cause an opaque Origin on browser form POSTs.
            # Never send the private session URL to a different origin.
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if not self.valid_host() or not parsed.path.startswith(root):
                self.reply("Not found", 404)
                return
            try:
                query = {k: v[-1] for k, v in parse_qs(parsed.query, max_num_fields=12).items()}
                if parsed.path == root + "status":
                    self.reply(json.dumps(workspace.status()), content_type="application/json; charset=utf-8")
                    return
                if parsed.path == root:
                    body = workspace.home(query)
                elif parsed.path == root + "performance":
                    body = workspace.performance_history()
                elif parsed.path == root + "live":
                    body = workspace.live_preview(query)
                elif parsed.path == root + "report":
                    body = workspace.report(query)
                elif parsed.path == root + "legacy-report":
                    from .central_tool import configuration_html
                    bundle = workspace.reviewed_snapshot(query["snapshot"])
                    body = configuration_html(bundle).replace("<main>", f'<main><p><a href="{root}report?{e(urlencode({"snapshot": query["snapshot"]}))}">Back to workspace</a></p>', 1)
                elif parsed.path == root + "overrides":
                    body = workspace.overrides(query)
                elif parsed.path == root + "advisor":
                    body = workspace.advisor(query)
                elif parsed.path == root + "nac":
                    body = workspace.nac(query)
                elif parsed.path == root + "assessment":
                    body = workspace.assessment(query)
                elif parsed.path == root + "assignments":
                    body = workspace.assignments(query)
                elif parsed.path == root + "sources":
                    body = workspace.sources(query)
                elif parsed.path == root + "impact":
                    body = workspace.impact(query)
                elif parsed.path == root + "advanced":
                    body = workspace.advanced(query)
                elif parsed.path == root + "library":
                    body = workspace.library(query)
                elif parsed.path == root + "unadapted":
                    body = workspace.unadapted(query)
                elif parsed.path == root + "coverage":
                    body = workspace.coverage(query)
                elif parsed.path == root + "scopes":
                    body = workspace.scopes(query)
                elif parsed.path == root + "compare":
                    body = workspace.comparison(query)
                elif parsed.path == root + "drift":
                    body = workspace.drift(query)
                elif parsed.path == root + "remediation":
                    body = workspace.remediation(query)
                elif parsed.path == root + "trends":
                    body = workspace.trends(query)
                elif parsed.path == root + "standards":
                    body = workspace.standards(query)
                else:
                    self.reply("Not found", 404)
                    return
                self.reply(body)
            except (ValueError, KeyError, OSError, TypeError):
                self.reply(page("Invalid request", "<p>Invalid snapshot or selection.</p>", workspace.nav()), 400)

        def do_POST(self):
            expected = f"http://127.0.0.1:{self.server.server_port}"
            origin = self.headers.get("Origin")
            fetch_site = self.headers.get("Sec-Fetch-Site")
            # Explicit cross-origin requests are always rejected. Older cached
            # form pages or privacy settings may send an opaque/null Origin;
            # permit that only with same-origin fetch metadata and a CSRF token.
            origin_ok = origin == expected or (origin in (None, "null") and fetch_site == "same-origin")
            if (not self.valid_host() or self.path not in (root + "refresh", root + "credentials", root + "save-standard", root + "approve-exception", root + "revoke-exception")
                    or not origin_ok or fetch_site not in (None, "same-origin")):
                self.reply("Forbidden: local session or origin check failed. Reopen the application.", 403)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 24576 or self.headers.get_content_type() != "application/x-www-form-urlencoded":
                    raise ValueError("Invalid form")
                self.connection.settimeout(10)
                values = parse_qs(self.rfile.read(length).decode("utf-8"),
                                  keep_blank_values=True, strict_parsing=True,
                                  max_num_fields=512 if self.path == root + "save-standard" else 12 if self.path in (root + "save-standard", root + "approve-exception", root + "revoke-exception") else 7)
                fields = values.pop("field_selection", []) if self.path == root + "save-standard" else []
                if any(len(v) != 1 for v in values.values()):
                    raise ValueError("Invalid form")
                token = values.pop("csrf", [""])[0]
                if not secrets.compare_digest(token.encode("utf-8"), workspace.csrf.encode("utf-8")):
                    self.reply("Forbidden: stale or invalid form token. Reopen the application.", 403)
                    return
                if self.path in (root + "save-standard", root + "approve-exception", root + "revoke-exception"):
                    from .local_standards import create_standard, approve_exception, revoke_exception
                    form = {key: value[0] for key, value in values.items()}
                    confirmed = form.pop("confirmed", "") == "yes"
                    if self.path == root + "save-standard":
                        if set(form) != {"name", "snapshot", "baseline_name", "persona", "reference", "module", "target"}:
                            raise ValueError("Invalid standard form")
                        record = create_standard(workspace.directory, **form, confirmed=confirmed,
                                                 field_selection=json.dumps(fields) if fields else None)
                        standard_id = record["id"]
                    elif self.path == root + "revoke-exception":
                        if set(form) != {"standard_id", "snapshot", "exception_id", "reason"}:
                            raise ValueError("Invalid revocation form")
                        read_audit(workspace.directory, form["snapshot"])
                        revoke_exception(workspace.directory, form["standard_id"], form["exception_id"], form["reason"])
                        standard_id = form["standard_id"]
                    else:
                        if set(form) != {"standard_id", "snapshot", "candidate", "reason", "expiry"}:
                            raise ValueError("Invalid exception form")
                        approve_exception(workspace.directory, **form, confirmed=confirmed)
                        standard_id = form["standard_id"]
                    self.send_response(303)
                    self.send_header("Location", root + "standards?" + urlencode({
                        "snapshot": form["snapshot"], "standard": standard_id,
                        "confirmed": "yes" if confirmed else ""}))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == root + "credentials":
                    depth = values.pop("depth", ["standard"])[0]
                    recovery = values.pop("checkpoint", ["fresh"])[0]
                    label = tenant_label(values.pop("tenant_name", [""])[0])
                    if set(values) != {"client_id", "client_secret", "region"} or depth not in ("standard", "deep", "exhaustive", "fast"):
                        raise ValueError("Invalid credential form")
                    from .collection_checkpoint import available_checkpoints
                    import uuid
                    checkpoint_path = None
                    resume = recovery not in ("", "fresh")
                    if resume:
                        if recovery not in {v["name"] for v in available_checkpoints(workspace.directory)}:
                            raise ValueError("Unknown or expired checkpoint")
                        checkpoint_path = workspace.directory / recovery
                    elif recovery == "":
                        checkpoint_path = workspace.directory / ("collection-" + uuid.uuid4().hex + ".db")
                    # Preserve compatibility for callers using a non-resumable refresh.
                    kwargs = {"deep_catalog": depth != "standard"}
                    if depth == "exhaustive":
                        kwargs["exhaustive_details"] = True
                    if depth == "fast":
                        kwargs["targeted_catalog"] = True
                    if checkpoint_path is not None:
                        kwargs.update(checkpoint_path=checkpoint_path, resume=resume)
                    if audit_files(workspace.directory):
                        kwargs["identity_guard"] = lambda incoming: verify_workspace_identity(workspace.directory, incoming)
                    refresh = credential_refresh(values["client_id"][0], values["client_secret"][0], values["region"][0], **kwargs)
                    values.clear()
                    started = workspace.start_refresh(refresh, checkpoint_path=checkpoint_path, tenant_name=label or None)
                else:
                    if values:
                        raise ValueError("Invalid refresh form")
                    started = workspace.start_refresh()
            except (ValueError, OSError, UnicodeError, KeyError, TypeError):
                self.reply("Invalid form or unavailable evidence", 400)
                return
            if not started:
                self.reply(page("Refresh unavailable", "<p>Refresh unavailable or already running.</p>",
                                workspace.nav()), 409)
                return
            self.send_response(303)
            self.send_header("Location", root)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
    return Handler


def serve(directory, refresh=None, port=0, open_browser=True):
    workspace = Workspace(directory, refresh)
    with ThreadingHTTPServer(("127.0.0.1", port), handler_for(workspace)) as server:
        url = f"http://127.0.0.1:{server.server_port}/{workspace.token}/"
        print("Local configuration workspace started on loopback. Press Ctrl+C to stop.", flush=True)
        if open_browser:
            webbrowser.open(url)
        else:
            print(url, flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
