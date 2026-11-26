"""Read-only Central VLAN discovery and conservative comparison."""
import argparse
import json
import os
import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

CONFIG = "/network-config/v1"
ALPHA = CONFIG + "alpha1"
VLAN = ALPHA + "/layer2-vlan"
INVENTORY = "/network-monitoring/v1/device-inventory"
TOKEN_URL = "https://sso.common.cloud.hpe.com/as/token.oauth2"
EU_REGIONS = tuple(f"https://de{i}.api.central.arubanetworks.com" for i in (1, 2, 3))
PERSONAS = {"ACCESS_SWITCH", "AGG_SWITCH", "CORE_SWITCH"}


class APIError(RuntimeError):
    def __init__(self, label, status):
        super().__init__(f"{label}: HTTP {status}")
        self.status = status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def rows(payload, keys):
    if not isinstance(payload, dict):
        raise ValueError("Expected an API response object")
    found = [payload[key] for key in keys if key in payload]
    if len(found) != 1 or not isinstance(found[0], list):
        raise ValueError("Unexpected response list envelope; validate against live API")
    if any(not isinstance(row, dict) for row in found[0]):
        raise ValueError("Unexpected response item type")
    return found[0]


def scope_id(row):
    value = row.get("scopeId", row.get("scopeID"))
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not str(value).isdigit():
        raise ValueError("Missing or invalid scope ID")
    return str(value)


class Central:
    def __init__(self, base, token=None, client_id=None, client_secret=None):
        parsed = urlsplit(base)
        if (parsed.scheme != "https" or not parsed.hostname
                or not re.fullmatch(r"[a-z0-9-]+\.api\.central\.arubanetworks\.com", parsed.hostname)
                or parsed.netloc != parsed.hostname or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment):
            raise ValueError("Use the official regional New Central HTTPS API base URL")
        if not token and not (client_id and client_secret):
            raise ValueError("Set CENTRAL_ACCESS_TOKEN or both CENTRAL_CLIENT_ID and CENTRAL_CLIENT_SECRET")
        self.base = base.rstrip("/")
        self.token = token
        self.client_id = client_id
        self.client_secret = client_secret
        self.expires = float("inf") if token else 0
        self._http = threading.local()
        self._token_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._retry_at = 0.0
        self._next_request_at = 0.0

    def _wait_rate_limit(self):
        # HPE documents 10 requests/s per account across all credentials.
        # Pace this client at 8/s, leaving limited headroom for other consumers.
        while True:
            with self._rate_lock:
                now = time.monotonic()
                delay = max(self._retry_at, self._next_request_at) - now
                if delay <= 0:
                    self._next_request_at = now + 0.125
                    return
            time.sleep(delay)

    def _request(self, request, label):
        if not hasattr(self._http, "opener"):
            self._http.opener = build_opener(NoRedirect())
        for attempt in range(4):
            if request.get_method() == "GET":
                self._wait_rate_limit()
            try:
                with self._http.opener.open(request, timeout=30) as response:
                    return json.load(response)
            except HTTPError as exc:
                if request.get_method() == "GET" and exc.code in (429, 500, 502, 503, 504) and attempt < 3:
                    delay = exc.headers.get("Retry-After", "")
                    if delay.isdigit() and int(delay) > 60:
                        raise RuntimeError(f"{label}: rate-limit delay exceeds retry budget") from None
                    seconds = int(delay) if delay.isdigit() else 2 ** attempt
                    if exc.code == 429:
                        with self._rate_lock:
                            self._retry_at = max(self._retry_at, time.monotonic() + seconds)
                    else:
                        time.sleep(seconds)
                    continue
                raise APIError(label, exc.code) from None

    def _token(self):
        with self._token_lock:
            if time.monotonic() >= self.expires:
                body = urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                                  "client_secret": self.client_secret}).encode()
                result = self._request(Request(TOKEN_URL, data=body, headers={
                    "Content-Type": "application/x-www-form-urlencoded"}), "OAuth")
                self.token = result["access_token"]
                self.expires = time.monotonic() + max(0, int(result["expires_in"]) - 60)
            return self.token

    def show_vlans(self, serial):
        return self.show_vlan_command(serial, "show vlan")

    def list_show_commands(self, serial):
        if not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", serial):
            raise ValueError("Invalid switch serial")
        return self.get("/network-troubleshooting/v1/cx/" + quote(serial, safe="") + "/show-commands")

    def show_vlan_command(self, serial, command, *, diagnostic=False):
        """Only fixed VLAN inspection commands; never retry submission."""
        if command not in {"show vlan", "show dhcp-snooping", "show running-config all", "show running-config", *VLAN_FEATURE_COMMANDS.values(), *VLAN_FEATURE_ALTERNATIVES.values()}:
            raise ValueError("Unsupported VLAN inspection command")
        if not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", serial):
            raise ValueError("Invalid switch serial")
        path = "/network-troubleshooting/v1/cx/" + quote(serial, safe="") + "/showCommands"
        request = Request(self.base + path, data=canonical({"commands": [command]}).encode("utf-8"),
                          headers={"Accept": "application/json", "Content-Type": "application/json",
                                   "Authorization": "Bearer " + self._token()}, method="POST")
        self._wait_rate_limit()
        if not hasattr(self._http, "opener"):
            self._http.opener = build_opener(NoRedirect())
        try:
            with self._http.opener.open(request, timeout=30) as response:
                if response.status != 202:
                    raise APIError("Show VLAN submission", response.status)
                location = response.headers.get("Location")
                payload = response.read()
                if not location and payload:
                    data = json.loads(payload)
                    location = data.get("location") if isinstance(data, dict) else None
        except HTTPError as exc:
            raise APIError("Show VLAN submission", exc.code) from None
        # Never send credentials to a location supplied by an untrusted response.
        task = location.rsplit("/", 1)[-1] if isinstance(location, str) else ""
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", task):
            raise ValueError("Invalid troubleshooting task ID")
        for attempt in range(12):
            result = self.get(path + "/async-operations/" + task)
            if not isinstance(result, dict):
                return {"status": "schema_unresolved", **({"result": result} if diagnostic else {})}
            if result.get("status") == "COMPLETED":
                command_output = extract_command_output(result, command)
                if command_output is not None and re.fullmatch(r"\s*Command ['\"]" + re.escape(command) + r"['\"] not allowed\s*", command_output, re.I):
                    return {"status": "command_not_allowed", **({"result": result} if diagnostic else {})}
                return {"status": "completed", "result": result}
            if result.get("status") == "FAILED":
                return {"status": "command_failed", **({"result": result} if diagnostic else {})}
            if result.get("status") not in ("INITIATED", "RUNNING"):
                return {"status": "schema_unresolved", **({"result": result} if diagnostic else {})}
            if attempt < 11:
                time.sleep(2)
        return {"status": "poll_timeout"}

    def change(self, method, path, params, body=None):
        """Private transport for explicit guarded change adapters; never retry writes."""
        if method not in ("POST", "DELETE") or not path.startswith(ALPHA + "/"):
            raise ValueError("Unsupported configuration operation")
        query = urlencode(params)
        request = Request(self.base + path + ("?" + query if query else ""),
                          data=None if body is None else canonical(body).encode("utf-8"),
                          headers={"Accept": "application/json",
                                   "Content-Type": "application/json",
                                   "Authorization": "Bearer " + self._token()}, method=method)
        self._wait_rate_limit()
        # Write success may have an empty response body. HTTP errors propagate
        # without a retry because the outcome may be uncertain.
        if not hasattr(self._http, "opener"):
            self._http.opener = build_opener(NoRedirect())
        try:
            with self._http.opener.open(request, timeout=30) as response:
                if response.status != 200:
                    raise APIError("Configuration write", response.status)
                response.read()
        except HTTPError as exc:
            raise APIError("Configuration write", exc.code) from None

    def get(self, path, **params):
        query = urlencode(params)
        url = self.base + path + ("?" + query if query else "")
        request = Request(url, headers={"Accept": "application/json",
                                        "Authorization": "Bearer " + self._token()}, method="GET")
        return self._request(request, path)


def detect_region(client, preferred=None):
    """Probe only official EU endpoints; never fall back after permission or transport failures."""
    def probe(base):
        client.base = base
        try:
            rows(client.get(INVENTORY, limit=1), ("items",))
            return True
        except APIError as exc:
            if exc.status != 401:
                raise
            return False

    if preferred:
        preferred = preferred.rstrip("/")
        if probe(preferred):
            return preferred
        if preferred not in EU_REGIONS:
            raise RuntimeError("Configured non-EU region rejected credentials; select the correct region explicitly.")
    matches = [region for region in EU_REGIONS if region != preferred and probe(region)]
    if len(matches) != 1:
        raise RuntimeError("Region detection found no authorized EU region." if not matches
                           else "Multiple EU regions accepted credentials; explicitly configure the intended region.")
    client.base = matches[0]
    return client.base


def inventory_page_total(payload, batch, previous):
    """Retain the first explicit total and reject changing/truncated inventories."""
    if "count" in payload and (type(payload["count"]) is not int or payload["count"] != len(batch)):
        raise ValueError("Inventory page count mismatch")
    if "total" not in payload:
        return previous
    total = payload["total"]
    if type(total) is not int or total < 0 or (previous is not None and total != previous):
        raise ValueError("Inventory pagination total changed or invalid")
    return total


def offset_rows(client, path, keys, *, page_size=100, **params):
    result, seen = [], set()
    offset, total = 0, None
    for _ in range(10000):
        try:
            payload = client.get(path, **params, limit=page_size, offset=offset)
        except APIError as exc:
            raise APIError(f"{path} (limit={page_size}, offset={offset})", exc.status) from None
        batch = rows(payload, keys)
        total = inventory_page_total(payload, batch, total)
        signatures = [canonical(row) for row in batch]
        if len(set(signatures)) != len(signatures) or seen.intersection(signatures):
            raise ValueError("Repeated offset record; pagination cannot be trusted")
        seen.update(signatures)
        result.extend(batch)
        offset += len(batch)
        if total is not None and (offset > total or (not batch and offset != total)):
            raise ValueError("Pagination total mismatch")
        if not batch or offset == total:
            return result
    raise ValueError("Pagination safety limit reached")


def inventory(client):
    result, cursors, records, cursor, total = [], set(), set(), None, None
    for _ in range(10000):
        payload = client.get(INVENTORY, limit=100, **({"next": cursor} if cursor else {}))
        batch = rows(payload, ("items",))
        total = inventory_page_total(payload, batch, total)
        signatures = [canonical(row) for row in batch]
        if len(set(signatures)) != len(signatures) or records.intersection(signatures):
            raise ValueError("Repeated inventory record")
        records.update(signatures)
        result.extend(batch)
        cursor = payload.get("next")
        if total is not None and len(result) > total:
            raise ValueError("Inventory total mismatch")
        if not cursor:
            if total is not None and len(result) != total:
                raise ValueError("Inventory total mismatch")
            return result
        if not batch or not isinstance(cursor, str) or cursor in cursors:
            raise ValueError("Invalid or repeated inventory cursor")
        cursors.add(cursor)
    raise ValueError("Inventory pagination safety limit reached")


class EmptyCommittedLocal(list):
    """Observed empty-object response for committed local VLAN queries."""


class VLANResponseError(RuntimeError):
    """A successful HTTP response whose VLAN schema could not be validated."""


def scoped_vlan_rows(payload, object_type="ANY"):
    """Recognize empty scoped views only when the response explicitly proves zero."""
    if not isinstance(payload, dict):
        raise ValueError("Scoped VLAN response is not an object")
    meta = payload.get("metadata", {})
    if not isinstance(meta, dict):
        raise ValueError("Unexpected scoped VLAN metadata")
    counts = meta.get("count_objects_in_module", {})
    if not isinstance(counts, dict):
        raise ValueError("Unexpected scoped VLAN object counts")
    expected = counts.get(object_type)
    if expected is not None and (type(expected) is not int or expected < 0):
        raise ValueError("Invalid scoped VLAN object count")
    if isinstance(payload.get("l2-vlan"), list):
        batch = rows(payload, ("l2-vlan",))
        if "total" in meta and (type(meta["total"]) is not int or meta["total"] != len(batch)):
            raise ValueError("Incomplete scoped VLAN response")
        if not batch and expected is not None and expected > 0:
            raise ValueError("Empty scoped VLAN list contradicts positive object count")
        return batch
    # Some scoped responses omit the module when no objects are present.
    # Require explicit zero for the requested view, no unexpected response
    # fields, and no conflicting pagination total. Never infer zero from {}.
    if (payload.get("l2-vlan") is None and set(payload) <= {"metadata", "l2-vlan"}
            and type(expected) is int and expected == 0
            and ("total" not in meta or (type(meta["total"]) is int and meta["total"] == 0))):
        return []
    safe_counts = {k: counts[k] for k in ("LOCAL", "SHARED", "ANY")
                   if type(counts.get(k)) is int}
    shape = {"module_present": "l2-vlan" in payload,
             "module_type": type(payload.get("l2-vlan")).__name__,
             "metadata_present": "metadata" in payload,
             "counts": safe_counts,
             "other_top_level_fields": len(set(payload) - {"metadata", "l2-vlan"})}
    raise ValueError(f"Unrecognized scoped VLAN envelope: {canonical(shape)}")


def vlan_rows(client, **params):
    """Retrieve full VLAN views and independently check the Library total."""
    try:
        if params.get("view-type") != "LIBRARY":
            payload = client.get(VLAN, **params)
            if (payload == {} and params.get("view-type") == "LOCAL"
                    and params.get("object-type") == "LOCAL"
                    and params.get("effective") == "false"):
                return EmptyCommittedLocal()
            return scoped_vlan_rows(payload, params.get("object-type", "ANY"))

        # The live unpaginated Library view returned all 29 profiles.
        # Cross-check against the independently reported paginated total and
        # first-page contents; do not depend on undocumented terminal offsets.
        first = client.get(VLAN, **params, limit=10, offset=0)
        metadata = first.get("metadata") if isinstance(first, dict) else None
        if not isinstance(metadata, dict):
            raise ValueError("Missing VLAN Library pagination metadata")
        total = metadata.get("total")
        count = metadata.get("count")
        if (type(total) is not int or type(count) is not int
                or not 0 <= count <= min(total, 10)):
            raise ValueError("Invalid VLAN Library total or count")
        page = rows(first, ("l2-vlan",))
        if len(page) != count or count != min(total, 10):
            raise ValueError("Inconsistent first VLAN Library page count")
        full = rows(client.get(VLAN, **params), ("l2-vlan",))
        if len(full) != total:
            raise ValueError(f"VLAN Library count mismatch: expected {total}, received {len(full)}")
        full_counts = Counter(canonical(item) for item in full)
        page_counts = Counter(canonical(item) for item in page)
        if page_counts - full_counts:
            raise ValueError("VLAN Library first page differs from full response")
        return full
    except APIError as exc:
        safe = {k: v for k, v in params.items() if k != "scope-id"}
        raise RuntimeError(f"{exc}; VLAN query: {canonical(safe)}") from None
    except ValueError as exc:
        safe = {k: v for k, v in params.items() if k != "scope-id"}
        raise VLANResponseError(f"{exc}; VLAN query: {canonical(safe)}") from None


def check_empty_local(annotated):
    """Cross-check observed empty local response against effective annotations."""
    if not annotated:
        return "no_effective_profiles"
    uncertain = False
    for profile in annotated:
        annotation = profile.get("@")
        if not isinstance(annotation, dict):
            uncertain = True
            continue
        inherited = annotation.get("aruba-annotation:inherited")
        object_type = annotation.get("aruba-annotation:object_type")
        if inherited is True:
            continue
        if inherited is False and isinstance(object_type, str) and object_type.upper() == "SHARED":
            continue
        if inherited is False and isinstance(object_type, str) and object_type.upper() == "LOCAL":
            return "contradictory_local_profile"
        uncertain = True
    return "unverified_annotations" if uncertain else "consistent_with_effective_annotations"


def discover_scopes(client, persona, devices):
    global_row = client.get(CONFIG + "/global")
    scopes = [{"id": scope_id(global_row), "kind": "global", "name": "Global"}]
    for kind, path, keys in (
        ("collection", "site-collections", ("items", "siteCollections", "site-collections")),
        ("site", "sites", ("items", "sites")),
        ("group", "device-groups", ("items", "deviceGroups", "device-groups")),
    ):
        for row in offset_rows(client, CONFIG + "/" + path, keys):
            scopes.append({"id": scope_id(row), "kind": kind, "name": row.get("scopeName", ""),
                           "metadata": row})
    excluded = []
    for device in devices:
        function = device_identity(device)["persona"]
        if function != persona:
            excluded.append(device)
            continue
        scopes.append({"id": scope_id(device), "kind": "device", "name": device.get("deviceName", ""),
                       "metadata": device})
    if len({s["id"] for s in scopes}) != len(scopes):
        raise ValueError("Duplicate scope IDs; stack or hierarchy semantics require validation")
    if not any(s["kind"] == "device" for s in scopes):
        raise ValueError("No devices matched the selected persona; check inventory and configuration authority")
    return scopes, excluded


def scan(client, persona, devices=None):
    if devices is None:
        devices = inventory(client)
    scopes, excluded = discover_scopes(client, persona, devices)
    device_count = sum(s["kind"] == "device" for s in scopes)
    print(f"Discovered {len(scopes)} scopes ({device_count} matching devices); reading VLAN Library", flush=True)
    library = vlan_rows(client, **{"view-type": "LIBRARY", "detailed": "false"})
    print(f"Library VLAN profiles: {len(library)}; reading shared assignments", flush=True)
    assignments = client.get(ALPHA + "/config-assignments")
    assignment_count = len(rows(assignments, ("config-assignment",)))
    print(f"Shared assignments: {assignment_count}", flush=True)
    failures = []
    for index, scope in enumerate(scopes, 1):
        label = f"VLAN scope {index}/{len(scopes)} ({scope['kind']})"
        print(f"Reading {label}", flush=True)
        params = {"view-type": "LOCAL", "scope-id": scope["id"], "device-function": persona}
        for view, query in (
            ("local", {"object-type": "LOCAL", "effective": "false", "detailed": "false"}),
            ("effective", {"effective": "true", "detailed": "false"}),
            ("annotated", {"effective": "true", "detailed": "true"}),
        ):
            try:
                scope[view] = vlan_rows(client, **params, **query)
                print(f"  {view}: {len(scope[view])} profiles", flush=True)
                if isinstance(scope[view], EmptyCommittedLocal):
                    scope["local_response_format"] = "empty_object"
            except VLANResponseError as exc:
                # Collect all schema mismatches in one scan, but never write a
                # partial snapshot. HTTP/transport errors still stop immediately.
                failures.append(f"{label} {view}: {exc}")
                print(f"  {view}: SCHEMA ERROR: {exc}", flush=True)
        if scope.get("local_response_format") == "empty_object" and "annotated" in scope:
            status = check_empty_local(scope["annotated"])
            scope["local_response_validation"] = status
            print(f"  empty local response: {status}", flush=True)
            if status == "contradictory_local_profile":
                failures.append(f"{label}: empty committed local conflicts with annotations")
    if failures:
        raise RuntimeError(f"{len(failures)} VLAN views could not be validated; no snapshot written.")
    return {"schema": 1, "captured_at": datetime.now(timezone.utc).isoformat(),
            "region": client.base, "persona": persona, "library": library,
            "assignments_raw": assignments, "scopes": scopes, "excluded_devices": excluded}


def vlan_map(profiles):
    result = {}
    for profile in profiles:
        vid = profile.get("vlan")
        if isinstance(vid, bool) or not isinstance(vid, (str, int)) or not str(vid).isdigit() or not 1 <= int(vid) <= 4094:
            raise ValueError("Unexpected VLAN identity")
        key = str(int(vid))
        if key in result:
            raise ValueError("Duplicate VLAN ID in a view; cannot establish unique effective configuration")
        result[key] = profile
    return result


MISSING = object()
# Only these known schema field names may appear in the shareable summary.
PUBLIC_VLAN_FIELDS = {"vlan", "name", "enable", "is-l3-vlan", "voice-enable",
                      "igmp", "mld", "snooping", "dhcpv4-snooping", "dhcpv6-snooping",
                      "description", "@"}


def field_differences(left, right, path=()):
    """Exact structured diff. Missing, null, false and zero remain distinct."""
    if isinstance(left, dict) and isinstance(right, dict):
        result = []
        for key in sorted(left.keys() | right.keys()):
            result.extend(field_differences(left.get(key, MISSING), right.get(key, MISSING),
                                            path + (key,)))
        return result
    if left is not MISSING and right is not MISSING and canonical(left) == canonical(right):
        return []
    if left is MISSING:
        kind = "missing_local"
    elif right is MISSING:
        kind = "missing_reference"
    elif left is None or right is None:
        kind = "null_vs_value"
    elif type(left) is not type(right):
        kind = "type_difference"
    else:
        kind = "value_difference"
    result = {"path": list(path), "kind": kind,
              "local_type": "missing" if left is MISSING else type(left).__name__,
              "reference_type": "missing" if right is MISSING else type(right).__name__}
    if left is not MISSING:
        result["local_value"] = left
    if right is not MISSING:
        result["reference_value"] = right
    return [result]


def safe_difference_path(path):
    return ".".join(part if part in PUBLIC_VLAN_FIELDS else "[other-field]" for part in path) or "[root]"


# Documented New Central VLAN profile defaults. These are review hints,
# not proof of identical deployment on a particular model or firmware.
# https://developer.arubanetworks.com/new-central-config/reference/replacelayer2vlanl2vlanbyid
# https://arubanetworking.hpe.com/techdocs/new-central/content/cfg/profiles/vlan-prof.htm
VLAN_DEFAULT_HINTS = {
    ("enable",): True,
    ("voice-enable",): False,
    ("dhcpv4-snooping",): {"enable": False},
    ("dhcpv6-snooping",): {"enable": False},
    ("dhcpv4-snooping", "enable"): False,
    ("dhcpv6-snooping", "enable"): False,
}


def classify_vlan_difference(diff, left, right):
    """Classify evidence without silently substituting values in either profile."""
    path = tuple(diff["path"])
    kind = diff["kind"]
    if path == ("is-l3-vlan",):
        # GET-only field. Null is not assumed false; verify the SVI separately.
        return "verify_l3_state"
    if kind in ("missing_local", "missing_reference"):
        value = diff.get("reference_value") if kind == "missing_local" else diff.get("local_value")
        if path in VLAN_DEFAULT_HINTS and canonical(value) == canonical(VLAN_DEFAULT_HINTS[path]):
            if path == ("voice-enable",) and ("voice-enable-alias" in left or "voice-enable-alias" in right):
                return "unresolved_alias"
            return "documented_default_candidate"
        if path and path[0] in ("igmp", "mld"):
            return "verify_multicast_default"
        return "unresolved_omission"
    return "explicit_difference"


def assess_vlan_reference(left, right):
    if right is None:
        return {"classification": "no_reference_profile", "differences": []}
    differences = field_differences(left, right)
    classified = [{**d, "assessment": classify_vlan_difference(d, left, right)} for d in differences]
    kinds = {d["assessment"] for d in classified}
    if not kinds:
        status = "exact_match"
    elif "explicit_difference" in kinds:
        status = "explicit_difference"
    elif kinds == {"documented_default_candidate"}:
        status = "documented_defaults_only"
    else:
        status = "requires_validation"
    return {"classification": status, "differences": classified}


def review_local_profiles(scopes, baseline, library):
    """Review each local definition, including singletons, without proposing writes."""
    device_maps = {s["id"]: vlan_map(s["effective"]) for s in scopes if s["kind"] == "device"}
    results = []
    for scope in scopes:
        effective = vlan_map(scope["effective"])
        annotated = vlan_map(scope.get("annotated", []))
        for vid, body in sorted(vlan_map(scope["local"]).items(), key=lambda pair: int(pair[0])):
            signature = canonical(body)
            global_match = vid in baseline and canonical(baseline[vid]) == signature
            library_state = ("identical" if vid in library and canonical(library[vid]) == signature
                             else "conflict" if vid in library else "absent")
            matching, differing, missing = [], [], []
            for device_id, config in device_maps.items():
                if vid not in config:
                    missing.append(device_id)
                elif canonical(config[vid]) == signature:
                    matching.append(device_id)
                else:
                    differing.append(device_id)
            annotation = annotated.get(vid, {}).get("@", {})
            if not isinstance(annotation, dict):
                annotation = {}
            same_effective = vid in effective and canonical(effective[vid]) == signature
            if annotation.get("aruba-annotation:is_default") is True:
                recommendation = "retain_default"
            elif not same_effective:
                recommendation = "inspect_local_effective_difference"
            elif scope["kind"] != "global" and global_match:
                recommendation = "review_restore_global_inheritance"
            elif library_state == "conflict":
                recommendation = "resolve_library_conflict"
            elif library_state == "identical":
                recommendation = "review_reuse_library_profile"
            else:
                recommendation = "review_create_library_profile"
            global_assessment = assess_vlan_reference(body, baseline.get(vid))
            library_assessment = assess_vlan_reference(body, library.get(vid))
            # Prefer existing Global coverage; do not promote a VLAN to Global merely
            # because it exists in the Library. All outputs remain review-only.
            if recommendation == "retain_default":
                proposed_review = "retain_default"
            elif not same_effective:
                proposed_review = "inspect_local_effective_difference"
            elif scope["kind"] != "global" and global_assessment["classification"] in ("exact_match", "documented_defaults_only"):
                proposed_review = "review_restore_global_inheritance"
            elif scope["kind"] != "global" and vid in baseline and global_assessment["classification"] == "requires_validation":
                proposed_review = "validate_global_inheritance_candidate"
            elif vid in baseline and global_assessment["classification"] == "explicit_difference":
                proposed_review = "review_intentional_global_exception"
            elif library_assessment["classification"] in ("exact_match", "documented_defaults_only"):
                proposed_review = "review_library_reuse_at_existing_scope"
            elif library_assessment["classification"] == "requires_validation":
                proposed_review = "validate_library_reuse_at_existing_scope"
            elif library_assessment["classification"] == "explicit_difference":
                proposed_review = "review_library_conflict"
            else:
                proposed_review = "review_library_creation_at_existing_scope"
            results.append({
                "scope": scope["id"], "scope_kind": scope["kind"], "scope_name": scope["name"],
                "vlan": vid, "profile": body, "library_state": library_state,
                "matches_global": global_match, "matches_scope_effective": same_effective,
                "matching_devices": matching, "different_devices": differing,
                "missing_devices": missing,
                "global_coverage": ("all_scanned_devices_match" if device_maps and len(matching) == len(device_maps)
                                    else "not_all_scanned_devices_match"),
                "annotations": annotation,
                "library_differences": field_differences(body, library[vid]) if vid in library else None,
                "global_differences": field_differences(body, baseline[vid]) if vid in baseline else None,
                "effective_differences": field_differences(body, effective[vid]) if vid in effective else None,
                "global_assessment": global_assessment,
                "library_assessment": library_assessment,
                "proposed_review": proposed_review,
                "recommendation": recommendation, "status": "review_only"
            })
    return results


# Version-specific rules are evidence, not blanket support claims.
# Each entry is restricted to documented model families and release trains.
MULTICAST_RULES = (
    {"models": ("6000", "6100"), "release": (10, 16),
     "igmp": True, "mld": True,
     "source": "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.16/PDF/cli_6000-6100.pdf"},
)


def device_identity(item):
    def first(*keys):
        return next((str(item[k]).strip() for k in keys if item.get(k)), "")
    persona = first("deviceFunction", "device-function", "persona").upper().replace(" ", "_")
    persona = {"AGGREGATION_SWITCH": "AGG_SWITCH", "CAMPUS_ACCESS_POINT": "CAMPUS_AP",
               "MOBILITY_GATEWAY": "MOBILITY_GW", "BRANCH_GATEWAY": "BRANCH_GW",
               "MICROBRANCH_ACCESS_POINT": "MICROBRANCH_AP", "HYBRID_NETWORK_ACCESS_CONTROL": "HYBRID_NAC"}.get(persona, persona)
    model = first("model", "modelName", "deviceModel")
    firmware = first("firmwareVersion", "softwareVersion", "firmware")
    match = re.fullmatch(r"(?:[A-Z]+\.)?(\d+)\.(\d+)(?:\.\d+)*(?:[-+][A-Za-z0-9.]+)?", firmware, re.IGNORECASE)
    release = tuple(map(int, match.groups())) if match else None
    return {"persona": persona or "UNKNOWN", "model": model or "UNKNOWN",
            "firmware": firmware or "UNKNOWN", "release": release}


def multicast_defaults(identity):
    for rule in MULTICAST_RULES:
        if (identity["persona"] in PERSONAS and identity["model"].lower() in rule["models"]
                and identity["release"] == rule["release"]):
            return {"status": "documented_release_default", "igmp": rule["igmp"],
                    "mld": rule["mld"], "source": rule["source"]}
    return {"status": "unknown"}


def inventory_capabilities(devices):
    """Keep every inventory entry, including unknown functions and non-switches."""
    records = []
    for item in devices:
        identity = device_identity(item)
        records.append({"inventory": item, "identity": identity,
                        "vlan_scan_supported_persona": identity["persona"] in PERSONAS,
                        "multicast_defaults": multicast_defaults(identity)})
    return records


def print_inventory_summary(records):
    print("Discovered device functions (inventory entries):")
    for (persona, supported), count in sorted(Counter(
            (r["identity"]["persona"], r["vlan_scan_supported_persona"]) for r in records).items()):
        # Unknown raw persona values may be customer-defined; do not print them.
        label = persona if persona in PERSONAS | {"CAMPUS_AP", "MICROBRANCH_AP",
                    "MOBILITY_GW", "BRANCH_GW", "BRIDGE", "HYBRID_NAC", "UNKNOWN"} else "OTHER"
        print(f"  {label}: {count}; VLAN scan adapter={'available' if supported else 'not qualified'}")
    print("Documented multicast defaults:", sum(r["multicast_defaults"]["status"] != "unknown" for r in records))


def scan_all(client):
    """Automatically select all qualified switch personas, preserving separate scope views."""
    devices = inventory(client)
    records = inventory_capabilities(devices)
    print_inventory_summary(records)
    personas = sorted({r["identity"]["persona"] for r in records if r["vlan_scan_supported_persona"]})
    if not personas:
        raise ValueError("No qualified switch persona discovered")
    snapshots = {}
    for persona in personas:
        print(f"Scanning persona: {persona}", flush=True)
        snapshots[persona] = scan(client, persona, devices)
    return {"schema": 1, "kind": "multi_persona_scan", "region": client.base,
            "inventory": records, "snapshots": snapshots}


DEPENDENCY_MODULES = ("vlan-interfaces", "mgmd-global", "ethernet-interfaces", "sw-port-profiles",
                      "interface-profiles", "roles", "portchannels")


def probe_operational_vlans(client, metadata):
    """Try discovered stack/conductor/serial identities; retain safe failure evidence."""
    candidates = []
    for key in ("stackId", "stackID", "conductorSerialNumber", "conductorSerial",
                "serialNumber", "serial"):
        serial = metadata.get(key)
        if (isinstance(serial, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,16}", serial)
                and serial not in {value for _, value in candidates}):
            candidates.append((key, serial))
    if not candidates:
        return {"status": "identity_unresolved"}
    attempts = []
    for key, serial in candidates:
        path = "/network-monitoring/v1/switches/" + quote(serial, safe="") + "/vlans"
        try:
            payload = client.get(path, limit=1000, offset=0)
        except APIError as exc:
            if exc.status not in (400, 403, 404, 405, 422):
                # Do not print a URL containing the inventory identifier.
                raise RuntimeError(f"Operational VLAN monitoring: HTTP {exc.status}") from None
            attempts.append({"identity_field": key, "http_error": exc.status})
            if exc.status == 403:
                return {"status": "permission_denied", "http_error": 403, "attempts": attempts}
            if exc.status not in (400, 404, 422):
                break
        else:
            return {"status": "response_received" if isinstance(payload, dict) else "schema_unresolved",
                    "payload": payload, "identity_field": key, "attempts": attempts}
    return {"status": "request_rejected", "http_error": attempts[-1]["http_error"],
            "attempts": attempts}


# Explicit reference-shaped fields, not arbitrary integers or VLAN names.
# This is a candidate index, never proof that every reference was discovered.
VLAN_REFERENCE_FIELDS = {"vlan", "vlan-id", "access-vlan", "native-vlan", "allowed-vlans",
                         "trusted-vlans", "tagged-vlans", "untagged-vlans",
                         "primary-vlan", "secondary-vlan", "voice-vlan", "access-vlan-id"}
VLAN_LIST_FIELDS = {"allowed-vlans", "trusted-vlans", "tagged-vlans", "untagged-vlans"}


def parse_reference_ids(value, allow_list=False):
    """Parse explicit IDs/ranges; wildcard and unknown expressions remain unresolved."""
    if type(value) is int:
        return {str(value)} if 1 <= value <= 4094 else None
    if isinstance(value, list):
        if not allow_list or not value:
            return None
        ids = set()
        for item in value:
            found = parse_reference_ids(item, True)
            if found is None:
                return None
            ids.update(found)
        return ids
    if not isinstance(value, str):
        return None
    result = set()
    parts = value.split(",") if allow_list else [value]
    for part in parts:
        match = re.fullmatch(r"\s*(\d{1,4})(?:\s*-\s*(\d{1,4}))?\s*", part)
        if not match or (match.group(2) and not allow_list):
            return None
        low = int(match.group(1))
        high = int(match.group(2) or low)
        if not 1 <= low <= high <= 4094:
            return None
        result.update(str(i) for i in range(low, high + 1))
    return result


def reference_candidates(payload, effective=None):
    """Index candidate VLAN references and unresolved VLAN-shaped paths privately."""
    references, unresolved = [], []
    names = defaultdict(set)
    for vid, profile in (effective or {}).items():
        if isinstance(profile.get("name"), str):
            names[profile["name"]].add(vid)
    def visit(value, path):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("@", "metadata"):
                    continue
                current = path + [key]
                if key == "access-vlan-name":
                    ids = names.get(item, set()) if isinstance(item, str) else set()
                    if len(ids) == 1:
                        references.append({"path": current, "vlan_ids": sorted(ids, key=int),
                                           "resolution": "effective_vlan_name"})
                    else:
                        unresolved.append(current)
                elif key == "vlan-type" and item in ("VLAN_ID", "VLAN_NAME"):
                    continue
                elif key == "vlan-parameters" and isinstance(item, dict):
                    visit(item, current)
                elif key in VLAN_REFERENCE_FIELDS:
                    ids = parse_reference_ids(item, key in VLAN_LIST_FIELDS)
                    if ids is not None:
                        references.append({"path": current, "vlan_ids": sorted(ids, key=int)})
                    else:
                        unresolved.append(current)
                        # Nested VLAN objects may themselves contain explicit IDs.
                        if isinstance(item, (dict, list)):
                            visit(item, current)
                else:
                    if "vlan" in key.lower() and isinstance(item, (str, int, list, dict)) and type(item) is not bool:
                        unresolved.append(current)
                    visit(item, current)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, path + [index])
    visit(payload, [])
    return {"references": references, "unresolved_paths": unresolved}


def operational_vlan_summary(evidence, effective=None):
    """Report observed response structure, without inferring unsupported state fields."""
    if not isinstance(evidence, dict) or evidence.get("status") != "response_received":
        result = {"status": evidence.get("status", "not_collected") if isinstance(evidence, dict) else "not_collected"}
        if isinstance(evidence, dict):
            result.update({k: evidence[k] for k in ("http_error", "attempts") if k in evidence})
        return result
    payload = evidence.get("payload")
    if not isinstance(payload, dict):
        return {"status": "schema_unresolved"}
    lists = [v for k, v in payload.items() if k != "metadata" and isinstance(v, list)]
    if len(lists) != 1 or not all(isinstance(item, dict) for item in lists[0]):
        return {"status": "schema_unresolved"}
    items = lists[0]
    result = {"status": "schema_observed", "rows": len(items),
              "fields": sorted({k for item in items for k in item}),
              "may_be_truncated": len(items) >= 1000,
              "identity_field": evidence.get("identity_field"), "attempts": evidence.get("attempts", [])}
    if effective is None:
        return result
    observed = {}
    for item in items:
        ids = parse_reference_ids(item.get("id"))
        if not ids or next(iter(ids)) in observed:
            result["comparison"] = "identity_unresolved"
            return result
        observed[next(iter(ids))] = item
    result["comparison"] = "observed_ids_compared"
    result["missing_ids"] = sorted(set(effective) - set(observed), key=int)
    result["additional_ids"] = sorted(set(observed) - set(effective), key=int)
    result["name_mismatches"] = sorted((vid for vid in effective.keys() & observed.keys()
        if isinstance(effective[vid].get("name"), str) and isinstance(observed[vid].get("name"), str)
        and effective[vid]["name"] != observed[vid]["name"]), key=int)
    result["names_not_comparable"] = sorted((vid for vid in effective.keys() & observed.keys()
        if not isinstance(effective[vid].get("name"), str) or not isinstance(observed[vid].get("name"), str)), key=int)
    result["multicast_operational_verified"] = False
    return result



def discover_dependencies(client, snapshot):
    """Probe applicable read-only module endpoints; record empty/error separately."""
    devices = []
    for index, scope in enumerate((s for s in snapshot["scopes"] if s["kind"] == "device"), 1):
        identity = device_identity(scope.get("metadata", {}))
        params = {"view-type": "LOCAL", "scope-id": scope["id"],
                  "device-function": snapshot["persona"], "effective": "true", "detailed": "true"}
        modules, capabilities = {}, {}
        for module in DEPENDENCY_MODULES:
            try:
                payload = client.get(ALPHA + "/" + module, **params)
            except APIError as exc:
                if exc.status not in (400, 403, 404, 405, 422):
                    raise
                modules[module] = {"http_error": exc.status}
                capabilities[module] = "permission_denied" if exc.status == 403 else "request_rejected"
            else:
                modules[module] = payload
                if payload == {}:
                    capabilities[module] = "empty_response"
                elif isinstance(payload, dict):
                    capabilities[module] = "response_received"
                else:
                    capabilities[module] = "schema_unresolved"
            print(f"  Device {index}: {module}: {capabilities[module]}", flush=True)
        operational = probe_operational_vlans(client, scope.get("metadata", {}))
        print(f"  Device {index}: operational VLANs: {operational['status']}", flush=True)
        devices.append({"scope_id": scope["id"], "identity": identity, "modules": modules,
                        "capabilities": capabilities, "operational_vlans": operational})
    return {"region": snapshot["region"], "persona": snapshot["persona"], "devices": devices,
            "captured_at": datetime.now(timezone.utc).isoformat()}


def dependency_items(modules, module):
    """Require a successful unambiguous list envelope; empty objects are not lists."""
    payload = modules.get(module)
    if not isinstance(payload, dict) or "http_error" in payload:
        raise ValueError("Dependency module missing or failed")
    lists = [value for key, value in payload.items()
             if key != "metadata" and isinstance(value, list)]
    if len(lists) != 1 or not all(isinstance(item, dict) for item in lists[0]):
        raise ValueError("Unrecognized dependency list envelope")
    return lists[0]


def svi_vlan_id(item):
    """Recognize only explicit SVI identifiers; do not infer from IPs or port names."""
    identifiers = set()
    for key in ("id", "vlan", "vlan-id"):
        if key not in item:
            continue
        value = item[key]
        if type(value) not in (int, str):
            raise ValueError("Invalid SVI identity")
        match = re.fullmatch(r"(?:vlan\s*)?([0-9]+)", str(value), re.IGNORECASE)
        if not match or not 1 <= int(match.group(1)) <= 4094:
            raise ValueError("Unrecognized SVI identity")
        identifiers.add(str(int(match.group(1))))
    if len(identifiers) != 1:
        raise ValueError("Missing or conflicting SVI identity")
    return identifiers.pop()


def dependency_review(snapshot, dependencies, data):
    """Join existing read-only snapshots; this is a review, not a migration plan."""
    if (dependencies.get("region") != snapshot["region"]
            or dependencies.get("persona") != snapshot["persona"]):
        raise ValueError("Dependency snapshot region or persona mismatch")
    devices = [scope for scope in snapshot["scopes"] if scope["kind"] == "device"]
    entries = dependencies["devices"]
    by_id = {entry["scope_id"]: entry["modules"] for entry in entries}
    if len(by_id) != len(entries) or set(by_id) != {scope["id"] for scope in devices}:
        raise ValueError("Dependency snapshot device coverage mismatch")
    operational_by_id = {entry["scope_id"]: entry.get("operational_vlans") for entry in entries}
    device_reviews = []
    protected = {}
    known_default = {}
    for scope in devices:
        sid = scope["id"]
        modules = by_id[sid]
        inventory = scope.get("metadata", {})
        identity = device_identity(inventory)
        model, firmware = identity["model"], identity["firmware"]
        # Older snapshots/tests may omit persona in device metadata.
        if identity["persona"] == "UNKNOWN":
            identity["persona"] = snapshot["persona"]
        known_default[sid] = multicast_defaults(identity)
        indicators = {vid for vid, profile in vlan_map(scope["effective"]).items()
                      if profile.get("is-l3-vlan") is True}
        svi_ids = set()
        issues = []
        counts = {}
        shapes = {}
        for module in ("vlan-interfaces", "ethernet-interfaces", "sw-port-profiles"):
            try:
                items = dependency_items(modules, module)
                counts[module] = len(items)
                # Keep schema paths only in the private output; no values in terminal.
                shapes[module] = sorted({key for item in items for key in item if key != "@"})
                if module == "vlan-interfaces":
                    svi_ids = {svi_vlan_id(item) for item in items}
                    if len(svi_ids) != len(items):
                        raise ValueError("Duplicate SVI identity")
            except ValueError:
                issues.append(module + "_unresolved")
        protected[sid] = indicators | svi_ids
        if indicators != svi_ids:
            issues.append("svi_indicator_mismatch")
        multicast = modules.get("mgmd-global")
        if multicast == {}:
            multicast_state = "empty_configuration_not_operational_state"
        elif isinstance(multicast, dict) and "http_error" not in multicast:
            multicast_state = "configuration_present_not_operational_state"
        else:
            multicast_state = "unresolved"
            issues.append("mgmd-global_unresolved")
        effective_map = vlan_map(scope["effective"])
        candidate_map = {}
        for module in ("ethernet-interfaces", "sw-port-profiles", "interface-profiles", "roles", "portchannels"):
            payload = modules.get(module)
            if isinstance(payload, dict) and payload and "http_error" not in payload:
                candidate_map[module] = reference_candidates(payload, effective_map)
        operational = operational_vlan_summary(operational_by_id.get(sid), effective_map)
        device_reviews.append({"scope": sid, "model": model, "firmware": firmware,
                               "reference_candidates": candidate_map, "operational_vlan_summary": operational,
                               "counts": counts, "module_fields": shapes,
                               "identity": identity, "multicast_defaults": known_default[sid],
                               "protected_vlan_ids": sorted(protected[sid], key=int),
                               "svi_ids": sorted(svi_ids, key=int),
                               "svi_indicators": sorted(indicators, key=int),
                               "multicast_state": multicast_state, "issues": issues})
    for row in data["local_profile_review"]:
        sid, vid = row["scope"], row["vlan"]
        blockers = []
        if row["proposed_review"] == "retain_default":
            blockers.append("default_profile")
        if sid not in protected:
            blockers.append("non_device_scope_dependency_coverage_unverified")
        else:
            if vid in protected[sid]:
                blockers.append("preserve_svi")
            if any(d["issues"] for d in device_reviews if d["scope"] == sid):
                blockers.append("dependency_schema_or_identity_unresolved")
        reference = row["global_assessment"]
        if reference["classification"] == "no_reference_profile":
            reference = row["library_assessment"]
        for difference in reference["differences"]:
            path = tuple(difference["path"])
            if difference["assessment"] == "verify_multicast_default":
                value = difference.get("reference_value")
                if (path and known_default.get(sid, {}).get(path[0]) is True and difference["kind"] == "missing_local"
                        and ((path in (("igmp",), ("mld",)) and value == {"snooping": False})
                             or (path in (("igmp", "snooping"), ("mld", "snooping")) and value is False))):
                    blockers.append("potential_aoscx_10_16_multicast_behavior_change")
                else:
                    blockers.append("multicast_operational_state_unverified")
            elif difference["assessment"] not in ("documented_default_candidate",):
                blockers.append(difference["assessment"])
        # A port-profile or Ethernet list is evidence of retrieval, not a complete
        # reference graph (LAGs, NAC and role-based VLAN assignments may also matter).
        blockers.append("full_vlan_reference_graph_unverified")
        blockers.append("operational_equivalence_unverified")
        device_evidence = next((d for d in device_reviews if d["scope"] == sid), {})
        row["reference_candidate_modules"] = sorted(module for module, evidence in
            device_evidence.get("reference_candidates", {}).items()
            if any(vid in ref["vlan_ids"] for ref in evidence["references"]))
        row["dependency_blockers"] = sorted(set(blockers))
        row["migration_eligible"] = False
    data["dependency_review"] = {"devices": device_reviews, "safe_to_apply": False,
                                 "operational_state_verified": False}
    return data


def print_dependency_summary(data):
    review = data["dependency_review"]
    print("Dependency review (read-only):")
    for index, device in enumerate(review["devices"], 1):
        print(f"  Device {index}: SVI identities={len(device['svi_ids'])}, "
              f"L3 indicators={len(device['svi_indicators'])}, "
              f"protected VLANs={len(device['protected_vlan_ids'])}")
        for module, evidence in sorted(device.get("reference_candidates", {}).items()):
            print(f"    {module}: reference fields={len(evidence['references'])}, "
                  f"unresolved paths={len(evidence['unresolved_paths'])}")
        operational = device.get("operational_vlan_summary", {})
        print(f"    operational VLANs: {operational.get('status', 'not_collected')}")
        if "http_error" in operational:
            print(f"    monitoring HTTP status={operational['http_error']}")
        if operational.get("comparison") == "observed_ids_compared":
            print(f"    observed VLAN ID comparison: missing={len(operational['missing_ids'])}, "
                  f"additional={len(operational['additional_ids'])}, "
                  f"name differences={len(operational['name_mismatches'])}, "
                  f"names not comparable={len(operational['names_not_comparable'])}")
        if "rows" in operational:
            print(f"    monitoring rows={operational['rows']}; possible truncation={operational['may_be_truncated']}")
            # Only print known, non-identifying schema field names.
            known = {"id", "vlanId", "vlan", "name", "status", "type", "voice", "igmp", "mld",
                     "isIgmpEnabled", "is_igmp_enabled", "taggedPorts", "untaggedPorts",
                     "accessPorts", "nativeVlan", "ipv4", "ipv6"}
            print("    known monitoring fields:", ", ".join(k for k in operational["fields"] if k in known))
        for issue in device["issues"]:
            print(f"    {issue}")
    print("Migration blockers (profile counts):")
    counts = Counter(reason for row in data["local_profile_review"] for reason in row["dependency_blockers"])
    for reason, count in sorted(counts.items()):
        print(f"  {reason}: {count}")
    print("Migration eligible: 0")


def print_review_summary(data):
    """Print only aggregate counts and ordinal device labels, no customer identifiers."""
    candidates = data["local_profile_review"]
    print("Local profile review (read-only):")
    for name, count in sorted(Counter(row["recommendation"] for row in candidates).items()):
        print(f"  {name}: {count}")
    for reference in ("library", "global", "effective"):
        field_counts = Counter()
        kind_counts = Counter()
        for candidate in candidates:
            differences = candidate.get(reference + "_differences")
            if differences is None:
                kind_counts["no_reference_profile"] += 1
                continue
            if not differences:
                kind_counts["exact_match"] += 1
                continue
            kinds = {d["kind"] for d in differences}
            category = ("includes_value_or_type_difference"
                        if kinds & {"value_difference", "type_difference", "null_vs_value"}
                        else "missing_fields_only")
            kind_counts[category] += 1
            for d in differences:
                field_counts[(safe_difference_path(d["path"]), d["kind"],
                              d["local_type"], d["reference_type"])] += 1
        print(f"Local vs {reference} (profiles):")
        for kind, count in sorted(kind_counts.items()):
            print(f"  {kind}: {count}")
        if field_counts:
            print("  Difference fields (counts, no values):")
            for (path, kind, local_type, ref_type), count in sorted(field_counts.items()):
                print(f"    {path}: {kind} ({local_type} vs {ref_type}) x{count}")
    print("Default-aware consolidation review (not an executable plan):")
    for action, count in sorted(Counter(row.get("proposed_review", "unavailable") for row in candidates).items()):
        print(f"  {action}: {count}")
    for reference in ("library", "global"):
        counts = Counter()
        evidence = Counter()
        for row in candidates:
            assessment = row.get(reference + "_assessment")
            if not assessment:
                continue
            counts[assessment["classification"]] += 1
            for diff in assessment["differences"]:
                path = safe_difference_path(diff["path"])
                # Only print booleans for explicitly allowlisted, non-identifying settings.
                safe_paths = {("enable",), ("voice-enable",), ("is-l3-vlan",),
                              ("igmp", "snooping"), ("mld", "snooping"),
                              ("dhcpv4-snooping", "enable"), ("dhcpv6-snooping", "enable")}
                def safe_flag(side):
                    if side + "_value" not in diff:
                        return "omitted"
                    value = diff[side + "_value"]
                    field = tuple(diff["path"])
                    if field in safe_paths and (type(value) is bool or value is None):
                        return str(value).lower()
                    if field in (("igmp",), ("mld",), ("dhcpv4-snooping",), ("dhcpv6-snooping",)) and isinstance(value, dict):
                        key = "snooping" if field[0] in ("igmp", "mld") else "enable"
                        if set(value) == {key} and type(value[key]) is bool:
                            return key + "=" + str(value[key]).lower()
                    return "[redacted]"
                evidence[(path, diff["assessment"], safe_flag("local"), safe_flag("reference"))] += 1
        print(f"Default-aware local vs {reference}:")
        for status, count in sorted(counts.items()):
            print(f"  {status}: {count}")
        for (path, status, local_flag, reference_flag), count in sorted(evidence.items()):
            print(f"    {path}: {status} ({local_flag} vs {reference_flag}) x{count}")
    print("Device deviations from Global:")
    for index, scope in enumerate((s for s in data["scope_comparisons"] if s["kind"] == "device"), 1):
        print(f"  Device {index}: local={len(scope['local_vlan_ids'])}, "
              f"matching-global-local={len(scope['local_matching_global'])}, "
              f"additional={len(scope['additional_vs_global'])}, "
              f"missing={len(scope['missing_vs_global'])}, "
              f"different={len(scope['different_vs_global'])}")
    print(f"Excluded inventory entries: {data['excluded_device_count']}")
    print("No changes are authorized; review full report locally.")


def report(snapshot):
    if snapshot.get("schema") != 1:
        raise ValueError("Unsupported snapshot schema")
    scopes = snapshot["scopes"]
    global_scopes = [s for s in scopes if s["kind"] == "global"]
    if len(global_scopes) != 1 or len({s["id"] for s in scopes}) != len(scopes):
        raise ValueError("Invalid scope inventory")
    baseline = vlan_map(global_scopes[0]["effective"])
    library = vlan_map(snapshot["library"])
    duplicates = defaultdict(list)
    comparisons = []
    for scope in scopes:
        effective = vlan_map(scope["effective"])
        local = vlan_map(scope["local"])
        if scope["kind"] != "global":
            for vid, body in local.items():
                duplicates[(vid, canonical(body))].append({
                    "scope": scope["id"], "kind": scope["kind"], "name": scope["name"],
                    "matches_effective_global": vid in baseline and canonical(body) == canonical(baseline[vid])
                })
        comparisons.append({
            "scope": scope["id"], "kind": scope["kind"], "name": scope["name"],
            "local_vlan_ids": sorted(local, key=int),
            "local_response_format": scope.get("local_response_format", "list_or_explicit_zero"),
            "local_response_validation": scope.get("local_response_validation", "not_required"),
            "additional_vs_global": sorted(effective.keys() - baseline.keys(), key=int),
            "missing_vs_global": sorted(baseline.keys() - effective.keys(), key=int),
            "different_vs_global": sorted((v for v in effective.keys() & baseline.keys()
                                           if canonical(effective[v]) != canonical(baseline[v])), key=int),
            "local_matching_global": sorted((v for v in local.keys() & baseline.keys()
                                            if canonical(local[v]) == canonical(baseline[v])), key=int)
        })
    candidates = []
    for (vid, body), locations in sorted(duplicates.items()):
        if len(locations) < 2:
            continue
        effective_matches, nonmatches = [], []
        for scope in scopes:
            if scope["kind"] != "device":
                continue
            current = vlan_map(scope["effective"]).get(vid)
            (effective_matches if current is not None and canonical(current) == body else nonmatches).append(scope["id"])
        candidates.append({"vlan": vid, "locations": locations,
                           "library_state": "identical" if vid in library and canonical(library[vid]) == body
                           else "conflict" if vid in library else "absent",
                           "matching_scanned_devices": effective_matches,
                           "other_scanned_devices": nonmatches,
                           "status": "review_only"})
    return {"schema": 1, "captured_at": snapshot["captured_at"], "persona": snapshot["persona"],
            "scope_comparisons": comparisons, "duplicate_local_candidates": candidates,
            "local_profile_review": review_local_profiles(scopes, baseline, library),
            "excluded_device_count": len(snapshot["excluded_devices"]),
            "safe_to_apply": False,
            "warning": "Exact equality is not proof of safe inheritance; verify annotations, authority, dependencies and all affected devices."}


def write_private(path, data):
    # Exclusive creation prevents accidental replacement; restrictive mode on POSIX.
    payload = json.dumps(data, indent=2, allow_nan=False) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(payload)


def audit(client):
    """Discover and review every qualified persona in one read-only operation."""
    source = scan_all(client)
    if source.get("kind") != "multi_persona_scan" or source.get("region") != client.base:
        raise ValueError("Expected a multi-persona snapshot from the connected region")
    results = {}
    for persona, snapshot in sorted(source["snapshots"].items()):
        if snapshot.get("persona") != persona or snapshot.get("region") != client.base:
            raise ValueError("Snapshot persona or region mismatch")
        print(f"Discovering dependencies: {persona}", flush=True)
        dependencies = discover_dependencies(client, snapshot)
        review = dependency_review(snapshot, dependencies, report(snapshot))
        print(f"Review: {persona}", flush=True)
        print_review_summary(review)
        print_dependency_summary(review)
        results[persona] = {"snapshot": snapshot, "dependencies": dependencies, "report": review}
    unqualified = Counter(r["identity"]["persona"] for r in source["inventory"]
                          if not r["vlan_scan_supported_persona"])
    print("Audit coverage:")
    print(f"  Inventory entries: {len(source['inventory'])}")
    print(f"  Reviewed switch personas: {len(results)}")
    print(f"  Inventory entries without a qualified configuration adapter: {sum(unqualified.values())}")
    print("  Migration authorized: no")
    return {"schema": 1, "kind": "tenant_audit", "region": client.base,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "inventory": source["inventory"], "unqualified_personas": dict(unqualified),
            "results": results, "safe_to_apply": False}


# Documented profile identities are intentionally explicit. Unknown envelopes or
# model-specific shapes remain unqualified instead of choosing arbitrary keys.
AP_PERSONAS = {"CAMPUS_AP", "MICROBRANCH_AP"}
GATEWAY_PERSONAS = {"MOBILITY_GW", "BRANCH_GW"}
NETWORK_PERSONAS = PERSONAS | AP_PERSONAS | GATEWAY_PERSONAS | {"BRIDGE"}
CONFIG_MODULES = {
    "layer2-vlan": ("vlan", PERSONAS, False),
    "vlan-interfaces": ("id", PERSONAS, False),
    "ethernet-interfaces": ("name", NETWORK_PERSONAS, True),
    "portchannels": ("name", PERSONAS | GATEWAY_PERSONAS, False),
    "sw-port-profiles": ("profile-name", PERSONAS, False),
    "interface-profiles": ("name", NETWORK_PERSONAS, False),
    "roles": ("name", NETWORK_PERSONAS, False),
    "switch-system": ("name", PERSONAS, False),
    "switch-profiles": ("name", PERSONAS, False),
    "qos-global": ("name", PERSONAS, False),
    "device-profile": ("name", PERSONAS, False),
    "wlan-ssids": ("ssid", AP_PERSONAS, False),
    "ap-system": ("name", AP_PERSONAS, False),
    "ap-port-profiles": ("profile-name", AP_PERSONAS, False),
    "gw-port-profiles": ("profile-name", GATEWAY_PERSONAS, False),
    # Additional documented collection endpoints and profile identity keys.
    # Persona sets are candidate adapters, not a hardware/firmware support claim.
    "dns": ("name", NETWORK_PERSONAS, False),
    "ntp": ("name", NETWORK_PERSONAS, False),
    "snmp": ("name", NETWORK_PERSONAS, False),
    "snmp-trap": ("name", NETWORK_PERSONAS, False),
    "logging": ("name", NETWORK_PERSONAS, False),
    "system-info": ("name", NETWORK_PERSONAS, False),
    "macauth": ("name", PERSONAS, False),
    "qos-queues": ("q-profile-name", PERSONAS, False),
    "mgmd-global": ("name", PERSONAS, False),
    "dhcp-pool": ("name", PERSONAS | GATEWAY_PERSONAS, False),
    "gw-system": ("name", GATEWAY_PERSONAS, False),
    "stp-gw": ("name", GATEWAY_PERSONAS, False),
    "auth-servers": ("name", NETWORK_PERSONAS, False),
    # Named resources documented by HPE; capture read-only across applicable
    # functions. Actual applicability and response qualification remain separate.
    "aliases": ("name", NETWORK_PERSONAS, False),
    "net-groups": ("name", NETWORK_PERSONAS, False),
    "policies": ("name", NETWORK_PERSONAS, False),
    "role-acls": ("name", NETWORK_PERSONAS, False),
    "alg": ("name", NETWORK_PERSONAS, False),
    # Central NAC authentication profiles use default query parameters.
    # Keep this existing catalog entry for historical audit compatibility.
    "auth-profiles": ("auth-profile-id", NETWORK_PERSONAS, False),
}


def module_view(payload, identity, object_type="ANY"):
    """Validate one list envelope; never infer an empty profile set from an error."""
    if payload == {}:
        return {"status": "empty_object", "profiles": {}}
    if not isinstance(payload, dict):
        return {"status": "schema_unresolved", "profiles": {}}
    metadata = payload.get("metadata", {})
    if not isinstance(metadata, dict):
        return {"status": "schema_unresolved", "profiles": {}}
    counts = metadata.get("count_objects_in_module", {})
    if not isinstance(counts, dict):
        return {"status": "schema_unresolved", "profiles": {}}
    expected = counts.get(object_type)
    # An omitted list with explicit zero for the requested object type is
    # evidence of zero returned profiles, unlike an unqualified empty object.
    empty_envelope = [key for key in payload if key != "metadata"]
    explicit_empty = (not empty_envelope or
                      (len(empty_envelope) == 1 and payload[empty_envelope[0]] is None))
    if explicit_empty and "metadata" in payload and type(expected) is int and expected == 0:
        if "total" in metadata and (type(metadata["total"]) is not int or metadata["total"] != 0):
            return {"status": "count_mismatch", "profiles": {}}
        return {"status": "list_parsed", "profiles": {}, "envelope": None,
                "count_confirmed": True}
    lists = [(k, v) for k, v in payload.items() if k != "metadata" and isinstance(v, list)]
    if len(lists) != 1 or set(payload) - {"metadata", lists[0][0]}:
        return {"status": "schema_unresolved", "profiles": {}}
    envelope, items = lists[0]
    if "offset" in metadata and (type(metadata["offset"]) is not int or metadata["offset"] not in (0, len(items))):
        return {"status": "count_mismatch", "profiles": {}}
    for count in (metadata.get("total"), metadata.get("count"), expected):
        if count is not None and (type(count) is not int or count != len(items)):
            return {"status": "count_mismatch", "profiles": {}}
    profiles = {}
    for item in items:
        if not isinstance(item, dict):
            return {"status": "schema_unresolved", "profiles": {}}
        value = item.get(identity)
        if type(value) not in (str, int) or not str(value).strip():
            return {"status": "identity_unresolved", "profiles": {}}
        if identity == "vlan":
            ids = parse_reference_ids(value)
            if not ids:
                return {"status": "identity_unresolved", "profiles": {}}
            key = next(iter(ids))
        else:
            key = str(value)
        if key in profiles:
            return {"status": "identity_unresolved", "profiles": {}}
        profiles[key] = item
    return {"status": "list_parsed", "profiles": profiles, "envelope": envelope,
            "count_confirmed": metadata.get("total") is not None or expected is not None}


def annotated_committed_local(payload, identity):
    """Recover local objects from an annotated, unfiltered committed response.

    Require a complete ANY view and explicit annotations for every object.
    Never trust a bare LOCAL count when nonempty objects contradict it.
    """
    parsed = module_view(payload, identity, "ANY")
    if parsed["status"] != "list_parsed" or not parsed.get("count_confirmed"):
        return {"status": "annotation_recovery_unverified", "profiles": {}}
    counts = payload.get("metadata", {}).get("count_objects_in_module", {})
    expected = counts.get("LOCAL")
    if type(expected) is not int or expected < 0:
        return {"status": "annotation_recovery_unverified", "profiles": {}}
    local = {}
    for key, profile in parsed["profiles"].items():
        annotation = profile.get("@")
        if not isinstance(annotation, dict):
            return {"status": "annotation_recovery_unverified", "profiles": {}}
        kind = annotation.get("aruba-annotation:object_type")
        inherited = annotation.get("aruba-annotation:inherited")
        if inherited is not False or kind not in ("LOCAL", "SHARED"):
            return {"status": "annotation_recovery_unverified", "profiles": {}}
        if kind == "LOCAL":
            local[key] = profile_body(profile)
    if len(local) != expected:
        return {"status": "annotation_recovery_unverified", "profiles": {}}
    return {"status": "list_parsed", "profiles": local, "count_confirmed": True,
            "qualification": "annotated_committed_local"}


def read_module_view(client, module, identity, params):
    try:
        raw = client.get(ALPHA + "/" + module, **params)
    except APIError as exc:
        if exc.status not in (400, 403, 404, 405, 406, 412, 422):
            raise
        return {"status": "permission_denied" if exc.status == 403 else "request_rejected",
                "http_error": exc.status, "profiles": {}}
    object_type = params.get("object-type", "ANY")
    parsed = module_view(raw, identity, object_type)
    # Central often returns complete unpaginated views. Recover only a proven
    # truncated collection, never reinterpret contradictory source counts.
    if parsed["status"] != "count_mismatch" or not isinstance(raw, dict):
        return {**parsed, "raw": raw}
    meta = raw.get("metadata")
    lists = [(k, v) for k, v in raw.items() if k != "metadata" and isinstance(v, list)]
    if not isinstance(meta, dict) or len(lists) != 1 or set(raw) != {"metadata", lists[0][0]}:
        return {**parsed, "raw": raw}
    envelope, initial = lists[0]
    counts = meta.get("count_objects_in_module", {})
    if not isinstance(counts, dict):
        return {**parsed, "raw": raw}
    total = meta.get("total", counts.get(object_type))
    if (type(total) is not int or not len(initial) < total
            or counts.get(object_type, total) != total):
        return {**parsed, "raw": raw}
    pages, items, seen = [], [], set()
    def incomplete(reason):
        return {**parsed, "raw": raw, "pagination_status": reason, "raw_pages": pages}
    # Start at zero so offset semantics do not depend on the implicit limit.
    for _ in range(10000):
        try:
            page = client.get(ALPHA + "/" + module, **params, limit=100, offset=len(items))
        except APIError as exc:
            if exc.status == 401:
                raise
            return {**incomplete("request_failed"), "http_error": exc.status}
        except (RuntimeError, OSError, ValueError):
            return incomplete("read_failed")
        pages.append(page)
        if not isinstance(page, dict) or set(page) != {"metadata", envelope}:
            return incomplete("schema_changed")
        page_meta, batch = page["metadata"], page[envelope]
        if (not isinstance(page_meta, dict)
                or page_meta.get("total", page_meta.get("count_objects_in_module", {}).get(object_type) if isinstance(page_meta.get("count_objects_in_module", {}), dict) else None) != total
                or not isinstance(batch, list) or not batch
                or page_meta.get("count", len(batch)) != len(batch)
                or page_meta.get("offset", len(items)) not in (len(items), len(items) + len(batch))
                or page_meta.get("count_objects_in_module", {}) != counts
                or len(items) + len(batch) > total):
            return incomplete("count_changed")
        # Validate identities per page without comparing collection totals
        # against the page size. Duplicate identities across pages are unsafe.
        page_view = module_view({envelope: batch}, identity, object_type)
        if page_view["status"] != "list_parsed" or seen.intersection(page_view["profiles"]):
            return incomplete("duplicate_or_invalid_identity")
        seen.update(page_view["profiles"])
        items.extend(batch)
        if len(items) == total:
            if Counter(canonical(item) for item in initial) - Counter(canonical(item) for item in items):
                return incomplete("initial_response_changed")
            combined = {"metadata": {**meta, "count": total, "offset": 0}, envelope: items}
            result = module_view(combined, identity, object_type)
            return {**result, "raw": combined, "initial_raw": raw, "raw_pages": pages,
                    "pagination_status": "complete"}
    return incomplete("page_limit_reached")


def recover_local_view(client, module, identity, params, local, effective=None):
    retry_empty = (local["status"] == "empty_object" and effective is not None
                   and effective["status"] == "list_parsed"
                   and check_empty_local(list(effective["profiles"].values())) == "contradictory_local_profile")
    if local["status"] not in ("count_mismatch", "schema_unresolved") and not retry_empty:
        return local
    # Query unfiltered committed configuration and require explicit source
    # annotations, rather than assuming the API honored object-type=LOCAL.
    fallback = read_module_view(client, module, identity,
                                {**params, "effective": "false", "detailed": "true"})
    recovered = annotated_committed_local(fallback["raw"], identity) if "raw" in fallback else {}
    if recovered.get("status") == "list_parsed":
        return {**recovered, "raw": local["raw"], "alternate_raw": fallback["raw"]}
    return {**local, "fallback_status": fallback["status"],
            **({"alternate_raw": fallback["raw"]} if "raw" in fallback else {})}


def profile_inventory_view(client, endpoint, envelope, **params):
    """Preserve positive inventory observations, even when pagination is incomplete."""
    read = read_raw_profile_collection(client, endpoint, params)
    if "raw" not in read:
        return {**read, "rows": []}
    try:
        records = rows(read["raw"], (envelope,))
    except ValueError:
        return {**read, "status": "schema_unresolved", "rows": []}
    return {**read, "rows": records}


def collect_scoped_assignments(client, initial, scopes_by_persona, workers=1, progress=None):
    """Cross-check tenant-wide assignments against documented scope/function reads.

    A scoped response is only evidence for the exact requested scope/function.
    Missing or conflicting evidence never proves an assignment is absent.
    """
    tasks = sorted({(persona, str(scope["id"])) for persona, scopes in scopes_by_persona.items()
                    for scope in scopes if persona in NETWORK_PERSONAS and str(scope["id"]).isdigit()})
    def read(task):
        persona, sid = task
        try:
            result = profile_inventory_view(client, "config-assignments", "config-assignment",
                                            **{"scope-id": sid, "device-function": persona})
            records = result.pop("rows")
            if result["status"] not in ("response_received", "partial_response", "count_mismatch"):
                return task, result, []
            raw = result["raw"]
            if any(str(r.get("scope-id")) != sid or r.get("device-function") != persona
                   or not isinstance(r.get("profile-type"), str)
                   or type(r.get("profile-instance")) not in (str, int) for r in records):
                return task, {**result, "status": "selector_mismatch"}, []
            # A truncated response can still prove that a returned assignment
            # exists. It cannot establish that another assignment is absent.
            return task, result, records
        except APIError as exc:
            if exc.status == 401:
                raise
            return task, {"status": "request_rejected", "http_error": exc.status}, []
        except (RuntimeError, OSError, ValueError):
            return task, {"status": "read_failed"}, []
    def identity(row):
        return (str(row.get("scope-id")), row.get("device-function"),
                row.get("profile-type"), str(row.get("profile-instance")))
    initial_rows = initial.get("rows", [])
    def identifiable(row):
        return (type(row.get("scope-id")) in (int, str) and
                isinstance(row.get("device-function"), str) and
                isinstance(row.get("profile-type"), str) and
                type(row.get("profile-instance")) in (int, str))
    unresolved = [row for row in initial_rows if not identifiable(row)]
    merged = {identity(row): row for row in initial_rows if identifiable(row)}
    original = set(merged)
    scoped, outcomes = {}, Counter()
    audit_progress(progress, "Assignment coverage", 0, len(tasks), "Checking profile assignments by scope")
    for (persona, sid), result, records in ordered_parallel(tasks, read, workers,
            completed=lambda done, total: audit_progress(progress, "Assignment coverage", done, total, "Checking profile assignments")):
        scoped_keys = {identity(row) for row in records}
        expected = {key for key in original if key[:2] == (sid, persona)}
        if result["status"] == "response_received" and expected - scoped_keys:
            result["status"] = "tenant_scope_disagreement"
        scoped.setdefault(persona, {})[sid] = result
        outcomes[result["status"]] += 1
        # Keep all positive observations from either read. Do not delete a
        # tenant-wide assignment simply because a scoped read did not return it.
        for row in records:
            merged.setdefault(identity(row), row)
    return {**initial, "rows": list(merged.values()) + unresolved,
            "status": "response_received" if initial.get("status") == "response_received" else
                      "partial_response" if merged else initial.get("status", "not_collected"),
            "scope_reads": scoped, "scope_read_outcomes": dict(outcomes),
            "additional_assignments": len(set(merged) - original),
            "coverage_verified": False}


def discover_profile_types(assignments, scope_maps):
    """Collect explicit module/function observations without inferring inheritance."""
    result = defaultdict(set)
    unresolved = 0
    for view, assignment in ((assignments, True), (scope_maps, False)):
        for row in view.get("rows", []):
            resource = row.get("profile-type") if assignment else row.get("resource")
            persona = row.get("device-function") if assignment else row.get("persona")
            if isinstance(resource, str) and not assignment:
                resource = resource.split("/", 1)[0]
            if (not isinstance(resource, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,127}", resource)
                    or not isinstance(persona, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", persona)):
                unresolved += 1
                continue
            result[resource].add(persona)
    return {"modules": {m: sorted(p) for m, p in sorted(result.items())},
            "unknown_adapter_modules": sorted(set(result) - set(CONFIG_MODULES)),
            "unresolved_records": unresolved, "complete": False}


def observed_identity_candidates(view):
    """Use exact source resource identities and count evidence, never field names alone."""
    instances = view.get("observed_instances", [])
    raw = view.get("committed", {}).get("raw")
    if not isinstance(raw, dict) or not instances or "" in instances:
        return set()
    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        return set()
    lists = [v for k, v in raw.items() if k != "metadata" and isinstance(v, list)]
    if len(lists) != 1 or not lists[0] or any(not isinstance(v, dict) for v in lists[0]):
        return set()
    items = lists[0]
    if len(items) != len(instances) or len(set(instances)) != len(instances):
        return set()
    candidates = set.intersection(*(set(item) for item in items)) - {"@"}
    matches = set()
    for key in candidates:
        if not isinstance(key, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,127}", key):
            continue
        values = [item[key] for item in items]
        if any(type(v) not in (str, int) for v in values):
            continue
        if {str(v) for v in values} != set(instances):
            continue
        parsed = module_view(raw, key, "ANY")
        if parsed["status"] != "list_parsed" or not parsed.get("count_confirmed"):
            continue
        if annotated_committed_local(raw, key)["status"] != "list_parsed":
            continue
        matches.add(key)
    return matches


def qualify_observed_identities(evidence):
    """Produce provisional source-scope read evidence; never promote an inferred write adapter.

    Require a unique field matching inventory identities in every nonempty
    committed capture for the persona, with two distinct observed identities.
    """
    by_persona = defaultdict(list)
    for view in evidence["source_views"]:
        by_persona[view["persona"]].append(view)
    results = {}
    for persona, views in sorted(by_persona.items()):
        nonempty = [v for v in views if v.get("observed_instances")]
        identities = {i for v in nonempty for i in v["observed_instances"] if i}
        sets = [observed_identity_candidates(v) for v in nonempty]
        common = set.intersection(*sets) if sets else set()
        if len(identities) < 2 or len(common) != 1:
            results[persona] = {"status": "identity_unresolved", "source_scopes": len(views),
                                "candidate_count": len(common), "safe_to_apply": False}
            continue
        identity = next(iter(common))
        reviews = []
        for view in views:
            committed = view.get("committed", {}).get("raw")
            effective = view.get("effective", {}).get("raw")
            local = annotated_committed_local(committed, identity)
            actual = module_view(effective, identity, "ANY")
            review = review_module_scope(local, actual, None)
            reviews.append({"scope": view["scope"], "review": review,
                            "local_status": local["status"], "effective_status": actual["status"]})
        qualified = sum(r["review"]["qualified"] for r in reviews)
        results[persona] = {"status": "source_identity_observed", "identity_field": identity,
                            "source_scopes": len(views), "comparable_source_scopes": qualified,
                            "reviews": reviews, "full_scope_coverage_verified": False,
                            "safe_to_apply": False}
    return results


AUDIT_WORKERS = 12


def ordered_parallel(items, function, workers=1, completed=None, item_completed=None):
    """Bound concurrent reads; preserve input order and propagate failures."""
    items = list(items)
    if workers == 1 or len(items) <= 1:
        result = []
        for item in items:
            result.append(function(item))
            if completed:
                completed(len(result), len(items))
            if item_completed:
                item_completed(len(result), len(items), item)
        return result
    result = [None] * len(items)
    with ThreadPoolExecutor(max_workers=min(AUDIT_WORKERS, workers, len(items))) as pool:
        pending = {pool.submit(function, item): index for index, item in enumerate(items)}
        try:
            for count, future in enumerate(as_completed(pending), 1):
                result[pending[future]] = future.result()
                if completed:
                    completed(count, len(items))
                if item_completed:
                    item_completed(count, len(items), items[pending[future]])
        except BaseException:
            for future in pending:
                future.cancel()
            raise
    return result


def audit_progress(callback, phase, done, total, detail):
    if callback:
        callback(phase, done, total, detail)


# Documented collections whose shapes/cardinality require further qualification.
# Survey these even if the assignment and scope-map inventories omit them.
DOCUMENTED_RAW_COLLECTIONS = {"arc", "policy-groups", "usb"}


def documented_profile_catalog():
    """Use the pinned HPE collection, not a tenant's assignment inventory.

    Only exact, non-parameterized configuration GET paths are executable.
    Other request definitions remain inventory for dedicated future adapters.
    No vendor script, authorization setting or example payload is executed.
    """
    catalog = json.loads(Path(__file__).with_name("central_api_catalog.json").read_text(encoding="utf-8"))
    if not isinstance(catalog.get("get_requests"), list):
        raise ValueError("Invalid bundled Central API catalog")
    modules = {}
    for request in catalog["get_requests"]:
        path = request.get("path", "")
        match = re.fullmatch(r"/network-config/v1alpha1/([a-z][a-z0-9-]*)", path)
        if (request.get("method") != "GET" or not match
                or not {"view-type", "scope-id", "effective", "detailed"} <= set(request.get("query", []))):
            continue
        module = match[1]
        # Config assignments have an explicit inventory collector.
        if module == "config-assignments":
            continue
        entry = modules.setdefault(module, {"source": "vendor_collection", "group": request["group"],
                                            "all_function_scope": False})
        entry["all_function_scope"] |= "device-function" in request.get("query", [])
    for entry in catalog.get("release_note_collections", []):
        match = re.fullmatch(r"/network-config/v1alpha1/([a-z][a-z0-9-]*)", entry["path"])
        if match:
            modules.setdefault(match[1], {"source": "release_notes", "group": "Additional documented profiles",
                                          "all_function_scope": False})
    return {"source": catalog["source_url"], "source_updated_at": catalog["source_updated_at"],
            "get_requests": len(catalog["get_requests"]),
            "unique_get_paths": len({r["path"] for r in catalog["get_requests"]}),
            "folders_read": sum(v["status"] == "read" for v in catalog["folder_outcomes"].values()),
            "folders_total": len(catalog["folder_outcomes"]),
            "modules": modules, "exhaustive": False}



def read_raw_profile_collection(client, module, params):
    """Preserve all pages of an explicitly truncated collection without assuming identity."""
    try:
        raw = client.get(ALPHA + "/" + module, **params)
    except APIError as exc:
        if exc.status not in (400, 403, 404, 405, 406, 410, 412, 422):
            raise
        return {"status": "request_rejected", "http_error": exc.status}
    result = {"status": "response_received" if raw else "empty_response", "raw": raw,
              "collection_count_verified": False}
    if not isinstance(raw, dict):
        return result
    meta = raw.get("metadata", {})
    lists = [(k, v) for k, v in raw.items() if k != "metadata" and isinstance(v, list)]
    if not isinstance(meta, dict) or len(lists) != 1 or set(raw) - {"metadata", lists[0][0]}:
        return result
    envelope, initial = lists[0]
    def declared_total(metadata):
        counts = metadata.get("count_objects_in_module", {})
        if not isinstance(counts, dict):
            return None, False
        expected = counts.get(params.get("object-type", "ANY"))
        total = metadata.get("total", expected)
        valid = ((total is None or (type(total) is int and total >= 0))
                 and (expected is None or (type(expected) is int and expected == total)))
        return total, valid
    total, valid = declared_total(meta)
    if (not valid or ("count" in meta and (type(meta["count"]) is not int or meta["count"] != len(initial)))
            or ("offset" in meta and (type(meta["offset"]) is not int or meta["offset"] not in (0, len(initial))))):
        return {**result, "status": "count_mismatch"}
    if total is None:
        return result
    if total == len(initial):
        if len({canonical(item) for item in initial}) != total:
            return {**result, "status": "count_mismatch"}
        return {**result, "collection_count_verified": True}
    if total < len(initial):
        return {**result, "status": "count_mismatch"}
    pages, combined, signatures = [], [], set()
    def incomplete(reason):
        return {**result, "status": "partial_response", "pagination_status": reason, "raw_pages": pages}
    for _ in range(10000):
        try:
            page = client.get(ALPHA + "/" + module, **params, limit=100, offset=len(combined))
        except APIError as exc:
            if exc.status == 401:
                raise
            return {**incomplete("request_failed"), "http_error": exc.status}
        except (RuntimeError, OSError, ValueError):
            return incomplete("read_failed")
        pages.append(page)
        if not isinstance(page, dict) or set(page) != {"metadata", envelope}:
            return incomplete("schema_changed")
        batch, page_meta = page[envelope], page["metadata"]
        if (not isinstance(batch, list) or not batch or not isinstance(page_meta, dict)
                or declared_total(page_meta) != (total, True)
                or page_meta.get("count_objects_in_module", {}) != meta.get("count_objects_in_module", {})
                or page_meta.get("count", len(batch)) != len(batch)
                or page_meta.get("offset", len(combined)) not in (len(combined), len(combined) + len(batch))
                or len(combined) + len(batch) > total):
            return incomplete("count_or_offset_changed")
        signature = canonical(batch)
        if signature in signatures:
            return incomplete("repeated_page")
        signatures.add(signature)
        combined.extend(batch)
        if len(combined) == total:
            if Counter(canonical(item) for item in initial) - Counter(canonical(item) for item in combined):
                return incomplete("initial_response_changed")
            if len({canonical(item) for item in combined}) != total:
                return incomplete("duplicate_records")
            # Retain a reconstructed collection for inspection, never qualify
            # identities or authorize a change based on this raw count alone.
            return {**result, "raw": {"metadata": {**meta, "count": total, "offset": 0}, envelope: combined},
                    "initial_raw": raw, "raw_pages": pages, "pagination_status": "complete",
                    "collection_count_verified": True}
    return incomplete("page_limit_reached")


def inspect_unadapted_profiles(client, discovery, assignments, scope_maps, workers=1, progress=None, *, scopes_by_persona=None, deep_catalog=False):
    """Inspect observed source scopes for modules without an explicit adapter.

    These are raw read-only diagnostics, not qualified local/effective views.
    Extend observed resource/function pairs across the discovered scope inventory.
    """
    unknown = set(discovery["unknown_adapter_modules"]) | set(discovery.get("survey_modules", []))
    targets = defaultdict(set)
    for view, assignment in ((assignments, True), (scope_maps, False)):
        for row in view.get("rows", []):
            resource = row.get("profile-type") if assignment else row.get("resource")
            persona = row.get("device-function") if assignment else row.get("persona")
            sid = row.get("scope-id")
            if isinstance(resource, str) and not assignment:
                resource, _, instance = resource.partition("/")
            else:
                instance = row.get("profile-instance")
            if (not isinstance(resource, str) or resource not in unknown
                    or not re.fullmatch(r"[a-z][a-z0-9-]{0,127}", resource)
                    or not isinstance(persona, str) or persona not in NETWORK_PERSONAS | {"HYBRID_NAC"}
                    or type(sid) not in (int, str) or not re.fullmatch(r"[0-9]+", str(sid))
                    or (instance is not None and type(instance) not in (int, str))):
                continue
            targets[(resource, persona, str(sid))].add("" if instance is None else str(instance))

    # An assignment or scope-map observation identifies a possible source,
    # not every scope on which that definition may be inherited or overridden.
    # Survey all discovered scopes for the observed device functions. Do not
    # guess functions for catalog-only modules or authorize changes.
    for module in sorted(unknown):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,127}", module):
            continue
        for persona in discovery["modules"].get(module, []):
            if persona not in NETWORK_PERSONAS:
                continue
            for scope in (scopes_by_persona or {}).get(persona, []):
                sid = str(scope["id"])
                if sid.isdigit():
                    targets.setdefault((module, persona, sid), set())

    documented = discovery.get("documented_catalog", {}).get("modules", {})
    global_ids = sorted({str(s["id"]) for scopes in (scopes_by_persona or {}).values()
                         for s in scopes if s.get("kind") == "global" and str(s["id"]).isdigit()})
    all_scope_ids = sorted({str(s["id"]) for scopes in (scopes_by_persona or {}).values()
                            for s in scopes if str(s["id"]).isdigit()})

    if deep_catalog:
        planned = sum(len(all_scope_ids) * 2 for module in unknown
                      if documented.get(module, {}).get("all_function_scope")
                      or documented.get(module, {}).get("source") == "vendor_collection")
        print(f"Deep catalog survey: up to {planned} additional unfiltered scope reads before pagination; "
              "rejected and incomplete reads remain visible.", flush=True)

    def capture(module, params):
        try:
            return read_raw_profile_collection(client, module, params)
        except APIError as exc:
            if exc.status in (401, 429):
                raise
            return {"status": "read_failed", "http_error": exc.status, "collection_count_verified": False}
        except (RuntimeError, OSError, ValueError):
            return {"status": "read_failed", "collection_count_verified": False}

    def inspect(module):
        evidence = []
        for (m, persona, sid), instances in sorted(targets.items()):
            if m != module:
                continue
            base = {"view-type": "LOCAL", "scope-id": sid, "device-function": persona, "detailed": "true"}
            committed = capture(module, {**base, "effective": "false"})
            effective = capture(module, {**base, "effective": "true"})
            evidence.append({"persona": persona, "scope": sid,
                             "observed_instances": sorted(instances), "committed": committed,
                             "effective": effective})
        # Documented collections absent from discovery still receive a Global
        # read for all functions. Keep the mixed-function results separate from
        # identified profile evidence and never use them to qualify a change.
        catalog_views = []
        contract = documented.get(module, {})
        all_functions = contract.get("all_function_scope", False)
        documented_scope = contract.get("source") == "vendor_collection"
        survey_ids = all_scope_ids if deep_catalog and (all_functions or documented_scope) else (
            global_ids if all_functions else [])
        survey_label = "ALL_DEVICE_FUNCTIONS" if all_functions else "UNFILTERED_SCOPE"
        if survey_ids:
            for sid in survey_ids:
                base = {"view-type": "LOCAL", "scope-id": sid, "detailed": "true"}
                catalog_views.append({"persona": survey_label, "scope": sid,
                                      "observed_instances": [],
                                      "committed": capture(module, {**base, "effective": "false"}),
                                      "effective": capture(module, {**base, "effective": "true"})})
        # Discover functions from explicit Global annotations. Positive data
        # warrants targeted scope reads even if the assignment inventory missed
        # the module. An empty Global response is never proof of no local data.
        observed_functions = set()
        global_functions = set()
        for view in catalog_views:
            for kind in ("committed", "effective"):
                payload = view[kind].get("raw")
                if not isinstance(payload, dict):
                    continue
                for key, items in payload.items():
                    if key == "metadata" or not isinstance(items, list):
                        continue
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        ann = item.get("@")
                        if isinstance(ann, dict):
                            function = ann.get("aruba-annotation:device_function")
                            if isinstance(function, str) and function in NETWORK_PERSONAS:
                                observed_functions.add(function)
                                if view["scope"] in global_ids:
                                    global_functions.add(function)
        visited = {(v["persona"], v["scope"]) for v in evidence}
        for function in sorted(observed_functions):
            for scope in (scopes_by_persona or {}).get(function, []):
                sid = str(scope["id"])
                if not sid.isdigit() or (function, sid) in visited:
                    continue
                base = {"view-type": "LOCAL", "scope-id": sid, "device-function": function, "detailed": "true"}
                evidence.append({"persona": function, "scope": sid, "observed_instances": [],
                                 "committed": capture(module, {**base, "effective": "false"}),
                                 "effective": capture(module, {**base, "effective": "true"})})
                visited.add((function, sid))
        result = {"status": "unqualified_adapter", "source_views": evidence + catalog_views,
                  "scope_read_outcomes": dict(Counter(v[k]["status"] for v in evidence + catalog_views for k in ("committed", "effective"))),
                  "library": capture(module, {"view-type": "LIBRARY", "detailed": "true"}),
                  "catalog_scope_coverage": {"global_scopes_attempted": sum(v["scope"] in global_ids for v in catalog_views),
                       "global_observed_functions": sorted(global_functions),
                       "observed_functions": sorted(observed_functions),
                       "deep_catalog_requested": deep_catalog,
                       "unfiltered_scopes_attempted": len(catalog_views),
                       "unfiltered_scopes_not_surveyed": len(set(all_scope_ids) - set(survey_ids)),
                       "discovered_scopes": len(all_scope_ids),
                       "all_function_scopes_not_surveyed": len(set(all_scope_ids) - set(survey_ids)) if all_functions else None,
                       "complete": False},
                  "safe_to_apply": False}
        result["identity_evidence"] = qualify_observed_identities(result)
        print(f"  Unadapted profile type {module}: source views={len(evidence)}; "
              f"Library={result['library']['status']}", flush=True)
        return module, result
    audit_progress(progress, "Additional profile types", 0, len(unknown), "Inspecting discovered modules")
    return dict(ordered_parallel(sorted(unknown), inspect, workers,
                lambda done, total: audit_progress(progress, "Additional profile types", done, total,
                                                   "Inspecting discovered modules")))


def library_inventory(client, modules, assignment_view=None, scope_map_view=None, workers=1, progress=None):
    """Read tenant-wide shared profiles once per module and preserve assignment evidence."""
    applicable = sorted(m for m in modules if not CONFIG_MODULES[m][2])
    def read(module):
        identity, _, _ = CONFIG_MODULES[module]
        params = {} if module == "auth-profiles" else {"view-type": "LIBRARY", "detailed": "true"}
        view = read_module_view(client, module, identity, params)
        print(f"  Library {module}: {view['status']}; profiles={len(view['profiles'])}", flush=True)
        return module, view
    audit_progress(progress, "Library", 0, len(applicable), "Reading shared profiles")
    results = dict(ordered_parallel(applicable, read, workers,
                   lambda done, total: audit_progress(progress, "Library", done, total,
                                                      "Reading shared profiles")))
    if assignment_view is None:
        assignment_view = profile_inventory_view(client, "config-assignments", "config-assignment")
    return {"modules": results, "assignments": assignment_view,
            "scope_maps": scope_map_view,
            "assignment_coverage_verified": False, "safe_to_apply": False}


def profile_body(profile):
    return {k: v for k, v in profile.items() if k != "@"}


def review_module_scope(local, effective, baseline, device_only=False, is_global=False):
    """Compare committed profiles and annotated effective profiles without inferring inheritance."""
    local_status = local["status"]
    if local_status == "empty_object" and effective["status"] == "list_parsed":
        validation = check_empty_local(list(effective["profiles"].values()))
        if validation in ("consistent_with_effective_annotations", "no_effective_profiles"):
            local_status = "empty_correlated"
        else:
            local_status = "empty_" + validation
    qualified = local_status in ("list_parsed", "empty_correlated") and effective["status"] == "list_parsed"
    result = {"local_status": local_status, "effective_status": effective["status"],
              "qualified": qualified, "profiles": [], "safe_to_apply": False}
    if not qualified:
        return result
    for key in sorted(local["profiles"].keys() | effective["profiles"].keys()):
        committed = local["profiles"].get(key)
        observed = effective["profiles"].get(key)
        annotation = observed.get("@", {}) if observed is not None else {}
        if not isinstance(annotation, dict):
            annotation = {}
        reference = baseline.get(key) if baseline is not None and not device_only and not is_global else None
        body = profile_body(committed) if committed is not None else None
        actual = profile_body(observed) if observed is not None else None
        base = profile_body(reference) if reference is not None else None
        differences = field_differences(body, base) if body is not None and base is not None else None
        if annotation.get("aruba-annotation:is_default") is True:
            status = "default_profile"
        elif committed is not None:
            if actual is None or canonical(body) != canonical(actual):
                status = "local_effective_mismatch"
            elif annotation.get("aruba-annotation:inherited") is True or annotation.get("aruba-annotation:object_type") == "SHARED":
                status = "source_conflict"
            elif device_only:
                status = "device_local_profile"
            elif is_global:
                status = "global_local_profile"
            elif reference is not None:
                status = "local_matches_global" if not differences else "local_differs_from_global"
            elif baseline is None:
                status = "global_reference_unverified"
            else:
                status = "local_without_global_match"
        elif annotation.get("aruba-annotation:inherited") is True:
            status = "inherited"
        elif annotation.get("aruba-annotation:object_type") == "SHARED":
            status = "shared"
        elif annotation.get("aruba-annotation:inherited") is False and annotation.get("aruba-annotation:object_type") == "LOCAL":
            status = "source_conflict"
        else:
            status = "effective_source_unverified"
        result["profiles"].append({"identity": key, "status": status, "local": body,
                                   "effective": actual, "global_reference": base,
                                   "global_differences": differences, "annotations": annotation})
    return result


def read_vlan_instance(client, persona, scope, vid, effective):
    """Read a specific VLAN without silently merging collection and instance views."""
    if persona not in PERSONAS or not str(scope).isdigit() or parse_reference_ids(vid) != {vid}:
        return {"status": "invalid_selector"}
    params = {"view-type": "LOCAL", "scope-id": scope, "device-function": persona,
              "effective": "true" if effective else "false", "detailed": "true"}
    if not effective:
        params["object-type"] = "LOCAL"
    try:
        raw = client.get(VLAN + "/" + quote(vid, safe=""), **params)
    except APIError as exc:
        return {"status": "permission_denied" if exc.status == 403 else "request_rejected",
                "http_error": exc.status}
    except (RuntimeError, OSError, ValueError):
        return {"status": "read_failed"}
    result = {"status": "schema_unresolved", "raw": raw}
    if not isinstance(raw, dict):
        return result
    parsed = module_view(raw, "vlan", params.get("object-type", "ANY"))
    if parsed["status"] == "list_parsed":
        if set(parsed["profiles"]) != {vid}:
            return {**result, "status": "identity_unresolved"}
        profile = parsed["profiles"][vid]
    elif parse_reference_ids(raw.get("vlan")) == {vid} and "metadata" not in raw:
        profile = raw
    elif set(raw) - {"metadata"} == {"l2-vlan"} and isinstance(raw["l2-vlan"], dict) and parse_reference_ids(raw["l2-vlan"].get("vlan")) == {vid}:
        profile = raw["l2-vlan"]
    else:
        return result
    annotation = profile.get("@", {})
    if not isinstance(annotation, dict):
        return result
    if not effective and (annotation.get("aruba-annotation:object_type") != "LOCAL"
                          or annotation.get("aruba-annotation:inherited") is not False):
        return {**result, "status": "source_unverified"}
    return {**result, "status": "observed", "profile": profile_body(profile),
            "annotations": annotation}


def keyed_profile_contracts():
    """Only exact documented single-key GET paths matching explicit adapters."""
    catalog = json.loads(Path(__file__).with_name("central_api_catalog.json").read_text(encoding="utf-8"))
    required = {"view-type", "object-type", "scope-id", "device-function", "effective", "detailed"}
    supported = {}
    for request in catalog["get_requests"]:
        match = re.fullmatch(r"/network-config/v1alpha1/([a-z][a-z0-9-]*)/:([a-z][a-z0-9-]*)",
                             request["path"])
        if not match or request["method"] != "GET" or not required <= set(request["query"]):
            continue
        module, key = match.groups()
        # Existing VLAN and special NAC adapters have separate query semantics.
        if module in ("layer2-vlan", "auth-profiles") or module not in CONFIG_MODULES:
            continue
        if key == CONFIG_MODULES[module][0]:
            supported[module] = key
    return supported


def keyed_profile_read(client, module, identity_key, identity, params, collection_profile):
    """Retain keyed evidence separately; do not promote or rewrite collection data."""
    if (not isinstance(identity, str) or not identity.strip() or len(identity) > 512
            or identity in (".", "..") or any(c in identity for c in ("/", "\\", "%"))
            or any(ord(c) < 32 or ord(c) == 127 for c in identity)):
        return {"status": "invalid_selector", "safe_to_apply": False}
    try:
        raw = client.get(ALPHA + "/" + module + "/" + quote(identity, safe=""), **params)
    except APIError as exc:
        if exc.status in (401, 429):
            raise
        return {"status": "request_rejected", "http_error": exc.status, "safe_to_apply": False}
    except (RuntimeError, OSError, ValueError):
        return {"status": "read_failed", "safe_to_apply": False}
    result = {"status": "schema_unresolved", "raw": raw, "safe_to_apply": False}
    if not isinstance(raw, dict):
        return result
    parsed = module_view(raw, identity_key, params.get("object-type", "ANY"))
    if parsed["status"] == "list_parsed":
        if set(parsed["profiles"]) != {identity}:
            return {**result, "status": "identity_unresolved"}
        profile = parsed["profiles"][identity]
    else:
        # An individual GET may return a single object or a single-object
        # envelope. Accept only exact identities, not arbitrary nested matches.
        def matches(value):
            return (isinstance(value, dict) and type(value.get(identity_key)) in (str, int)
                    and str(value[identity_key]) == identity)
        if "metadata" not in raw and matches(raw):
            profile = raw
        elif len(raw) == 1 and matches(next(iter(raw.values()))):
            profile = next(iter(raw.values()))
        else:
            return result
    body = profile_body(profile)
    return {**result, "status": "identity_observed", "profile": body,
            "annotations": profile.get("@"), "source_verified": False,
            "differences": field_differences(profile_body(collection_profile), body)
                           if isinstance(collection_profile, dict) else None}


def capture_keyed_profile_details(client, results, library, workers=AUDIT_WORKERS, progress=None):
    """Deep survey of observed Library definitions and saved local identities.

    Effective reads are paired with each local identity. Do not query guessed
    identifiers, inherited-only profiles, or special multi-key resources.
    """
    contracts = keyed_profile_contracts()
    tasks = []
    for module, view in sorted(library.get("modules", {}).items()):
        if module in contracts and view.get("status") == "list_parsed":
            for identity, profile in sorted(view["profiles"].items()):
                tasks.append(("Library", "", module, identity, "library", profile))
    for persona, entry in sorted(results.items()):
        for module, data in sorted(entry["modules"].items()):
            if module not in contracts:
                continue
            for view in data["scope_results"]:
                sid = str(view["scope"])
                local = view["local_view"]
                effective = view["effective_view"]
                if not sid.isdigit() or local.get("status") != "list_parsed":
                    continue
                for identity, profile in sorted(local["profiles"].items()):
                    tasks.append((persona, sid, module, identity, "local", profile))
                    tasks.append((persona, sid, module, identity, "effective",
                                  effective.get("profiles", {}).get(identity)
                                  if effective.get("status") == "list_parsed" else None))

    def collect(task):
        persona, sid, module, identity, kind, profile = task
        params = {"view-type": "LIBRARY", "detailed": "true"} if kind == "library" else {
            "view-type": "LOCAL", "scope-id": sid, "device-function": persona,
            "effective": "true" if kind == "effective" else "false", "detailed": "true"}
        if kind == "local":
            params["object-type"] = "LOCAL"
        return task[:5], keyed_profile_read(client, module, contracts[module], identity, params, profile)
    print(f"Keyed profile details: {len(tasks)} observed profile reads; additional evidence only", flush=True)
    audit_progress(progress, "Profile details", 0, len(tasks), "Reading individual configuration profiles")
    observations = {}
    outcomes = Counter()
    for (persona, sid, module, identity, kind), evidence in ordered_parallel(
            tasks, collect, workers, completed=lambda done, total: audit_progress(
                progress, "Profile details", done, total, "Reading individual configuration profiles")):
        observations.setdefault(persona, {}).setdefault(sid, {}).setdefault(module, {}).setdefault(
            identity, {})[kind] = evidence
        outcomes[evidence["status"]] += 1
    print("Keyed profile details: " + canonical(dict(outcomes)), flush=True)
    return {"supported_modules": sorted(contracts), "outcomes": dict(outcomes), "profiles": observations,
            "complete": False, "safe_to_apply": False}


def capture_vlan_instance_details(client, results, workers=AUDIT_WORKERS, progress=None):
    """Target only local switch VLANs with missing name/admin-state evidence."""
    tasks = []
    for persona, entry in sorted(results.items()):
        if persona not in PERSONAS:
            continue
        for scope in entry["modules"].get("layer2-vlan", {}).get("scope_results", []):
            if scope["scope_kind"] != "device" or not scope["review"]["qualified"]:
                continue
            for row in scope["review"]["profiles"]:
                if row["local"] is None:
                    continue
                for kind in ("local", "effective"):
                    body = row[kind]
                    reference = row.get("global_reference")
                    omitted = isinstance(body, dict) and isinstance(reference, dict) and any(
                        d["kind"] == "missing_local" for d in field_differences(body, reference))
                    if isinstance(body, dict) and (omitted or any(k not in body for k in ("name", "enable"))):
                        tasks.append((persona, scope["scope"], row["identity"], kind))
    def collect(task):
        persona, scope, vid, kind = task
        return task, read_vlan_instance(client, persona, scope, vid, kind == "effective")
    audit_progress(progress, "VLAN details", 0, len(tasks), "Checking omitted VLAN settings by ID")
    evidence = {}
    for (persona, scope, vid, kind), detail in ordered_parallel(tasks, collect, workers,
            completed=lambda done, total: audit_progress(progress, "VLAN details", done, total, "Checking omitted VLAN settings by ID")):
        evidence.setdefault(persona, {}).setdefault(scope, {}).setdefault(vid, {})[kind] = detail
    return evidence


def health_serial(row):
    """Recognize only explicit, non-conflicting device identifiers."""
    if not isinstance(row, dict):
        return None
    values = {row[k] for k in ("serial", "serialNumber")
              if isinstance(row.get(k), str) and row[k]}
    if len(values) != 1:
        return None
    serial = next(iter(values))
    return serial if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", serial) else None


def capture_configuration_health(client, inventory_records, workers=AUDIT_WORKERS, progress=None):
    """Collect deployment health independently of profile interpretation."""
    def read(path, **params):
        try:
            return {"status": "response_received", "raw": client.get(ALPHA + path, **params)}
        except APIError as exc:
            if exc.status in (401, 429):
                raise
            return {"status": "request_rejected", "http_error": exc.status}
        except (RuntimeError, OSError, ValueError):
            return {"status": "read_failed"}

    pages, observed, seen = [], [], set()
    envelope, total = None, None
    summary_status = "page_limit_reached"
    count_confirmed = False
    for _ in range(10000):
        result = read("/config-health/devices", limit=100, offset=len(observed), sort="serial asc")
        pages.append(result)
        if result["status"] != "response_received":
            summary_status = result["status"]
            break
        payload = result["raw"]
        if not isinstance(payload, dict):
            summary_status = "schema_unqualified"
            break
        lists = [(key, value) for key, value in payload.items() if isinstance(value, list)]
        if len(lists) != 1:
            summary_status = "schema_unqualified"
            break
        key, batch = lists[0]
        if ((envelope is not None and key != envelope) or len(batch) > 100
                or any(not isinstance(row, dict) for row in batch)):
            summary_status = "schema_unqualified"
            break
        envelope = key
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            summary_status = "schema_unqualified"
            break
        totals = [v for source in (payload, metadata) for k, v in source.items() if k == "total"]
        if (any(type(v) is not int or v < 0 for v in totals) or len(set(totals)) > 1
                or (total is not None and totals and total != totals[0])):
            summary_status = "count_mismatch"
            break
        if totals:
            total = totals[0]
        identities = [health_serial(row) for row in batch]
        if None in identities or len(set(identities)) != len(identities) or seen.intersection(identities):
            summary_status = "identity_unqualified"
            break
        if total is not None and len(observed) + len(batch) > total:
            summary_status = "count_mismatch"
            break
        observed.extend(batch)
        seen.update(identities)
        if total is not None and len(observed) == total:
            count_confirmed = True
            summary_status = "count_confirmed"
            break
        if not batch:
            summary_status = "count_mismatch" if total is not None else "pagination_exhausted"
            break
        # Without a declared total, keep requesting until an empty page. A
        # short nonempty page is not necessarily the final page.
    inventory_serials = {health_serial(record.get("inventory")) for record in inventory_records}
    missing_identity = sum(health_serial(record.get("inventory")) is None for record in inventory_records)
    inventory_serials.discard(None)
    serials = sorted(inventory_serials | seen)

    def issues(serial):
        return serial, read("/config-health/active-issue", serial=serial)
    audit_progress(progress, "Configuration health", 0, len(serials), "Reading active issues")
    issue_results = dict(ordered_parallel(serials, issues, workers,
        completed=lambda done, total: audit_progress(progress, "Configuration health", done, total,
                                                      "Reading active issues")))
    print(f"Configuration health: summary={summary_status}; observed={len(observed)}; "
          f"issue reads={sum(v['status'] == 'response_received' for v in issue_results.values())}/{len(serials)}; "
          f"inventory entries without serial={missing_identity}", flush=True)
    return {"summary_status": summary_status, "count_confirmed": count_confirmed,
            "summary_pages": pages, "devices": observed, "active_issues": issue_results,
            "inventory_serials_missing_from_summary": sorted(inventory_serials - seen),
            "inventory_entries_without_serial": missing_identity, "safe_to_apply": False}


def capture_configuration_operational_vlans(client, results, workers=AUDIT_WORKERS, progress=None):
    """Best-effort switch monitoring evidence; never block the configuration audit."""
    tasks = [(persona, scope) for persona, entry in sorted(results.items())
             if persona in PERSONAS for scope in entry["scopes"] if scope["kind"] == "device"]
    def collect(task):
        persona, scope = task
        try:
            metadata = scope.get("metadata") or {}
            evidence = probe_operational_vlans(client, metadata)
            if evidence.get("status") == "response_received":
                evidence["voice_filter"] = collect_monitoring_voice_filter(client, metadata, evidence)
        except (RuntimeError, OSError, ValueError):
            evidence = {"status": "monitoring_read_failed"}
        return persona, scope["id"], {**evidence, "captured_at": datetime.now(timezone.utc).isoformat()}
    audit_progress(progress, "Operational VLANs", 0, len(tasks), "Reading switch monitoring")
    observations = defaultdict(dict)
    for persona, sid, evidence in ordered_parallel(tasks, collect, workers,
            completed=lambda done, total: audit_progress(progress, "Operational VLANs", done, total, "Reading switch monitoring")):
        observations[persona][sid] = evidence
    return dict(observations)


def parse_show_vlan(result):
    """Accept a uniquely recognizable CX show vlan table; never infer from arbitrary text."""
    texts = []
    def collect(value):
        if isinstance(value, str) and "\n" in value:
            texts.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)
    collect(result)
    header = re.compile(r"^\s*VLAN\s+Name\s+Status\s+Reason\s+Type\s+Interfaces\s*$", re.I)
    candidates = [s for s in texts if any(header.fullmatch(line) for line in s.splitlines())]
    if len(candidates) != 1:
        return {"status": "schema_unresolved", "vlans": {}}
    vlans = {}
    seen = False
    for line in candidates[0].splitlines():
        if header.fullmatch(line):
            seen = True
            continue
        if not seen:
            continue
        match = re.fullmatch(r"\s*(\d+)\s+(.+?)\s+(up|down)\s+(\S+)\s+(\S+)(?:\s+.*)?", line, re.I)
        if not match:
            continue
        vid, name, state, reason, vlan_type = match.groups()
        if not 1 <= int(vid) <= 4094 or vid in vlans:
            return {"status": "identity_unresolved", "vlans": {}}
        record = {"name": name, "status": state.lower(), "reason": reason, "type": vlan_type}
        # Up/ok explicitly proves an operationally enabled VLAN; down alone
        # does not establish administrative shutdown.
        if state.lower() == "up" and reason.lower() == "ok":
            record["enable"] = True
        elif state.lower() == "down" and reason.lower() == "admin_down":
            record["enable"] = False
        vlans[vid] = record
    return {"status": "observed" if vlans else "schema_unresolved", "vlans": vlans}


VLAN_FEATURE_COMMANDS = {
    "voice-enable": "show vlan voice",
    "igmp": "show ip igmp snooping",
    "mld": "show ipv6 mld snooping",
    "dhcpv4-snooping": "show dhcpv4-snooping",
    "dhcpv6-snooping": "show dhcpv6-snooping",
}


VLAN_FEATURE_ALTERNATIVES = {"igmp": "show ip igmp", "mld": "show ipv6 mld"}


def parse_multicast_interface_output(text, field, vlan_ids):
    """Only explicit snooping flags in VLAN interface records are evidence."""
    if not isinstance(text, str) or field not in VLAN_FEATURE_ALTERNATIVES:
        return {}
    records, conflicts, current = {}, set(), None
    for line in text.splitlines():
        match = re.fullmatch(r"\s*Interface\s*:\s*(.*?)\s*", line, re.I)
        if match:
            vlan = re.fullmatch(r"vlan\s*(\d+)", match[1], re.I)
            current = vlan[1] if vlan and vlan[1] in vlan_ids else None
            continue
        if re.match(r"\s*VRF Name\s*:", line, re.I):
            current = None
            continue
        flag = re.fullmatch(r"\s*" + field.upper() + r" Snoop Enabled on VLAN\s*:\s*(True|False)\s*", line, re.I)
        if current is not None and flag:
            value = {"snooping": flag[1].lower() == "true"}
            if current in records and records[current] != value:
                conflicts.add(current)
            records[current] = value
    return {vid: value for vid, value in records.items() if vid not in conflicts}


def multicast_interface_evidence(text, field, vlan_ids):
    """Recognize empty L3 interface output without guessing L2 snooping."""
    values = parse_multicast_interface_output(text, field, vlan_ids)
    if values:
        status = "observed" if set(values) == vlan_ids else "partial"
    elif field in VLAN_FEATURE_ALTERNATIVES and isinstance(text, str) and re.fullmatch(
            r"\s*" + field.upper() + r" is not enabled on any of the interfaces\.\s*", text):
        status = "no_multicast_interfaces"
    else:
        status = "schema_unresolved"
    return {"status": status, "vlans": values}


def extract_command_output(result, command):
    """Read the exact live Central result envelope, not arbitrary strings."""
    if not isinstance(result, dict) or not isinstance(result.get("output"), dict):
        return None
    records = result["output"].get("results")
    if not isinstance(records, list):
        return None
    matches = [r.get("output") for r in records if isinstance(r, dict) and r.get("command") == command]
    return matches[0] if len(matches) == 1 and isinstance(matches[0], str) else None


def supported_show_commands(payload):
    """Collect exact CLI strings from the returned command inventory."""
    commands = set()
    def walk(value):
        if isinstance(value, str) and re.fullmatch(r"show [a-zA-Z0-9 _./|<>-]+", value):
            commands.add(value.strip())
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(payload)
    return commands


def parse_vlan_feature(result, field, vlan_ids):
    """Only use explicit, recognized CLI evidence for known VLAN identities."""
    texts = []
    def collect(value):
        if isinstance(value, str) and value.strip():
            texts.append(value)
        elif isinstance(value, dict):
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
    if isinstance(result, dict):
        output = extract_command_output(result, VLAN_FEATURE_COMMANDS[field])
        if output is not None:
            texts.append(output)
        else:
            return {"status": "schema_unresolved", "vlans": {}}
    else:
        collect(result)
    candidates = []
    for body in texts:
        if re.fullmatch(r"\s*Command ['\"].+?['\"] not allowed\s*", body, re.I):
            return {"status": "command_not_allowed", "vlans": {}}
        lines = body.splitlines()
        if field == "voice-enable":
            if any(re.fullmatch(r"\s*Voice VLAN not configured\s*", line, re.I) for line in lines):
                candidates.append({vid: False for vid in vlan_ids})
                continue
            header = re.compile(r"\s*VLAN\s+Name\s+Status\s+Type\s+Interfaces\s*", re.I)
            if not any(header.fullmatch(line) for line in lines):
                continue
            seen, members, invalid = False, set(), False
            for line in lines:
                if header.fullmatch(line):
                    seen = True
                    continue
                if not seen or not line.strip() or re.fullmatch(r"\s*-+\s*", line):
                    continue
                match = re.fullmatch(r"\s*(\d+)\s+.+?\s+(?:up|down)\s+\S+(?:\s+.*)?", line, re.I)
                if match and match[1] in vlan_ids:
                    members.add(match[1])
                elif re.match(r"\s*\d+\s", line):
                    invalid = True
            if not invalid and members:
                candidates.append({vid: vid in members for vid in vlan_ids})
        elif field in ("dhcpv4-snooping", "dhcpv6-snooping"):
            label = "DHCPv6-Snooping" if field == "dhcpv6-snooping" else "(?:DHCPv4-Snooping|DHCP-Snooping)"
            # CX prints two labelled columns on one line. Match the exact
            # global label and exact Enabled VLANs column, excluding trusted bindings.
            global_states = [m[1].lower() for line in lines
                             if (m := re.match(r"\s*" + label + r"\s*:\s*(Yes|No)(?:\s{2,}.*)?\s*$", line, re.I))]
            values = [m[1].strip() for line in lines
                      if (m := re.search(r"(?:^\s*|\s{2,})Enabled VLANs\s*:\s*(.*?)\s*$", line, re.I))]
            if len(global_states) != 1 or len(values) != 1:
                continue
            members = set() if values[0].lower() in ("", "none") else parse_reference_ids(values[0], True)
            if members is not None and members <= vlan_ids:
                candidates.append({vid: {"enable": vid in members} for vid in vlan_ids})
        else:
            protocol = field.upper()
            records, current, invalid = {}, None, False
            for line in lines:
                match = re.fullmatch(r"\s*VLAN ID\s*:\s*(\d+)\s*", line, re.I)
                if match:
                    current = match[1]
                    if current in records:
                        invalid = True
                    continue
                if current not in vlan_ids:
                    continue
                disabled = re.fullmatch(r"\s*" + protocol + r" Snooping is not enabled\s*", line, re.I)
                enabled = re.fullmatch(r"\s*" + protocol + r" Operating Version\s*:\s*[123]\s*", line, re.I)
                if disabled or enabled:
                    value = {"snooping": bool(enabled)}
                    if current in records and records[current] != value:
                        invalid = True
                    records[current] = value
            if records and not invalid:
                candidates.append(records)
    if len(candidates) != 1:
        return {"status": "schema_unresolved", "vlans": {}}
    return {"status": "observed", "vlans": candidates[0]}


def parse_vlan_running_config(text, vlan_ids):
    """Extract explicit VLAN-context feature commands only; absent is unknown."""
    if not isinstance(text, str) or not re.search(r"(?m)^vlan [0-9]", text):
        return {}
    patterns = {
        "voice": ("voice-enable", True), "no voice": ("voice-enable", False),
        "ip igmp snooping enable": ("igmp", {"snooping": True}),
        "ip igmp snooping disable": ("igmp", {"snooping": False}),
        "no ip igmp snooping enable": ("igmp", {"snooping": False}),
        "ipv6 mld snooping enable": ("mld", {"snooping": True}),
        "ipv6 mld snooping disable": ("mld", {"snooping": False}),
        "no ipv6 mld snooping enable": ("mld", {"snooping": False}),
    }
    records, conflicts, current = {}, set(), set()
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            match = re.fullmatch(r"vlan ([0-9, -]+)", line.strip())
            current = ((parse_reference_ids(match[1], True) or set()) & vlan_ids) if match else set()
            continue
        parsed = patterns.get(line.strip())
        if parsed is None:
            continue
        field, value = parsed
        for vid in current:
            record = records.setdefault(vid, {})
            if field in record and canonical(record[field]) != canonical(value):
                conflicts.add((vid, field))
            record[field] = value
    for vid, field in conflicts:
        records[vid].pop(field, None)
    return {vid: record for vid, record in records.items() if record}


def capture_switch_vlan_cli(client, results, details, workers=AUDIT_WORKERS, progress=None):
    """One bounded show vlan task per affected switch, after direct API reads."""
    tasks = []
    for persona, entry in sorted(results.items()):
        for scope in entry["scopes"]:
            sid = scope["id"]
            if persona not in PERSONAS or scope["kind"] != "device" or not details.get(persona, {}).get(sid):
                continue
            metadata = scope.get("metadata") or {}
            # Use the discovered serial, not a guessed stack identifier.
            serial = metadata.get("conductorSerialNumber") or metadata.get("serialNumber") or metadata.get("serial")
            tasks.append((persona, sid, serial))
    def collect(task):
        persona, sid, serial = task
        result = {"status": "identity_unresolved"}
        if isinstance(serial, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", serial):
            try:
                response = client.show_vlans(serial)
                result = parse_show_vlan(response["result"]) if response["status"] == "completed" else response
            except APIError as exc:
                result = {"status": "permission_denied" if exc.status == 403 else "request_rejected",
                          "http_error": exc.status}
            except (RuntimeError, OSError, ValueError, AttributeError):
                result = {"status": "read_failed"}
        return persona, sid, {**result, "captured_at": datetime.now(timezone.utc).isoformat()}
    audit_progress(progress, "Switch VLAN verification", 0, len(tasks), "Reading show vlan on affected switches")
    output = {}
    for persona, sid, evidence in ordered_parallel(tasks, collect, min(workers, 4),
            completed=lambda done, total: audit_progress(progress, "Switch VLAN verification", done, total, "Reading show vlan")):
        output.setdefault(persona, {})[sid] = evidence
    # Run feature commands separately: a rejected command must not discard
    # successful evidence from other commands or the base VLAN table.
    feature_tasks = []
    for persona, sid, serial in tasks:
        base = output[persona][sid]
        if base["status"] == "observed":
            feature_tasks.append((persona, sid, serial, set(base["vlans"])))
    def collect_feature(task):
        persona, sid, serial, field, command, ids = task
        try:
            response = client.show_vlan_command(serial, command)
            result = parse_vlan_feature(response["result"], field, ids) if response["status"] == "completed" else response
        except APIError as exc:
            result = {"status": "permission_denied" if exc.status == 403 else "request_rejected",
                      "http_error": exc.status}
        except (RuntimeError, OSError, ValueError, AttributeError):
            result = {"status": "read_failed"}
        return persona, sid, field, result
    def collect_features(task):
        persona, sid, serial, ids = task
        try:
            allowed = supported_show_commands(client.list_show_commands(serial))
        except (RuntimeError, OSError, ValueError, AttributeError):
            allowed = set()
        results = []
        for field, command in VLAN_FEATURE_COMMANDS.items():
            alternative = VLAN_FEATURE_ALTERNATIVES.get(field)
            if allowed and command not in allowed and alternative in allowed:
                try:
                    response = client.show_vlan_command(serial, alternative)
                    if response["status"] == "completed":
                        result = multicast_interface_evidence(extract_command_output(response["result"], alternative), field, ids)
                        result["sources"] = {vid: alternative for vid in result["vlans"]}
                    else:
                        result = response
                except APIError as exc:
                    result = {"status": "request_rejected", "http_error": exc.status}
                except (RuntimeError, OSError, ValueError, AttributeError):
                    result = {"status": "read_failed"}
                results.append((persona, sid, field, result))
            elif allowed and command not in allowed:
                results.append((persona, sid, field, {"status": "command_not_listed"}))
            else:
                results.append(collect_feature((persona, sid, serial, field, command, ids)))
        # Prefer the explicit-default config when Central actually lists it.
        # Never store or log the full running configuration.
        missing = {field for _, _, field, result in results
                   if field in ("voice-enable", "igmp", "mld")
                   and set(result.get("vlans", {})) != ids}
        config_command = next((cmd for cmd in ("show running-config all", "show running-config") if cmd in allowed), None)
        if missing and config_command:
            try:
                response = client.show_vlan_command(serial, config_command)
                parsed = parse_vlan_running_config(extract_command_output(response.get("result"), config_command), ids)
                for index, (_, _, field, result) in enumerate(results):
                    if field not in missing:
                        continue
                    values = {vid: fields[field] for vid, fields in parsed.items() if field in fields}
                    if values:
                        existing = result.get("vlans", {})
                        merged = {**values, **existing}
                        results[index] = (persona, sid, field, {"status": "observed" if set(merged) == ids else "partial",
                            "vlans": merged, "sources": {**result.get("sources", {}), **{vid: config_command for vid in values if vid not in existing}}})
            except (RuntimeError, OSError, ValueError, AttributeError):
                pass
        return results
    audit_progress(progress, "Switch VLAN features", 0, len(feature_tasks), "Reading snooping and voice VLAN settings")
    # Run at most one command at a time on each device.
    for feature_results in ordered_parallel(feature_tasks, collect_features, min(workers, 4),
            completed=lambda done, total: audit_progress(progress, "Switch VLAN features", done, total, "Reading VLAN feature evidence")):
        for persona, sid, field, result in feature_results:
            base = output[persona][sid]
            base.setdefault("features", {})[field] = {"status": result["status"],
                                                     **({"http_error": result["http_error"]} if "http_error" in result else {})}
            for vid, value in result.get("vlans", {}).items():
                base["vlans"][vid][field] = value
                if vid in result.get("sources", {}):
                    base["vlans"][vid].setdefault("feature_sources", {})[field] = result["sources"][vid]
    return output


def vlan_comparison_evidence(bundle, persona, sid, row):
    """Resolve observed values without inventing saved configuration or hiding disagreements."""
    import copy
    details = bundle.get("vlan_instance_details", {}).get(persona, {}).get(sid, {}).get(row["identity"], {})
    local = copy.deepcopy(row["local"])
    effective = copy.deepcopy(row["effective"])
    sources = {}
    conflicts = []
    def merge(target, extra, path, source):
        for key, value in extra.items():
            here = path + (key,)
            if key not in target:
                target[key] = copy.deepcopy(value)
                sources[".".join(here)] = source
            elif isinstance(target[key], dict) and isinstance(value, dict):
                merge(target[key], value, here, source)
            elif canonical(target[key]) != canonical(value):
                conflicts.append(".".join(here))
    for kind, body in (("local", local), ("effective", effective)):
        detail = details.get(kind, {})
        if isinstance(body, dict) and detail.get("status") == "observed":
            merge(body, detail["profile"], (kind,), "Central VLAN by ID")
    if isinstance(local, dict) and isinstance(effective, dict):
        conflicts.extend("local_vs_effective." + ".".join(map(str, d["path"])) for d in field_differences(local, effective)
                         if d["kind"] not in ("missing_local", "missing_reference"))
    deployed = {}
    cli = bundle.get("switch_vlan_cli", {}).get(persona, {}).get(sid, {})
    live = cli.get("vlans", {}).get(row["identity"], {}) if cli.get("status") == "observed" else {}
    monitor = configuration_operational_vlan(bundle, persona, sid, row["identity"])
    if monitor["status"] == "observed":
        fields = monitor["fields"]
        if isinstance(fields.get("name"), str):
            deployed["name"] = {"value": fields["name"], "source": "Switch monitoring"}
        voice = voice_state(fields.get("voice"))
        if voice is not None:
            deployed["voice-enable"] = {"value": voice, "source": "Switch monitoring"}
        else:
            filter_view = bundle.get("operational_vlans", {}).get(persona, {}).get(sid, {}).get("voice_filter", {})
            filtered = filter_view.get("values", {}).get(row["identity"])
            if filter_view.get("status") == "observed" and type(filtered) is bool:
                deployed["voice-enable"] = {"value": filtered, "source": "Switch monitoring voice filter"}
    for key in ("name", "enable", *VLAN_FEATURE_COMMANDS):
        if key in live:
            if key in deployed and canonical(deployed[key]["value"]) != canonical(live[key]):
                conflicts.append("device." + key)
            deployed[key] = {"value": live[key], "source": "Switch " + live.get("feature_sources", {}).get(key, VLAN_FEATURE_COMMANDS.get(key, "show vlan"))}
    # Actual device observations complement the comparison, but are not saved
    # local fields and must not be used as executable configuration.
    comparison = copy.deepcopy(effective)
    if isinstance(comparison, dict):
        for key, observed in deployed.items():
            if key not in comparison:
                comparison[key] = observed["value"]
                sources["comparison." + key] = observed["source"]
            elif isinstance(comparison[key], dict) and isinstance(observed["value"], dict):
                merge(comparison[key], observed["value"], ("comparison", key), observed["source"])
            elif canonical(comparison[key]) != canonical(observed["value"]):
                conflicts.append("device." + key)
    reference = row["global_reference"]
    differences = field_differences(comparison, reference) if comparison is not None and reference is not None else None
    return {"local": local, "effective": effective, "comparison": comparison,
            "sources": sources, "device_observations": deployed, "conflicts": sorted(set(conflicts)),
            "feature_status": {field: outcome.get("status") for field, outcome in cli.get("features", {}).items()},
            "differences": differences, "safe_to_apply": False}


# The VLAN identity is not a configuration match. Count the actual settings,
# including known fields omitted on both sides. Keep GET-only L3 evidence
# separate from the configurable settings.
VLAN_REVIEW_FIELDS = ("name", "enable", "voice-enable", "igmp", "mld",
                      "dhcpv4-snooping", "dhcpv6-snooping")


def comparison_fields(effective, reference, *, vlan=False, conflicts=(), saved=None):
    """Return one consistent, non-executable field assessment for review.

    Compare structured leaves, not serialized objects. Missing/null values
    are unknown, not equal or different. Arrays retain exact ordering.
    """
    def walk(left, right, local, path):
        if any(isinstance(v, dict) for v in (left, right, local)):
            if all(v is MISSING or isinstance(v, dict) for v in (left, right, local)):
                keys = set().union(*(v.keys() for v in (left, right, local) if isinstance(v, dict)))
                if keys:
                    for key in sorted(keys):
                        yield from walk(*(v.get(key, MISSING) if isinstance(v, dict) else MISSING
                                          for v in (left, right, local)), path + (key,))
                    return
        field = ".".join(map(str, path))
        conflicted = any(c == field or c.endswith("." + field) or ("." + field + ".") in c
                         for c in conflicts)
        if conflicted:
            state = "conflict"
        elif left is MISSING or right is MISSING or left is None or right is None:
            state = "unavailable"
        else:
            state = "matching" if canonical(left) == canonical(right) else "different"
        yield {"path": list(path), "state": state}

    left = effective if isinstance(effective, dict) else {}
    right = reference if isinstance(reference, dict) else {}
    local = saved if isinstance(saved, dict) else {}
    keys = left.keys() | right.keys() | local.keys()
    if vlan:
        keys |= set(VLAN_REVIEW_FIELDS)
    rows = [row for key in sorted(keys) for row in walk(left.get(key, MISSING), right.get(key, MISSING),
                                                        local.get(key, MISSING), (key,))]
    relevant = [r for r in rows if not vlan or r["path"][0] not in ("vlan", "is-l3-vlan")]
    counts = dict.fromkeys(("matching", "different", "unavailable", "conflict"), 0)
    for row in relevant:
        counts[row["state"]] += 1
    return {"rows": rows, "counts": counts, "unavailable": [r["path"] for r in relevant if r["state"] == "unavailable"],
            "different": [r["path"] for r in relevant if r["state"] == "different"],
            "safe_to_apply": False}


def vlan_evidence_summary(bundle):
    """Anonymous diagnostics: field names and counts only; no tenant values."""
    states, fields, sources, cli, details, monitoring = (Counter() for _ in range(6))
    features = defaultdict(Counter)
    for persona, entry in bundle["results"].items():
        if persona not in PERSONAS:
            continue
        for scope in entry["modules"].get("layer2-vlan", {}).get("scope_results", []):
            if scope["scope_kind"] != "device" or not scope["review"]["qualified"]:
                continue
            sid = scope["scope"]
            for row in scope["review"]["profiles"]:
                if row["local"] is None or row["global_reference"] is None:
                    continue
                evidence = vlan_comparison_evidence(bundle, persona, sid, row)
                sources.update(evidence["sources"].values())
                if row["identity"] == "1":
                    states["protected_default_vlan"] += 1
                    fields.update(safe_difference_path(d["path"]) for d in (evidence["differences"] or [])
                                  if d["kind"] in ("missing_local", "missing_reference"))
                    continue
                if evidence["conflicts"]:
                    states["conflicting_observations"] += 1
                elif evidence["differences"] == []:
                    states["observed_match"] += 1
                elif evidence["differences"] is not None:
                    missing = [d for d in evidence["differences"] if d["kind"] in ("missing_local", "missing_reference")]
                    states["unresolved_fields" if missing else "explicit_difference"] += 1
                    fields.update(safe_difference_path(d["path"]) for d in missing)
                else:
                    states["not_comparable"] += 1
    for scopes in bundle.get("switch_vlan_cli", {}).values():
        for value in scopes.values():
            cli[value["status"]] += 1
            for field, outcome in value.get("features", {}).items():
                features[field][outcome["status"]] += 1
    for scopes in bundle.get("operational_vlans", {}).values():
        for value in scopes.values():
            monitoring[value["status"]] += 1
    for scopes in bundle.get("vlan_instance_details", {}).values():
        for instances in scopes.values():
            for views in instances.values():
                details.update(v["status"] for v in views.values())
    return {"comparisons": dict(states), "remaining_fields": dict(fields),
            "recovered_values": dict(sources), "individual_vlan_reads": dict(details),
            "switch_cli": dict(cli), "monitoring": dict(monitoring),
            "feature_cli": {field: dict(counts) for field, counts in features.items()}}


def monitoring_vlan_records(payload):
    """Recognize one complete, uniquely keyed monitoring list."""
    if not isinstance(payload, dict):
        return None
    lists = [v for k, v in payload.items() if k != "metadata" and isinstance(v, list)]
    if len(lists) != 1 or len(lists[0]) >= 1000:
        return None
    if any(type(payload[key]) is not int or payload[key] != len(lists[0])
           for key in ("count", "total") if key in payload):
        return None
    if "offset" in payload and (type(payload["offset"]) is not int or payload["offset"] != 0):
        return None
    records = {}
    for item in lists[0]:
        ids = parse_reference_ids(item.get("id")) if isinstance(item, dict) else None
        if not ids or next(iter(ids)) in records:
            return None
        records[next(iter(ids))] = item
    return records


def voice_state(value):
    if type(value) is bool:
        return value
    if isinstance(value, str) and value.lower() in ("enabled", "disabled"):
        return value.lower() == "enabled"
    return None


def collect_monitoring_voice_filter(client, metadata, evidence):
    """Verify complementary documented filters against the unfiltered VLAN set."""
    records = monitoring_vlan_records(evidence.get("payload"))
    if not records or all(voice_state(r.get("voice")) is not None for r in records.values()):
        return {"status": "not_needed_or_unavailable", "values": {}}
    serial = metadata.get(evidence.get("identity_field"))
    if not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,16}", serial):
        return {"status": "identity_unresolved", "values": {}}
    path = "/network-monitoring/v1/switches/" + quote(serial, safe="") + "/vlans"
    observations = {}
    counts = {}
    for label, enabled in (("Enabled", True), ("Disabled", False)):
        try:
            raw = client.get(path, limit=1000, offset=0, filter=f"voice eq '{label}'")
            rows = monitoring_vlan_records(raw)
        except (RuntimeError, OSError, ValueError):
            return {"status": "filter_read_failed", "values": {}, "counts": counts}
        if rows is None:
            return {"status": "filter_schema_unresolved", "values": {}, "counts": counts}
        counts[label] = len(rows)
        for vid, row in rows.items():
            explicit = voice_state(row.get("voice"))
            original = voice_state(records.get(vid, {}).get("voice"))
            if (vid in observations or vid not in records or
                    any(value is not None and value != enabled for value in (explicit, original))):
                return {"status": "filter_conflict", "values": {}, "counts": counts}
            observations[vid] = enabled
    if set(observations) != set(records):
        return {"status": "filter_incomplete", "values": {}, "counts": counts}
    return {"status": "observed", "values": observations, "counts": counts}


def configuration_operational_vlan(bundle, persona, sid, vid):
    """Return the exact reported monitoring fields for one uniquely observed VLAN."""
    evidence = bundle.get("operational_vlans", {}).get(persona, {}).get(sid, {})
    result = {"status": evidence.get("status", "not_collected"), "captured_at": evidence.get("captured_at")}
    if result["status"] != "response_received":
        return result
    payload = evidence.get("payload")
    if not isinstance(payload, dict):
        return {**result, "status": "schema_unresolved"}
    lists = [v for k, v in payload.items() if k != "metadata" and isinstance(v, list)]
    if len(lists) != 1 or not all(isinstance(v, dict) for v in lists[0]):
        return {**result, "status": "schema_unresolved"}
    matches = [v for v in lists[0] if parse_reference_ids(v.get("id")) == {str(vid)}]
    if len(matches) != 1:
        return {**result, "status": "identity_unresolved" if len(matches) > 1 else
                "not_observed", "may_be_truncated": len(lists[0]) >= 1000}
    return {**result, "status": "observed", "fields": {k: matches[0][k] for k in
            ("id", "name", "status", "type", "ipv4", "taggedPorts", "untaggedPorts", "voice") if k in matches[0]},
            "may_be_truncated": len(lists[0]) >= 1000}


def configuration_audit(client, selected_persona=None, *, workers=AUDIT_WORKERS, progress=None, deep_catalog=False):
    """Inventory-driven read-only audit with bounded parallel scope reads."""
    from api_coverage import ReadCoverage
    client = ReadCoverage(client)
    audit_progress(progress, "Discovery", 0, 0, "Reading device inventory and assignments")
    devices = inventory(client)
    records = inventory_capabilities(devices)
    personas = sorted({r["identity"]["persona"] for r in records})
    if selected_persona:
        if selected_persona not in personas:
            raise ValueError("Selected persona is not in inventory")
        personas = [selected_persona]
    assignments = profile_inventory_view(client, "config-assignments", "config-assignment")
    # The vendor SDK still uses deprecated scope-maps as read-only evidence
    # for local profiles. Its absence never means there are no local profiles.
    scope_maps = profile_inventory_view(client, "scope-maps", "scope-map")
    # Enumerate scopes once, then supplement the assignment inventory before
    # choosing the module catalog so newly discovered types are included.
    scopes_by_persona = {}
    for persona in personas:
        if persona not in NETWORK_PERSONAS:
            continue
        audit_progress(progress, "Discovery", 0, 0, f"Discovering {persona} scopes")
        scopes_by_persona[persona], _ = discover_scopes(client, persona, devices)
    assignments = collect_scoped_assignments(client, assignments, scopes_by_persona, workers, progress)
    print("Assignment evidence coverage: " + canonical({
        "additional_assignments": assignments["additional_assignments"],
        "scope_reads": assignments["scope_read_outcomes"]}), flush=True)
    profile_types = discover_profile_types(assignments, scope_maps)
    catalog = documented_profile_catalog()
    profile_types["documented_catalog"] = catalog
    profile_types["survey_modules"] = sorted((DOCUMENTED_RAW_COLLECTIONS | set(catalog["modules"])) - set(CONFIG_MODULES))
    print(f"Documented catalog: {catalog['get_requests']} GET definitions; "
          f"{len(catalog['modules'])} profile collections; "
          f"{len(profile_types['survey_modules'])} additional Library surveys", flush=True)
    print(f"Observed profile types: {len(profile_types['modules'])}; "
          f"without adapter: {len(profile_types['unknown_adapter_modules'])}", flush=True)
    results = {}
    unqualified = []
    plans = []
    for persona in personas:
        modules = {m: spec for m, spec in CONFIG_MODULES.items()
                   if m != "auth-profiles" and (persona in spec[1]
                   or persona in profile_types["modules"].get(m, []))}
        if not modules:
            unqualified.append(persona)
            continue
        scopes = scopes_by_persona.get(persona)
        if scopes is None:
            scopes, _ = discover_scopes(client, persona, devices)
        plans.append((persona, modules, scopes))
    total_scopes = sum(sum(not spec[2] or s["kind"] == "device" for s in scopes)
                       for _, modules, scopes in plans for spec in modules.values())
    completed_scopes = 0
    for persona, modules, scopes in plans:
        module_results = {}
        print(f"Configuration audit: {persona}; scopes={len(scopes)}; modules={len(modules)}", flush=True)
        tasks = [(module, identity, scope)
                 for module, (identity, _, device_only) in modules.items()
                 for scope in scopes if not device_only or scope["kind"] == "device"]
        audit_progress(progress, "Configuration scopes", completed_scopes, total_scopes, persona)
        def read_scope(task):
            module, identity, scope = task
            params = {"view-type": "LOCAL", "scope-id": scope["id"], "device-function": persona}
            local = read_module_view(client, module, identity, {**params, "object-type": "LOCAL",
                                                                "effective": "false", "detailed": "false"})
            effective = read_module_view(client, module, identity, {**params, "effective": "true", "detailed": "true"})
            local = recover_local_view(client, module, identity, params, local, effective)
            return module, scope, local, effective
        grouped = defaultdict(list)
        for module, scope, local, effective in ordered_parallel(
                tasks, read_scope, workers,
                item_completed=lambda done, total, task: audit_progress(
                    progress, "Configuration scopes", completed_scopes + done,
                    total_scopes, f"{persona} / {task[0]}")):
            grouped[module].append((scope, local, effective))
        completed_scopes += len(tasks)
        for module, (identity, _, device_only) in modules.items():
            scope_results = []
            baseline = None
            totals = Counter()
            captured = grouped[module]
            applicable = captured
            for scope, _, effective in captured:
                if scope["kind"] == "global" and effective["status"] == "list_parsed":
                    baseline = effective["profiles"]
            for scope, local, effective in captured:
                review = review_module_scope(local, effective, baseline, device_only, scope["kind"] == "global")
                totals["qualified_scopes" if review["qualified"] else "unqualified_scopes"] += 1
                totals.update(row["status"] for row in review["profiles"])
                scope_results.append({"scope": scope["id"], "scope_kind": scope["kind"],
                                      "local_view": local, "effective_view": effective, "review": review})
            module_results[module] = {"scope_results": scope_results, "summary": dict(totals),
                                      "device_scope_only": device_only}
            print(f"  {module}: qualified={totals['qualified_scopes']}/{len(applicable)}; "
                  f"local differing from Global={totals['local_differs_from_global']}; "
                  f"local matching Global={totals['local_matches_global']}; "
                  f"other local={sum(totals[k] for k in ('device_local_profile', 'global_local_profile', 'local_without_global_match', 'global_reference_unverified', 'local_effective_mismatch'))}; "
                  f"source conflicts={totals['source_conflict']}", flush=True)
            errors = Counter((v["status"], v.get("http_error")) for s in scope_results
                             for v in (s["local_view"], s["effective_view"])
                             if v["status"] not in ("list_parsed", "empty_object"))
            for (status, http), count in sorted(errors.items(), key=str):
                print(f"    {status}{' HTTP ' + str(http) if http else ''}: {count}", flush=True)
        results[persona] = {"scopes": scopes, "modules": module_results}
    # Library definitions can exist without any assignment or active device
    # function. Always survey the entire explicitly supported Library catalog.
    applicable_modules = set(CONFIG_MODULES)
    print("Reading tenant Library and assignments", flush=True)
    library = library_inventory(client, applicable_modules, assignments, scope_maps, workers, progress)
    unadapted = inspect_unadapted_profiles(client, profile_types, assignments, scope_maps, workers, progress,
                                           scopes_by_persona=scopes_by_persona, deep_catalog=deep_catalog)
    health = capture_configuration_health(client, records, workers, progress)
    keyed_details = capture_keyed_profile_details(client, results, library, workers, progress) if deep_catalog else None
    details = capture_vlan_instance_details(client, results, workers, progress)
    operational = capture_configuration_operational_vlans(client, results, workers, progress)
    cli = capture_switch_vlan_cli(client, results, details, workers, progress)
    print(f"Configuration audit coverage: personas reviewed={len(results)}; "
          f"personas without adapter={len(unqualified)}; migration authorized=no")
    bundle = {"schema": 1, "kind": "configuration_audit", "region": client.base,
            "captured_at": datetime.now(timezone.utc).isoformat(), "inventory": records,
            "results": results, "unqualified_personas": unqualified, "library": library,
            "profile_type_discovery": profile_types, "unadapted_profiles": unadapted,
            "operational_vlans": operational, "vlan_instance_details": details, "switch_vlan_cli": cli,
            "configuration_health": health,
            "keyed_profile_details": keyed_details,
            "api_read_coverage": client.report(),
            "catalog_exhaustive": False, "safe_to_apply": False}

    coverage_counts = Counter(row["status"] for row in bundle["api_read_coverage"]["operations"])
    print("Documented GET operation outcomes: " + canonical(dict(coverage_counts)), flush=True)
    print("VLAN evidence coverage: " + canonical(vlan_evidence_summary(bundle)), flush=True)
    return bundle


def configuration_view_shape(view):
    """Shareable structural diagnostics; never emit profile keys, names or values."""
    raw = view.get("raw")
    shape = {"status": view.get("status", "unknown")}
    if "http_error" in view:
        shape["http"] = view["http_error"]
    if isinstance(raw, dict):
        metadata = raw.get("metadata", {})
        shape["list_lengths"] = sorted(len(v) for k, v in raw.items()
                                       if k != "metadata" and isinstance(v, list))
        shape["object_fields"] = sum(isinstance(v, dict) for k, v in raw.items() if k != "metadata")
        shape["other_fields"] = sum(not isinstance(v, (dict, list)) for k, v in raw.items() if k != "metadata")
        if isinstance(metadata, dict):
            for key in ("total", "count", "offset", "limit"):
                if type(metadata.get(key)) is int:
                    shape[key] = metadata[key]
            counts = metadata.get("count_objects_in_module")
            if isinstance(counts, dict):
                shape["object_counts"] = {k: counts[k] for k in ("LOCAL", "SHARED", "ANY")
                                          if type(counts.get(k)) is int}
    return shape


def config_review_rows(bundle):
    if bundle.get("schema") != 1 or bundle.get("kind") != "configuration_audit":
        raise ValueError("Expected a configuration audit bundle")
    for persona, entry in sorted(bundle["results"].items()):
        names = {s["id"]: s.get("name", s["kind"]) for s in entry["scopes"]}
        for module, data in sorted(entry["modules"].items()):
            for scope in data["scope_results"]:
                yield persona, module, names.get(scope["scope"], scope["scope_kind"]), scope


def print_configuration_diagnostics(bundle):
    diagnostics = defaultdict(Counter)
    for persona, module, _, scope in config_review_rows(bundle):
        if scope["review"]["qualified"]:
            continue
        for kind in ("local", "effective"):
            view = scope[kind + "_view"]
            shape = configuration_view_shape(view)
            shape["review_status"] = scope["review"][kind + "_status"]
            diagnostics[persona, module][(scope["scope_kind"], kind, canonical(shape))] += 1
    print("Unqualified configuration views (anonymous shape diagnostics):")
    for (persona, module), shapes in sorted(diagnostics.items()):
        print(f"  {persona}/{module}:")
        for (scope_kind, kind, shape), count in sorted(shapes.items()):
            print(f"    {scope_kind} {kind} x{count}: {shape}")


def refresh_configuration_review(bundle):
    """Reparse saved raw views with current adapters, without network access."""
    if bundle.get("schema") != 1 or bundle.get("kind") != "configuration_audit":
        raise ValueError("Expected a configuration audit bundle")
    for entry in bundle["results"].values():
        for module, data in entry["modules"].items():
            if module not in CONFIG_MODULES:
                continue
            identity, _, device_only = CONFIG_MODULES[module]
            baseline = None
            totals = Counter()
            scopes = sorted(data["scope_results"], key=lambda s: s["scope_kind"] != "global")
            for scope in scopes:
                for kind, object_type in (("local", "LOCAL"), ("effective", "ANY")):
                    view = scope[kind + "_view"]
                    if "raw" in view:
                        parsed = module_view(view["raw"], identity, object_type)
                        if kind == "local" and "alternate_raw" in view and parsed["status"] != "list_parsed":
                            alternative = annotated_committed_local(view["alternate_raw"], identity)
                            if alternative["status"] == "list_parsed":
                                parsed = alternative
                        scope[kind + "_view"] = {**view, **parsed}
                effective = scope["effective_view"]
                if scope["scope_kind"] == "global" and effective["status"] == "list_parsed":
                    baseline = effective["profiles"]
                review = review_module_scope(scope["local_view"], effective, baseline,
                                             device_only, scope["scope_kind"] == "global")
                scope["review"] = review
                totals["qualified_scopes" if review["qualified"] else "unqualified_scopes"] += 1
                totals.update(row["status"] for row in review["profiles"])
            data["summary"] = dict(totals)
    return bundle


def configuration_html(bundle):
    """Generate a private offline dashboard from validated configuration evidence."""
    from config_dashboard import render_dashboard
    return render_dashboard(bundle, list(config_review_rows(bundle)), configuration_view_shape)


def write_private_text(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(payload)


def audit_snapshots(bundle):
    if bundle.get("schema") != 1 or bundle.get("kind") != "tenant_audit":
        raise ValueError("Expected a tenant audit bundle")
    snapshots = {p: entry["snapshot"] for p, entry in bundle["results"].items()}
    if any(s.get("persona") != p or s.get("region") != bundle["region"] for p, s in snapshots.items()):
        raise ValueError("Audit snapshot persona or region mismatch")
    return snapshots


def compare_vlan_views(before, after):
    old, new = vlan_map(before), vlan_map(after)
    return {"added": sorted(new.keys() - old.keys(), key=int),
            "removed": sorted(old.keys() - new.keys(), key=int),
            "modified": [{"vlan": vid, "differences": field_differences(old[vid], new[vid])}
                         for vid in sorted(old.keys() & new.keys(), key=int)
                         if canonical(old[vid]) != canonical(new[vid])]}


def vlan_assignment_evidence(snapshot, vid, scope_id):
    """Find exact endpoint/ID assignments without assuming ancestor relationships."""
    raw = snapshot.get("assignments_raw")
    if not isinstance(raw, dict) or not isinstance(raw.get("config-assignment"), list):
        return {"status": "unavailable", "matches": []}
    matches = [row for row in raw["config-assignment"] if isinstance(row, dict)
               and row.get("profile-type") == "layer2-vlan"
               and row.get("device-function") == snapshot["persona"]
               and parse_reference_ids(row.get("profile-instance")) == {vid}]
    global_id = next(s["id"] for s in snapshot["scopes"] if s["kind"] == "global")
    return {"status": "exact_assignment_matches" if matches else "no_exact_assignment_match",
            "matches": matches,
            "global_assignment": any(row.get("scope-id") == global_id for row in matches),
            "same_scope_assignment": any(row.get("scope-id") == scope_id for row in matches),
            "inheritance_verified": False}


def observed_vlan_record(bundle, persona, sid, vid):
    entries = bundle["results"][persona].get("dependencies", {}).get("devices", [])
    matches = [entry for entry in entries if entry.get("scope_id") == sid]
    if len(matches) != 1:
        return None
    evidence = matches[0].get("operational_vlans", {})
    if evidence.get("status") != "response_received":
        return None
    payload = evidence.get("payload")
    if not isinstance(payload, dict):
        return None
    lists = [v for k, v in payload.items() if k != "metadata" and isinstance(v, list)]
    if len(lists) != 1 or len(lists[0]) >= 1000:
        return None
    records = [item for item in lists[0] if isinstance(item, dict)
               and parse_reference_ids(item.get("id")) == {vid}]
    return records[0] if len(records) == 1 else None


def removal_evidence(previous, current, persona, sid, vid, before, after):
    if before is None or after is None:
        return {"effective_assessment": "not_comparable", "observed_fields": {},
                "behavior_preserved_verified": False}
    assessment = assess_vlan_reference(before, after)
    old = observed_vlan_record(previous, persona, sid, vid)
    new = observed_vlan_record(current, persona, sid, vid)
    observed = {}
    for field in ("name", "taggedPorts", "untaggedPorts", "voice", "ipv4", "status", "type"):
        if old is None or new is None or field not in old or field not in new:
            observed[field] = "not_comparable"
        else:
            observed[field] = "unchanged" if canonical(old[field]) == canonical(new[field]) else "changed"
    return {"effective_assessment": assessment["classification"],
            "effective_differences": assessment["differences"], "observed_fields": observed,
            "multicast_operational_verified": False, "behavior_preserved_verified": False}


def compare_audits(previous, current):
    """Compare captured bodies, not presumed device behavior or inferred causality."""
    old, new = audit_snapshots(previous), audit_snapshots(current)
    if previous["region"] != current["region"]:
        raise ValueError("Audit region mismatch")
    results = {}
    for persona in sorted(old.keys() & new.keys()):
        a, b = old[persona], new[persona]
        def index(snapshot):
            result = {s["id"]: s for s in snapshot["scopes"]}
            if len(result) != len(snapshot["scopes"]):
                raise ValueError("Duplicate scope IDs")
            return result
        x, y = index(a), index(b)
        global_a = [s["id"] for s in x.values() if s["kind"] == "global"]
        global_b = [s["id"] for s in y.values() if s["kind"] == "global"]
        if len(global_a) != 1 or global_a != global_b:
            raise ValueError("Audit Global scope mismatch")
        changes = []
        for sid in sorted(x.keys() & y.keys()):
            if x[sid]["kind"] != y[sid]["kind"]:
                raise ValueError("Scope kind changed")
            local = compare_vlan_views(x[sid]["local"], y[sid]["local"])
            effective = compare_vlan_views(x[sid]["effective"], y[sid]["effective"])
            if any(local.values()) or any(effective.values()):
                before_effective, after_effective = vlan_map(x[sid]["effective"]), vlan_map(y[sid]["effective"])
                removals = []
                for vid in local["removed"]:
                    if vid not in after_effective:
                        status = "effective_vlan_absent"
                    elif vid not in before_effective:
                        status = "previous_effective_vlan_absent"
                    elif canonical(before_effective[vid]) == canonical(after_effective[vid]):
                        status = "effective_body_unchanged"
                    else:
                        status = "effective_body_changed"
                    evidence = removal_evidence(previous, current, persona, sid, vid,
                                                before_effective.get(vid), after_effective.get(vid))
                    removals.append({"vlan": vid, "status": status, "evidence": evidence,
                                     "current_assignment_evidence": vlan_assignment_evidence(b, vid, sid)})
                changes.append({"scope": sid, "kind": y[sid]["kind"], "local": local,
                                "effective": effective, "local_removal_outcomes": removals})
        results[persona] = {"added_scopes": sorted(y.keys() - x.keys()),
                            "removed_scopes": sorted(x.keys() - y.keys()),
                            "library": compare_vlan_views(a["library"], b["library"]),
                            "assignment_response_changed": canonical(a.get("assignments_raw")) != canonical(b.get("assignments_raw")),
                            "scope_changes": changes}
    return {"added_personas": sorted(new.keys() - old.keys()), "removed_personas": sorted(old.keys() - new.keys()),
            "results": results, "same_tenant_verified": False,
            "warning": "Region and Global scope checks do not independently prove tenant identity. Captures are not atomic."}


def offline_audit_review(bundle, previous=None):
    """Regenerate private review and reference previews without contacting Central."""
    snapshots = audit_snapshots(bundle)
    results = {}
    for persona, snapshot in sorted(snapshots.items()):
        dependencies = bundle["results"][persona]["dependencies"]
        review = dependency_review(snapshot, dependencies, report(snapshot))
        baseline = vlan_map(next(s["effective"] for s in snapshot["scopes"] if s["kind"] == "global"))
        library = vlan_map(snapshot["library"])
        previews = []
        for row in review["local_profile_review"]:
            if row["proposed_review"] == "retain_default":
                continue
            vid = row["vlan"]
            # The Global body is a comparison reference, not a prediction of
            # inheritance after deletion; intermediate assignments may intervene.
            target = baseline.get(vid) if row["scope_kind"] != "global" else None
            target_kind = "global_effective_reference" if target is not None else "library_reference"
            if target is None:
                target = library.get(vid)
            previews.append({"scope": row["scope"], "scope_kind": row["scope_kind"], "vlan": vid,
                             "current_local_body": row["profile"], "reference_kind": target_kind,
                             "reference_body": target,
                             "reference_differences": field_differences(row["profile"], target) if target is not None else None,
                             "proposed_review": row["proposed_review"],
                             "assignment_evidence": vlan_assignment_evidence(snapshot, vid, row["scope"]),
                             "blockers": row["dependency_blockers"],
                             "reference_candidate_modules": row["reference_candidate_modules"],
                             "effective_after_change_verified": False, "executable": False})
        results[persona] = {"review": review, "previews": previews}
        print(f"Offline review: {persona}")
        print(f"  Reference previews: {len(previews)}; executable: 0")
        print("  Assignment evidence (profile counts):")
        for label, count in sorted(Counter(
                "global_assignment_observed" if p["assignment_evidence"].get("global_assignment")
                else "same_scope_assignment_observed" if p["assignment_evidence"].get("same_scope_assignment")
                else p["assignment_evidence"]["status"] for p in previews).items()):
            print(f"    {label}: {count}")
        for action, count in sorted(Counter(p["proposed_review"] for p in previews).items()):
            print(f"  {action}: {count}")
    data = {"schema": 1, "kind": "offline_audit_review", "region": bundle["region"],
            "results": results, "safe_to_apply": False}
    if previous is not None:
        comparison = compare_audits(previous, bundle)
        data["comparison"] = comparison
        print("Audit comparison (exact captured bodies):")
        for persona, change in comparison["results"].items():
            print(f"  {persona}: changed scopes={len(change['scope_changes'])}, "
                  f"added scopes={len(change['added_scopes'])}, removed scopes={len(change['removed_scopes'])}")
            print(f"    Library added={len(change['library']['added'])}, removed={len(change['library']['removed'])}, "
                  f"modified={len(change['library']['modified'])}")
            for view in ("local", "effective"):
                totals = Counter()
                for scope in change["scope_changes"]:
                    for kind, values in scope[view].items():
                        totals[kind] += len(values)
                print(f"    {view}: added={totals['added']}, removed={totals['removed']}, modified={totals['modified']}")
            for status, count in sorted(Counter(r["status"] for s in change["scope_changes"]
                    for r in s["local_removal_outcomes"]).items()):
                print(f"    local removal: {status} x{count}")
            removals = [r for s in change["scope_changes"] for r in s["local_removal_outcomes"]]
            for index, removal in enumerate(removals, 1):
                evidence = removal["evidence"]
                print(f"    Removal {index}: {evidence['effective_assessment']}")
                for diff in evidence.get("effective_differences", []):
                    print(f"      {safe_difference_path(diff['path'])}: {diff['kind']} ({diff['assessment']})")
                for field, status in sorted(evidence["observed_fields"].items()):
                    print(f"      monitoring {field}: {status}")
                print("      multicast and behavior preservation: not verified")
    return data


def select_snapshot(data, persona=None):
    if data.get("kind") != "multi_persona_scan":
        if persona and data.get("persona") != persona:
            raise ValueError("Snapshot persona mismatch")
        return data
    snapshots = data["snapshots"]
    if not persona and len(snapshots) == 1:
        return next(iter(snapshots.values()))
    if not persona or persona not in snapshots:
        raise ValueError("Specify a discovered persona with --persona")
    return snapshots[persona]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    discovery = commands.add_parser("scan")
    discovery.add_argument("--persona", choices=sorted(PERSONAS), default="ACCESS_SWITCH")
    discovery.add_argument("--output", required=True, type=Path)
    discovery.add_argument("--region-file", type=Path, help="Optional local file for cached API region")
    all_scan = commands.add_parser("scan-all", help="Automatically scan all discovered switch personas")
    all_scan.add_argument("--output", required=True, type=Path)
    all_scan.add_argument("--region-file", type=Path)
    audit_cmd = commands.add_parser("audit", help="Discover, scan, probe dependencies and review all supported switch personas")
    audit_cmd.add_argument("--output", required=True, type=Path)
    audit_cmd.add_argument("--region-file", type=Path)
    config = commands.add_parser("config-audit", help="Audit documented configuration modules for discovered device personas")
    config.add_argument("--output", required=True, type=Path)
    config.add_argument("--region-file", type=Path)
    config.add_argument("--deep-catalog", action="store_true", help="Survey documented unadapted collections at every discovered scope; may take substantially longer")
    config.add_argument("--persona", choices=sorted(NETWORK_PERSONAS), help="Optional limit to one discovered persona")
    browser = commands.add_parser("review-config", help="Generate an offline configuration browser and anonymous schema diagnostics")
    browser.add_argument("audit", type=Path)
    browser.add_argument("--output", required=True, type=Path, help="Private HTML output")
    app = commands.add_parser("app", help="Open the local configuration workspace")
    app.add_argument("--directory", required=True, type=Path, help="Private customer audit directory")
    app.add_argument("--region-file", type=Path)
    app.add_argument("--enable-refresh", action="store_true", help="Enable read-only Central refresh using environment credentials")
    app.add_argument("--no-browser", action="store_true")
    app.add_argument("--deep-catalog", action="store_true", help="Use deep catalog scope surveys for environment-credential refreshes")
    inv = commands.add_parser("inventory", help="Discover every device and its known compatibility")
    inv.add_argument("--output", required=True, type=Path)
    inv.add_argument("--region-file", type=Path)
    dep = commands.add_parser("dependencies", help="Probe dependency modules from a saved VLAN snapshot")
    dep.add_argument("snapshot", type=Path)
    dep.add_argument("--output", required=True, type=Path)
    dep.add_argument("--persona", choices=sorted(PERSONAS), help="Select a persona from a scan-all snapshot")
    offline = commands.add_parser("review-audit", help="Review saved audit and optionally compare with an earlier audit")
    offline.add_argument("audit", type=Path)
    offline.add_argument("--previous", type=Path)
    offline.add_argument("--output", required=True, type=Path)
    analysis = commands.add_parser("report")
    analysis.add_argument("snapshot", type=Path)
    analysis.add_argument("--output", required=True, type=Path)
    analysis.add_argument("--dependencies", type=Path, help="Existing read-only dependency snapshot")
    analysis.add_argument("--persona", choices=sorted(PERSONAS), help="Select a persona from a scan-all snapshot")
    args = parser.parse_args()
    try:
        if args.command == "app":
            from config_app import serve
            refresh = None
            if args.enable_refresh:
                preferred = os.getenv("CENTRAL_BASE_URL")
                if not preferred and args.region_file and args.region_file.exists():
                    preferred = args.region_file.read_text(encoding="utf-8-sig").strip()
                client = Central(preferred or EU_REGIONS[0], os.getenv("CENTRAL_ACCESS_TOKEN"),
                                 os.getenv("CENTRAL_CLIENT_ID"), os.getenv("CENTRAL_CLIENT_SECRET"))
                def refresh(progress=None):
                    audit_progress(progress, "Connection", 0, 0, "Authenticating and detecting region")
                    detect_region(client, preferred)
                    return configuration_audit(client, progress=progress, deep_catalog=args.deep_catalog)
            serve(args.directory, refresh=refresh, open_browser=not args.no_browser)
            return 0
        if args.output.exists():
            raise ValueError("Output already exists")
        if args.command == "review-config":
            bundle = json.loads(args.audit.read_text(encoding="utf-8"))
            bundle = refresh_configuration_review(bundle)
            html = configuration_html(bundle)
            print_configuration_diagnostics(bundle)
            write_private_text(args.output, html)
            print("Completed offline configuration review; private HTML report saved.")
            return 0
        if args.command in ("scan", "scan-all", "audit", "config-audit", "inventory", "dependencies"):
            source = json.loads(args.snapshot.read_text(encoding="utf-8")) if args.command == "dependencies" else None
            if args.command == "dependencies" and source is not None and source.get("kind") == "multi_persona_scan":
                source = select_snapshot(source, args.persona)
            region_file = getattr(args, "region_file", None)
            preferred = source["region"] if source else os.getenv("CENTRAL_BASE_URL")
            if not preferred and region_file and region_file.exists():
                preferred = region_file.read_text(encoding="utf-8-sig").strip()
            client = Central(preferred or EU_REGIONS[0], os.getenv("CENTRAL_ACCESS_TOKEN"),
                             os.getenv("CENTRAL_CLIENT_ID"), os.getenv("CENTRAL_CLIENT_SECRET"))
            region = detect_region(client, preferred)
            if source and region != source["region"]:
                raise ValueError("Dependency snapshot region mismatch")
            if region_file:
                region_file.write_text(region + "\n", encoding="utf-8")
            print(f"API region: {region}", flush=True)
            if args.command == "scan":
                data = scan(client, args.persona)
            elif args.command == "scan-all":
                data = scan_all(client)
            elif args.command == "audit":
                data = audit(client)
            elif args.command == "config-audit":
                data = configuration_audit(client, args.persona, deep_catalog=args.deep_catalog)
            elif args.command == "inventory":
                records = inventory_capabilities(inventory(client))
                data = {"region": region, "devices": records}
                print_inventory_summary(records)
            else:
                data = discover_dependencies(client, source)
        elif args.command == "review-audit":
            bundle = json.loads(args.audit.read_text(encoding="utf-8"))
            previous = json.loads(args.previous.read_text(encoding="utf-8")) if args.previous else None
            data = offline_audit_review(bundle, previous)
        else:
            snapshot = select_snapshot(json.loads(args.snapshot.read_text(encoding="utf-8")), args.persona)
            data = report(snapshot)
            if args.dependencies:
                dependencies = json.loads(args.dependencies.read_text(encoding="utf-8"))
                data = dependency_review(snapshot, dependencies, data)
        write_private(args.output, data)
        if args.command == "report":
            print_review_summary(data)
            if "dependency_review" in data:
                print_dependency_summary(data)
        print("Completed read-only operation; output stored locally.")
    except (ValueError, OSError, KeyError, RuntimeError) as exc:
        # Do not log API payloads, URLs containing query data, or secrets.
        print(f"Operation failed: {type(exc).__name__}. Check local settings, API access and response schema.", file=sys.stderr)
        if isinstance(exc, RuntimeError):
            print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
