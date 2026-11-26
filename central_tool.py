"""Read-only Central VLAN discovery and conservative comparison."""
import argparse
import json
import os
import re
import sys
import time
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
        self.opener = build_opener(NoRedirect())

    def _request(self, request, label):
        for attempt in range(4):
            try:
                with self.opener.open(request, timeout=30) as response:
                    return json.load(response)
            except HTTPError as exc:
                if request.get_method() == "GET" and exc.code in (429, 500, 502, 503, 504) and attempt < 3:
                    delay = exc.headers.get("Retry-After", "")
                    if delay.isdigit() and int(delay) > 60:
                        raise RuntimeError(f"{label}: rate-limit delay exceeds retry budget") from None
                    time.sleep(int(delay) if delay.isdigit() else 2 ** attempt)
                    continue
                raise APIError(label, exc.code) from None

    def _token(self):
        if time.monotonic() >= self.expires:
            body = urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                              "client_secret": self.client_secret}).encode()
            result = self._request(Request(TOKEN_URL, data=body, headers={
                "Content-Type": "application/x-www-form-urlencoded"}), "OAuth")
            self.token = result["access_token"]
            self.expires = time.monotonic() + max(0, int(result["expires_in"]) - 60)
        return self.token

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


def offset_rows(client, path, keys, *, page_size=100, **params):
    result, seen = [], set()
    offset = 0
    for _ in range(10000):
        try:
            payload = client.get(path, **params, limit=page_size, offset=offset)
        except APIError as exc:
            raise APIError(f"{path} (limit={page_size}, offset={offset})", exc.status) from None
        batch = rows(payload, keys)
        if not batch:
            return result
        signature = canonical(batch)
        if signature in seen:
            raise ValueError("Repeated offset page; pagination cannot be trusted")
        seen.add(signature)
        result.extend(batch)
        offset += len(batch)
        if isinstance(payload.get("total"), int) and offset >= payload["total"]:
            if offset != payload["total"]:
                raise ValueError("Pagination total mismatch")
            return result
    raise ValueError("Pagination safety limit reached")


def inventory(client):
    result, seen, cursor = [], set(), None
    for _ in range(10000):
        payload = client.get(INVENTORY, limit=100, **({"next": cursor} if cursor else {}))
        result.extend(rows(payload, ("items",)))
        cursor = payload.get("next")
        if not cursor:
            if isinstance(payload.get("total"), int) and len(result) != payload["total"]:
                raise ValueError("Inventory total mismatch")
            return result
        if not isinstance(cursor, str) or cursor in seen:
            raise ValueError("Invalid or repeated inventory cursor")
        seen.add(cursor)
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


def scan(client, persona, devices=None):
    if devices is None:
        devices = inventory(client)
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
        if args.output.exists():
            raise ValueError("Output already exists")
        if args.command in ("scan", "scan-all", "audit", "inventory", "dependencies"):
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
