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
from urllib.parse import urlencode, urlsplit
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


def scan(client, persona):
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
        function = str(device.get("deviceFunction", "")).upper().replace(" ", "_")
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    discovery = commands.add_parser("scan")
    discovery.add_argument("--persona", choices=sorted(PERSONAS), default="ACCESS_SWITCH")
    discovery.add_argument("--output", required=True, type=Path)
    discovery.add_argument("--region-file", type=Path, help="Optional local file for cached API region")
    analysis = commands.add_parser("report")
    analysis.add_argument("snapshot", type=Path)
    analysis.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError("Output already exists")
        if args.command == "scan":
            preferred = os.getenv("CENTRAL_BASE_URL")
            if not preferred and args.region_file and args.region_file.exists():
                preferred = args.region_file.read_text(encoding="utf-8-sig").strip()
            client = Central(preferred or EU_REGIONS[0], os.getenv("CENTRAL_ACCESS_TOKEN"),
                             os.getenv("CENTRAL_CLIENT_ID"), os.getenv("CENTRAL_CLIENT_SECRET"))
            region = detect_region(client, preferred)
            if args.region_file:
                args.region_file.write_text(region + "\n", encoding="utf-8")
            print(f"API region: {region}", flush=True)
            data = scan(client, args.persona)
        else:
            data = report(json.loads(args.snapshot.read_text(encoding="utf-8")))
        write_private(args.output, data)
        if args.command == "report":
            print_review_summary(data)
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
