"""Read-only Central VLAN discovery and conservative comparison."""
import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict
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


def offset_rows(client, path, keys, **params):
    result, seen = [], set()
    offset = 0
    for _ in range(10000):
        payload = client.get(path, **params, limit=100, offset=offset)
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


def vlan_rows(client, **params):
    return offset_rows(client, VLAN, ("l2-vlan",), **params)


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
    library = vlan_rows(client, **{"view-type": "LIBRARY", "detailed": "false"})
    assignments = client.get(ALPHA + "/config-assignments")
    for scope in scopes:
        params = {"view-type": "LOCAL", "scope-id": scope["id"], "device-function": persona}
        scope["local"] = vlan_rows(client, **params, **{"object-type": "LOCAL", "effective": "false", "detailed": "false"})
        scope["effective"] = vlan_rows(client, **params, effective="true", detailed="false")
        scope["annotated"] = vlan_rows(client, **params, effective="true", detailed="true")
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
