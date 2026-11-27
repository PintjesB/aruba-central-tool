"""Additional read-only hierarchy and assignment observations.

https://arubanetworking.hpe.com/techdocs/hpe-central/content/automation/api-change-log-in-february-2026.html
Only discovered scope IDs and observed assignment selectors are queried.
"""
import re
from collections import Counter
from urllib.parse import quote
from central_tool import ALPHA, CONFIG, APIError, NETWORK_PERSONAS, audit_progress, ordered_parallel, canonical

SCOPE_TYPES = {"global": "org", "collection": "site-collection", "site": "site",
               "group": "device-groups", "device": "device"}
ASSIGNMENT_KEYS = ("scope-id", "device-function", "profile-type", "profile-instance")


def evidence_read(client, path, **params):
    try:
        raw = client.get(path, **params)
    except APIError as exc:
        if exc.status in (401, 429):
            raise
        return {"status": "request_rejected", "http_error": exc.status}
    except (RuntimeError, OSError, ValueError):
        return {"status": "read_failed"}
    return {"status": "response_received" if raw else "empty_response", "raw": raw}


def hierarchy_capture(client, scopes_by_persona, workers=1, progress=None):
    tasks = sorted({(str(scope["id"]), scope["kind"])
                    for scopes in scopes_by_persona.values() for scope in scopes
                    if scope.get("kind") in SCOPE_TYPES and str(scope["id"]).isdigit()})
    def read(task):
        sid, kind = task
        # v1 uses id/type; retain rejected candidate scope-type mappings as evidence.
        result = evidence_read(client, CONFIG + "/hierarchy", id=sid, type=SCOPE_TYPES[kind])
        return {"scope": sid, "kind": kind, "scope_type": SCOPE_TYPES[kind], **result}
    records = ordered_parallel(tasks, read, workers, completed=lambda done, total:
        audit_progress(progress, "Scope hierarchy", done, total, "Reading discovered scope relationships"))
    return {"records": records, "outcomes": dict(Counter(r["status"] for r in records)),
            "complete": False, "safe_to_apply": False}


def assignment_identity(row):
    if not isinstance(row, dict):
        return None
    values = [row.get(key) for key in ASSIGNMENT_KEYS]
    if any(type(value) not in (str, int) or not str(value).strip() for value in values):
        return None
    return tuple(str(value) for value in values)


def valid_assignment_selector(identity):
    if identity is None:
        return False
    sid, persona, module, instance = identity
    numeric_port = module == "ethernet-interfaces" and re.fullmatch(r"[0-9]{1,4}/[0-9]{1,4}/[0-9]{1,4}", instance)
    return (sid.isdigit() and persona in NETWORK_PERSONAS | {"HYBRID_NAC"}
            and re.fullmatch(r"[a-z][a-z0-9-]{0,127}", module) is not None
            and len(instance) <= 512 and instance not in (".", "..")
            and not any(c in instance for c in ("\\", "%"))
            and ("/" not in instance or bool(numeric_port))
            and not any(ord(c) < 32 or ord(c) == 127 for c in instance))


def legacy_assignment_status(raw, identity):
    """Validate the observed scope-map representation of a keyed assignment.

    The resource string is module/instance (split only once, since an
    Ethernet interface name itself contains slashes). Bare resources do
    not independently establish a named profile instance.
    """
    if not isinstance(raw, dict) or type(raw.get("scope-id")) not in (int, str):
        return "schema_unresolved"
    sid, persona, module, instance = identity
    if str(raw["scope-id"]) != sid or any(
            key in raw and str(raw[key]) != expected
            for key, expected in zip(ASSIGNMENT_KEYS[1:], identity[1:])):
        return "identity_unresolved"
    if "persona" in raw and raw["persona"] != persona:
        return "identity_unresolved"
    if "resource" in raw:
        resource = raw["resource"]
        if not isinstance(resource, str):
            return "identity_unresolved"
        if resource not in (module, module + "/" + instance):
            return "identity_unresolved"
        if resource == module + "/" + instance and raw.get("persona") == persona:
            return "identity_observed"
    return "scope_only_observed"


def keyed_assignment_capture(client, assignments, workers=1, progress=None):
    tasks = {}
    invalid = 0
    for row in assignments.get("rows", []):
        identity = assignment_identity(row)
        if not valid_assignment_selector(identity):
            invalid += 1
            continue
        tasks.setdefault(identity, row)
    def read(identity):
        path = ALPHA + "/config-assignments/" + "/".join(quote(v, safe="") for v in identity)
        # The keyed GET publishes the same view selectors as the collection.
        # Explicitly request the committed mapping at its observed context.
        # https://www.postman.com/hpe-aruba-networking/new-hpe-aruba-networking-central/request/32717089-299748d9-7ce9-432e-9f84-c55c093fa38f
        sid, persona, _, _ = identity
        result = evidence_read(client, path, **{"view-type": "LOCAL", "scope-id": sid,
                                                "device-function": persona,
                                                "effective": "false", "detailed": "true"})
        raw = result.get("raw")
        if result["status"] == "response_received":
            rows = None
            if isinstance(raw, dict):
                if all(key in raw for key in ASSIGNMENT_KEYS):
                    rows = [raw]
                elif set(raw) <= {"metadata", "config-assignment"}:
                    value = raw.get("config-assignment")
                    rows = value if isinstance(value, list) else [value] if isinstance(value, dict) else None
            if rows is None:
                result["status"] = legacy_assignment_status(raw, identity)
                if result["status"] == "identity_observed":
                    result["identity_format"] = "scope_map_resource"
                    # Different response representations are not directly
                    # comparable as full bodies.
                elif result["status"] == "scope_only_observed":
                    result["missing_identity_fields"] = [key for key in ASSIGNMENT_KEYS if key not in raw]
            elif len(rows) != 1 or assignment_identity(rows[0]) != identity:
                result["status"] = "identity_unresolved"
            else:
                metadata = raw.get("metadata", {})
                counts = metadata.get("count_objects_in_module", {}) if isinstance(metadata, dict) else None
                if (not isinstance(counts, dict)
                        or any(type(value) is not int or value != 1 for value in
                               (metadata.get("count", 1), metadata.get("total", 1), counts.get("ANY", 1)))):
                    result["status"] = "count_mismatch"
                else:
                    result["status"] = "identity_observed"
                    result["body_matches_inventory"] = canonical(rows[0]) == canonical(tasks[identity])
        return {"selector": dict(zip(ASSIGNMENT_KEYS, identity)), **result}
    records = ordered_parallel(sorted(tasks), read, workers, completed=lambda done, total:
        audit_progress(progress, "Individual assignments", done, total, "Reading observed assignment identities"))
    outcomes = Counter(r["status"] for r in records)
    if invalid:
        outcomes["invalid_selector"] += invalid
    return {"records": records, "outcomes": dict(outcomes), "complete": False, "safe_to_apply": False}
