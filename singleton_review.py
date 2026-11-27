"""Read-only system-level configuration evidence without synthetic profile IDs.

Documented object contracts:
https://developer.arubanetworks.com/new-central-config/reference/updatelacp
https://developer.arubanetworks.com/new-central-config/reference/createairgroupsystem
https://developer.arubanetworks.com/new-central-config/reference/updatefirmwarecompliance
https://developer.arubanetworks.com/new-central-config/reference/readpolicygroups
"""
from central_tool import AP_PERSONAS, NETWORK_PERSONAS, field_differences, profile_body

# Candidate read selectors, not proof of platform applicability.
SINGLETON_PERSONAS = {"lacp": NETWORK_PERSONAS, "airgroup-system": AP_PERSONAS,
                      "firmware-compliance": NETWORK_PERSONAS, "policy-groups": NETWORK_PERSONAS}
CONTRACTS = {
    "lacp": ("lacp", {"hash", "system-priority"}),
    "airgroup-system": ("airgroup-system", {"enable", "protocol", "cppm", "guest-multicast", "multi-swarm"}),
    "firmware-compliance": ("firmware-compliance", {"name", "description", "enable", "active-partition",
                            "allow-unsafe-upgrades", "enforcement-schedule", "local-image-server-url",
                            "upgrade-mode", "version-chart"}),
    "policy-groups": ("policy-group", {"policy-group-list"}),
}


def singleton_view(module, read):
    """Identify an explicit object, never convert a mixed response to one profile."""
    envelope, known = CONTRACTS[module]
    output = {"status": "schema_unqualified", "settings": None, "source_verified": False}
    if read.get("status") != "response_received":
        return {**output, "status": read.get("status", "not_collected")}
    raw = read.get("raw")
    if not isinstance(raw, dict):
        return output
    fields = {k: v for k, v in raw.items() if k not in ("metadata", "@")}
    if set(fields) == {envelope} and isinstance(fields[envelope], dict):
        obj = fields[envelope]
    elif known.intersection(fields) and envelope not in fields:
        obj = {k: v for k, v in raw.items() if k != "metadata"}
    else:
        return output
    settings = profile_body(obj)
    if not known.intersection(settings):
        return output
    # Keep unknown fields too, rather than assuming the documented list is exhaustive.
    return {**output, "status": "settings_observed", "settings": settings,
            "annotations": obj.get("@"), "complete": False}


def singleton_review(module, committed, effective):
    saved = singleton_view(module, committed)
    applied = singleton_view(module, effective)
    differences = None
    if saved["status"] == applied["status"] == "settings_observed":
        differences = field_differences(saved["settings"], applied["settings"])
    return {"committed": saved, "effective": applied, "differences": differences,
            "complete": False, "safe_to_apply": False}
