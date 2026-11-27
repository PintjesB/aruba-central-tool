"""Inspect documented feature applicability against retained device-scope evidence.

Feature applicability describes deployment, not necessarily the raw GET contract.
Never convert this evidence into omitted Deep capture selectors.
"""
from collections import Counter, defaultdict
from .central_tool import AP_PERSONAS, NETWORK_PERSONAS

# Vendor API descriptions explicitly limit these features to APs.
AP_ONLY = {
    "ids": "https://developer.arubanetworks.com/new-central-config/reference/readids",
    "time-ranges": "https://developer.arubanetworks.com/new-central-config/reference/readtimeranges",
    "airgroup-system": "https://developer.arubanetworks.com/new-central-config/reference/readairgroupsystem",
    "airgroup-service-definitions": "https://developer.arubanetworks.com/new-central-config/reference/readairgroupservicedefinitions",
    "internal-user": "https://developer.arubanetworks.com/new-central-config/reference/readinternaluser",
}


def applicability_evidence(bundle):
    functions = defaultdict(set)
    kinds = defaultdict(set)
    for persona, entry in bundle.get("results", {}).items():
        for scope in entry.get("scopes", []):
            sid = str(scope.get("id"))
            kinds[sid].add(scope.get("kind"))
            if scope.get("kind") == "device":
                functions[sid].add(persona)
    rows = defaultdict(Counter)
    for module, data in (bundle.get("unadapted_profiles") or {}).items():
        if module not in AP_ONLY:
            continue
        for source in data.get("source_views", []):
            sid = str(source.get("scope"))
            if kinds[sid] != {"device"}:
                continue
            known = functions[sid]
            persona = next(iter(known)) if len(known) == 1 and known <= NETWORK_PERSONAS else "unknown"
            platform = "AP" if persona in AP_PERSONAS else "unknown" if persona == "unknown" else "non_AP"
            requested = source.get("persona")
            selector = "unfiltered" if requested in ("ALL_DEVICE_FUNCTIONS", "UNFILTERED_SCOPE") else (
                requested if requested in NETWORK_PERSONAS else "unknown")
            for side in ("committed", "effective"):
                view = source.get(side, {})
                row = rows[module, platform, selector, side]
                row["views"] += 1
                raw = view.get("raw")
                if view.get("status") not in ("response_received", "empty_response") or not isinstance(raw, dict):
                    row["unqualified"] += 1
                elif any(key not in ("metadata", "@") and value not in (None, [], {}) for key, value in raw.items()):
                    row["positive"] += 1
                elif view.get("collection_count_verified") is True:
                    row["counted_empty"] += 1
                else:
                    row["unqualified_empty"] += 1
    return {
        "documented_AP_only_features": dict(AP_ONLY),
        "device_scope_observations": [
            {"module": module, "inventory_platform": platform, "selector": selector,
             "view": side, **dict(row)}
            for (module, platform, selector, side), row in sorted(rows.items())
        ],
        "deep_scope_suppression_qualified": False,
        "complete": False,
    }
