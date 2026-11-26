"""Read-only authorization policy and enforcement review.

HPE requires default query parameters for authz-policies and identity-stores.
https://developer.arubanetworks.com/new-central-config/reference/readauthzpolicies
https://developer.arubanetworks.com/new-central-config/reference/readidentitystores
https://developer.arubanetworks.com/new-central-config/reference/replaceauthzpoliciespolicybyid
"""
from collections import defaultdict
from central_tool import canonical, profile_body


NAC_TENANT_MODULES = {"authz-policies": "policy-id", "identity-stores": "id", "static-tag": "tag-id"}


def capture_nac_configuration(client, progress=None, *, checkpoint=None):
    from central_tool import APIError, read_module_view, audit_progress
    results = {}
    for i, (module, identity) in enumerate(NAC_TENANT_MODULES.items(), 1):
        audit_progress(progress, "NAC configuration", i-1, len(NAC_TENANT_MODULES), module)
        try:
            read = lambda: read_module_view(client, module, identity, {})
            results[module] = checkpoint.observe("nac_configuration", [module, identity], read, lambda v: v.get("status") == "list_parsed" and v.get("count_confirmed") is True) if checkpoint else read()
        except APIError as exc:
            if exc.status in (401, 429):
                raise
            results[module] = {"status": "request_rejected", "http_error": exc.status, "profiles": {}}
        except (OSError, RuntimeError, ValueError):
            results[module] = {"status": "read_failed", "profiles": {}}
        audit_progress(progress, "NAC configuration", i, len(NAC_TENANT_MODULES), module)
    return results


def nac_collection(bundle, module):
    from central_tool import module_view
    views = bundle.get("nac_configuration", {})
    if module in views:
        current = views[module]
        if module != "static-tag" or current.get("status") == "list_parsed":
            return current
        raw = bundle.get("unadapted_profiles", {}).get(module, {}).get("library", {})
        fallback = module_view(raw.get("raw"), NAC_TENANT_MODULES[module]) if raw.get("status") == "response_received" else {}
        if fallback.get("status") == "list_parsed":
            return {**fallback, "qualification": "raw_library_fallback", "tenant_read_status": current.get("status")}
        return current
    if module == "auth-profiles":
        return bundle.get("library", {}).get("modules", {}).get(module, {})
    # Older captures have only generic raw Library evidence.
    raw = bundle.get("unadapted_profiles", {}).get(module, {}).get("library", {})
    if raw.get("status") == "response_received" and module in NAC_TENANT_MODULES:
        return module_view(raw.get("raw"), NAC_TENANT_MODULES[module])
    return {"status": raw.get("status", "not_collected"), "profiles": {}}


def explicit_state(value):
    if type(value) is bool:
        return value
    if value in ("true", "false"):
        return value == "true"
    return None


def enforcement_attributes(profiles):
    """Extract explicit RADIUS attributes; retain unsupported/ambiguous evidence."""
    attributes, gaps = {}, []
    if not isinstance(profiles, list):
        return attributes, ["Enforcement profile not returned as a list"]
    for i, profile in enumerate(profiles):
        if not isinstance(profile, dict) or set(profile) != {"radius-profile"}:
            gaps.append(f"Profile {i+1}: unsupported enforcement structure")
            continue
        radius = profile["radius-profile"]
        if not isinstance(radius, dict) or set(radius) - {"defined-attr", "custom-attr"}:
            gaps.append(f"Profile {i+1}: unsupported RADIUS structure")
            continue
        for kind, field in (("defined-attr", "attr-name"), ("custom-attr", "custom-attr-name")):
            values = radius.get(kind, [])
            if not isinstance(values, list):
                gaps.append(f"Profile {i+1}: invalid {kind} list")
                continue
            for item in values:
                if (not isinstance(item, dict) or set(item) != {field, "value"}
                        or not isinstance(item[field], str) or not item[field] or not isinstance(item["value"], str)):
                    gaps.append(f"Profile {i+1}: unqualified {kind} attribute")
                    continue
                key = (kind, item[field])
                if key in attributes:
                    gaps.append(f"Repeated {kind} attribute: {item[field]}")
                else:
                    attributes[key] = item["value"]
    return attributes, gaps


def attribute_rows(defaults, overrides):
    return [{"kind": kind, "name": name, "value": value,
             "source": "rule" if (kind, name) in overrides else "default"}
            for (kind, name), value in sorted({**defaults, **overrides}.items())]


def identity_store_refs(profile, store_view):
    values = profile.get("identity-stores")
    if not isinstance(values, list):
        return {"status": "reference_list_unverified", "references": []}
    stores = store_view.get("profiles", {}) if store_view.get("status") == "list_parsed" else {}
    references = [{"identity": value, "status": "observed" if isinstance(value, str) and value in stores else
                   "not_observed" if isinstance(value, str) and store_view.get("count_confirmed") is True else "unverified"}
                  for value in values]
    return {"status": "observed", "references": references}


def policy_review(bundle):
    policies = nac_collection(bundle, "authz-policies")
    stores = nac_collection(bundle, "identity-stores")
    auth = nac_collection(bundle, "auth-profiles")
    reports = []
    profiles = policies.get("profiles", {}) if policies.get("status") == "list_parsed" else {}
    positions = [body.get("position") for body in profiles.values()]
    order_verified = (all(type(pos) is int and 0 <= pos <= 255 for pos in positions)
                      and len(set(positions)) == len(positions))
    for identity, raw in profiles.items():
        body = profile_body(raw)
        defaults, gaps = enforcement_attributes(body.get("default-enf-profile"))
        rules = body.get("rule")
        report = {"id": identity, "name": body.get("name"), "type": body.get("policy-type"),
                  "position": body.get("position"), "enabled": explicit_state(body.get("enable")),
                  "identity_stores": identity_store_refs(body, stores), "conditions": body.get("conditions"),
                  "default_attributes": attribute_rows(defaults, {}), "default_gaps": gaps, "rules": [],
                  "rules_observed": isinstance(rules, list), "rule_order_verified": False}
        if isinstance(rules, list):
            pos = [r.get("position") if isinstance(r, dict) else None for r in rules]
            report["rule_order_verified"] = all(type(p) is int and p >= 0 for p in pos) and len(set(pos)) == len(pos)
            if report["rule_order_verified"]:
                rules = sorted(rules, key=lambda rule: rule["position"])
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                overrides, issues = enforcement_attributes(rule.get("enf-profile"))
                combined = attribute_rows(defaults, overrides) if not gaps and not issues else []
                report["rules"].append({"position": rule.get("position"), "enabled": explicit_state(rule.get("enable")),
                    "conditions": rule.get("conditions"), "attributes": attribute_rows({}, overrides),
                    "combined_candidate_attributes": combined, "gaps": [*gaps, *issues],
                    "status": "candidate_if_rule_matches" if not gaps and not issues else "enforcement_unqualified"})
        reports.append(report)
    if order_verified:
        reports.sort(key=lambda p: p["position"])
    authentication = [{"id": identity, "name": raw.get("name"), "type": raw.get("auth-type"),
                       "networks": raw.get("networks"), "identity_stores": identity_store_refs(raw, stores)}
                      for identity, raw in auth.get("profiles", {}).items()] if auth.get("status") == "list_parsed" else []
    return {"policy_capture_status": policies.get("status", "not_collected"),
            "policy_count_confirmed": policies.get("count_confirmed") is True,
            "store_capture_status": stores.get("status", "not_collected"),
            "auth_capture_status": auth.get("status", "not_collected"),
            "policy_order_verified": order_verified and policies.get("status") == "list_parsed",
            "policies": reports, "authentication": authentication, "safe_to_apply": False}
