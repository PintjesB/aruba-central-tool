"""Assess saved port settings independently of effective similarity."""
from .central_tool import canonical, profile_body, field_differences

def port_conversion_review(entry, ports, portable, matches):
    views = {v["scope"]: v for v in entry["modules"].get("ethernet-interfaces", {}).get("scope_results", [])}
    results = []
    for port in ports:
        sid, identity = port["scope"], port["port"]
        local = views.get(sid, {}).get("local_view", {})
        raw = local.get("profiles", {}).get(identity) if local.get("status") == "list_parsed" else None
        body = profile_body(raw) if isinstance(raw, dict) else None
        current = port["before"]
        expected = {k: v for k, v in current.items() if k in ("name", "description")}
        shared_fields = sorted(set(body or {}) & set(portable))
        retained = {k: v for k, v in (body or {}).items() if k not in portable}
        differences = field_differences({k: v for k, v in (body or {}).items() if k in portable}, portable)
        if body is None:
            state = "saved_configuration_unverified"
        elif canonical(body) != canonical(current):
            state = "saved_effective_differ"
        elif port["unsupported"]:
            state = "unsupported_settings"
        else:
            state = "exact_saved_effective_match"
        visibility = {m["identity"]: next((v["status"] for v in m["visibility"] if v["scope"] == sid), "unknown")
                      for m in matches}
        results.append({"scope": sid, "device": port["device"], "port": identity,
                        "status": state, "saved": body, "effective": current,
                        "proposed_shared_fields": shared_fields, "retained_local_fields": retained,
                        "expected_identity_fields": expected, "saved_vs_shared": differences,
                        "candidate_visibility": visibility,
                        "safe_to_apply": False})
    return results
