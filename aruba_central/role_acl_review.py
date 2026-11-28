"""Conservative literal IP destination comparison for documented role ACL rules.

Schema: https://developer.arubanetworks.com/new-central-config/reference/updateroleaclsaclbyid
HPE Postman configuration examples document src-role, position, vrf,
action, count, and destination ADDRESS_HOST/ADDRESS_NETWORK fields.
"""
import ipaddress
import re
from collections import Counter


def literal_destination(value, version):
    if not isinstance(value, dict):
        return None
    address_key = f"ipv{version}-address"
    subnet_key = f"ipv{version}-subnet-address"
    prefix_key = f"ipv{version}-prefix"
    try:
        if value.get("address-type") == "ADDRESS_HOST" and set(value) == {"address-type", address_key}:
            raw = value[address_key]
            if not isinstance(raw, str) or "%" in raw:
                return None
            addr = ipaddress.ip_address(raw)
            if addr.version == version:
                return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}")
        elif value.get("address-type") == "ADDRESS_NETWORK" and set(value) == {"address-type", subnet_key, prefix_key}:
            raw = value[subnet_key]
            if not isinstance(raw, str) or "%" in raw:
                return None
            prefix = value[prefix_key]
            if type(prefix) is int:
                length = prefix
            elif isinstance(prefix, str) and re.fullmatch(r"/?[0-9]{1,3}", prefix):
                length = int(prefix.lstrip("/"))
            else:
                return None
            net = ipaddress.ip_network(f"{raw}/{length}", strict=True)
            if net.version == version:
                return net
    except (ValueError, TypeError):
        pass
    return None


def acl_qualification(rule, version):
    """Return a qualified predicate or an exact structural rejection reason."""
    if not isinstance(rule, dict):
        return None, "rule_not_object"
    if set(rule) - {"src-role", "position", "vrf", "action", "count", "description", "destination"}:
        return None, "additional_rule_fields"
    role, vrf = rule.get("src-role"), rule.get("vrf")
    if not isinstance(role, str) or not role:
        return None, "source_role_unqualified"
    if not isinstance(vrf, str) or not vrf:
        return None, "vrf_unqualified"
    if rule.get("action") not in ("PERMIT", "DENY"):
        return None, "action_unqualified"
    destination = literal_destination(rule.get("destination"), version)
    if destination is None:
        return None, "literal_destination_unqualified"
    return (role, vrf, destination), None


def acl_match(rule, version):
    return acl_qualification(rule, version)[0]


def acl_prefix_review(body, limit=2000):
    rules = body.get("rules", [])
    version = {"ACL_IPV4": 4, "ACL_IPV6": 6}.get(body.get("acl-type"))
    result = {"qualified_match_rules": 0, "unsupported_rules": len(rules),
              "order_verified": False, "truncated": False, "findings": [], "acl_unsupported_reasons": {}}
    positions = [r.get("position") if isinstance(r, dict) else None for r in rules]
    if not version or any(type(p) is not int or not 0 <= p <= 4294967295 for p in positions) or len(set(positions)) != len(positions):
        if rules:
            result["acl_unsupported_reasons"] = {"family_unqualified" if not version else "order_unqualified": len(rules)}
        return result
    result["order_verified"] = True
    ordered = sorted(rules, key=lambda r: r["position"])
    qualified = [acl_qualification(r, version) for r in ordered]
    matches = [match for match, _ in qualified]
    result["acl_unsupported_reasons"] = dict(Counter(reason for _, reason in qualified if reason is not None))
    result["qualified_match_rules"] = sum(m is not None for m in matches)
    result["unsupported_rules"] = len(rules) - result["qualified_match_rules"]
    comparisons = 0
    for i, current in enumerate(matches):
        if current is None:
            continue
        for j in range(i):
            comparisons += 1
            if comparisons > 100000 or len(result["findings"]) >= limit:
                result["truncated"] = True
                return result
            previous = matches[j]
            if previous is None or previous[:2] != current[:2] or not previous[2].overlaps(current[2]):
                continue
            earlier, later = ordered[j], ordered[i]
            coverage = ("same_destination" if previous[2] == current[2] else
                        "earlier_contains_later" if current[2].subnet_of(previous[2]) else "later_contains_earlier")
            same_action = earlier["action"] == later["action"]
            def counter(rule):
                value = rule.get("count")
                if type(value) is bool:
                    return value
                if value in ("true", "false"):
                    return value == "true"
                return None
            a, b = counter(earlier), counter(later)
            result["findings"].append({"status": "acl_prefix_overlap_same_action" if same_action else "acl_prefix_overlap_different_action",
                "coverage": coverage, "source_role": current[0], "vrf": current[1],
                "earlier_network": str(previous[2]), "later_network": str(current[2]),
                "counter_setting": "unverified" if a is None or b is None else "same" if a == b else "different",
                "earlier_position": earlier["position"], "later_position": later["position"],
                "earlier": earlier, "later": later})
    return result
