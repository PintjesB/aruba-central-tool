"""Conservative ordered security policy review from captured vendor rule shapes.

See HPE's policy configuration VSG and New Central Open SSID workflow:
https://arubanetworking.hpe.com/techdocs/VSG/docs/002-central/central-040-policy-configuration/
https://developer.arubanetworks.com/new-central/docs/wlan-config-open-ssid
Never claim that a captured policy has the same resultant device behavior.
"""
from collections import defaultdict
from central_tool import canonical, profile_body


def address(value):
    if value == {"type": "ADDRESS_ANY"}:
        return ("any",)
    if (isinstance(value, dict) and set(value) == {"type", "role"}
            and value["type"] == "ADDRESS_ROLE" and isinstance(value["role"], str) and value["role"]):
        return ("role", value["role"])
    return None


def simple_match(rule):
    if not isinstance(rule, dict) or set(rule) - {"position", "description", "condition", "action"}:
        return None
    condition = rule.get("condition")
    if (not isinstance(condition, dict) or set(condition) != {"type", "rule-type", "source", "destination"}
            or condition["type"] != "CONDITION_DEFAULT" or condition["rule-type"] != "RULE_ANY"):
        return None
    source, destination = address(condition["source"]), address(condition["destination"])
    return (source, destination) if source and destination else None


def covers(earlier, later):
    return all(a == ("any",) or a == b for a, b in zip(earlier, later))


def rule_review(module, body, limit=2000):
    result = {"findings": [], "rules": 0, "qualified_match_rules": 0, "unsupported_rules": 0,
              "order_verified": False, "truncated": False, "safe_to_apply": False}
    if module == "role-acls":
        rules = body.get("rules")
        if not isinstance(rules, list):
            result["status"] = "rule_schema_unqualified"
            return result
        result["rules"] = len(rules)
        result["unsupported_rules"] = len(rules)
        seen = {}
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            key = canonical(rule)
            if key in seen:
                result["findings"].append({"status": "identical_acl_record", "earlier_index": seen[key],
                                           "later_index": i, "earlier": rules[seen[key]], "later": rule})
                if len(result["findings"]) >= limit:
                    result["truncated"] = True
                    break
            else:
                seen[key] = i
        result["status"] = "structural_acl_review"
        return result
    security = body.get("security-policy")
    if (body.get("type") != "POLICY_TYPE_SECURITY" or not isinstance(security, dict)
            or security.get("type") != "SECURITY_POLICY_TYPE_DEFAULT"
            or not isinstance(security.get("policy-rule"), list)):
        result["status"] = "rule_schema_unqualified"
        return result
    rules = security["policy-rule"]
    result["rules"] = len(rules)
    positions = [r.get("position") if isinstance(r, dict) else None for r in rules]
    if any(type(p) is not int or p < 0 for p in positions) or len(set(positions)) != len(positions):
        result["status"] = "rule_order_unqualified"
        result["unsupported_rules"] = len(rules)
        return result
    result["order_verified"] = True
    ordered = sorted(rules, key=lambda r: r["position"])
    matches = [simple_match(r) for r in ordered]
    result["qualified_match_rules"] = sum(m is not None for m in matches)
    result["unsupported_rules"] = len(rules) - result["qualified_match_rules"]
    # Bound comparisons for unusually large customer policy lists. Never hide truncation.
    comparisons = 0
    for i, later in enumerate(ordered):
        if not matches[i] or not isinstance(later.get("action"), dict) or not later["action"].get("type"):
            continue
        for j in range(i):
            comparisons += 1
            if comparisons > 100000 or len(result["findings"]) >= limit:
                result["truncated"] = True
                result["status"] = "comparison_limit_reached"
                return result
            earlier = ordered[j]
            if not matches[j] or not isinstance(earlier.get("action"), dict) or not earlier["action"].get("type"):
                continue
            if not covers(matches[j], matches[i]):
                continue
            same_condition = matches[j] == matches[i]
            same_action = canonical(earlier["action"]) == canonical(later["action"])
            result["findings"].append({
                "status": ("duplicate_condition_same_action" if same_action else "same_condition_different_action")
                          if same_condition else ("broader_earlier_same_action" if same_action else "broader_earlier_different_action"),
                "earlier_position": earlier["position"], "later_position": later["position"],
                "earlier": earlier, "later": later})
    result["status"] = "captured_order_review"
    return result


def policy_rule_groups(bundle):
    """Deduplicate identical captured policy bodies per function and identity."""
    groups = {}
    def add(persona, module, identity, raw, location):
        if not isinstance(raw, dict):
            return
        body = profile_body(raw)
        key = (persona, module, identity, canonical(body))
        if key not in groups:
            groups[key] = {"persona": persona, "module": module, "identity": identity,
                           "locations": [], **rule_review(module, body)}
        groups[key]["locations"].append(location)
    modules = ("policies", "role-acls")
    for persona, entry in sorted(bundle["results"].items()):
        scopes = {s["id"]: s for s in entry["scopes"]}
        for module in modules:
            for row in entry["modules"].get(module, {}).get("scope_results", []):
                scope = scopes.get(row["scope"], {})
                view = row.get("effective_view", {})
                if scope.get("kind") != "device" or view.get("status") != "list_parsed":
                    continue
                for identity, raw in view["profiles"].items():
                    add(persona, module, identity, raw, {"scope": row["scope"], "name": scope.get("name") or row["scope"],
                                                        "view": "effective"})
    for module in modules:
        view = bundle.get("library", {}).get("modules", {}).get(module, {})
        if view.get("status") == "list_parsed":
            for identity, raw in view["profiles"].items():
                add("Library", module, identity, raw, {"scope": "", "name": "Library", "view": "library"})
    return sorted(groups.values(), key=lambda r: (-len(r["findings"]), r["persona"], r["module"], r["identity"]))
