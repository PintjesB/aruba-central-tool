"""Conservative ordered security policy review from captured vendor rule shapes.

See HPE's policy configuration VSG and New Central Open SSID workflow:
https://arubanetworking.hpe.com/techdocs/VSG/docs/002-central/central-040-policy-configuration/
https://developer.arubanetworks.com/new-central/docs/wlan-config-open-ssid
Never claim that a captured policy has the same resultant device behavior.
"""
from collections import defaultdict, Counter
from .central_tool import canonical, profile_body


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


def condition_relationship(earlier,later):
    """Only compare exact qualified role/any predicates; no role hierarchy."""
    if earlier==later:
        return "same_condition"
    if covers(earlier,later):
        return "earlier_contains_later"
    if covers(later,earlier):
        return "later_contains_earlier"
    if all(a==b or a==("any",) or b==("any",) for a,b in zip(earlier,later)):
        return "partial_overlap"
    return None


def unsupported_security_reason(rule):
    if not isinstance(rule,dict):
        return "rule_not_object"
    if set(rule)-{"position","description","condition","action"}:
        return "additional_rule_fields"
    condition=rule.get("condition")
    if not isinstance(condition,dict):
        return "condition_not_object"
    if set(condition)!={"type","rule-type","source","destination"}:
        return "unsupported_condition_fields"
    if condition["type"]!="CONDITION_DEFAULT":
        return "unsupported_condition_type"
    if condition["rule-type"]!="RULE_ANY":
        return "unsupported_rule_type"
    if not address(condition["source"]) or not address(condition["destination"]):
        return "unsupported_address_shape"
    action=rule.get("action")
    if not isinstance(action,dict) or not isinstance(action.get("type"),str) or not action["type"]:
        return "action_unqualified"
    return None


def rule_review(module, body, limit=2000):
    result = {"findings": [], "rules": 0, "qualified_match_rules": 0, "unsupported_rules": 0,
              "order_verified": False, "truncated": False, "safe_to_apply": False,"unsupported_reasons":{}}
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
        from .role_acl_review import acl_prefix_review
        semantic = acl_prefix_review(body, limit=max(0, limit - len(result["findings"])))
        result["findings"].extend(semantic.pop("findings"))
        semantic["truncated"] |= result["truncated"]
        result.update(semantic)
        if result["unsupported_rules"]:
            reason="acl_order_or_family_unqualified" if not result["order_verified"] else "acl_predicate_unqualified"
            result["unsupported_reasons"]={reason:result["unsupported_rules"]}
        result["status"] = "literal_acl_prefix_review" if result["order_verified"] else "structural_acl_review"
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
        if rules:
            result["unsupported_reasons"]={"security_order_unqualified":len(rules)}
        return result
    result["order_verified"] = True
    ordered = sorted(rules, key=lambda r: r["position"])
    reasons=[unsupported_security_reason(r) for r in ordered]
    result["unsupported_reasons"]=dict(Counter(reason for reason in reasons if reason is not None))
    matches = [simple_match(r) if reason is None else None for r,reason in zip(ordered,reasons)]
    result["qualified_match_rules"] = sum(m is not None for m in matches)
    result["unsupported_rules"] = len(rules) - result["qualified_match_rules"]
    # Exact repeated unsupported records are structural evidence only. Keep
    # all fields except the position; do not infer match or action semantics.
    seen = {}
    for rule, match in zip(ordered, matches):
        if match is not None:
            continue
        signature = canonical({k: v for k, v in rule.items() if k != "position"})
        if signature not in seen:
            seen[signature] = rule
            continue
        if len(result["findings"]) >= limit:
            result["truncated"] = True
            result["status"] = "comparison_limit_reached"
            return result
        previous = seen[signature]
        result["findings"].append({"status": "identical_unsupported_security_rule_body",
            "earlier_position": previous["position"], "later_position": rule["position"],
            "earlier": previous, "later": rule})
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
            relationship=condition_relationship(matches[j],matches[i])
            if relationship is None:
                continue
            same_action = canonical(earlier["action"]) == canonical(later["action"])
            if relationship=="same_condition":
                status="duplicate_condition_same_action" if same_action else "same_condition_different_action"
            elif relationship=="earlier_contains_later":
                status="broader_earlier_same_action" if same_action else "broader_earlier_different_action"
            else:
                status=relationship+("_same_action" if same_action else "_different_action")
            result["findings"].append({
                "status":status,"condition_relationship":relationship,
                "earlier_position": earlier["position"], "later_position": later["position"],
                "earlier": earlier, "later": later})
    result["status"] = "captured_order_review"
    return result


def policy_rule_groups(bundle):
    """Deduplicate identical captured policy bodies per function and identity."""
    from .standard_evidence import conflicting_profiles
    groups = {}
    def add_conflicts(persona,module,location,conflicts):
        for identity,evidence in conflicts.items():
            key=(persona,module,identity,"individual_evidence_conflict",canonical(evidence))
            if key not in groups:
                groups[key]={"persona":persona,"module":module,"identity":identity,"locations":[],
                             "findings":[],"rules":0,"qualified_match_rules":0,"unsupported_rules":0,
                             "order_verified":False,"truncated":False,"status":"individual_evidence_conflict",
                             "individual_conflict":evidence,"safe_to_apply":False}
            groups[key]["locations"].append(location)
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
                location={"scope":row["scope"],"name":scope.get("name") or row["scope"],"view":"effective"}
                conflicts=conflicting_profiles(bundle,persona,module,row["scope"],view)
                add_conflicts(persona,module,location,conflicts)
                for identity, raw in view["profiles"].items():
                    if identity not in conflicts:
                        add(persona,module,identity,raw,location)
    for module in modules:
        view = bundle.get("library", {}).get("modules", {}).get(module, {})
        if view.get("status") == "list_parsed":
            location={"scope":"","name":"Library","view":"library"}
            conflicts=conflicting_profiles(bundle,"Library",module,"",view,side="library")
            add_conflicts("Library",module,location,conflicts)
            for identity,raw in view["profiles"].items():
                if identity not in conflicts:
                    add("Library",module,identity,raw,location)
    return sorted(groups.values(), key=lambda r: (-len(r["findings"]), r["persona"], r["module"], r["identity"]))
