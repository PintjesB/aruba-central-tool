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


# Documented top-level types are not interchangeable:
# https://developer.arubanetworks.com/new-central-config/reference/replacepoliciespolicybyid
POLICY_TYPES = {"POLICY_TYPE_SECURITY": "security", "POLICY_NETWORK_ACL": "network_acl",
                "POLICY_QOS": "qos", "POLICY_PBR": "pbr", "POLICY_MIRROR": "mirror"}
POLICY_SCHEMA_STATES = ("qualified", "network_acl", "qos", "pbr", "mirror", "policy_type_missing",
                        "policy_type_unrecognized", "security_body_missing", "security_type_unqualified",
                        "security_rule_list_unqualified", "acl_rule_list_unqualified")


def policy_schema_state(module, body):
    if module == "role-acls":
        return "qualified" if isinstance(body.get("rules"), list) else "acl_rule_list_unqualified"
    kind = body.get("type")
    if kind is None:
        return "policy_type_missing"
    family = POLICY_TYPES.get(kind) if isinstance(kind, str) else None
    if family is None:
        return "policy_type_unrecognized"
    if family != "security":
        return family
    security = body.get("security-policy")
    if not isinstance(security, dict):
        return "security_body_missing"
    if security.get("type") != "SECURITY_POLICY_TYPE_DEFAULT":
        return "security_type_unqualified"
    if not isinstance(security.get("policy-rule"), list):
        return "security_rule_list_unqualified"
    return "qualified"


POLICY_BODY_SHAPES = ("identity_only", "metadata_only", "security_wrapper_missing",
    "security_wrapper_invalid", "security_subtype_missing", "security_subtype_other",
    "rule_list_missing", "rule_list_null", "rule_list_invalid", "rule_list_empty", "rule_list_present")


def policy_body_shape(body):
    """Describe the captured structure without inferring a default type or rules."""
    if set(body) <= {"name"}:
        return "identity_only"
    if set(body) <= {"name", "description", "association", "type", "dsf-enable"}:
        return "metadata_only"
    if "security-policy" not in body:
        return "security_wrapper_missing"
    sec = body["security-policy"]
    if not isinstance(sec, dict):
        return "security_wrapper_invalid"
    if "type" not in sec:
        return "security_subtype_missing"
    if sec["type"] != "SECURITY_POLICY_TYPE_DEFAULT":
        return "security_subtype_other"
    if "policy-rule" not in sec:
        return "rule_list_missing"
    rules = sec["policy-rule"]
    if rules is None:
        return "rule_list_null"
    if not isinstance(rules, list):
        return "rule_list_invalid"
    return "rule_list_present" if rules else "rule_list_empty"


def conditional_security_rules(body):
    """Return observed default security rules only when the outer type is omitted.

    Never supply a missing type, override an explicit type, or use a preview
    to qualify the effective policy. The outer type determines rule semantics.
    """
    if "type" in body or set(body) - {"name","description","association","dsf-enable","security-policy"}:
        return None
    sec = body.get("security-policy")
    if not isinstance(sec, dict) or sec.get("type") != "SECURITY_POLICY_TYPE_DEFAULT":
        return None
    rules = sec.get("policy-rule")
    return rules if isinstance(rules,list) else None


def rule_review(module, body, limit=2000):
    result = {"findings": [], "rules": 0, "qualified_match_rules": 0, "unsupported_rules": 0,
              "order_verified": False, "truncated": False, "safe_to_apply": False,"unsupported_reasons":{},
              "schema_state": policy_schema_state(module, body)}
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
    result["body_shape"] = policy_body_shape(body)
    from .policy_transport_review import transport_review
    result["transport_evidence"]=transport_review(body)
    security = body.get("security-policy")
    if result["schema_state"] != "qualified":
        result["status"] = "rule_schema_unqualified"
        candidate = conditional_security_rules(body)
        if candidate is not None:
            preview = {"findings":[],"rules":0,"qualified_match_rules":0,"unsupported_rules":0,
                       "order_verified":False,"truncated":False,"safe_to_apply":False,"unsupported_reasons":{}}
            result["conditional_security_preview"] = {
                **review_security_rules(candidate,preview,limit), "context":"outer_policy_type_missing"}
        return result
    return review_security_rules(security["policy-rule"],result,limit)


# Vendor-documented shapes only. These are structural diagnostics, not
# qualification of protocols, services, addresses or actions.
PREDICATE_FIELDS = ("type","rule-type","source","destination","services","transport-fields",
                    "ip-header","icmp-fields","ethernet-header")
PREDICATE_KINDS = ("RULE_ANY","RULE_TCP","RULE_UDP","RULE_ICMP","RULE_ACL_IP",
                   "RULE_ACL_IPV6","RULE_ACL_MAC")
ADDRESS_KINDS = ("ADDRESS_ANY","ADDRESS_ROLE")
PREDICATE_SHAPE_KEYS = ("condition_shape","rule_kind","source_kind","destination_kind",
                        "service_fields","transport_fields","header_fields","additional_fields")


def predicate_pattern_summary(groups):
    """Aggregate only fixed documented structural categories and counts."""
    reasons=("rule_not_object","additional_rule_fields","condition_not_object",
             "unsupported_condition_fields","unsupported_condition_type","unsupported_rule_type",
             "unsupported_address_shape","action_unqualified","security_order_unqualified")
    counts=Counter()
    allowed=("CONDITION_DEFAULT","missing","other","unknown","not_object")
    def fixed(value,choices):
        return value if isinstance(value,str) and value in choices else "unknown"
    for group in groups:
        for context,record in (("captured",group),("conditional",group.get("conditional_security_preview",{}))):
            for shape in record.get("unsupported_predicate_shapes",[]):
                n=shape.get("rules")
                if type(n) is not int or n<0:
                    continue
                key=(context,fixed(shape.get("reason"),reasons),
                     fixed(shape.get("condition_shape"),allowed),
                     fixed(shape.get("rule_kind"),PREDICATE_KINDS+("missing","other","unknown")),
                     fixed(shape.get("source_kind"),ADDRESS_KINDS+("missing","other","unknown")),
                     fixed(shape.get("destination_kind"),ADDRESS_KINDS+("missing","other","unknown")),
                     *(shape.get(k) is True for k in PREDICATE_SHAPE_KEYS[4:]))
                counts[key]+=n
    return [{"context":context,"reason":reason,**dict(zip(PREDICATE_SHAPE_KEYS,shape)),"rules":n}
            for (context,reason,*shape),n in sorted(counts.items(),key=lambda item:(-item[1],item[0]))]


def predicate_shape(rule):
    condition = rule.get("condition") if isinstance(rule,dict) else None
    if not isinstance(condition,dict):
        return ("not_object","unknown","unknown","unknown",False,False,False,False)
    def kind(value,allowed):
        return value if isinstance(value,str) and value in allowed else "missing" if value is None else "other"
    def addr(value):
        return kind(value.get("type"),ADDRESS_KINDS) if isinstance(value,dict) else "missing" if value is None else "other"
    return (kind(condition.get("type"),("CONDITION_DEFAULT",)),
            kind(condition.get("rule-type"),PREDICATE_KINDS),
            addr(condition.get("source")),addr(condition.get("destination")),
            "services" in condition,"transport-fields" in condition,
            bool({"ip-header","icmp-fields","ethernet-header"} & condition.keys()),
            bool(condition.keys()-set(PREDICATE_FIELDS)))


def review_security_rules(rules,result,limit):
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
    shapes = Counter((reason,*predicate_shape(rule)) for rule,reason in zip(ordered,reasons) if reason is not None)
    result["unsupported_predicate_shapes"] = [
        {"reason":reason,**dict(zip(PREDICATE_SHAPE_KEYS,shape)),"rules":count}
        for (reason,*shape),count in sorted(shapes.items(),key=lambda item:(-item[1],item[0]))]
    # Compare exact unsupported condition records independently of semantic
    # findings. Extra rule fields may impose additional matching restrictions;
    # keep them out of the condition-only comparison.
    result["structural_condition_pairs"] = []
    result["structural_condition_pairs_truncated"] = False
    groups = {}
    for rule,match in zip(ordered,matches):
        if match is not None or set(rule)-{"position","description","condition","action"}:
            continue
        condition,action=rule.get("condition"),rule.get("action")
        if not isinstance(condition,dict) or not condition or not isinstance(action,dict) or not isinstance(action.get("type"),str) or not action["type"]:
            continue
        signature=canonical(condition)
        # Keep a bounded representative per exact action body for this
        # condition. Do not claim that two records match the same packets.
        action_key=canonical(action)
        group=groups.setdefault(signature,{})
        previous=group.get(action_key)
        if previous is None and group:
            previous=next(iter(group.values()))
        if previous is not None:
            if len(result["structural_condition_pairs"]) >= limit:
                result["structural_condition_pairs_truncated"]=True
            else:
                result["structural_condition_pairs"].append({
                    "status":"identical_unsupported_condition_record",
                    "earlier_position":previous["position"],"later_position":rule["position"],
                    "same_action_body":canonical(previous["action"])==action_key,
                    "earlier":previous,"later":rule})
        group.setdefault(action_key,rule)
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
    from .policy_service_review import service_evidence
    service_views={(persona,row["scope"]):row.get("effective_view",{})
                   for persona,entry in bundle["results"].items()
                   for row in entry["modules"].get("net-services",{}).get("scope_results",[])}
    service_views["Library",""]=(bundle.get("library") or {}).get("modules",{}).get("net-services",{})
    library = (bundle.get("library") or {}).get("modules", {}).get("policies", {})
    library_conflicts = conflicting_profiles(bundle,"Library","policies","",library,side="library")
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
        group = groups[key]
        if module == "policies" and persona != "Library" and group.get("status") == "rule_schema_unqualified":
            candidate = library.get("profiles", {}).get(identity) if library.get("status") == "list_parsed" else None
            if identity in library_conflicts:
                group["library_body_relation"] = "individual_conflict"
            elif not isinstance(candidate, dict):
                group["library_body_relation"] = "not_observed"
            else:
                other = profile_body(candidate)
                if canonical(body) == canonical(other):
                    group["library_body_relation"] = "exact_body_match"
                elif "type" not in body and isinstance(other.get("type"), str) and other["type"] in POLICY_TYPES and canonical(body) == canonical({k:v for k,v in other.items() if k != "type"}):
                    group["library_body_relation"] = "only_missing_policy_type"
                else:
                    group["library_body_relation"] = "different_body"
        group["locations"].append(location)
        if module == "policies":
            evidence=service_evidence(bundle,persona,location["scope"],body,service_views.get((persona,location["scope"]),{}))
            if evidence:
                group.setdefault("service_definition_evidence",[]).append({"location":location,"references":evidence})
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
