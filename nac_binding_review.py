"""Cross-reference NAC tag values and configured VLAN attributes with captured evidence."""
from collections import defaultdict
from central_tool import PERSONAS


def tag_condition_observations(conditions, tags):
    """Match exact captured values only; do not interpret attribute semantics."""
    result = []
    if not isinstance(conditions, dict) or not isinstance(conditions.get("condition"), list):
        return result
    by_value = defaultdict(set)
    for identity, tag in tags.items():
        by_value[identity].add(identity)
        if isinstance(tag.get("name"), str) and tag["name"]:
            by_value[tag["name"]].add(identity)
    for group in conditions["condition"]:
        if not isinstance(group, dict) or not isinstance(group.get("condition-group"), list):
            continue
        for predicate in group["condition-group"]:
            if not isinstance(predicate, dict):
                continue
            values = [predicate.get("value")]
            if isinstance(predicate.get("values"), list):
                values += predicate["values"]
            for value in dict.fromkeys(v for v in values if isinstance(v, str) and v):
                if value in by_value:
                    result.append({"value": value, "attribute": predicate.get("attr"),
                                   "operator": predicate.get("operator"), "condition_position": group.get("position"),
                                   "predicate_position": predicate.get("position"), "tag_candidates": sorted(by_value[value]),
                                   "status": "exact_value_observation_not_tag_semantics"})
    return result


def vlan_identity(value):
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 4:
        n = int(value)
        if 1 <= n <= 4094:
            return str(n)
    return None


def vlan_coverage(bundle, identities):
    """Only switch device configuration is eligible for L2 VLAN visibility checks."""
    output = {identity: [] for identity in identities}
    for persona, entry in sorted(bundle["results"].items()):
        if persona not in PERSONAS:
            continue
        views = {row["scope"]: row.get("effective_view", {}) for row in
                 entry["modules"].get("layer2-vlan", {}).get("scope_results", [])}
        for scope in entry["scopes"]:
            if scope["kind"] != "device":
                continue
            view = views.get(scope["id"], {})
            profiles = view.get("profiles", {}) if view.get("status") == "list_parsed" else {}
            for vid in identities:
                raw = profiles.get(vid)
                state = ("observed" if isinstance(raw, dict) else
                         "count_confirmed_absence" if view.get("status") == "list_parsed" and view.get("count_confirmed") is True else
                         "unverified")
                output[vid].append({"persona": persona, "scope": scope["id"], "device": scope.get("name") or scope["id"],
                                    "status": state, "name": raw.get("name") if isinstance(raw, dict) else None})
    return output


def nac_bindings(bundle, registrations, authorization):
    tags = registrations["tag_definitions"]
    conditions, vlan_targets = [], []
    for policy in authorization["policies"]:
        for row in tag_condition_observations(policy["conditions"], tags):
            conditions.append({"policy_id": policy["id"], "policy": policy["name"], "rule": None, **row})
        groups = [(None, policy["default_attributes"], not policy["default_gaps"], policy["enabled"])]
        for rule in policy["rules"]:
            for row in tag_condition_observations(rule["conditions"], tags):
                conditions.append({"policy_id": policy["id"], "policy": policy["name"], "rule": rule["position"], **row})
            groups.append((rule["position"], rule["combined_candidate_attributes"] if not rule["gaps"] else rule["attributes"],
                           not rule["gaps"], rule["enabled"]))
        for position, attrs, qualified, enabled in groups:
            for attr in attrs:
                if attr["kind"] != "defined-attr" or attr["name"] != "ATTR_VLAN_ID":
                    continue
                vid = vlan_identity(attr["value"])
                vlan_targets.append({"policy_id": policy["id"], "policy": policy["name"], "rule": position,
                    "policy_enabled": policy["enabled"], "rule_enabled": enabled if position is not None else None,
                    "value": attr["value"], "vlan_id": vid, "source": attr["source"],
                    "status": "conditional_vlan_candidate" if qualified and vid is not None else "unqualified_vlan_attribute"})
    identities = {v["vlan_id"] for v in vlan_targets if v["vlan_id"] is not None}
    coverage = vlan_coverage(bundle, identities)
    usage = defaultdict(set)
    for row in registrations["rows"]:
        for ref in row["references"]:
            if ref["status"] == "observed_id":
                usage[ref["candidates"][0]].add(row["id"])
    tag_summary = [{"id": identity, "name": tag.get("name"),
                    "registered_id_count": len(usage[identity]),
                    "condition_observations": [row for row in conditions if identity in row["tag_candidates"]]}
                   for identity, tag in tags.items()]
    return {"tag_summary": tag_summary, "tag_condition_observations": conditions, "vlan_targets": vlan_targets,
            "vlan_visibility": coverage, "complete": False, "safe_to_apply": False}
