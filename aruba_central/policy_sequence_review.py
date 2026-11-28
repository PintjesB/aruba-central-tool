"""Review captured policy-group ordering and explicit references in context.

HPE documents ascending unique positions and names:
https://developer.arubanetworks.com/new-central-config/reference/replacepolicygroupspolicygrouppolicygrouplistbyid
The resultant policy still depends on role and device applicability.
"""
from .central_tool import canonical, profile_body
from .policy_rule_review import condition_relationship, simple_match


def sequence_entries(evidence):
    if evidence.get("status") != "response_received":
        return {"status": "read_unqualified", "entries": []}
    raw = evidence.get("raw")
    if not isinstance(raw, dict) or set(raw) - {"metadata", "policy-group"}:
        return {"status": "schema_unqualified", "entries": []}
    group = raw.get("policy-group")
    if not isinstance(group, dict) or set(group) - {"@", "policy-group-list"}:
        return {"status": "schema_unqualified", "entries": []}
    entries = group.get("policy-group-list")
    if not isinstance(entries, list):
        return {"status": "schema_unqualified", "entries": []}
    if any(not isinstance(row, dict) or set(row) - {"@", "description", "name", "position"}
           or not isinstance(row.get("name"), str) or not row["name"]
           or type(row.get("position")) is not int or not 1 <= row["position"] <= 2000 for row in entries):
        return {"status": "entry_unqualified", "entries": entries}
    if len({r["name"] for r in entries}) != len(entries) or len({r["position"] for r in entries}) != len(entries):
        return {"status": "duplicate_name_or_position", "entries": entries}
    return {"status": "order_observed", "entries": sorted(entries, key=lambda row: row["position"])}


def qualified_rules(body):
    sec = body.get("security-policy")
    if (body.get("type") != "POLICY_TYPE_SECURITY" or not isinstance(sec, dict)
            or sec.get("type") != "SECURITY_POLICY_TYPE_DEFAULT" or not isinstance(sec.get("policy-rule"), list)):
        return None
    rules = sec["policy-rule"]
    positions = [r.get("position") if isinstance(r, dict) else None for r in rules]
    if any(type(pos) is not int or pos < 0 for pos in positions) or len(set(positions)) != len(positions):
        return None
    return sorted(rules, key=lambda r: r["position"])


def compare_sequence(parsed, policy_view, limit=1000, *, conflicts=None):
    result = {**parsed, "references": [], "findings": [], "truncated": False,
              "complete": False, "safe_to_apply": False}
    if parsed["status"] != "order_observed":
        return result
    profiles = policy_view.get("profiles", {}) if policy_view.get("status") == "list_parsed" else {}
    earlier = []
    comparisons = 0
    for entry in parsed["entries"]:
        name = entry["name"]
        if name in (conflicts or {}):
            result["references"].append({"name":name,"position":entry["position"],
                                         "status":"individual_evidence_conflict","individual_conflict":conflicts[name]})
            continue
        body = profiles.get(name)
        rules = qualified_rules(profile_body(body)) if isinstance(body, dict) else None
        status = ("rules_observed" if rules is not None else "rule_schema_unqualified" if isinstance(body, dict)
                  else "not_observed" if policy_view.get("status") == "list_parsed" and policy_view.get("count_confirmed") is True
                  else "target_unverified")
        result["references"].append({"name": name, "position": entry["position"], "status": status})
        if rules is None:
            continue
        candidates = []
        for rule in rules:
            match = simple_match(rule)
            action = rule.get("action")
            if not match or not isinstance(action, dict) or not action.get("type"):
                continue
            candidates.append((name, entry["position"], rule, match))
            for prev_name, prev_position, prev_rule, prev_match in earlier:
                comparisons += 1
                if comparisons > 100000 or len(result["findings"]) >= limit:
                    result["truncated"] = True
                    break
                relationship=condition_relationship(prev_match,match)
                if relationship is not None:
                    result["findings"].append({"condition_relationship":relationship,"earlier_policy": prev_name, "earlier_policy_position": prev_position,
                         "earlier_rule": prev_rule, "later_policy": name, "later_policy_position": entry["position"],
                         "later_rule": rule, "same_action": canonical(prev_rule["action"]) == canonical(action),
                         "status": "candidate_cross_policy_overlap"})
            if result["truncated"]:
                break
        if not result["truncated"]:
            earlier.extend(candidates)
    return result


def policy_sequence_reviews(bundle):
    from .standard_evidence import conflicting_profiles
    evidence = bundle.get("unadapted_profiles", {}).get("policy-groups", {})
    output = []
    for capture in evidence.get("source_views", []):
        persona, scope = capture["persona"], str(capture["scope"])
        entry = bundle["results"].get(persona, {})
        source = next((s for s in entry.get("scopes", []) if str(s["id"]) == scope), {})
        view = next((s.get("effective_view", {}) for s in entry.get("modules", {}).get("policies", {}).get("scope_results", [])
                     if str(s["scope"]) == scope), {})
        # Unfiltered observations preserve order evidence but cannot establish
        # target policy visibility for a specific function.
        report = compare_sequence(sequence_entries(capture.get("effective", {})), view,
                                  conflicts=conflicting_profiles(bundle,persona,"policies",scope,view))
        output.append({"persona": persona, "scope": scope, "name": source.get("name") or scope, **report})
    if "library" in evidence:
        view=bundle.get("library", {}).get("modules", {}).get("policies", {})
        report = compare_sequence(sequence_entries(evidence["library"]),view,
                                  conflicts=conflicting_profiles(bundle,"Library","policies","",view,side="library"))
        output.append({"persona": "Library", "scope": "", "name": "Library", **report})
    return output
