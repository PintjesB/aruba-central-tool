"""Review captured policy-group ordering and explicit references in context.

HPE documents ascending unique positions and names:
https://developer.arubanetworks.com/new-central-config/reference/replacepolicygroupspolicygrouppolicygrouplistbyid
The resultant policy still depends on role and device applicability.
"""
from .central_tool import canonical, profile_body
from .policy_rule_review import condition_relationship, simple_match, unsupported_security_reason, policy_schema_state


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
        reference = {"name": name, "position": entry["position"], "status": status}
        if isinstance(body, dict):
            reference["schema_state"] = policy_schema_state("policies", profile_body(body))
        result["references"].append(reference)
        if rules is None:
            continue
        qualified = [(rule, simple_match(rule)) for rule in rules if unsupported_security_reason(rule) is None]
        reference.update({"rule_count": len(rules), "qualified_rule_count": len(qualified),
                          "unsupported_rule_count": len(rules) - len(qualified)})
        if result["truncated"]:
            continue
        candidates = []
        for rule, match in qualified:
            action = rule["action"]
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
    scopes, views = {}, {}
    from collections import defaultdict
    from .central_tool import module_view
    views_by_scope = defaultdict(dict)
    unfiltered_reads = defaultdict(list)
    for capture in (bundle.get("unadapted_profiles") or {}).get("policies", {}).get("source_views", []):
        if capture.get("persona") in ("ALL_DEVICE_FUNCTIONS", "UNFILTERED_SCOPE"):
            read = capture.get("effective", {})
            if read.get("status") == "response_received":
                raw = read.get("raw")
                # The policies collection has a documented named identity.
                # Do not use mixed responses for typed traversal or absence.
                if isinstance(raw, dict) and isinstance(raw.get("policy"), list):
                    unfiltered_reads[str(capture["scope"])].append(module_view(raw, "name"))
    library_view = (bundle.get("library") or {}).get("modules", {}).get("policies", {})
    library_conflicts = conflicting_profiles(bundle,"Library","policies","",library_view,side="library")
    library_previews = {}
    for persona, entry in bundle["results"].items():
        for source in entry.get("scopes", []):
            scopes.setdefault((persona, str(source["id"])), source)
        for row in entry.get("modules", {}).get("policies", {}).get("scope_results", []):
            key = (persona, str(row["scope"]))
            views.setdefault(key, row.get("effective_view", {}))
            views_by_scope[key[1]].setdefault(persona, views[key])
    for capture in evidence.get("source_views", []):
        persona, scope = capture["persona"], str(capture["scope"])
        key = (persona, scope)
        source = scopes.get(key, {})
        view = views.get(key, {})
        context = ("unfiltered_function" if persona == "ALL_DEVICE_FUNCTIONS" else
                   "function_not_collected" if persona not in bundle["results"] else
                   "scope_not_observed" if key not in scopes else
                   "policy_view_not_collected" if key not in views else
                   "policy_view_unqualified" if view.get("status") != "list_parsed" else
                   "policy_view_parsed")
        # Unfiltered observations preserve order evidence but cannot establish
        # target policy visibility for a specific function.
        report = compare_sequence(sequence_entries(capture.get("effective", {})), view,
                                  conflicts=conflicting_profiles(bundle,persona,"policies",scope,view))
        for ref in report["references"]:
            if ref["status"] == "rules_observed":
                continue
            name = ref["name"]
            observations = []
            for other, other_view in sorted(views_by_scope[scope].items()):
                if other == persona or other_view.get("status") != "list_parsed" or name not in other_view.get("profiles", {}):
                    continue
                conflicts = conflicting_profiles(bundle,other,"policies",scope,other_view,{name})
                observations.append({"context":"other_function_same_scope","persona":other,
                    "status":"individual_evidence_conflict" if name in conflicts else "identity_observed"})
            for mixed in unfiltered_reads[scope]:
                if mixed.get("status") == "list_parsed" and name in mixed.get("profiles", {}):
                    observations.append({"context":"unfiltered_same_scope","status":"identity_observed"})
            if library_view.get("status") == "list_parsed" and name in library_view.get("profiles", {}):
                observations.append({"context":"library_definition","status":"individual_evidence_conflict" if name in library_conflicts else "identity_observed"})
            if observations:
                ref["alternative_observations"] = observations
        # A separate definition-only analysis uses the captured sequence order
        # and exclusively Library bodies. Never mix Library and effective rules
        # or replace an unresolved scope target with a definition.
        if report["status"] == "order_observed" and any(ref["status"] != "rules_observed" for ref in report["references"]):
            signature = canonical(report["entries"])
            if signature not in library_previews:
                preview = compare_sequence({"status": report["status"], "entries": report["entries"]},
                                           library_view, conflicts=library_conflicts)
                library_previews[signature] = {**preview, "context": "library_definition_only"}
            report["library_preview"] = library_previews[signature]
        output.append({"persona": persona, "scope": scope, "name": source.get("name") or scope,
                       "target_context": context, **report})
    if "library" in evidence:
        modules=(bundle.get("library") or {}).get("modules", {})
        view=modules.get("policies", {})
        context = ("policy_view_not_collected" if "policies" not in modules else
                   "policy_view_parsed" if view.get("status") == "list_parsed" else "policy_view_unqualified")
        report = compare_sequence(sequence_entries(evidence["library"]),view,
                                  conflicts=conflicting_profiles(bundle,"Library","policies","",view,side="library"))
        output.append({"persona": "Library", "scope": "", "name": "Library",
                       "target_context": context, **report})
    return output
