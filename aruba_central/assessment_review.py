"""Consolidated read-only configuration assessment with actionable worklists."""
from collections import Counter
from .advanced_review import advanced_analysis
from .assignment_review import assignment_review
from .consolidation import profile_recommendations
from .policy_variants import policy_variants
from .policy_rule_review import policy_rule_groups
from .policy_sequence_review import policy_sequence_reviews


def assessment(bundle, *, findings=None, engineering=None, assignments=None, collisions=None):
    devices = {(p, s["id"]) for p, e in bundle["results"].items()
               for s in e["scopes"] if s["kind"] == "device"}
    findings = profile_recommendations(bundle) if findings is None else findings
    engineering = advanced_analysis(bundle) if engineering is None else engineering
    assignments = assignment_review(bundle) if assignments is None else assignments
    variants = policy_variants(bundle)
    from .identity_review import identity_collisions
    collisions = identity_collisions(bundle) if collisions is None else collisions
    rules = policy_rule_groups(bundle)
    sequences = policy_sequence_reviews(bundle)
    coverage = Counter()
    for entry in bundle["results"].values():
        for module in entry["modules"].values():
            for row in module["scope_results"]:
                for kind in ("local_view", "effective_view"):
                    view = row.get(kind, {})
                    coverage["expected"] += 1
                    if view.get("status") == "list_parsed":
                        coverage["parsed"] += 1
                        if view.get("count_confirmed") is True:
                            coverage["count_confirmed"] += 1
    reference_reasons=Counter()
    for ref in engineering["references"]:
        if ref.get("source_evidence")=="nac_enforcement":
            continue
        if ref["status"]=="conflicting_observation":
            source,target=bool(ref.get("source_body_conflict")),bool(ref.get("target_body_conflict"))
            reason="both_ends" if source and target else "source_only" if source else "target_only" if target else "other_conflict"
        elif ref["status"] not in ("observed","definition_observed"):
            reason="unknown_identity" if ref["target"] is None else "named_target_not_observed" if ref["status"]=="not_observed" else "named_target_unqualified"
        else:
            continue
        reference_reasons[reason]+=1
    scope_reasons=Counter(row.get("scope_resolution","unknown") for row in assignments["rows"] if not row["scope_resolved"])
    actions = Counter(f["action"] for f in findings)
    review = [f for f in findings if f["action"] in ("remove_override", "promote_local", "reuse_library")]
    return {"device_function_pairs": len(devices), "coverage": dict(coverage),
            "actions": dict(actions), "consolidation": {"groups": len(review),
                "reviewable": sum(f.get("preview_selectable") is True for f in review),
                "source_definitions": sum(len(f["sources"]) for f in review)},
            "engineering": {"duplicate_groups": len(engineering["library_duplicates"]),
                "repeated_port_groups": len(engineering["port_groups"]),
                "ports_in_groups": sum(len(g["ports"]) for g in engineering["port_groups"]),
                "scope_observations": len(engineering["shadowed"]),
                "unresolved_references": sum(ref["status"] not in ("observed", "definition_observed") and ref.get("source_evidence")!="nac_enforcement" for ref in engineering["references"]),
                "conditional_nac_observations":sum(ref.get("source_evidence")=="nac_enforcement" for ref in engineering["references"]),
                "conflicting_reference_observations":sum(ref.get("status")=="conflicting_observation" for ref in engineering["references"]),
                **{key:reference_reasons[key] for key in ("both_ends","source_only","target_only","other_conflict","unknown_identity","named_target_not_observed","named_target_unqualified")}},
            "assignments": {"observed": len(assignments["rows"]), "overlaps": len(assignments["overlaps"]),
                "unknown_scopes": sum(not row["scope_resolved"] for row in assignments["rows"]),
                **{key:scope_reasons[key] for key in ("function_not_collected","scope_observed_other_function","scope_not_observed","unknown")},
                "invalid": len(assignments["invalid_rows"]),
                "individual_conflicts": sum(bool(r.get("library_individual_conflict") or any(d.get("individual_conflict") for d in r["recipients"])) for r in assignments["rows"])},
            "identity_collisions": {"groups":len(collisions), "same_context_groups":sum(r["same_context_collisions"]>0 for r in collisions),
                "linked_individual_responses":sum(len(r["unresolved_individual_responses"]) for r in collisions),
                "linked_same_context_responses":sum(v["both_names_observed_in_context"] for r in collisions for v in r["unresolved_individual_responses"])},
            "variants": {"groups": len(variants), "explicit": sum(v["status"] == "explicit_differences" for v in variants),
                "groups_with_conflicts":sum(bool(r.get("individual_conflicts")) for r in variants),
                "mixed_site_groups":sum(any(m["scope"] is not None and len(m["variant_numbers"])>1 for m in r.get("membership_distribution",{}).get("site",[])) for r in variants)},
            "policy_rules": {"groups": len(rules), "groups_with_findings": sum(bool(row["findings"]) for row in rules),
                "observations": sum(len(row["findings"]) for row in rules),
                "groups_with_unsupported_rules": sum(bool(row["unsupported_rules"]) or row["status"] == "rule_schema_unqualified" for row in rules),
                "unsupported_schema_groups":sum(row["status"]=="rule_schema_unqualified" for row in rules),
                "unsupported_rule_occurrences":sum(row["unsupported_rules"] for row in rules),
                "unsupported_order_occurrences":sum(sum(count for reason,count in row.get("unsupported_reasons",{}).items() if reason in ("security_order_unqualified","acl_order_or_family_unqualified")) for row in rules),
                "unsupported_condition_occurrences":sum(sum(count for reason,count in row.get("unsupported_reasons",{}).items() if reason.startswith("unsupported_") or reason=="condition_not_object") for row in rules),
                "unsupported_acl_predicate_occurrences":sum(row.get("unsupported_reasons",{}).get("acl_predicate_unqualified",0) for row in rules),
                "unqualified_order": sum(not row["order_verified"] for row in rules),
                "individual_conflict_groups":sum(row["status"]=="individual_evidence_conflict" for row in rules),
                "structural_security_repetitions":sum(f["status"]=="identical_unsupported_security_rule_body" for row in rules for f in row["findings"]),
                "partial_overlap_candidates":sum(f.get("condition_relationship")=="partial_overlap" for row in rules for f in row["findings"]),
                "reverse_containment_candidates":sum(f.get("condition_relationship")=="later_contains_earlier" for row in rules for f in row["findings"]),
                "truncated": sum(row["truncated"] for row in rules)},
            "policy_sequences": {"captures": len(sequences),
                "unqualified_order": sum(row["status"] != "order_observed" for row in sequences),
                "unqualified_targets": sum(ref["status"] != "rules_observed" for row in sequences for ref in row["references"]),
                "cross_policy_candidates": sum(len(row["findings"]) for row in sequences),
                "partial_overlap_candidates":sum(f.get("condition_relationship")=="partial_overlap" for row in sequences for f in row["findings"]),
                "conflicting_targets":sum(ref["status"]=="individual_evidence_conflict" for row in sequences for ref in row["references"]),
                "truncated": sum(row["truncated"] for row in sequences)},
            "checkpoint": bundle.get("collection_checkpoint", {}), "captured_at": bundle.get("captured_at"),
            "complete": False, "safe_to_apply": False}
