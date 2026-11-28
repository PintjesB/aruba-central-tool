"""Consolidated read-only configuration assessment with actionable worklists."""
from collections import Counter
from .advanced_review import advanced_analysis
from .assignment_review import assignment_review
from .consolidation import profile_recommendations
from .policy_variants import policy_variants
from .policy_rule_review import policy_rule_groups, POLICY_SCHEMA_STATES, POLICY_BODY_SHAPES, predicate_pattern_summary
from .policy_sequence_review import policy_sequence_reviews
from .dependency_evidence import reference_semantics, REFERENCE_SEMANTICS

SECURITY_REASONS = ("rule_not_object", "additional_rule_fields", "condition_not_object",
    "unsupported_condition_fields", "unsupported_condition_type", "unsupported_rule_type",
    "unsupported_address_shape", "action_unqualified", "security_order_unqualified")
ACL_REASONS = ("rule_not_object", "additional_rule_fields", "source_role_unqualified", "vrf_unqualified",
    "action_unqualified", "literal_destination_unqualified", "family_unqualified", "order_unqualified")
SEQUENCE_CONTEXTS = ("unfiltered_function", "function_not_collected", "scope_not_observed",
    "policy_view_not_collected", "policy_view_unqualified", "policy_view_parsed", "unknown")
POLICY_LIBRARY_RELATIONS = ("exact_body_match","only_missing_policy_type","different_body","not_observed","individual_conflict")
ALTERNATIVE_POLICY_CONTEXTS = ("other_function_same_scope", "unfiltered_same_scope", "library_definition")
ASSIGNMENT_FUNCTION_CONTEXTS = ("function_collected", "function_adapter_unqualified", "hybrid_nac_not_network_scope",
    "function_outside_network_adapter", "function_in_inventory_not_collected", "function_inventory_unavailable",
    "function_not_observed_in_inventory", "unknown")
SEQUENCE_TARGET_STATES = ("rules_observed", "rule_schema_unqualified", "not_observed",
    "target_unverified", "individual_evidence_conflict")


def assessment(bundle, *, findings=None, engineering=None, assignments=None, collisions=None,
               variants=None, rules=None, sequences=None):
    devices = {(p, s["id"]) for p, e in bundle["results"].items()
               for s in e["scopes"] if s["kind"] == "device"}
    findings = profile_recommendations(bundle) if findings is None else findings
    engineering = advanced_analysis(bundle) if engineering is None else engineering
    assignments = assignment_review(bundle) if assignments is None else assignments
    variants = policy_variants(bundle) if variants is None else variants
    from .identity_review import identity_collisions
    collisions = identity_collisions(bundle) if collisions is None else collisions
    rules = policy_rule_groups(bundle) if rules is None else rules
    sequences = policy_sequence_reviews(bundle) if sequences is None else sequences
    security_reasons, acl_reasons = Counter(), Counter()
    schema_reasons = Counter(row.get("schema_state") if row.get("schema_state") in POLICY_SCHEMA_STATES else "unknown"
                             for row in rules if row["status"] == "rule_schema_unqualified")
    sequence_schema_reasons, alternative_targets = Counter(), Counter()
    body_shapes=Counter(row.get("body_shape") if row.get("body_shape") in POLICY_BODY_SHAPES else "unknown" for row in rules if row["status"] == "rule_schema_unqualified")
    library_relations=Counter(row.get("library_body_relation") for row in rules if row["status"] == "rule_schema_unqualified" and row.get("library_body_relation") in POLICY_LIBRARY_RELATIONS)
    previews=[row["library_preview"] for row in sequences if "library_preview" in row]
    from .central_tool import canonical
    unique_library_candidates={canonical(finding) for row in previews for finding in row["findings"]}
    conditional_previews=[row["conditional_security_preview"] for row in rules if "conditional_security_preview" in row]
    for row in rules:
        if row.get("module") == "policies":
            security_reasons.update(row.get("unsupported_reasons", {}))
        elif row.get("module") == "role-acls":
            acl_reasons.update(row.get("acl_unsupported_reasons", {}))
    sequence_context_gaps = Counter()
    sequence_target_states = Counter()
    for row in sequences:
        context = row.get("target_context", "unknown")
        if context not in SEQUENCE_CONTEXTS:
            context = "unknown"
        for ref in row["references"]:
            sequence_target_states[ref["status"]] += 1
            if ref["status"] != "rules_observed":
                sequence_context_gaps[context] += 1
                if ref["status"] == "rule_schema_unqualified":
                    sequence_schema_reasons[ref.get("schema_state") if ref.get("schema_state") in POLICY_SCHEMA_STATES else "unknown"] += 1
                alternatives = {v.get("context") for v in ref.get("alternative_observations", []) if v.get("status") == "identity_observed" and v.get("context") in ALTERNATIVE_POLICY_CONTEXTS}
                alternative_targets.update(alternatives)
                if alternatives:
                    alternative_targets["any"] += 1
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
    from .vlan_membership import member_count
    absent_semantics = Counter()
    compact_fields=Counter()
    absent_fields = set()
    for ref in engineering["references"]:
        if ref.get("source_evidence")=="nac_enforcement":
            continue
        if ref.get("target_member_ranges"):
            compact_fields["fields"]+=1
            compact_fields["members"]+=ref["target_member_count"]
            compact_fields[ref["status"]]+=1
        if ref["status"] == "not_observed" and ref.get("target_evidence") in ("count_confirmed_absence","set_count_confirmed_absence"):
            semantics = reference_semantics(ref)
            absent_semantics[semantics] += member_count(ref)
            if semantics != "direct_or_unclassified":
                absent_fields.add((ref.get("persona"),ref.get("scope"),ref.get("source_view"),ref.get("source_module"),ref.get("source"),tuple(ref.get("path",[]))))
        if ref["status"]=="conflicting_observation":
            source,target=bool(ref.get("source_body_conflict")),bool(ref.get("target_body_conflict"))
            reason="both_ends" if source and target else "source_only" if source else "target_only" if target else "other_conflict"
        elif ref["status"] not in ("observed","definition_observed"):
            reason="compact_membership" if ref.get("target_member_ranges") else "unknown_identity" if ref["target"] is None else "named_target_not_observed" if ref["status"]=="not_observed" else "named_target_unqualified"
        else:
            continue
        reference_reasons[reason]+=1
    reference_contexts = ("library_definition","other_function_same_scope","same_site_observation")
    reference_alternatives = Counter()
    for ref in engineering["references"]:
        if ref["status"] != "unresolved" or ref.get("target") is None or ref.get("source_evidence") == "nac_enforcement":
            continue
        contexts = {obs.get("context") for obs in ref.get("target_alternative_observations",[])
                    if obs.get("status") == "identity_observed" and obs.get("context") in reference_contexts}
        reference_alternatives.update(contexts)
        reference_alternatives["any" if contexts else "none"] += 1
    scope_reasons=Counter(row.get("scope_resolution","unknown") for row in assignments["rows"] if not row["scope_resolved"])
    function_contexts = Counter(row.get("function_context") if row.get("function_context") in ASSIGNMENT_FUNCTION_CONTEXTS else "unknown"
                                for row in assignments["rows"] if not row["scope_resolved"])
    unresolved_assignment_reads=Counter(row.get("assignment_evidence_state","not_collected") for row in assignments["rows"] if not row["scope_resolved"])
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
                "precedence_conflicts": len(engineering.get("precedence_conflicts", [])),
                "port_conversion_conflicts": sum(r["status"] == "individual_evidence_conflict" for g in engineering["port_groups"] for r in g.get("conversion_review", [])),
                "port_library_conflicts": sum(len(g.get("conflicting_library_matches", [])) for g in engineering["port_groups"]),
                "port_visibility_conflicts": sum(v["status"] == "individual_evidence_conflict" for g in engineering["port_groups"] for m in g.get("matching_library_profiles", []) for v in m["visibility"]),
                "reference_target_collection_incomplete": sum(r.get("target_evidence") == "target_collection_incomplete" for r in engineering["references"]),
                "reference_target_view_unqualified": sum(r.get("target_evidence") == "target_view_unqualified" for r in engineering["references"]),
                **{"reference_absence_"+key:absent_semantics[key] for key in REFERENCE_SEMANTICS},
                "reference_absent_set_source_fields":len(absent_fields),
                "compact_membership_fields":compact_fields["fields"],
                "compact_membership_members":compact_fields["members"],
                "compact_membership_unresolved_fields":compact_fields["unresolved"],
                "compact_membership_absent_fields":compact_fields["not_observed"],
                "reference_target_count_confirmed_absence": sum(member_count(r) for r in engineering["references"] if r.get("target_evidence") in ("count_confirmed_absence","set_count_confirmed_absence")),
                "unresolved_reference_target_individual_identity": sum(r.get("status") == "unresolved" and r.get("target_individual_status") == "identity_observed" for r in engineering["references"]),
                **{"reference_alternative_"+key:reference_alternatives[key] for key in reference_contexts+("any","none")},
                "unresolved_references": sum(ref["status"] not in ("observed", "definition_observed") and ref.get("source_evidence")!="nac_enforcement" for ref in engineering["references"]),
                "unresolved_member_equivalents":sum(member_count(ref) for ref in engineering["references"] if ref["status"] not in ("observed","definition_observed") and ref.get("source_evidence")!="nac_enforcement"),
                "compact_membership_conflicting_fields":compact_fields["conflicting_observation"],
                "conditional_nac_observations":sum(ref.get("source_evidence")=="nac_enforcement" for ref in engineering["references"]),
                "conflicting_reference_observations":sum(ref.get("status")=="conflicting_observation" for ref in engineering["references"]),
                **{key:reference_reasons[key] for key in ("both_ends","source_only","target_only","other_conflict","unknown_identity","named_target_not_observed","named_target_unqualified","compact_membership")}},
            "assignments": {"observed": len(assignments["rows"]), "overlaps": len(assignments["overlaps"]),
                "unknown_scopes": sum(not row["scope_resolved"] for row in assignments["rows"]),
                **{"unresolved_function_" + key: function_contexts[key] for key in ASSIGNMENT_FUNCTION_CONTEXTS},
                **{"unresolved_scope_keyed_"+key:unresolved_assignment_reads[key] for key in ("identity_observed","body_difference_observed","scope_only_observed","multiple_observations","not_collected","individual_read_unqualified")},
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
                "conditional_preview_groups":len(conditional_previews),
                "conditional_preview_order_verified":sum(row["order_verified"] for row in conditional_previews),
                "conditional_preview_rules":sum(row["rules"] for row in conditional_previews),
                "conditional_preview_predicates":sum(row["qualified_match_rules"] for row in conditional_previews),
                "conditional_preview_candidates":sum(len(row["findings"]) for row in conditional_previews),
                "conditional_preview_truncated":sum(row["truncated"] for row in conditional_previews),
                "conditional_structural_condition_pairs":sum(len(row.get("structural_condition_pairs",[])) for row in conditional_previews),
                "conditional_structural_truncated":sum(row.get("structural_condition_pairs_truncated") is True for row in conditional_previews),
                "captured_structural_condition_pairs":sum(len(row.get("structural_condition_pairs",[])) for row in rules),
                **{"schema_" + key: schema_reasons[key] for key in POLICY_SCHEMA_STATES + ("unknown",)},
                **{"body_shape_" + key: body_shapes[key] for key in POLICY_BODY_SHAPES + ("unknown",)},
                **{"library_relation_" + key: library_relations[key] for key in POLICY_LIBRARY_RELATIONS},
                "unsupported_rule_occurrences":sum(row["unsupported_rules"] for row in rules),
                "unsupported_order_occurrences":sum(sum(count for reason,count in row.get("unsupported_reasons",{}).items() if reason in ("security_order_unqualified","acl_order_or_family_unqualified")) for row in rules),
                "unsupported_condition_occurrences":sum(sum(count for reason,count in row.get("unsupported_reasons",{}).items() if reason.startswith("unsupported_") or reason=="condition_not_object") for row in rules),
                "unsupported_acl_predicate_occurrences":sum(row.get("unsupported_reasons",{}).get("acl_predicate_unqualified",0) for row in rules),
                "unqualified_order": sum(not row["order_verified"] for row in rules),
                "individual_conflict_groups":sum(row["status"]=="individual_evidence_conflict" for row in rules),
                "structural_security_repetitions":sum(f["status"]=="identical_unsupported_security_rule_body" for row in rules for f in row["findings"]),
                "partial_overlap_candidates":sum(f.get("condition_relationship")=="partial_overlap" for row in rules for f in row["findings"]),
                "reverse_containment_candidates":sum(f.get("condition_relationship")=="later_contains_earlier" for row in rules for f in row["findings"]),
                "truncated": sum(row["truncated"] for row in rules),
                **{"security_" + key: security_reasons[key] for key in SECURITY_REASONS},
                **{"acl_" + key: acl_reasons[key] for key in ACL_REASONS}},
            "policy_sequences": {"captures": len(sequences),
                "unqualified_order": sum(row["status"] != "order_observed" for row in sequences),
                "unqualified_targets": sum(ref["status"] != "rules_observed" for row in sequences for ref in row["references"]),
                "cross_policy_candidates": sum(len(row["findings"]) for row in sequences),
                "library_preview_captures":len(previews),
                "library_preview_candidates":sum(len(row["findings"]) for row in previews),
                "library_preview_distinct_candidate_bodies":len(unique_library_candidates),
                "conditional_effective_targets":sum("conditional_security_rule_count" in ref for row in sequences for ref in row["references"]),
                "conditional_effective_predicates":sum(ref.get("conditional_security_predicate_count",0) for row in sequences for ref in row["references"]),
                "conditional_library_targets":sum("conditional_security_rule_count" in ref for row in previews for ref in row["references"]),
                "conditional_library_predicates":sum(ref.get("conditional_security_predicate_count",0) for row in previews for ref in row["references"]),
                "library_preview_unqualified_targets":sum(ref["status"]!="rules_observed" for row in previews for ref in row["references"]),
                "library_preview_qualified_targets":sum(ref["status"]=="rules_observed" for row in previews for ref in row["references"]),
                "library_preview_truncated":sum(row["truncated"] for row in previews),
                "qualified_rule_occurrences": sum(ref.get("qualified_rule_count", 0) for row in sequences for ref in row["references"]),
                "unsupported_rule_occurrences": sum(ref.get("unsupported_rule_count", 0) for row in sequences for ref in row["references"]),
                "targets_with_unsupported_rules": sum(ref.get("unsupported_rule_count", 0) > 0 for row in sequences for ref in row["references"]),
                "partial_overlap_candidates":sum(f.get("condition_relationship")=="partial_overlap" for row in sequences for f in row["findings"]),
                "conflicting_targets":sum(ref["status"]=="individual_evidence_conflict" for row in sequences for ref in row["references"]),
                "truncated": sum(row["truncated"] for row in sequences),
                **{"gap_context_" + key: sequence_context_gaps[key] for key in SEQUENCE_CONTEXTS},
                **{"schema_" + key: sequence_schema_reasons[key] for key in POLICY_SCHEMA_STATES + ("unknown",)},
                **{"alternative_" + key: alternative_targets[key] for key in ALTERNATIVE_POLICY_CONTEXTS + ("any",)},
                **{"target_" + key: sequence_target_states[key] for key in SEQUENCE_TARGET_STATES}},
            "policy_predicate_patterns":predicate_pattern_summary(rules),
            "checkpoint": bundle.get("collection_checkpoint", {}), "captured_at": bundle.get("captured_at"),
            "complete": False, "safe_to_apply": False}
