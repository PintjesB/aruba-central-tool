"""Anonymous qualification of aggregate engineering observations."""
from .central_tool import refresh_configuration_review
from .assessment_review import assessment

# Fixed output keys only. Do not serialize action names, checkpoint data,
# timestamps, names, identities, values or any raw report structures.
FIELDS={
    "engineering":("duplicate_groups","repeated_port_groups","ports_in_groups","scope_observations",
                   "unresolved_references","conditional_nac_observations","conflicting_reference_observations",
                   "both_ends","source_only","target_only","other_conflict","unknown_identity","named_target_not_observed","named_target_unqualified"),
    "identity_collisions":("groups","same_context_groups","linked_individual_responses","linked_same_context_responses"),
    "variants":("groups","explicit","groups_with_conflicts","mixed_site_groups"),
    "policy_rules":("groups","groups_with_findings","observations","groups_with_unsupported_rules","unsupported_schema_groups","unsupported_rule_occurrences","unsupported_order_occurrences",
                    "unsupported_condition_occurrences","unsupported_acl_predicate_occurrences","unqualified_order",
                    "individual_conflict_groups","structural_security_repetitions","partial_overlap_candidates","reverse_containment_candidates","truncated"),
    "policy_sequences":("captures","unqualified_order","unqualified_targets","cross_policy_candidates","qualified_rule_occurrences","unsupported_rule_occurrences","targets_with_unsupported_rules",
                        "partial_overlap_candidates","conflicting_targets","truncated"),
    "assignments":("observed","overlaps","unknown_scopes","invalid","individual_conflicts",
                   "function_not_collected","scope_observed_other_function","scope_not_observed","unknown"),
    "consolidation":("groups","reviewable","source_definitions")
}


def engineering_qualification(bundle):
    report=assessment(refresh_configuration_review(bundle))
    counts={}
    for category,fields in FIELDS.items():
        counts[category]={}
        for field in fields:
            value=report[category][field]
            if type(value) is not int or value<0:
                raise ValueError("Invalid aggregate engineering count")
            counts[category][field]=value
    return {"schema":1,"kind":"anonymous_engineering_qualification","counts":counts,
            "central_api_requests":0,"complete":False,"safe_to_apply":False}
