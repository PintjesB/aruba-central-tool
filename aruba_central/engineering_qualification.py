"""Anonymous qualification of aggregate engineering observations."""
from .central_tool import refresh_configuration_review
from .assessment_review import (assessment, SECURITY_REASONS, ACL_REASONS, SEQUENCE_CONTEXTS, SEQUENCE_TARGET_STATES,
    POLICY_SCHEMA_STATES, ALTERNATIVE_POLICY_CONTEXTS, ASSIGNMENT_FUNCTION_CONTEXTS)

# Fixed output keys only. Do not serialize action names, checkpoint data,
# timestamps, names, identities, values or any raw report structures.
FIELDS={
    "engineering":("duplicate_groups","repeated_port_groups","ports_in_groups","scope_observations",
                   "precedence_conflicts","port_conversion_conflicts","port_library_conflicts","port_visibility_conflicts",
                   "reference_target_collection_incomplete","reference_target_view_unqualified","reference_target_count_confirmed_absence","unresolved_reference_target_individual_identity",
                   "unresolved_references","conditional_nac_observations","conflicting_reference_observations",
                   "both_ends","source_only","target_only","other_conflict","unknown_identity","named_target_not_observed","named_target_unqualified"),
    "identity_collisions":("groups","same_context_groups","linked_individual_responses","linked_same_context_responses"),
    "variants":("groups","explicit","groups_with_conflicts","mixed_site_groups"),
    "policy_rules":("groups","groups_with_findings","observations","groups_with_unsupported_rules","unsupported_schema_groups","unsupported_rule_occurrences","unsupported_order_occurrences",
                    "unsupported_condition_occurrences","unsupported_acl_predicate_occurrences","unqualified_order",
                    "individual_conflict_groups","structural_security_repetitions","partial_overlap_candidates","reverse_containment_candidates","truncated")
                    + tuple("schema_" + key for key in POLICY_SCHEMA_STATES + ("unknown",))
                    + tuple("security_" + key for key in SECURITY_REASONS)
                    + tuple("acl_" + key for key in ACL_REASONS),
    "policy_sequences":("captures","unqualified_order","unqualified_targets","cross_policy_candidates","qualified_rule_occurrences","unsupported_rule_occurrences","targets_with_unsupported_rules",
                        "partial_overlap_candidates","conflicting_targets","truncated")
                    + tuple("gap_context_" + key for key in SEQUENCE_CONTEXTS)
                    + tuple("target_" + key for key in SEQUENCE_TARGET_STATES)
                    + tuple("schema_" + key for key in POLICY_SCHEMA_STATES + ("unknown",))
                    + tuple("alternative_" + key for key in ALTERNATIVE_POLICY_CONTEXTS + ("any",)),
    "assignments":("observed","overlaps","unknown_scopes","invalid","individual_conflicts",
                   "unresolved_scope_keyed_identity_observed","unresolved_scope_keyed_body_difference_observed","unresolved_scope_keyed_scope_only_observed",
                   "unresolved_scope_keyed_multiple_observations","unresolved_scope_keyed_not_collected","unresolved_scope_keyed_individual_read_unqualified",
                   "function_not_collected","scope_observed_other_function","scope_not_observed","unknown")
                   + tuple("unresolved_function_" + key for key in ASSIGNMENT_FUNCTION_CONTEXTS),
    "consolidation":("groups","reviewable","source_definitions")
}


def engineering_qualification(bundle, *, include_reference_patterns=False):
    reviewed = refresh_configuration_review(bundle)
    engineering = None
    if include_reference_patterns:
        from .advanced_review import advanced_analysis
        engineering = advanced_analysis(reviewed)
    report = assessment(reviewed) if engineering is None else assessment(reviewed, engineering=engineering)
    counts={}
    for category,fields in FIELDS.items():
        counts[category]={}
        for field in fields:
            value=report[category][field]
            if type(value) is not int or value<0:
                raise ValueError("Invalid aggregate engineering count")
            counts[category][field]=value
    result = {"schema":1,"kind":"anonymous_engineering_qualification","counts":counts,
              "central_api_requests":0,"complete":False,"safe_to_apply":False}
    if engineering is not None:
        result["reference_identity_patterns"] = reference_identity_patterns(engineering["references"])
    return result


# Static vendor schema keys only. Do not serialize arbitrary JSON keys, path
# components, values, configuration identities, scope IDs or device names.
def reference_identity_patterns(references):
    from collections import Counter
    from .central_tool import CONFIG_MODULES, VLAN_REFERENCE_FIELDS
    fields = VLAN_REFERENCE_FIELDS | {
        "access-vlan-name", "vlan-parameters", "vlan-type", "vlan-selector",
        "vlan-id-range", "vlan-name", "unknown-vlans", "vlan-range",
        "vlan-mode", "vlan-list", "vlan-pool", "vlan-map", "vlan-assignment",
        "forbid-vlans", "vlan-tagging", "vlan-tag", "vlan-membership",
        "sw-profile-alias", "sw-profile", "ap-profile", "gw-profile",
        "rfc3576-server-list", "server-name", "net-service", "net-group",
        "exclude", "role", "policy", "name", "identity", "src-role",
        "default-role", "auth-server-group", "acct-server-group",
        "object-group-ipv4", "object-group-ipv6"}
    modules = set(CONFIG_MODULES)
    known_views = {"effective", "saved", "library"}
    counts = Counter()
    for row in references:
        if row.get("status") != "unresolved" or row.get("target") is not None or row.get("source_evidence") == "nac_enforcement":
            continue
        source, target = (row.get(key) if row.get(key) in modules else "other"
                          for key in ("source_module", "target_module"))
        path = row.get("path")
        path = path if isinstance(path, list) else []
        leaf = next((value for value in reversed(path) if isinstance(value, str)), "")
        field = leaf if leaf in fields else "other"
        shape = ("list_member" if any(type(v) is int for v in path) else
                 "root_field" if len(path) == 1 else "nested_field" if path else "unknown")
        view = row.get("source_view") if row.get("source_view") in known_views else "other"
        counts[source, target, field, shape, view] += 1
    return [{"source_module":s, "target_module":t, "field":f, "path_shape":p,
             "source_view":v, "observations":count}
            for (s,t,f,p,v),count in sorted(counts.items(), key=lambda item:(-item[1],item[0]))]


def main():
    import argparse
    from pathlib import Path
    from .config_app import audit_files, read_audit
    from .central_tool import write_private
    parser = argparse.ArgumentParser(description="Anonymous focused engineering qualification; no browser or Central requests.")
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--snapshot", help="Exact saved snapshot filename; defaults to latest")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output already exists; choose a new filename")
    try:
        paths = audit_files(args.directory)
        path = next((p for p in paths if args.snapshot is None or p.name == args.snapshot), None)
        if path is None:
            raise ValueError("No matching capture")
        def fingerprint():
            if path.is_symlink():
                raise ValueError("Snapshot changed")
            s = path.stat()
            return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        initial = fingerprint()
        report = engineering_qualification(read_audit(args.directory,path.name),include_reference_patterns=True)
        if fingerprint() != initial:
            raise ValueError("Snapshot changed")
        report["same_capture_verified"] = True
    except Exception:
        parser.error("Engineering qualification failed; verify the unchanged saved capture")
    write_private(args.output, report)
    print("Anonymous engineering qualification saved.")


if __name__ == "__main__":
    main()
