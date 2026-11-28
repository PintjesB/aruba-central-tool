"""Anonymous qualification of aggregate engineering observations."""
from .central_tool import refresh_configuration_review
from .assessment_review import (assessment, SECURITY_REASONS, ACL_REASONS, SEQUENCE_CONTEXTS, SEQUENCE_TARGET_STATES,
    POLICY_SCHEMA_STATES, ALTERNATIVE_POLICY_CONTEXTS, ASSIGNMENT_FUNCTION_CONTEXTS, POLICY_BODY_SHAPES, POLICY_LIBRARY_RELATIONS)
from .dependency_evidence import REFERENCE_SEMANTICS, reference_semantics
from .policy_service_review import SERVICE_STATES
from .policy_transport_review import TRANSPORT_STATES

# Fixed output keys only. Do not serialize action names, checkpoint data,
# timestamps, names, identities, values or any raw report structures.
FIELDS={
    "engineering":("duplicate_groups","repeated_port_groups","ports_in_groups","scope_observations",
                   "precedence_conflicts","port_conversion_conflicts","port_library_conflicts","port_visibility_conflicts",
                   "reference_target_collection_incomplete","reference_target_view_unqualified","reference_target_count_confirmed_absence","unresolved_reference_target_individual_identity",
                   "unresolved_references","conditional_nac_observations","conflicting_reference_observations",
                   "reference_alternative_library_definition","reference_alternative_other_function_same_scope",
                   "reference_alternative_same_site_observation","reference_alternative_any","reference_alternative_none",
                   "both_ends","source_only","target_only","other_conflict","unknown_identity","named_target_not_observed","named_target_unqualified",
                   "reference_absent_set_source_fields","compact_membership","compact_membership_fields","compact_membership_members",
                   "compact_membership_unresolved_fields","compact_membership_absent_fields","compact_membership_conflicting_fields","unresolved_member_equivalents") + tuple("reference_absence_"+key for key in REFERENCE_SEMANTICS),
    "identity_collisions":("groups","same_context_groups","linked_individual_responses","linked_same_context_responses"),
    "variants":("groups","explicit","groups_with_conflicts","mixed_site_groups"),
    "policy_rules":("groups","groups_with_findings","observations","groups_with_unsupported_rules","unsupported_schema_groups","unsupported_rule_occurrences","unsupported_order_occurrences",
                    "conditional_preview_groups","conditional_preview_order_verified","conditional_preview_rules",
                    "conditional_preview_predicates","conditional_preview_candidates","conditional_preview_truncated",
                    "conditional_structural_condition_pairs","conditional_structural_truncated","captured_structural_condition_pairs",
                    "unsupported_condition_occurrences","unsupported_acl_predicate_occurrences","unqualified_order",
                    "individual_conflict_groups","structural_security_repetitions","partial_overlap_candidates","reverse_containment_candidates","truncated")
                    + tuple("schema_" + key for key in POLICY_SCHEMA_STATES + ("unknown",))
                    + tuple("body_shape_" + key for key in POLICY_BODY_SHAPES + ("unknown",))
                    + tuple("library_relation_" + key for key in POLICY_LIBRARY_RELATIONS)
                    + tuple("service_" + key for key in SERVICE_STATES)
                    + tuple("transport_" + key for key in TRANSPORT_STATES)
                    + tuple("security_" + key for key in SECURITY_REASONS)
                    + tuple("acl_" + key for key in ACL_REASONS),
    "policy_sequences":("captures","unqualified_order","unqualified_targets","cross_policy_candidates","qualified_rule_occurrences","unsupported_rule_occurrences","targets_with_unsupported_rules",
                        "partial_overlap_candidates","conflicting_targets","truncated","library_preview_captures","library_preview_candidates",
                        "library_preview_unqualified_targets","library_preview_qualified_targets","library_preview_truncated",
                        "library_preview_distinct_candidate_bodies","conditional_effective_targets","conditional_effective_predicates",
                        "conditional_library_targets","conditional_library_predicates")
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
        from .policy_rule_review import policy_rule_groups
        rules = policy_rule_groups(reviewed)
    report = assessment(reviewed) if engineering is None else assessment(reviewed, engineering=engineering, rules=rules)
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
        result["policy_predicate_patterns"] = report["policy_predicate_patterns"]
        result["reference_identity_patterns"] = reference_identity_patterns(engineering["references"])
        result["named_reference_gaps"] = named_reference_gaps(engineering["references"])
        result["named_reference_field_gaps"] = named_reference_field_gaps(engineering["references"])
        result["reference_absence_patterns"] = reference_absence_patterns(engineering["references"])
        result["role_vlan_name_evidence"] = role_vlan_name_evidence(engineering["references"])
        result["reference_conflict_patterns"] = reference_conflict_patterns(engineering["references"])
        result["policy_clause_gaps"] = policy_clause_gaps(rules)
        result["named_reference_target_groups"] = named_reference_target_groups(engineering["references"])
    return result


# Static vendor schema keys only. Do not serialize arbitrary JSON keys, path
# components, values, configuration identities, scope IDs or device names.
def reference_identity_patterns(references):
    from collections import Counter
    from .central_tool import CONFIG_MODULES, VLAN_REFERENCE_FIELDS
    from .advanced_review import REFERENCE_VALUE_SHAPES
    fields = VLAN_REFERENCE_FIELDS | {
        "access-vlan-name", "vlan-parameters", "vlan-type", "vlan-selector",
        "vlan-id-range", "vlan-name", "unknown-vlans", "vlan-range",
        "vlan-mode", "vlan-list", "vlan-pool", "vlan-map", "vlan-assignment",
        "forbid-vlans", "vlan-tagging", "vlan-tag", "vlan-membership",
        "sw-profile-alias", "sw-profile", "ap-profile", "gw-profile",
        "rfc3576-server-list", "server-name", "net-service", "net-group",
        "exclude", "role", "policy", "name", "identity", "src-role",
        "default-role", "auth-server-group", "acct-server-group",
        "object-group-ipv4", "object-group-ipv6", "vlan-id-ranges", "vlan-alias", "allowed-vlan-name",
        "allowed-vlan-selector","trunk-vlan-ranges","trunk-vlans","trunk-vlan-all","named-vlan",
        "trunk-native-vlan","wired-access-vlan-id","wired-access-vlan-name","trunk-allowed-vlans",
        "trunk-allowed-vlan-names","trunk-native-vlan-name","private-vlan-port-type",
        "rpvst-mstp-interconnect-vlan","mstp-vlans","vlans","vlan-log-state-transitions"}
    modules = set(CONFIG_MODULES)
    known_views = {"effective", "saved", "library"}
    counts = Counter()
    for row in references:
        if row.get("status") != "unresolved" or row.get("target") is not None or row.get("target_member_ranges") or row.get("source_evidence") == "nac_enforcement":
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
        value_shape = row.get("source_value_shape")
        value_shape = value_shape if value_shape in REFERENCE_VALUE_SHAPES else "unknown"
        counts[source, target, field, shape, view, value_shape] += 1
    return [{"source_module":s, "target_module":t, "field":f, "path_shape":p,
             "source_view":v, "source_value_shape":value_shape,"observations":count}
            for (s,t,f,p,v,value_shape),count in sorted(counts.items(), key=lambda item:(-item[1],item[0]))]


def named_reference_gaps(references):
    """Count named unresolved edges by fixed vendor module and evidence categories."""
    from collections import Counter
    from .central_tool import CONFIG_MODULES
    contexts = {"library_definition","other_function_same_scope","same_site_observation"}
    reasons = {"target_view_unqualified","target_collection_incomplete","identity_unqualified","count_confirmed_absence"}
    counts = Counter()
    for row in references:
        if row.get("status") != "unresolved" or row.get("target") is None or row.get("source_evidence") == "nac_enforcement":
            continue
        source,target = (row.get(k) if row.get(k) in CONFIG_MODULES else "other" for k in ("source_module","target_module"))
        reason = row.get("target_evidence") if row.get("target_evidence") in reasons else "other"
        positive = tuple(sorted({obs.get("context") for obs in row.get("target_alternative_observations",[])
                                 if obs.get("status") == "identity_observed" and obs.get("context") in contexts}))
        counts[source,target,reason,positive] += 1
    return [{"source_module":s,"target_module":t,"reason":r,"positive_contexts":list(p),"observations":n}
            for (s,t,r,p),n in sorted(counts.items(),key=lambda item:(-item[1],item[0]))]


def named_reference_field_gaps(references):
    """Anonymous source fields behind named gaps without positive alternatives."""
    from collections import Counter,defaultdict
    from .central_tool import CONFIG_MODULES,VLAN_REFERENCE_FIELDS
    from .dependency_evidence import REFERENCE_SEMANTICS
    fields=VLAN_REFERENCE_FIELDS | {"access-vlan-name","trunk-vlan-ranges","trunk-vlans","trunk-native-vlan",
        "wired-access-vlan-id","vlan-id-ranges","vlan-id-range","mstp-vlans","vlans",
        "default-role","role","src-role","net-service","net-group","identity","name","server-name"}
    contexts={"library_definition","other_function_same_scope","same_site_observation"}
    counts=Counter()
    sources=defaultdict(set)
    targets=defaultdict(set)
    for row in references:
        if row.get("status")!="unresolved" or row.get("target") is None or row.get("source_evidence")=="nac_enforcement":
            continue
        if any(obs.get("status")=="identity_observed" and obs.get("context") in contexts for obs in row.get("target_alternative_observations",[])):
            continue
        source,target=(row.get(k) if row.get(k) in CONFIG_MODULES else "other" for k in ("source_module","target_module"))
        path=row.get("path",[])
        leaf=next((part for part in reversed(path) if isinstance(part,str)),"")
        reason=row.get("target_evidence")
        key=(source,target,leaf if leaf in fields else "other",
             reason if reason in ("target_view_unqualified","target_collection_incomplete") else "other",
             reference_semantics(row))
        counts[key]+=1
        sources[key].add((row.get("persona"),row.get("scope"),row.get("source_view"),row.get("source"),tuple(path)))
        targets[key].add(row["target"])
    return [{"source_module":s,"target_module":t,"field":f,"reason":r,"semantics":kind,
             "observations":n,"distinct_source_fields":len(sources[s,t,f,r,kind]),
             "distinct_target_identities":len(targets[s,t,f,r,kind])}
            for (s,t,f,r,kind),n in sorted(counts.items(),key=lambda item:(-item[1],item[0]))]


def named_reference_target_groups(references):
    """Count exact distinct targets across reasons without revealing identities.

    Group privately by actual module and identity; export only fixed module
    categories and cardinalities. Repeated observations remain separate from
    distinct identities, and positive alternatives do not qualify applicability.
    """
    from collections import Counter,defaultdict
    from .central_tool import CONFIG_MODULES
    contexts={"library_definition","other_function_same_scope","same_site_observation"}
    groups=defaultdict(lambda:defaultdict(list))
    for row in references:
        if row.get("status")!="unresolved" or row.get("target") is None or row.get("source_evidence")=="nac_enforcement":
            continue
        if any(obs.get("status")=="identity_observed" and obs.get("context") in contexts for obs in row.get("target_alternative_observations",[])):
            continue
        module=row.get("target_module")
        category=module if module in CONFIG_MODULES else "other"
        groups[category][module,row["target"]].append(row)
    result=[]
    for category,targets in sorted(groups.items()):
        reason_counts=Counter()
        for rows in targets.values():
            reasons={r.get("target_evidence") if r.get("target_evidence") in ("target_view_unqualified","target_collection_incomplete") else "other" for r in rows}
            reason_counts["multiple_reasons" if len(reasons)>1 else next(iter(reasons))]+=1
        result.append({"target_module":category,"distinct_target_identities":len(targets),
                       "observations":sum(len(rows) for rows in targets.values()),
                       "reason_groups":dict(sorted(reason_counts.items()))})
    return result


def reference_absence_patterns(references):
    """Allowlisted counts; no identities, raw ranges, paths or tenant values."""
    from collections import Counter
    from .central_tool import CONFIG_MODULES
    counts = Counter()
    for row in references:
        if row.get("status") != "not_observed" or row.get("target_evidence") not in ("count_confirmed_absence","set_count_confirmed_absence"):
            continue
        source,target = (row.get(k) if row.get(k) in CONFIG_MODULES else "other" for k in ("source_module","target_module"))
        from .vlan_membership import member_count
        counts[source,target,reference_semantics(row)] += member_count(row)
    return [{"source_module":s,"target_module":t,"semantics":kind,"observations":n}
            for (s,t,kind),n in sorted(counts.items(),key=lambda item:(-item[1],item[0]))]


def role_vlan_name_evidence(references):
    """Fixed state/context counts, never configured VLAN names or IDs."""
    from collections import Counter
    states={"single_candidate_id","multiple_candidate_ids","no_observed_candidate","conflicting_evidence"}
    fields={"gateway_access_vlan_name","nested_access_vlan_name"}
    contexts={"library_vlan_name","same_site_vlan_name"}
    counts=Counter()
    for row in references:
        review=row.get("role_vlan_name_review")
        if not isinstance(review,dict) or row.get("status")!="unresolved":
            continue
        state=review.get("status") if review.get("status") in states else "unknown"
        field=review.get("field_context") if review.get("field_context") in fields else "unknown"
        positive=tuple(sorted({obs.get("context") for obs in review.get("observations",[])
                               if obs.get("status")=="identity_observed" and obs.get("context") in contexts}))
        counts[field,state,positive]+=1
    return [{"field_context":f,"status":s,"positive_contexts":list(p),"observations":n}
            for (f,s,p),n in sorted(counts.items(),key=lambda item:(-item[1],item[0]))]


def reference_conflict_patterns(references):
    """Distinguish repeated edge observations from distinct exact endpoints."""
    from collections import Counter, defaultdict
    from .central_tool import CONFIG_MODULES
    from .standard_evidence import CONFLICT_KINDS
    counts=Counter()
    endpoints=defaultdict(set)
    for row in references:
        if row.get("status")!="conflicting_observation":
            continue
        for side in ("source","target"):
            if row.get(side+"_body_conflict") is not True:
                continue
            module=row.get(side+"_module")
            kind=row.get(side+"_conflict_kind")
            key=(side,module if module in CONFIG_MODULES else "other",
                 kind if kind in CONFLICT_KINDS else "unknown")
            counts[key]+=1
            view=row.get("source_view") if side=="source" else "library" if row.get("persona")=="Library" else "effective"
            endpoints[key].add((row.get("persona"),row.get("scope"),view,row.get(side+"_module"),row.get(side)))
    return [{"side":s,"module":m,"kind":k,"observations":n,"distinct_endpoints":len(endpoints[s,m,k])}
            for (s,m,k),n in sorted(counts.items(),key=lambda item:(-item[1],item[0]))]


def policy_clause_gaps(groups):
    from collections import Counter
    from .policy_service_review import SERVICE_SHAPES
    from .policy_transport_review import PORT_CLAUSE_SHAPES
    service, transport=Counter(),Counter()
    for group in groups:
        for loc in group.get("service_definition_evidence",[]):
            for ref in loc["references"]:
                if ref.get("status")=="service_schema_unqualified":
                    shape=ref.get("definition_shape")
                    service[shape if shape in SERVICE_SHAPES else "unknown"]+=1
        for row in group.get("transport_evidence",[]):
            for side in ("source_port","destination_port"):
                clause=row[side]
                if clause["state"]=="unqualified":
                    shape=clause.get("shape")
                    transport[side,shape if shape in PORT_CLAUSE_SHAPES else "unknown"]+=1
    return {"service":[{"shape":s,"observations":n} for s,n in sorted(service.items())],
            "transport":[{"side":side,"shape":s,"observations":n} for (side,s),n in sorted(transport.items())]}


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
