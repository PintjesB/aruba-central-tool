"""Attach observed dependency evidence to optimization groups without inferring disuse."""
from collections import defaultdict
from .vlan_membership import target_matches


def attach_dependency_review(findings, references):
    incoming, outgoing, unresolved = defaultdict(list), defaultdict(list), defaultdict(list)
    all_incoming, all_outgoing, all_unresolved = defaultdict(list), defaultdict(list), defaultdict(list)
    compact = defaultdict(list)
    for ref in references:
        context = ref["persona"]
        outgoing[(context, ref["source_module"], ref["source"])].append(ref)
        all_outgoing[ref["source_module"], ref["source"]].append(ref)
        if ref.get("target_member_ranges"):
            compact[ref["target_module"]].append(ref)
        elif ref["target"] is None:
            unresolved[(context, ref["target_module"])].append(ref)
            all_unresolved[ref["target_module"]].append(ref)
        else:
            incoming[(context, ref["target_module"], ref["target"])].append(ref)
            all_incoming[ref["target_module"], ref["target"]].append(ref)
    for finding in findings:
        persona, module, identity = (finding[k] for k in ("persona", "module", "identity"))
        contexts = (persona, "Library")
        membership=[r for r in compact[module] if target_matches(r,module,identity)]
        consumers = [r for c in contexts for r in incoming[(c, module, identity)]] + [r for r in membership if r["persona"] in contexts]
        dependencies = [r for c in contexts for r in outgoing[(c, module, identity)]]
        unknown = [r for c in contexts for r in unresolved[(c, module)]]
        gaps = [r for r in consumers + dependencies if r["status"] not in ("observed", "definition_observed")]
        devices = {(r["persona"], r["scope"]) for r in consumers if r.get("source_scope_kind") == "device" and r.get("source_view") == "effective" and not r.get("target_member_ranges")}
        # A Library identity can be visible to several device functions.
        # Preserve other-function observations separately: identical names
        # do not establish that those consumers use the proposed definition.
        cross_consumers = [r for r in all_incoming[module, identity] if r["persona"] not in contexts] + [r for r in membership if r["persona"] not in contexts]
        cross_dependencies = [r for r in all_outgoing[module, identity] if r["persona"] not in contexts]
        cross_unknown = [r for r in all_unresolved[module] if r["persona"] not in contexts]
        finding["dependency_review"] = {"consumers": consumers, "dependencies": dependencies,
                                        "unresolved_target_observations": unknown, "unqualified_edges": gaps,
                                        "observed_consumer_devices": len(devices),
                                        "other_function_consumers": cross_consumers,
                                        "other_function_dependencies": cross_dependencies,
                                        "other_function_unresolved_targets": cross_unknown,
                                        "complete": False, "safe_to_apply": False}
    return findings
