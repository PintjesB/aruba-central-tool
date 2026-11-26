"""Attach observed dependency evidence to optimization groups without inferring disuse."""
from collections import defaultdict


def attach_dependency_review(findings, references):
    incoming, outgoing, unresolved = defaultdict(list), defaultdict(list), defaultdict(list)
    for ref in references:
        context = ref["persona"]
        outgoing[(context, ref["source_module"], ref["source"])].append(ref)
        if ref["target"] is None:
            unresolved[(context, ref["target_module"])].append(ref)
        else:
            incoming[(context, ref["target_module"], ref["target"])].append(ref)
    for finding in findings:
        persona, module, identity = (finding[k] for k in ("persona", "module", "identity"))
        contexts = (persona, "Library")
        consumers = [r for c in contexts for r in incoming[(c, module, identity)]]
        dependencies = [r for c in contexts for r in outgoing[(c, module, identity)]]
        unknown = [r for c in contexts for r in unresolved[(c, module)]]
        gaps = [r for r in consumers + dependencies if r["status"] not in ("observed", "definition_observed")]
        devices = {(r["persona"], r["scope"]) for r in consumers if r.get("source_scope_kind") == "device" and r.get("source_view") == "effective"}
        finding["dependency_review"] = {"consumers": consumers, "dependencies": dependencies,
                                        "unresolved_target_observations": unknown, "unqualified_edges": gaps,
                                        "observed_consumer_devices": len(devices),
                                        "complete": False, "safe_to_apply": False}
    return findings
