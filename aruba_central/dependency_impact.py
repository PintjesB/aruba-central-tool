"""Trace captured dependency paths without merging unrelated scope identities."""
from collections import defaultdict, deque

RESOLVED = {"observed", "definition_observed"}


def dependency_impact(references, module, identity, *, persona="", scope="", limit=1000):
    """Find direct and transitive incoming/outgoing reference observations.

    Traverse only resolved edges within one effective device or Library context.
    Saved definitions and unresolved targets remain direct review evidence, not
    proof of the identity or deployment of a transitively referenced object.
    Each reachable object is shown once per context/direction by shortest path.
    """
    root = (module, identity)
    contexts = defaultdict(list)
    unqualified = defaultdict(list)
    root_contexts = set()
    direct = []
    unresolved = []
    tenant_candidates = []
    for ref in references:
        # Tenant policy applicability and device location are unknown.
        # Preserve possible consumers even for a scope-filtered device
        # selection, but do not attach them to that selected scope.
        if ref.get("source_evidence")=="nac_enforcement" and ref["target_module"]==module and ref["target"] in (identity,None):
            tenant_candidates.append(ref)
        if persona and ref["persona"] != persona or scope and str(ref["scope"]) != scope:
            continue
        source = (ref["source_module"], ref["source"])
        target = (ref["target_module"], ref["target"])
        view = ref.get("source_view", "effective")
        context = (ref["persona"], str(ref["scope"]), view)
        if source == root or target == root:
            direct.append(ref)
        if ref["target_module"] == module and ref["target"] is None:
            unresolved.append(ref)
        if view in ("effective","library") and (ref["status"] not in RESOLVED or ref["target"] is None):
            unqualified[context].append((source,target,ref))
            if source == root or target == root:
                root_contexts.add(context)
        if view in ("effective", "library") and ref["status"] in RESOLVED and ref["target"] is not None:
            contexts[context].append((source, target, ref))
            if source == root or target == root:
                root_contexts.add(context)
    paths = []
    boundaries = []
    boundary_keys = set()
    boundary_truncated = False
    truncated = False
    # Include contexts with an incident unqualified edge, even when no
    # resolved path exists. Never traverse that edge or infer its target.
    # Avoid building adjacency maps for unrelated contexts.
    for context in sorted(root_contexts):
        edges = contexts.get(context, ())
        for direction in ("consumers", "dependencies"):
            adjacency = defaultdict(list)
            for source, target, ref in edges:
                start, end = (target, source) if direction == "consumers" else (source, target)
                adjacency[start].append((end, ref))
            stopped = defaultdict(list)
            for source,target,ref in unqualified[context]:
                start = target if direction == "consumers" else source
                stopped[start].append(ref)
            queue = deque([(root, [])])
            seen = {root}
            while queue:
                node, chain = queue.popleft()
                # Keep the first exact reachable boundary without extending
                # a chain through a contradicted or unresolved edge.
                for ref in stopped[node]:
                    key=(context,direction,id(ref))
                    if key in boundary_keys:
                        continue
                    if len(boundaries)>=limit:
                        boundary_truncated=True
                        break
                    boundary_keys.add(key)
                    boundaries.append({"persona":context[0],"scope":context[1],"view":context[2],
                        "direction":direction,"module":node[0],"identity":node[1],
                        "depth":len(chain),"resolved_prefix":chain,"unqualified_edge":ref})
                for end, ref in adjacency[node]:
                    if end in seen:
                        continue
                    seen.add(end)
                    next_chain = chain + [ref]
                    if len(paths) >= limit:
                        truncated = True
                        queue.clear()
                        break
                    paths.append({"persona": context[0], "scope": context[1],
                                  "view": context[2], "direction": direction,
                                  "module": end[0], "identity": end[1],
                                  "depth": len(next_chain), "edges": next_chain})
                    queue.append((end, next_chain))
                if truncated:
                    break
            if truncated:
                break
        if truncated:
            break
    return {"module": module, "identity": identity, "direct": direct,
            "unresolved_target_observations": unresolved, "paths": paths,
            "unqualified_boundaries":boundaries,"boundary_truncated":boundary_truncated,
            "conditional_tenant_observations":tenant_candidates,
            "truncated": truncated, "complete": False, "safe_to_apply": False}
