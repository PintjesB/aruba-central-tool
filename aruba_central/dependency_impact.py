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
    direct = []
    unresolved = []
    for ref in references:
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
        if view in ("effective", "library") and ref["status"] in RESOLVED and ref["target"] is not None:
            contexts[context].append((source, target, ref))
    paths = []
    truncated = False
    for context, edges in sorted(contexts.items()):
        for direction in ("consumers", "dependencies"):
            adjacency = defaultdict(list)
            for source, target, ref in edges:
                start, end = (target, source) if direction == "consumers" else (source, target)
                adjacency[start].append((end, ref))
            queue = deque([(root, [])])
            seen = {root}
            while queue:
                node, chain = queue.popleft()
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
            "truncated": truncated, "complete": False, "safe_to_apply": False}
