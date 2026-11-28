"""Qualify captured reference edges without guessing reference semantics."""
from .central_tool import canonical, profile_body


def qualify_reference_edges(bundle, references, effective):
    direct = (bundle.get("keyed_profile_details") or {}).get("profiles", {})
    library = (bundle.get("library") or {}).get("modules", {})
    # Index committed views as well as effective views. A committed direct
    # read does not qualify an effective observation, or the reverse.
    local = {persona: {module: {r["scope"]: r.get("local_view", {})
                               for r in data["scope_results"]}
                       for module, data in entry["modules"].items()}
             for persona, entry in bundle["results"].items()}
    cache = {}
    def individual(persona, sid, module, identity, side):
        if identity is None:
            return {}
        return direct.get(persona, {}).get("" if persona == "Library" else str(sid), {}).get(
            module, {}).get(identity, {}).get(side, {})

    def contradiction(persona, sid, module, identity, side):
        if identity is None:
            return False
        key = persona, sid, module, identity, side
        if key in cache:
            return cache[key]
        read = individual(persona, sid, module, identity, side)
        if read.get("status") != "identity_observed" or not isinstance(read.get("profile"), dict):
            cache[key] = False
            return False
        collection = (library.get(module, {}) if persona == "Library" else
                      (local if side == "local" else effective).get(persona, {}).get(module, {}).get(sid, {}))
        if collection.get("status") != "list_parsed":
            cache[key] = False
            return False
        profile = collection.get("profiles", {}).get(identity)
        # Positive evidence can contradict only an observed body or a
        # count-confirmed absence, never an unqualified collection gap.
        value = (collection.get("count_confirmed") is True if profile is None else
                 canonical(profile_body(profile)) != canonical(profile_body(read["profile"])))
        cache[key] = value
        return value

    from collections import defaultdict
    from .consolidation import scope_memberships
    kinds, sites = {}, {}
    for persona, entry in bundle["results"].items():
        for scope in entry["scopes"]:
            sid = scope["id"]
            kinds[persona,sid] = scope["kind"]
            if scope["kind"] == "site":
                sites[persona,sid] = sid
        for sid, membership in scope_memberships(entry["scopes"]).items():
            if membership["site"] is not None:
                sites[persona,sid] = membership["site"]

    # Index only positive target identities needed by unresolved references.
    # Exact same-site membership is contextual evidence, not physical adjacency.
    needed = defaultdict(set)
    for ref in references:
        if ref["status"] == "unresolved" and ref.get("target") is not None:
            needed[ref["target_module"]].add(ref["target"])
    by_scope, by_site = defaultdict(list), defaultdict(list)
    for persona, modules in effective.items():
        for module, identities in needed.items():
            for sid, view in modules.get(module, {}).items():
                if view.get("status") != "list_parsed":
                    continue
                kind = kinds.get((persona,sid))
                site = sites.get((persona,sid))
                for identity in identities.intersection(view.get("profiles", {})):
                    status = "individual_evidence_conflict" if contradiction(persona,sid,module,identity,"effective") else "identity_observed"
                    observation = {"persona":persona,"scope":sid,"scope_kind":kind or "unknown","status":status}
                    if kind is not None:
                        by_scope[module,identity,sid,kind].append(observation)
                    if site is not None:
                        by_site[module,identity,site].append(observation)

    alternatives_cache = {}
    def alternatives(persona,sid,module,identity):
        key = persona,sid,module,identity
        if key in alternatives_cache:
            return alternatives_cache[key]
        observations, seen = [], set()
        if persona != "Library":
            view = library.get(module,{})
            if view.get("status") == "list_parsed" and identity in view.get("profiles",{}):
                status = "individual_evidence_conflict" if contradiction("Library","",module,identity,"library") else "identity_observed"
                observations.append({"context":"library_definition","persona":"Library","scope":"","status":status})
            kind = kinds.get((persona,sid))
            site = sites.get((persona,sid))
            if kind is not None:
                for obs in by_scope[module,identity,sid,kind]:
                    if obs["persona"] != persona:
                        seen.add((obs["persona"],obs["scope"]))
                        observations.append({**obs,"context":"other_function_same_scope"})
            if site is not None:
                for obs in by_site[module,identity,site]:
                    context = (obs["persona"],obs["scope"])
                    if context != (persona,sid) and context not in seen:
                        seen.add(context)
                        observations.append({**obs,"context":"same_site_observation"})
        alternatives_cache[key] = observations
        return observations

    for ref in references:
        persona, sid = ref["persona"], ref["scope"]
        side = {"saved": "local", "effective": "effective", "library": "library"}.get(ref.get("source_view"))
        if side is None:
            continue
        source_conflict = contradiction(persona, sid, ref["source_module"], ref["source"], side)
        target_side = "library" if persona == "Library" else "effective"
        target_read = individual(persona, sid, ref["target_module"], ref["target"], target_side)
        if target_read:
            # A positive individual response can add target evidence, but does
            # not establish collection completeness or deployment. Preserve
            # the original traversal state, including confirmed contradictions.
            target_status = target_read.get("status")
            if target_status == "identity_observed" and not isinstance(target_read.get("profile"), dict):
                target_status = "schema_unresolved"
            ref["target_individual_status"] = target_status or "unqualified"
        target_conflict = contradiction(persona, sid, ref["target_module"], ref["target"], target_side)
        if source_conflict or target_conflict:
            ref["previous_status"] = ref["status"]
            ref["status"] = "conflicting_observation"
            ref["collection_conflict"] = True
            ref["source_body_conflict"] = source_conflict
            ref["target_body_conflict"] = target_conflict
        elif ref["status"] == "unresolved" and ref.get("target") is not None:
            observations = alternatives(persona,sid,ref["target_module"],ref["target"])
            if observations:
                ref["target_alternative_observations"] = observations
    return references
