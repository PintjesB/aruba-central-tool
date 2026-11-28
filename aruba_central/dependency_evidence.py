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
    return references
