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
    def contradiction(persona, sid, module, identity, side):
        if identity is None:
            return False
        key = persona, sid, module, identity, side
        if key in cache:
            return cache[key]
        read = direct.get(persona, {}).get("" if persona == "Library" else str(sid), {}).get(
            module, {}).get(identity, {}).get(side, {})
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
        target_conflict = contradiction(persona, sid, ref["target_module"], ref["target"],
                                        "library" if persona == "Library" else "effective")
        if source_conflict or target_conflict:
            ref["previous_status"] = ref["status"]
            ref["status"] = "conflicting_observation"
            ref["collection_conflict"] = True
            ref["source_body_conflict"] = source_conflict
            ref["target_body_conflict"] = target_conflict
    return references
