"""Qualify captured reference edges without guessing reference semantics."""
from .central_tool import canonical, profile_body


def reference_semantics(ref):
    """Classify documented set membership separately from direct references.

    Keep each exact member edge for reverse lookup and removal safety. A
    member absent from a captured view is not by itself a broken dependency.
    Do not treat VLAN selection pools as permission lists.
    """
    if ref.get("target_module") != "layer2-vlan":
        return "direct_or_unclassified"
    module = ref.get("source_module")
    path = tuple(ref.get("path", []))
    if module == "named-vlan" and path == ("vlan", "vlan-id-ranges"):
        return "vlan_selection_member"
    if module == "wlan-ssids" and path == ("vlan-id-range",):
        return "vlan_selection_member"
    if module == "stp" and len(path) == 3 and path[0] == "mstp" and type(path[1]) is int and path[2] in ("mstp-vlans", "vlans"):
        return "vlan_stp_member"
    if module in ("ap-port-profiles","sw-port-profiles","ethernet-interfaces","portchannels") and path in (
        ("switchport","trunk-vlan-ranges"), ("switchport","trunk-vlans"), ("switchport","allowed-vlans"), ("allowed-vlans",)):
        return "vlan_allowed_member"
    if module == "roles" and path == ("vlan-parameters","trunk-allowed-vlans"):
        return "vlan_allowed_member"
    return "direct_or_unclassified"


REFERENCE_SEMANTICS = ("direct_or_unclassified", "vlan_selection_member", "vlan_stp_member", "vlan_allowed_member")


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
    conflict_kinds={}
    from .standard_evidence import body_conflict_kind
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
        kind = ("count_confirmed_absence" if collection.get("count_confirmed") is True else None) if profile is None else body_conflict_kind(profile_body(profile),profile_body(read["profile"]))
        conflict_kinds[key]=kind
        cache[key] = kind is not None
        return cache[key]

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

    # Root role access-vlan-name is documented for gateways. A captured
    # name can be compared with explicit Layer2 VLAN display names, but
    # neither a Library match nor a same-site match proves gateway binding.
    # https://developer.arubanetworks.com/new-central-config/reference/updaterolesrolebyid
    from .central_tool import parse_reference_ids
    role_paths = (("access-vlan-name",), ("vlan-parameters","access-vlan-name"))
    def role_name(ref):
        path = tuple(ref.get("path", []))
        if ref["source_module"] != "roles" or ref["target_module"] != "layer2-vlan" or path not in role_paths:
            return None
        persona, sid = ref["persona"], ref["scope"]
        side = {"saved":"local","effective":"effective","library":"library"}.get(ref.get("source_view"))
        if side is None:
            return None
        if ref.get("source_evidence") == "individual":
            read = individual(persona,sid,"roles",ref["source"],side)
            profile = read.get("profile") if read.get("status") == "identity_observed" else None
        else:
            view = (library.get("roles",{}) if persona == "Library" else
                    (local if side == "local" else effective).get(persona,{}).get("roles",{}).get(sid,{}))
            profile = view.get("profiles",{}).get(ref["source"]) if view.get("status") == "list_parsed" else None
        if not isinstance(profile,dict):
            return None
        value = profile_body(profile)
        for key in path:
            if not isinstance(value,dict):
                return None
            value = value.get(key)
        return value if isinstance(value,str) and value.strip() else None

    name_needed = {name for ref in references if ref["status"] == "unresolved" and ref.get("target") is None
                   if (name := role_name(ref)) is not None}
    names_by_site, library_names = defaultdict(list), defaultdict(list)
    def index_names(view,persona,sid,index,site=None):
        if view.get("status") != "list_parsed":
            return
        for vid,profile in view.get("profiles",{}).items():
            if not isinstance(profile,dict) or parse_reference_ids(vid) != {vid}:
                continue
            name = profile.get("name")
            if not isinstance(name,str) or name not in name_needed:
                continue
            status = "individual_evidence_conflict" if contradiction(persona,sid,"layer2-vlan",vid,"library" if persona=="Library" else "effective") else "identity_observed"
            key = name if site is None else (site,name)
            index[key].append({"context":"library_vlan_name" if persona=="Library" else "same_site_vlan_name",
                               "persona":persona,"scope":sid,"vlan_id":vid,"status":status})
    if name_needed:
        index_names(library.get("layer2-vlan",{}),"Library","",library_names)
        for persona,modules in effective.items():
            for sid,view in modules.get("layer2-vlan",{}).items():
                site=sites.get((persona,sid))
                if site is not None:
                    index_names(view,persona,sid,names_by_site,site)

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
        ref["reference_semantics"] = reference_semantics(ref)
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
            if source_conflict:
                ref["source_conflict_kind"]=conflict_kinds[persona,sid,ref["source_module"],ref["source"],side]
            if target_conflict:
                ref["target_conflict_kind"]=conflict_kinds[persona,sid,ref["target_module"],ref["target"],target_side]
        elif ref["status"] == "unresolved" and ref.get("target") is None:
            name = role_name(ref)
            if name is not None:
                site = sites.get((persona,sid))
                observations = library_names.get(name,[]) + (names_by_site.get((site,name),[]) if site is not None else [])
                positive = {obs["vlan_id"] for obs in observations if obs["status"] == "identity_observed"}
                conflicted = any(obs["status"] == "individual_evidence_conflict" for obs in observations)
                state = ("conflicting_evidence" if conflicted else "multiple_candidate_ids" if len(positive)>1 else
                         "single_candidate_id" if positive else "no_observed_candidate")
                ref["role_vlan_name_review"] = {"status":state,"configured_name":name,
                    "field_context":"gateway_access_vlan_name" if ref["path"] == ["access-vlan-name"] else "nested_access_vlan_name",
                    "observations":observations,"safe_to_apply":False}
        elif ref["status"] == "unresolved" and ref.get("target") is not None:
            observations = alternatives(persona,sid,ref["target_module"],ref["target"])
            if observations:
                ref["target_alternative_observations"] = observations
    return references
