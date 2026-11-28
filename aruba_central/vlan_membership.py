"""Compact VLAN member evidence; not a claim of deployment or availability."""
from .central_tool import parse_reference_ids


def intervals(ids):
    """Return sorted disjoint inclusive ranges, with no invented members."""
    result=[]
    for value in sorted(map(int,ids)):
        if result and value == result[-1][1]+1:
            result[-1]=(result[-1][0],value)
        else:
            result.append((value,value))
    return tuple(result)


def member_targets(ids,module,path,known_ids):
    """Compact only explicitly classified set membership, not scalar references."""
    from .dependency_evidence import reference_semantics
    semantics=reference_semantics({"source_module":module,"target_module":"layer2-vlan","path":path})
    if known_ids is not None and semantics!="direct_or_unclassified" and len(ids)>64:
        ids=set(ids)
        remaining=ids-known_ids
        ids=ids & known_ids
        if remaining:
            yield intervals(remaining)
    yield from sorted(ids,key=int)


def member_count(ref):
    return ref.get("target_member_count",1)


def known_vlan_ids(bundle, effective):
    """Retain explicit edges for every VLAN identity captured in any context."""
    ids=set()
    def add(view):
        if view.get("status")=="list_parsed":
            ids.update(view.get("profiles",{}))
    add((bundle.get("library") or {}).get("modules",{}).get("layer2-vlan",{}))
    for modules in effective.values():
        for view in modules.get("layer2-vlan",{}).values():
            add(view)
    for entry in bundle["results"].values():
        for row in entry["modules"].get("layer2-vlan",{}).get("scope_results",[]):
            add(row.get("local_view",{}))
    for scopes in (bundle.get("keyed_profile_details") or {}).get("profiles",{}).values():
        for modules in scopes.values():
            # Keep even unqualified direct selectors as individually traceable.
            ids.update(modules.get("layer2-vlan",{}))
    return {v for v in ids if isinstance(v,str) and parse_reference_ids(v)=={v}}


def target_fields(view, identity):
    if not isinstance(identity,tuple):
        return {"target":identity}
    return {"target":None,"target_member_ranges":[list(pair) for pair in identity],
            "target_member_count":sum(high-low+1 for low,high in identity)}


def target_token(ref):
    if "target_member_ranges" in ref:
        return tuple(tuple(pair) for pair in ref["target_member_ranges"])
    return ref["target"]


def target_matches(ref, module, identity):
    if ref["target_module"] != module:
        return False
    if ref["target"] == identity and not ref.get("target_member_ranges"):
        return True
    if module!="layer2-vlan" or not ref.get("target_member_ranges"):
        return False
    if not isinstance(identity,str) or parse_reference_ids(identity)!={identity}:
        return False
    return any(low<=int(identity)<=high for low,high in ref["target_member_ranges"])
