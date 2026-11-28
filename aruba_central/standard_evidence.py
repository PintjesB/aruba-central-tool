"""Exact collection/individual contradictions for configuration standards."""
from .central_tool import canonical, profile_body


def conflicting_profiles(bundle,persona,module,scope,view,identities=None,*,side="effective"):
    if view.get("status") != "list_parsed":
        return {}
    reads=(bundle.get("keyed_profile_details") or {}).get("profiles",{}).get(persona,{}).get(str(scope),{}).get(module,{})
    output={}
    for identity, sides in reads.items():
        if identities is not None and identity not in identities:
            continue
        read=sides.get(side,{})
        if read.get("status")!="identity_observed" or not isinstance(read.get("profile"),dict):
            continue
        raw=view.get("profiles",{}).get(identity)
        body=profile_body(read["profile"])
        if isinstance(raw,dict):
            saved=profile_body(raw)
            if canonical(saved)!=canonical(body):
                output[identity]={"collection_state":"present","collection_body":saved,"individual_body":body}
        elif view.get("count_confirmed") is True:
            output[identity]={"collection_state":"count_confirmed_absent","individual_body":body}
    return output

CONFLICT_KINDS=("count_confirmed_absence","collection_missing_fields","individual_missing_fields",
                "field_presence_difference","list_order_difference","value_difference","mixed_difference")


def body_conflict_kind(collection, individual):
    """Describe exact body discrepancies, never normalize away evidence."""
    flags=set()
    def visit(left,right):
        if canonical(left)==canonical(right):
            return
        if isinstance(left,dict) and isinstance(right,dict):
            if right.keys()-left.keys():
                flags.add("collection_missing_fields")
            if left.keys()-right.keys():
                flags.add("individual_missing_fields")
            for key in left.keys() & right.keys():
                visit(left[key],right[key])
        elif isinstance(left,list) and isinstance(right,list):
            if sorted(map(canonical,left))==sorted(map(canonical,right)):
                flags.add("list_order_difference")
            else:
                flags.add("value_difference")
        else:
            flags.add("value_difference")
    visit(collection,individual)
    if not flags:
        return None
    if len(flags)==1:
        return next(iter(flags))
    if flags=={"collection_missing_fields","individual_missing_fields"}:
        return "field_presence_difference"
    return "mixed_difference"
