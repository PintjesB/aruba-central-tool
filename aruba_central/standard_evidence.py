"""Exact collection/individual contradictions for configuration standards."""
from .central_tool import canonical, profile_body


def conflicting_profiles(bundle,persona,module,scope,view,identities=None):
    if view.get("status") != "list_parsed":
        return {}
    reads=(bundle.get("keyed_profile_details") or {}).get("profiles",{}).get(persona,{}).get(str(scope),{}).get(module,{})
    output={}
    for identity, sides in reads.items():
        if identities is not None and identity not in identities:
            continue
        read=sides.get("effective",{})
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
