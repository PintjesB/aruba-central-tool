"""Correlate exact NAC attribute values with role observations, not rule outcomes.

HPE documents Aruba-User-Role as a RADIUS VSA, but the public authz-policies
API reference does not expose every nested defined-attribute enum. Only the
explicitly named custom Aruba-User-Role attribute is treated as a role attribute;
other matching values remain candidates, not interpreted attribute semantics.
"""
from collections import defaultdict
from .central_tool import canonical, profile_body
from .remediation_review import captured_observation


def role_enforcement_review(bundle, attribute_rows):
    library=(bundle.get("library") or {}).get("modules",{}).get("roles",{})
    lib_profiles=library.get("profiles",{}) if library.get("status")=="list_parsed" else {}
    devices=[]
    identities=set(lib_profiles)
    for persona,entry in sorted(bundle.get("results",{}).items()):
        views={r["scope"]:r.get("effective_view",{}) for r in entry.get("modules",{}).get("roles",{}).get("scope_results",[])}
        if not views:
            continue
        for scope in entry["scopes"]:
            if scope["kind"]!="device":
                continue
            sid=scope["id"]
            view=views.get(sid,{})
            profiles=view.get("profiles",{}) if view.get("status")=="list_parsed" else {}
            identities.update(profiles)
            devices.append((persona,scope,view,profiles))
    candidates=[]
    for row in attribute_rows:
        value=row["value"]
        if not isinstance(value,str) or not value:
            continue
        explicit=row["kind"]=="custom-attr" and row["name"]=="Aruba-User-Role"
        if row["kind"]=="defined-attr" and row["name"]=="ATTR_VLAN_ID":
            continue
        if not explicit and value not in identities:
            continue
        candidates.append({**row,"role_identity":value,
                           "status":"explicit_role_attribute" if explicit else "exact_role_name_candidate_not_attribute_semantics"})
    visibility={}
    for identity in sorted({row["role_identity"] for row in candidates}):
        raw=lib_profiles.get(identity)
        lib_body=profile_body(raw) if isinstance(raw,dict) else None
        read=(bundle.get("keyed_profile_details") or {}).get("profiles",{}).get("Library",{}).get("",{}).get("roles",{}).get(identity,{}).get("library",{})
        individual=read.get("profile")
        conflict=(library.get("status")=="list_parsed" and read.get("status")=="identity_observed" and isinstance(individual,dict) and
                  ((lib_body is not None and canonical(lib_body)!=canonical(profile_body(individual))) or
                   (lib_body is None and library.get("count_confirmed") is True)))
        library_state=("individual_evidence_conflict" if conflict else "observed" if lib_body is not None else
                       "count_confirmed_absence" if library.get("status")=="list_parsed" and library.get("count_confirmed") is True else "unverified")
        result=[]
        for persona,scope,view,profiles in devices:
            raw=profiles.get(identity)
            direct=captured_observation(bundle,persona,"roles",scope["id"],"effective",identity)["state"]=="individual_evidence_conflict"
            if direct:
                state="individual_evidence_conflict"
            elif isinstance(raw,dict):
                state="observed"
            elif view.get("status")=="list_parsed" and view.get("count_confirmed") is True:
                state="count_confirmed_absence"
            else:
                state="unverified"
            body=profile_body(raw) if isinstance(raw,dict) else None
            comparison=("unverified" if conflict or direct or lib_body is None or body is None else
                        "exact_library_body" if canonical(lib_body)==canonical(body) else "different_library_body")
            result.append({"persona":persona,"scope":scope["id"],"device":scope.get("name") or scope["id"],
                           "status":state,"library_comparison":comparison})
        visibility[identity]={"library_status":library_state,"devices":result,
                             "similar_exact_names":sorted(i for i in identities if i!=identity and i.casefold()==identity.casefold())}
    return {"targets":candidates,"visibility":visibility,"complete":False,"safe_to_apply":False}
