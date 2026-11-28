"""Evidence for named service definitions, not qualified packet predicates.

HPE documents named IP protocol identities, explicit port lists and port-range
operators: https://developer.arubanetworks.com/new-central-config/reference/createnetservicesnetservicebyid
ALG and proxy options affect interpretation and are not flattened.
"""
from .central_tool import profile_body, canonical
from .standard_evidence import conflicting_profiles

SERVICE_STATES=("literal_service_observed","service_schema_unqualified","service_reference_shape_unqualified",
                "service_view_unqualified","service_not_observed","service_collection_incomplete",
                "service_individual_conflict")


def literal_service(body):
    if set(body)-{"name","description","protocol","ports","port-range","http-proxy","https-proxy"}:
        return None
    if any(key in body and body[key] is not False for key in ("http-proxy","https-proxy")):
        return None
    protocol=body.get("protocol")
    if type(protocol) not in (str,int):
        return None
    if protocol in ("IP_TCP",6):
        kind="tcp"
    elif protocol in ("IP_UDP",17):
        kind="udp"
    else:
        return None
    def valid(port):
        return type(port) is int and 0<=port<=65535
    if "ports" in body and "port-range" not in body:
        ports=body["ports"]
        if not isinstance(ports,list) or not ports or not all(valid(p) for p in ports):
            return None
        ranges=[(p,p) for p in sorted(set(ports))]
    elif "port-range" in body and "ports" not in body:
        spec=body["port-range"]
        if not isinstance(spec,dict) or not valid(spec.get("min")):
            return None
        if set(spec) in ({"operator","min"},{"operator","min","max"}) and spec["operator"]=="COMPARISON_EQ" and ("max" not in spec or valid(spec["max"])):
            # HPE explicitly documents that only min is used for EQ.
            # Retain the complete original definition in private evidence.
            ranges=[(spec["min"],spec["min"])]
        elif set(spec)=={"operator","min","max"} and spec["operator"]=="COMPARISON_RANGE" and valid(spec["max"]) and spec["min"]<=spec["max"]:
            ranges=[(spec["min"],spec["max"])]
        else:
            return None
    else:
        return None
    merged=[]
    for low,high in ranges:
        if merged and low<=merged[-1][1]+1:
            merged[-1][1]=max(merged[-1][1],high)
        else:
            merged.append([low,high])
    return {"protocol":kind,"port_ranges":merged}


def service_shape(body):
    """Fixed public schema categories; never emit service values or names."""
    if not isinstance(body,dict):
        return "invalid_body"
    if "alg-service" in body or "alg-config" in body:
        return "alg_configuration"
    if any(k in body and body[k] is not False for k in ("http-proxy","https-proxy")):
        return "proxy_configuration"
    if set(body)-{"name","description","protocol","ports","port-range","http-proxy","https-proxy"}:
        return "additional_fields"
    protocol=body.get("protocol")
    if type(protocol) not in (str,int) or protocol not in ("IP_TCP","IP_UDP",6,17):
        return "non_tcp_udp_or_missing_protocol"
    if "ports" in body and "port-range" in body:
        return "conflicting_port_forms"
    if "ports" not in body and "port-range" not in body:
        return "no_port_clause"
    if "ports" in body:
        return "port_list"
    spec=body["port-range"]
    if not isinstance(spec,dict):
        return "invalid_port_range"
    if set(spec)-{"operator","min","max"}:
        return "additional_range_fields"
    if spec.get("operator")=="COMPARISON_EQ":
        return "eq_with_max" if "max" in spec else "eq_without_max"
    if spec.get("operator")=="COMPARISON_RANGE":
        return "range"
    return "other_operator"


SERVICE_SHAPES=("invalid_body","alg_configuration","proxy_configuration","additional_fields",
                "non_tcp_udp_or_missing_protocol","conflicting_port_forms","no_port_clause","port_list",
                "invalid_port_range","additional_range_fields","eq_with_max","eq_without_max","range","other_operator")


def service_references(body):
    sec=body.get("security-policy")
    if not isinstance(sec,dict) or not isinstance(sec.get("policy-rule"),list):
        return []
    refs=[]
    for index,rule in enumerate(sec["policy-rule"]):
        if not isinstance(rule,dict) or not isinstance(rule.get("condition"),dict):
            continue
        condition=rule["condition"]
        if "services" not in condition:
            continue
        services=condition["services"]
        name=services.get("net-service") if isinstance(services,dict) else None
        refs.append({"rule_index":index,"position":rule.get("position"),
                     "service":name if isinstance(name,str) and name.strip() else None})
    return refs


def service_evidence(bundle,persona,scope,body,view):
    refs=service_references(body)
    if not refs:
        return []
    library=persona=="Library"
    conflicts=conflicting_profiles(bundle,persona,"net-services",scope,view,side="library" if library else "effective")
    for row in refs:
        name=row["service"]
        if name is None:
            state="service_reference_shape_unqualified"
        elif name in conflicts:
            state="service_individual_conflict"
            row["individual_conflict"]=conflicts[name]
        elif view.get("status")!="list_parsed":
            state="service_view_unqualified"
        elif name not in view.get("profiles",{}):
            state="service_not_observed" if view.get("count_confirmed") is True else "service_collection_incomplete"
        else:
            raw=view["profiles"][name]
            literal=literal_service(profile_body(raw)) if isinstance(raw,dict) else None
            state="literal_service_observed" if literal is not None else "service_schema_unqualified"
            row["definition"]=raw
            row["definition_shape"]=service_shape(profile_body(raw) if isinstance(raw,dict) else None)
            if literal is not None:
                row["literal_service"]=literal
        row["status"]=state
        row["context"]="library_definition" if library else "same_effective_scope"
        row["safe_to_apply"]=False
    return refs
