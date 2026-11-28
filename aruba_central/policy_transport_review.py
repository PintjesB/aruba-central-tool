"""Review explicit transport clauses without supplying omitted policy semantics.

HPE's published network ACL example documents the TCP rule type, explicit
IP protocol header, source-port EQ clause and established flag:
https://community.networking.hpe.com/discussion/new-central-and-source-ports-in-acls
A missing port is not normalized to ANY. Other condition fields can constrain
the actual packet predicate. This is field evidence only, never a rule finding.
"""
TRANSPORT_STATES=("literal_clauses_observed","transport_shape_unqualified",
                  "protocol_header_unqualified","protocol_header_conflict",
                  "port_clause_unqualified","additional_transport_fields",
                  "transport_without_port_clauses")


def port_clause(value):
    if not isinstance(value,dict):
        return None
    def valid(port):
        return type(port) is int and 0<=port<=65535
    if set(value)=={"operator","min"} and value["operator"]=="COMPARISON_EQ" and valid(value["min"]):
        return {"operator":"COMPARISON_EQ","min":value["min"]}
    # Preserve an explicitly bounded range as a captured clause; do not
    # interpret omitted bounds or unsupported comparison operators.
    if set(value)=={"operator","min","max"} and value["operator"]=="COMPARISON_RANGE" and valid(value["min"]) and valid(value["max"]) and value["min"]<=value["max"]:
        return {"operator":"COMPARISON_RANGE","min":value["min"],"max":value["max"]}
    return None


def transport_review(body):
    security=body.get("security-policy")
    if not isinstance(security,dict) or not isinstance(security.get("policy-rule"),list):
        return []
    result=[]
    for index,rule in enumerate(security["policy-rule"]):
        condition=rule.get("condition") if isinstance(rule,dict) else None
        if not isinstance(condition,dict) or "transport-fields" not in condition:
            continue
        transport=condition["transport-fields"]
        row={"rule_index":index,"position":rule.get("position"),"safe_to_apply":False,
             "condition_type_observed":"type" in condition,
             "outer_policy_type_observed":"type" in body,
             "transport":transport,"ip_header":condition.get("ip-header"),
             "source_port":{"state":"not_specified"},"destination_port":{"state":"not_specified"}}
        header=condition.get("ip-header")
        kind=condition.get("rule-type")
        expected="IP_TCP" if kind=="RULE_TCP" else "IP_UDP" if kind=="RULE_UDP" else None
        if not isinstance(transport,dict) or expected is None:
            state="transport_shape_unqualified"
        elif not isinstance(header,dict) or "protocol" not in header:
            state="protocol_header_unqualified"
        elif header["protocol"]!=expected:
            state="protocol_header_conflict"
        else:
            row["protocol"]=expected
            state="literal_clauses_observed"
            for key,field in (("source-port","source_port"),("destination-port","destination_port")):
                if key not in transport:
                    continue
                clause=port_clause(transport[key])
                row[field]={"state":"literal_observed",**clause} if clause is not None else {"state":"unqualified"}
                if clause is None:
                    state="port_clause_unqualified"
            if "established" in transport:
                if kind=="RULE_TCP" and type(transport["established"]) is bool:
                    row["established"]=transport["established"]
                else:
                    state="additional_transport_fields"
            if set(transport)-{"source-port","destination-port","established"} or set(header)-{"protocol"}:
                state="additional_transport_fields"
            if state=="literal_clauses_observed" and all(row[k]["state"]=="not_specified" for k in ("source_port","destination_port")):
                state="transport_without_port_clauses"
        row["status"]=state
        result.append(row)
    return result
