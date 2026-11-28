"""Expose NAC enforcement targets as conditional dependency observations.

Never attach a policy to a device, infer attribute semantics or traverse an
authorization candidate as a resolved configuration dependency.
"""
from .nac_authorization import policy_review
from .nac_binding_review import nac_bindings
from .central_tool import canonical


def nac_dependency_references(bundle):
    policies=policy_review(bundle)
    if not policies["policies"]:
        return []
    bindings=nac_bindings(bundle,{"tag_definitions":{},"rows":[]},policies)
    result=[]
    seen=set()
    for module,targets in (("layer2-vlan",bindings["vlan_targets"]),("roles",bindings["role_enforcement"]["targets"])):
        for row in targets:
            identity=row.get("vlan_id") if module=="layer2-vlan" else row["role_identity"]
            path=["default-enf-profile"] if row["rule_index"] is None else ["rule",row.get("captured_rule_index",row["rule_index"])]
            path += [row["source"],row.get("name","ATTR_VLAN_ID")]
            ref={"persona":"NAC","scope":"NAC","device":str(row["policy"] or row["policy_id"]),
                 "source_scope_kind":"tenant","source_view":"tenant","source_module":"authz-policies","source":row["policy_id"],
                 "target_module":module,"target":identity,"path":path,"status":"conditional_enforcement_candidate" if identity is not None else "unresolved",
                 "source_evidence":"nac_enforcement","attribute_status":row["status"],"policy_enabled":row["policy_enabled"],
                 "rule_enabled":row["rule_enabled"],"rule_position":row["rule"],"rule_index":row["rule_index"]}
            # Paths identify review occurrences, not an executable JSON patch.
            key=canonical(ref)
            if key not in seen:
                seen.add(key)
                result.append(ref)
    return result
