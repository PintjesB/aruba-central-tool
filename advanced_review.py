"""Additional read-only engineering analyses. Never infer reference completeness."""
from collections import defaultdict
from central_tool import CONFIG_MODULES, canonical, profile_body, reference_candidates
from consolidation import scope_memberships

# Only portable, documented L2 port settings. Other fields are retained in
# evidence and prevent an automatic conversion; descriptions stay per port.
PORT_FIELDS = {"enable", "switchport", "poe", "lldp", "speed-duplex", "mtu",
               "aaa-profile", "trusted-vlans", "forbid-vlans", "energy-efficient",
               "broadcast-limit", "routing"}
PORT_IDENTITY = {"name", "description"}
PORT_TOPOLOGY = {"lag", "lacp", "ip", "ipv4", "ipv6", "vrrp", "vrf-forwarding",
                 "virtual-router", "sw-profile", "sw-profile-alias"}
NAMED_REFERENCES = {"sw-profile": "sw-port-profiles"}
ADDITIVE = {"layer2-vlan", "roles", "wlan-ssids", "auth-servers"}
PRECEDENCE = ("group", "site", "collection", "global")


def effective_views(entry):
    return {module: {s["scope"]: s.get("effective_view", {}) for s in data["scope_results"]}
            for module, data in entry["modules"].items()}


def explicit_references(value, path=()):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("@", "metadata"):
                continue
            here = path + (key,)
            if key in NAMED_REFERENCES:
                yield NAMED_REFERENCES[key], item if isinstance(item, str) and item else None, here
            elif key == "sw-profile-alias":
                yield "sw-port-profiles", None, here
            else:
                yield from explicit_references(item, here)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from explicit_references(item, path + (i,))


def advanced_analysis(bundle):
    result = {"port_groups": [], "shadowed": [], "library_duplicates": [],
              "references": [], "coverage": [], "reference_graph_complete": False,
              "safe_to_apply": False}
    library = bundle.get("library") or {}
    assignments = (library.get("assignments") or {}).get("rows", [])
    for persona, entry in sorted(bundle["results"].items()):
        views = effective_views(entry)
        members = scope_memberships(entry["scopes"])
        names = {s["id"]: s.get("name") or s["id"] for s in entry["scopes"]}
        port_groups = defaultdict(list)
        for device in (s for s in entry["scopes"] if s["kind"] == "device"):
            sid = device["id"]
            def get(module):
                return views.get(module, {}).get(sid, {})
            def emit(source_module, source, target, identity, path):
                target_view = get(target)
                status = ("unresolved" if identity is None or target_view.get("status") != "list_parsed"
                          else "observed" if identity in target_view["profiles"] else "not_observed")
                result["references"].append({"persona": persona, "device": names[sid], "scope": sid,
                    "source_module": source_module, "source": source, "target_module": target,
                    "target": identity, "path": list(path), "status": status})
            for module in sorted(views):
                view = get(module)
                result["coverage"].append({"persona": persona, "scope": sid, "module": module,
                                           "status": view.get("status", "not_collected")})
                if view.get("status") != "list_parsed":
                    continue
                vlan_view = get("layer2-vlan")
                vlans = vlan_view.get("profiles", {}) if vlan_view.get("status") == "list_parsed" else {}
                for identity, raw in view["profiles"].items():
                    body = profile_body(raw)
                    if module != "layer2-vlan":
                        vlan_refs = reference_candidates(body, vlans)
                        for ref in vlan_refs["references"]:
                            # A VLAN interface's own identity is a dependency, not a dangling reference.
                            for vid in ref["vlan_ids"]:
                                emit(module, identity, "layer2-vlan", vid, ref["path"])
                        for path in vlan_refs["unresolved_paths"]:
                            emit(module, identity, "layer2-vlan", None, path)
                        if module == "vlan-interfaces" and identity.isdigit():
                            emit(module, identity, "layer2-vlan", identity, ["identity"])
                    for target, ref, path in explicit_references(body):
                        emit(module, identity, target, ref, path)
                    if module == "ethernet-interfaces" and persona.endswith("_SWITCH"):
                        if body.get("routing") is True or PORT_TOPOLOGY & body.keys():
                            continue
                        portable = {k: v for k, v in body.items() if k in PORT_FIELDS}
                        if not portable or not isinstance(portable.get("switchport"), dict):
                            continue
                        unsupported = sorted(set(body) - PORT_FIELDS - PORT_IDENTITY)
                        # Include all non-identity fields in the signature: unknown fields
                        # cannot disappear from the comparison.
                        signature = canonical({k: v for k, v in body.items() if k not in PORT_IDENTITY})
                        port_groups[signature].append({"scope": sid, "device": names[sid],
                            "port": identity, "description": body.get("description"),
                            "portable": portable, "unsupported": unsupported})
            for module in ADDITIVE & views.keys():
                device_view = get(module)
                if device_view.get("status") != "list_parsed":
                    continue
                for identity, raw in device_view["profiles"].items():
                    annotation = raw.get("@", {})
                    if not isinstance(annotation, dict) or annotation.get("aruba-annotation:is_default") is True:
                        continue
                    # A direct device LOCAL or SHARED profile is observed as winner.
                    if annotation.get("aruba-annotation:inherited") is not False or annotation.get("aruba-annotation:object_type") not in ("LOCAL", "SHARED"):
                        continue
                    for kind in PRECEDENCE:
                        ancestor = members[sid][kind]
                        upstream = views[module].get(ancestor, {})
                        if upstream.get("status") != "list_parsed" or identity not in upstream["profiles"]:
                            continue
                        other = profile_body(upstream["profiles"][identity])
                        actual = profile_body(raw)
                        result["shadowed"].append({"persona": persona, "module": module,
                            "identity": identity, "device": names[sid], "scope": sid,
                            "higher_scope": names[ancestor], "higher_scope_id": ancestor,
                            "relationship": "same_body" if canonical(other) == canonical(actual) else "different_body",
                            "effective": actual, "higher_body": other,
                            "safe_to_apply": False})
        for ports in port_groups.values():
            if len(ports) < 2:
                continue
            result["port_groups"].append({"persona": persona, "ports": ports,
                "portable_settings": ports[0]["portable"], "unsupported_fields": ports[0]["unsupported"],
                "recommendation": "Review shared switch port profile; preserve mapping and descriptions",
                "safe_to_apply": False})
    for module, view in sorted(library.get("modules", {}).items()):
        # Identity is semantic for numeric VLAN IDs and SSIDs. Report equivalent
        # named bodies only; never assume interchangeability.
        if module in ("layer2-vlan", "vlan-interfaces", "wlan-ssids") or module not in CONFIG_MODULES or view.get("status") != "list_parsed":
            continue
        key = CONFIG_MODULES[module][0]
        groups = defaultdict(list)
        for identity, raw in view["profiles"].items():
            if not isinstance(raw.get(key), str) or raw[key] != identity:
                continue
            body = profile_body(raw)
            body.pop(key, None)
            if body:
                groups[canonical(body)].append(identity)
        for signature, identities in groups.items():
            if len(identities) > 1:
                result["library_duplicates"].append({"module": module, "identities": sorted(identities),
                    "assignments": [a for a in assignments if a.get("profile-type") == module
                                    and str(a.get("profile-instance")) in identities],
                    "recommendation": "Review identity-independent body match and all references before merging",
                    "safe_to_apply": False})
    return result
