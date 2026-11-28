"""Additional read-only engineering analyses. Never infer reference completeness."""
from collections import defaultdict
from .central_tool import CONFIG_MODULES, canonical, profile_body, reference_candidates
from .consolidation import scope_memberships

# Only portable, documented L2 port settings. Other fields are retained in
# evidence and prevent an automatic conversion; descriptions stay per port.
PORT_FIELDS = {"enable", "switchport", "poe", "lldp", "speed-duplex", "mtu",
               "aaa-profile", "trusted-vlans", "forbid-vlans", "energy-efficient",
               "broadcast-limit", "routing"}
PORT_IDENTITY = {"name", "description"}
PORT_TOPOLOGY = {"lag", "lacp", "ip", "ipv4", "ipv6", "vrrp", "vrf-forwarding",
                 "virtual-router", "sw-profile", "sw-profile-alias", "portchannel-lag",
                 "ap-profile", "gw-profile", "br-profile", "retain-profile-configs", "port-monitor", "vsx"}
NAMED_REFERENCES = {"sw-profile": "sw-port-profiles", "ap-profile": "ap-port-profiles",
                    "gw-profile": "gw-port-profiles", "portchannel-lag": "portchannels"}
# Reference fields are scoped to documented source profile families.
# https://developer.arubanetworks.com/new-central-config/reference/updatewlanssidswlanssidbyid
# https://developer.arubanetworks.com/new-central-config/reference/replaceapportprofilesprofilebyid
AUTH_REFERENCES = {"default-role": "roles", "auto-default-role": "roles",
                   "mac-auth-only-role": "roles", "pre-auth-role": "roles",
                   "auth-server-group": "server-groups", "acct-server-group": "server-groups",
                   "primary-auth-server": "auth-servers", "backup-auth-server": "auth-servers",
                   "primary-acct-server": "auth-servers", "backup-acct-server": "auth-servers"}
# Explicit reference fields documented in Ethernet and switch port profile schemas.
# https://developer.arubanetworks.com/new-central-config/reference/replaceethernetinterfacesinterfacebyid
# https://developer.arubanetworks.com/new-central-config/reference/replaceswportprofilesprofilebyid
PORT_SECURITY_REFERENCES = {"macsec-policy": "macsec", "mka-policy": "mka",
                            "fault-monitor-profile": "fault-monitor"}
SWITCH_PORT_REFERENCES = {**PORT_SECURITY_REFERENCES, "aaa-profile": "aaa-profile",
                          "dfp-profile": "devicefingerprinting-profile", "nd-snooping-profile": "nd-snooping"}
# https://developer.arubanetworks.com/new-central-config/reference/replaceaaaprofileprofilebyid
AAA_REFERENCES = {"dpp-netaccess-default-role": "roles", "dpp-netaccess-server-group": "server-groups",
                  "acct-server-group": "server-groups", "rfc3576-profile": "auth-servers"}
LIST_REFERENCES = {"aaa-profile": {"rfc3576-server-list": "auth-servers"}}
MODULE_REFERENCES = {"wlan-ssids": AUTH_REFERENCES, "ap-port-profiles": AUTH_REFERENCES,
                     "aaa-profile": AAA_REFERENCES,
                     "role-acls": {"src-role": "roles"},
                     "ethernet-interfaces": PORT_SECURITY_REFERENCES,
                     "sw-port-profiles": SWITCH_PORT_REFERENCES,
                     "devicefingerprinting-interface": {"profile-name": "devicefingerprinting-profile"},
                     "roles": {"macsec-policy": "macsec", "object-group-ipv4": "object-groups",
                               "object-group-ipv6": "object-groups"}}
ADDITIVE = {"layer2-vlan", "roles", "wlan-ssids", "auth-servers"}
PRECEDENCE = ("group", "site", "collection", "global")


def effective_views(entry):
    return {module: {s["scope"]: s.get("effective_view", {}) for s in data["scope_results"]}
            for module, data in entry["modules"].items()}


def policy_named_target(path, key):
    """Recognize named service/group fields only in documented rule conditions.

    HPE's policy collection example distinguishes services, transport fields
    and source/destination role options. Do not guess the family of generic
    address-group or port group fields.
    """
    if len(path) < 4 or path[:2] != ("security-policy", "policy-rule") or type(path[2]) is not int or path[3] != "condition":
        return None
    relative = path[4:]
    if relative == ("services",) and key == "net-service":
        return "net-services"
    if relative == ("transport-fields",) and key in ("destination-port-net-group", "source-port-net-group"):
        return "net-groups"
    if relative in (("source", "role-options"), ("destination", "role-options")) and key == "net-group":
        return "net-groups"
    return None


def explicit_references(value, path=(), module=None):
    named = {**NAMED_REFERENCES, **MODULE_REFERENCES.get(module, {})}
    if isinstance(value, dict):
        if module == "policies" and value.get("type") == "ADDRESS_ROLE":
            role = value.get("role")
            yield "roles", role if isinstance(role, str) and role else None, path + ("role",)
        for key, item in value.items():
            if key in ("@", "metadata"):
                continue
            here = path + (key,)
            list_target = LIST_REFERENCES.get(module, {}).get(key)
            if list_target:
                if isinstance(item, list):
                    for i, member in enumerate(item):
                        yield list_target, member if isinstance(member, str) and member else None, here + (i,)
                else:
                    yield list_target, None, here
            # HPE net-group schema: a root exclude points to another netdestination.
            # https://developer.arubanetworks.com/new-central-config/reference/createnetgroupsnetgroupbyid
            elif module == "net-groups" and not path and key == "exclude":
                yield "net-groups", item if isinstance(item, str) and item.strip() else None, here
            # HPE server-group schema: ordered members refer to auth-server
            # names, not server addresses or arbitrary nested name fields.
            # https://developer.arubanetworks.com/new-central-config/reference/replaceservergroupsservergroupbyid
            elif module == "server-groups" and path == () and key == "servers":
                if isinstance(item, list):
                    for i, member in enumerate(item):
                        name = member.get("server-name") if isinstance(member, dict) else None
                        yield "auth-servers", name if isinstance(name, str) and name.strip() else None, here + (i, "server-name")
                else:
                    yield "auth-servers", None, here
            elif module == "policies" and (target := policy_named_target(path, key)):
                yield target, item if isinstance(item, str) and item else None, here
            elif key in named:
                yield named[key], item if isinstance(item, str) and item else None, here
            elif key == "sw-profile-alias":
                yield "sw-port-profiles", None, here
            else:
                yield from explicit_references(item, here, module)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from explicit_references(item, path + (i,), module)


def library_usage(bundle, module, identities, references):
    """Separate assignments, observed shared deployments, and explicit references.

    A matching local body is not proof that a Library profile is used.
    Counts are lower bounds from captured evidence, not a complete usage graph.
    """
    library = bundle.get("library") or {}
    view = library.get("modules", {}).get(module, {})
    assignment_view = library.get("assignments") or {}
    wanted = set(identities)
    if not wanted:
        return {}
    direct = (bundle.get("keyed_profile_details") or {}).get("profiles", {})
    def contradicts(collection, identity, read):
        if (collection.get("status") != "list_parsed" or read.get("status") != "identity_observed"
                or not isinstance(read.get("profile"), dict)):
            return False
        profile = collection.get("profiles", {}).get(identity)
        return (collection.get("count_confirmed") is True if profile is None else
                canonical(profile_body(profile)) != canonical(profile_body(read["profile"])))
    assigned, referenced = defaultdict(list), defaultdict(list)
    for row in assignment_view.get("rows", []):
        if isinstance(row, dict) and row.get("profile-type") == module and str(row.get("profile-instance")) in wanted:
            assigned[str(row["profile-instance"])].append(row)
    for ref in references:
        if ref["target_module"] == module and ref["target"] in wanted:
            referenced[ref["target"]].append(ref)
    expected_signatures = {identity: canonical(profile_body(profile))
                           for identity, profile in view.get("profiles", {}).items() if identity in wanted and profile is not None}
    result = {}
    for identity in sorted(wanted):
        rows = assigned[identity]
        unique = {(str(a.get("scope-id")), str(a.get("device-function"))) for a in rows
                  if a.get("scope-id") is not None and a.get("device-function") is not None}
        refs = referenced[identity]
        configured = [r for r in refs if r.get("source_evidence") != "nac_enforcement"]
        nac = [r for r in refs if r.get("source_evidence") == "nac_enforcement"]
        def consumer(r):
            return (r["persona"], r["scope"], r["source_module"], r["source"])
        consumers = {consumer(r) for r in configured}
        definitions = {consumer(r) for r in configured if r.get("source_view") in ("saved", "library")}
        effective = {consumer(r) for r in configured if r.get("source_view", "effective") == "effective"}
        result[identity] = {"identity": identity, "assignment_count": len(unique),
                            "assignment_status": assignment_view.get("status", "not_collected"),
                            "assignments": rows, "reference_count": len(consumers),
                            "definition_reference_count": len(definitions), "effective_reference_count": len(effective),
                            "reference_devices": len({(r["persona"], r["scope"]) for r in refs if r.get("source_scope_kind", "device") == "device" and r.get("source_view", "effective") == "effective"}),
                            "references": refs, "conditional_nac_observations": len(nac), "conflicting_reference_count": len({consumer(r) for r in refs if r.get("collection_conflict")}),
                            "shared_devices": [], "matching_other_devices": [],
                            "different_devices": [], "unknown_devices": [], "absent_devices": [], "compared_devices": 0,
                            "coverage_complete": False}
        individual = direct.get("Library", {}).get("", {}).get(module, {}).get(identity, {}).get("library", {})
        if contradicts(view, identity, individual):
            result[identity]["library_individual_conflict"] = True
    for persona, entry in sorted(bundle["results"].items()):
        if module not in entry["modules"]:
            continue
        views = {s["scope"]: s.get("effective_view", {}) for s in entry["modules"][module]["scope_results"]}
        for device in (s for s in entry["scopes"] if s["kind"] == "device"):
            sid = device["id"]
            record = {"persona": persona, "scope": sid, "name": device.get("name") or sid}
            actual = views.get(sid, {})
            individual = direct.get(persona, {}).get(str(sid), {}).get(module, {})
            for identity, usage in result.items():
                conflict = contradicts(actual, identity, individual.get(identity, {}).get("effective", {}))
                if usage.get("library_individual_conflict") or conflict:
                    evidence = {**record, "individual_conflict": True,
                                "library_conflict": bool(usage.get("library_individual_conflict")),
                                "effective_conflict": conflict}
                    usage["unknown_devices"].append(evidence)
                    usage.setdefault("individual_conflict_devices", []).append(evidence)
                    continue
                if actual.get("status") != "list_parsed":
                    usage["unknown_devices"].append(record)
                    continue
                usage["compared_devices"] += 1
                profile = actual["profiles"].get(identity)
                if profile is None:
                    usage["absent_devices" if actual.get("count_confirmed") is True else "unknown_devices"].append(record)
                    continue
                if identity not in expected_signatures or canonical(profile_body(profile)) != expected_signatures[identity]:
                    usage["different_devices"].append(record)
                    continue
                annotation = profile.get("@", {})
                if isinstance(annotation, dict) and annotation.get("aruba-annotation:object_type") == "SHARED":
                    usage["shared_devices"].append(record)
                else:
                    usage["matching_other_devices"].append(record)
    return result


def preferred_duplicate(usage):
    """Suggest the least observed reference/assignment migration, not safe deletion."""
    if not usage or any(u["assignment_status"] != "response_received" or u.get("conflicting_reference_count", 0)
                        or u.get("library_individual_conflict") or u.get("individual_conflict_devices") or u.get("conditional_nac_observations",0)
                        for u in usage.values()):
        return None
    # Do not add incomparable metrics together. Prefer more explicit consumers,
    # then more observed shared deployments, then more assignments.
    def score(u):
        return (u.get("definition_reference_count", 0), u["assignment_count"], u["reference_count"], len(u["shared_devices"]))
    ordered = sorted(usage.values(), key=score, reverse=True)
    if len(ordered) < 2 or score(ordered[0]) == score(ordered[1]) or not any(score(ordered[0])):
        return None
    return ordered[0]["identity"]


def duplicate_migration_preview(module, usage, keep, bundle=None):
    """A concrete review worklist, never executable or complete."""
    if keep not in usage:
        raise ValueError("Choose an observed duplicate profile")
    def assignment_keys(u):
        return {(str(a["scope-id"]), str(a["device-function"])) for a in u["assignments"]
                if type(a.get("scope-id")) in (str, int) and isinstance(a.get("device-function"), str)
                and a["device-function"]}
    retained = assignment_keys(usage[keep])
    assignments, definitions, impacts = [], [], []
    seen = set()
    for identity, u in sorted(usage.items()):
        if identity == keep:
            continue
        for sid, persona in sorted(assignment_keys(u)):
            assignments.append({"from": identity, "to": keep, "scope": sid, "persona": persona,
                                "action": "verify_existing_assignment" if (sid, persona) in retained else "review_target_assignment"})
        for ref in u["references"]:
            evidence = {**ref, "from": identity, "to": keep}
            key = canonical(evidence)
            if key in seen:
                continue
            seen.add(key)
            if ref.get("source_view") in ("saved", "library"):
                definitions.append(evidence)
            else:
                impacts.append(evidence)
    from .migration_review import migration_recipient_review
    recipients = migration_recipient_review(bundle, usage, keep, assignments, definitions, impacts)
    return {"module": module, "retain": keep, "assignments": assignments, "saved_references": definitions,
            "effective_references": impacts, **recipients,
            "target_conflicts": usage[keep]["different_devices"], "target_unknown_reads": usage[keep]["unknown_devices"],
            "blockers": ["Verify all assignments and reverse references, including unadapted modules.",
                         "Verify the retained profile is visible and equivalent on every affected device.",
                         "Do not delete the old names until fresh effective configuration and references are verified."],
            "safe_to_apply": False, "complete": False}


def target_reference_evidence(view, identity, *, definition=False):
    """Distinguish a missing identity from an incomplete or unavailable read."""
    if identity is None:
        return "unresolved", "identity_unqualified"
    if view.get("status") != "list_parsed":
        return "unresolved", "target_view_unqualified"
    if identity in view.get("profiles", {}):
        return ("definition_observed" if definition else "observed"), "identity_observed"
    if view.get("count_confirmed") is True:
        return "not_observed", "count_confirmed_absence"
    return "unresolved", "target_collection_incomplete"


REFERENCE_VALUE_SHAPES = ("missing_path","null","empty_string","wildcard_string","nonempty_string",
    "integer","boolean","empty_list","wildcard_list","literal_list","object_list","mixed_list",
    "object","other","unknown")


def reference_value_shape(body,path):
    """Report only fixed structural categories, never source values."""
    value=body
    for part in path:
        if isinstance(value,dict) and isinstance(part,str) and part in value:
            value=value[part]
        elif isinstance(value,list) and type(part) is int and 0 <= part < len(value):
            value=value[part]
        else:
            return "missing_path"
    def wildcard(item):
        return isinstance(item,str) and item.strip().casefold() in ("all","any","*")
    if value is None:
        return "null"
    if isinstance(value,str):
        return "empty_string" if not value.strip() else "wildcard_string" if wildcard(value) else "nonempty_string"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if isinstance(value,list):
        if not value:
            return "empty_list"
        if all(wildcard(v) for v in value):
            return "wildcard_list"
        if all(type(v) in (str,int) for v in value):
            return "literal_list"
        if all(isinstance(v,dict) for v in value):
            return "object_list"
        return "mixed_list"
    if isinstance(value,dict):
        return "object"
    return "other"


def profile_reference_observations(module, identity, body, vlans):
    """Use identical reference extraction for all qualified source reads."""
    handled = set()
    # Named VLAN is a mapping container, not itself an unresolved scalar.
    # https://developer.arubanetworks.com/new-central-config/reference/createnamedvlanprofilebyid
    # The two documented alternatives are mutually exclusive.
    if module == "named-vlan":
        mapping = body.get("vlan")
        if isinstance(mapping, dict) and set(mapping) == {"vlan-id-ranges"}:
            from .central_tool import parse_reference_ids
            handled.add("vlan")
            ids = parse_reference_ids(mapping["vlan-id-ranges"], allow_list=True)
            if ids:
                for vid in sorted(ids, key=int):
                    yield "layer2-vlan", vid, ["vlan", "vlan-id-ranges"]
            else:
                yield "layer2-vlan", None, ["vlan", "vlan-id-ranges"]
        elif isinstance(mapping, dict) and set(mapping) == {"vlan-alias"}:
            handled.add("vlan")
            alias = mapping["vlan-alias"]
            yield "aliases", alias if isinstance(alias, str) and alias.strip() else None, ["vlan", "vlan-alias"]
    # HPE WLAN SSID explicitly distinguishes a named-VLAN profile from
    # literal VLAN-ID ranges; the name is not a layer2-vlan display name.
    # https://developer.arubanetworks.com/new-central-config/reference/updatewlanssidswlanssidbyid
    if module == "wlan-ssids":
        selector = body.get("vlan-selector")
        if selector == "NAMED_VLAN" and "vlan-id-range" not in body:
            handled.update(("vlan-selector", "vlan-name"))
            name = body.get("vlan-name")
            yield "named-vlan", name if isinstance(name, str) and name.strip() else None, ["vlan-name"]
        elif selector == "VLAN_RANGES" and "vlan-name" not in body:
            from .central_tool import parse_reference_ids
            handled.update(("vlan-selector", "vlan-id-range"))
            ids = parse_reference_ids(body.get("vlan-id-range"), allow_list=True)
            if ids:
                for vid in sorted(ids, key=int):
                    yield "layer2-vlan", vid, ["vlan-id-range"]
            else:
                yield "layer2-vlan", None, ["vlan-id-range"]
    # GVRP mode is an enum, not a VLAN identity.
    # https://developer.arubanetworks.com/new-central-config/reference/updateethernetinterfacesinterfacebyid
    if module == "ethernet-interfaces" and body.get("unknown-vlans") in ("BLOCK", "DISABLE", "LEARN"):
        handled.add("unknown-vlans")
    # Preserve unrelated nested fields for generic review; specialize only
    # documented paths in the relevant source profile.
    filtered = {k:v for k,v in body.items() if k not in handled}
    from .central_tool import parse_reference_ids
    def numeric(value, path, allow_list=False):
        ids = parse_reference_ids(value, allow_list=allow_list)
        if ids:
            for vid in sorted(ids,key=int):
                yield "layer2-vlan",vid,path
        else:
            yield "layer2-vlan",None,path
    if module == "ap-port-profiles" and isinstance(filtered.get("switchport"),dict):
        port = dict(filtered["switchport"])
        # https://developer.arubanetworks.com/new-central-config/reference/replaceapportprofilesprofilebyid
        # The explicit ranges selector is a mode, not a reference. Unknown
        # selectors and any contradictory named value remain unresolved.
        # A literal range field is positive evidence of configured members
        # even when the collection omits the selector. Do not infer the
        # omitted selector or override a conflicting named/all alternative.
        explicit_ranges = "allowed-vlan-selector" not in port or port["allowed-vlan-selector"] == "VLAN_RANGES"
        no_named_value = "allowed-vlan-name" not in port
        if explicit_ranges and no_named_value:
            if any(k in port for k in ("trunk-vlan-ranges","trunk-vlans")) or port.get("trunk-vlan-all") is True:
                port.pop("allowed-vlan-selector", None)
                for key in ("trunk-vlan-ranges","trunk-vlans"):
                    if key in port:
                        yield from numeric(port.pop(key),["switchport",key],True)
                if port.get("trunk-vlan-all") is True:
                    yield "layer2-vlan",None,["switchport","trunk-vlan-all"]
        filtered["switchport"] = port
    if module == "stp":
        # https://developer.arubanetworks.com/new-central-config/reference/createstpprofilebyid
        if "rpvst-mstp-interconnect-vlan" in filtered:
            yield from numeric(filtered.pop("rpvst-mstp-interconnect-vlan"),["rpvst-mstp-interconnect-vlan"])
        if isinstance(filtered.get("mstp"),list):
            instances=[]
            for index,instance in enumerate(filtered["mstp"]):
                if isinstance(instance,dict):
                    instance=dict(instance)
                    for key in ("mstp-vlans","vlans"):
                        if key in instance:
                            yield from numeric(instance.pop(key),["mstp",index,key],True)
                instances.append(instance)
            filtered["mstp"]=instances
        if isinstance(filtered.get("rpvst"),list):
            instances=[]
            for index,instance in enumerate(filtered["rpvst"]):
                if isinstance(instance,dict):
                    instance=dict(instance)
                    if type(instance.get("vlan-log-state-transitions")) is bool:
                        instance.pop("vlan-log-state-transitions")
                instances.append(instance)
            filtered["rpvst"]=instances
    if module == "roles" and isinstance(filtered.get("vlan-parameters"),dict):
        parameters=dict(filtered["vlan-parameters"])
        # The vendor role response distinguishes named-vlan and literal IDs.
        # access-vlan-name and trunk names stay under existing conservative review.
        if "named-vlan" in parameters:
            value=parameters.pop("named-vlan")
            yield "named-vlan",value if isinstance(value,str) and value.strip() else None,["vlan-parameters","named-vlan"]
        for key in ("trunk-native-vlan","wired-access-vlan-id","trunk-allowed-vlans"):
            if key in parameters:
                yield from numeric(parameters.pop(key),["vlan-parameters",key],key=="trunk-allowed-vlans")
        if parameters.get("private-vlan-port-type") in ("PROMISCUOUS","SECONDARY","ISL"):
            parameters.pop("private-vlan-port-type")
        filtered["vlan-parameters"]=parameters
    if module != "layer2-vlan":
        vlan_refs = reference_candidates(filtered, vlans)
        for ref in vlan_refs["references"]:
            for vid in ref["vlan_ids"]:
                yield "layer2-vlan", vid, ref["path"]
        for path in vlan_refs["unresolved_paths"]:
            yield "layer2-vlan", None, path
        if module == "vlan-interfaces" and identity.isdigit():
            yield "layer2-vlan", identity, ["identity"]
    yield from explicit_references(body, module=module)


def advanced_analysis(bundle):
    result = {"port_groups": [], "shadowed": [], "library_duplicates": [],
              "references": [], "coverage": [], "precedence_conflicts": [], "reference_graph_complete": False,
              "safe_to_apply": False}
    library = bundle.get("library") or {}
    library_modules = library.get("modules", {})
    port_library = library_modules.get("sw-port-profiles", {})
    from .standard_evidence import conflicting_profiles
    port_library_conflicts = conflicting_profiles(bundle, "Library", "sw-port-profiles", "", port_library, side="library")
    port_library_index = defaultdict(list)
    if port_library.get("status") == "list_parsed":
        for name, profile in sorted(port_library["profiles"].items()):
            content = {k: v for k, v in profile_body(profile).items() if k not in ("profile-name", "description")}
            port_library_index[canonical(content)].append(name)
    persona_views = {persona: effective_views(entry) for persona, entry in bundle["results"].items()}
    for persona, entry in sorted(bundle["results"].items()):
        views = persona_views[persona]
        members = scope_memberships(entry["scopes"])
        names = {s["id"]: s.get("name") or s["id"] for s in entry["scopes"]}
        scope_kinds = {s["kind"] for s in entry["scopes"]}
        precedence_conflicts = {}
        precedence_local = {module: {row["scope"]: row.get("local_view", {}) for row in entry["modules"][module]["scope_results"]}
                            for module in ADDITIVE & views.keys()}
        def scope_contradiction(module, scope, identity):
            key = (module, scope)
            if key not in precedence_conflicts:
                precedence_conflicts[key] = {
                    "effective": conflicting_profiles(bundle, persona, module, scope, views[module].get(scope, {})),
                    "local": conflicting_profiles(bundle, persona, module, scope, precedence_local[module].get(scope, {}), side="local")}
            return {side: conflicts[identity] for side, conflicts in precedence_conflicts[key].items() if identity in conflicts}
        port_groups = defaultdict(list)
        port_saved_views = {v["scope"]: v for v in entry["modules"].get("ethernet-interfaces", {}).get("scope_results", [])}
        port_conflicts, profile_conflicts = {}, {}
        for device in (s for s in entry["scopes"] if s["kind"] == "device"):
            sid = device["id"]
            def get(module):
                return views.get(module, {}).get(sid, {})
            def emit(source_module, source, target, identity, path, body):
                target_view = get(target)
                status, reason = target_reference_evidence(target_view, identity)
                result["references"].append({"persona": persona, "device": names[sid], "scope": sid,
                    "source_module": source_module, "source": source, "source_view": "effective", "source_scope_kind": "device", "target_module": target,
                    "target": identity, "path": list(path), "status": status, "target_evidence": reason,
                    **({"source_value_shape":reference_value_shape(body,path)} if identity is None else {})})
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
                    for target, ref, path in profile_reference_observations(module, identity, body, vlans):
                        emit(module, identity, target, ref, path, body)
                    if module == "ethernet-interfaces" and persona.endswith("_SWITCH"):
                        if body.get("routing") is True or PORT_TOPOLOGY & body.keys():
                            continue
                        portable = {k: v for k, v in body.items() if k in PORT_FIELDS}
                        if not portable or not isinstance(portable.get("switchport"), dict):
                            continue
                        unsupported = sorted(set(body) - PORT_FIELDS - PORT_IDENTITY)
                        if sid not in port_conflicts:
                            port_conflicts[sid] = {
                                "effective": conflicting_profiles(bundle, persona, module, sid, view),
                                "local": conflicting_profiles(bundle, persona, module, sid, port_saved_views.get(sid, {}).get("local_view", {}), side="local")}
                        evidence_conflicts = {side: records[identity] for side, records in port_conflicts[sid].items() if identity in records}
                        # Include all non-identity fields in the signature: unknown fields
                        # cannot disappear from the comparison.
                        signature = canonical({k: v for k, v in body.items() if k not in PORT_IDENTITY})
                        port_groups[signature].append({"scope": sid, "device": names[sid],
                            "port": identity, "description": body.get("description"),
                            "portable": portable, "unsupported": unsupported,
                            "before": body, **({"individual_conflicts": evidence_conflicts} if evidence_conflicts else {})})
            for module in sorted(ADDITIVE & views.keys()):
                device_view = get(module)
                if device_view.get("status") != "list_parsed":
                    continue
                for identity, raw in device_view["profiles"].items():
                    annotation = raw.get("@", {})
                    if not isinstance(annotation, dict) or annotation.get("aruba-annotation:is_default") is True:
                        continue
                    def record_conflict(scope, evidence):
                        result["precedence_conflicts"].append({"persona": persona, "device": names[sid], "scope": sid,
                            "module": module, "identity": identity, "conflicting_scope": scope,
                            "conflicting_scope_name": names[scope], "individual_conflict": evidence, "safe_to_apply": False})
                    conflict = scope_contradiction(module, sid, identity)
                    if conflict:
                        record_conflict(sid, conflict)
                        continue
                    # A direct winner must have explicit annotations at a known
                    # member scope, and agree exactly with the device effective body.
                    actual = profile_body(raw)
                    actual_signature = canonical(actual)
                    chain = [("device", sid)] + [(kind, members[sid][kind]) for kind in PRECEDENCE]
                    winner = None
                    unknown_higher = False
                    for index, (kind, scope_id) in enumerate(chain):
                        if scope_id is None:
                            # Optional absent membership is not proven by a missing ID.
                            if kind in scope_kinds:
                                unknown_higher = True
                            continue
                        effective = views[module].get(scope_id, {})
                        conflict = scope_contradiction(module, scope_id, identity)
                        if conflict:
                            record_conflict(scope_id, conflict)
                            unknown_higher = True
                            continue
                        if effective.get("status") != "list_parsed":
                            unknown_higher = True
                            continue
                        candidate = effective["profiles"].get(identity)
                        if candidate is None:
                            if effective.get("count_confirmed") is not True:
                                unknown_higher = True
                            continue
                        ann = candidate.get("@", {})
                        if not isinstance(ann, dict) or ann.get("aruba-annotation:inherited") is not False or ann.get("aruba-annotation:object_type") not in ("LOCAL", "SHARED") or ann.get("aruba-annotation:is_default") is True:
                            continue
                        if canonical(profile_body(candidate)) == actual_signature:
                            if not unknown_higher:
                                winner = (index, kind, scope_id)
                            break
                        # A direct higher-precedence body conflicts with the observed device.
                        unknown_higher = True
                    if winner is None:
                        continue
                    index, winning_kind, winning_scope = winner
                    for kind, ancestor in chain[index + 1:]:
                        if not ancestor:
                            continue
                        upstream = views[module].get(ancestor, {})
                        conflict = scope_contradiction(module, ancestor, identity)
                        if conflict:
                            record_conflict(ancestor, conflict)
                            continue
                        if upstream.get("status") != "list_parsed" or identity not in upstream["profiles"]:
                            continue
                        other = profile_body(upstream["profiles"][identity])
                        result["shadowed"].append({"persona": persona, "module": module,
                            "identity": identity, "device": names[sid], "scope": sid,
                            "winning_scope": names[winning_scope], "winning_scope_id": winning_scope,
                            "winning_scope_kind": winning_kind,
                            "higher_scope": names[ancestor], "higher_scope_id": ancestor,
                            "relationship": "same_body" if canonical(other) == actual_signature else "different_body",
                            "effective": actual, "higher_body": other,
                            "safe_to_apply": False})
        port_reference_index = defaultdict(list)
        for ref in result["references"]:
            if ref["persona"] == persona and ref["source_module"] == "ethernet-interfaces":
                port_reference_index[(ref["scope"], ref["source"])].append(ref)
        for ports in port_groups.values():
            if len(ports) < 2:
                continue
            settings = ports[0]["portable"]
            profile_view = port_library
            library_matches = []
            conflicting_library_matches = []
            settings_signature = canonical(settings)
            if profile_view.get("status") == "list_parsed":
                for name in port_library_index.get(settings_signature, ()):
                    if name in port_library_conflicts:
                        conflicting_library_matches.append({"identity": name, "individual_conflict": port_library_conflicts[name]})
                        continue
                    visibility = []
                    for sid in sorted({p["scope"] for p in ports}):
                        v = views.get("sw-port-profiles", {}).get(sid, {})
                        actual = v.get("profiles", {}).get(name) if v.get("status") == "list_parsed" else None
                        if sid not in profile_conflicts:
                            profile_conflicts[sid] = conflicting_profiles(bundle, persona, "sw-port-profiles", sid, v)
                        status = ("individual_evidence_conflict" if name in profile_conflicts[sid] else
                                  "unknown" if v.get("status") != "list_parsed" else
                                  ("not_observed" if v.get("count_confirmed") is True else "unknown") if actual is None else
                                  "matching" if canonical({k: val for k, val in profile_body(actual).items()
                                                           if k not in ("profile-name", "description")}) == settings_signature
                                  else "different")
                        visibility.append({"scope": sid, "device": names[sid], "status": status,
                                           **({"individual_conflict": profile_conflicts[sid][name]} if name in profile_conflicts[sid] else {})})
                    library_matches.append({"identity": name, "visibility": visibility})
            port_ids = {(p["scope"], p["port"]) for p in ports}
            dependencies = [r for key in sorted(port_ids) for r in port_reference_index[key]]
            from .port_conversion_review import port_conversion_review
            result["port_groups"].append({"persona": persona, "ports": ports,
                "conversion_review": port_conversion_review(entry, ports, settings, library_matches, views=port_saved_views),
                "portable_settings": settings, "unsupported_fields": ports[0]["unsupported"],
                "matching_library_profiles": library_matches, "conflicting_library_matches": conflicting_library_matches,
                "library_status": profile_view.get("status", "not_collected"),
                "dependencies": dependencies,
                "recommendation": "Resolve contradictory port or Library evidence" if conflicting_library_matches or any(p.get("individual_conflicts") for p in ports) or any(v["status"] == "individual_evidence_conflict" for m in library_matches for v in m["visibility"]) else
                                  "Review existing matching Library profile" if library_matches else
                                  "Review creation of a reusable switch port profile",
                "proposed_mapping": [{"scope": p["scope"], "port": p["port"],
                                      "retain_description": p["description"],
                                      "candidate_profile_reference_field": "sw-profile"} for p in ports],
                "blockers": ["Confirm hardware and port role compatibility, including uplinks and LAG membership.",
                             "Confirm profile assignment and retain/remove semantics in lab.",
                             "Verify all dependencies and complete effective port configuration."],
                "safe_to_apply": False})
    # Index saved definitions even when they are not currently deployed. A
    # Library object or a higher-scope profile may reference another profile
    # that has no observed device-level consumer yet.
    def definition_refs(persona, sid, name, kind, module, profiles, target_views):
        vlan_view = target_views.get("layer2-vlan", {})
        vlans = vlan_view.get("profiles", {}) if vlan_view.get("status") == "list_parsed" else {}
        for identity, raw in profiles.items():
            body = profile_body(raw)
            for target, target_id, path in profile_reference_observations(module, identity, body, vlans):
                view = target_views.get(target, {})
                # Existence in Library is not proof of device applicability.
                state, reason = target_reference_evidence(view, target_id, definition=True)
                result["references"].append({"persona": persona, "scope": sid, "device": name,
                    "source_scope_kind": kind, "source_view": "library" if kind == "library" else "saved", "source_module": module, "source": identity,
                    "target_module": target, "target": target_id, "path": list(path), "status": state, "target_evidence": reason,
                    **({"source_value_shape":reference_value_shape(body,path)} if target_id is None else {})})
    for persona, entry in sorted(bundle["results"].items()):
        views = persona_views[persona]
        scopes = {s["id"]: s for s in entry["scopes"]}
        target_views_by_scope = {}
        for module, by_scope in views.items():
            for sid, view in by_scope.items():
                target_views_by_scope.setdefault(sid, {})[module] = view
        for module, data in sorted(entry["modules"].items()):
            for scope in data["scope_results"]:
                sid = scope["scope"]
                meta = scopes.get(sid)
                local = scope.get("local_view", {})
                if not meta or local.get("status") != "list_parsed":
                    continue
                definition_refs(persona, sid, meta.get("name") or sid, meta["kind"], module,
                                local["profiles"], target_views_by_scope.get(sid, {}))
    for module, view in sorted(library_modules.items()):
        if view.get("status") == "list_parsed":
            definition_refs("Library", "Library", "Library", "library", module, view["profiles"], library_modules)

    # Direct individual responses can reveal dependencies absent from the
    # collection. Preserve the observed source separately, deduplicate exact
    # references, and expose contradictory values without resolving them.
    # A sampled observation is never a fetched profile; local individual
    # responses do not independently establish a saved source.
    existing = defaultdict(set)
    for ref in result["references"]:
        key = (ref["persona"], str(ref["scope"]), ref["source_module"], ref["source"],
               ref["source_view"], tuple(ref["path"]), ref["target_module"])
        existing[key].add(ref["target"])
    details = (bundle.get("keyed_profile_details") or {}).get("profiles", {})
    for persona, scopes in sorted(details.items()):
        entry = bundle["results"].get(persona, {})
        scope_meta = {str(scope["id"]): scope for scope in entry.get("scopes", [])}
        views = persona_views.get(persona, {})
        for sid, modules in sorted(scopes.items()):
            meta = scope_meta.get(str(sid))
            if persona == "Library" and sid == "":
                kind, source_view, scope_id, label, targets = "library", "library", "Library", "Library", library_modules
                read_kind = "library"
            elif meta and meta["kind"] == "device":
                kind, source_view, scope_id, label = "device", "effective", str(sid), meta.get("name") or str(sid)
                targets = {m: v.get(sid, {}) for m, v in views.items()}
                read_kind = "effective"
            else:
                continue
            for module, profiles in sorted(modules.items()):
                for identity, reads in sorted(profiles.items()):
                    evidence = reads.get(read_kind, {})
                    body = evidence.get("profile")
                    if evidence.get("status") != "identity_observed" or not isinstance(body, dict):
                        continue
                    vlan_view = targets.get("layer2-vlan", {})
                    vlans = vlan_view.get("profiles", {}) if vlan_view.get("status") == "list_parsed" else {}
                    for target, target_id, path in profile_reference_observations(module, identity, profile_body(body), vlans):
                        key = (persona, scope_id, module, identity, source_view, tuple(path), target)
                        if target_id in existing[key]:
                            continue
                        conflict = bool(existing[key])
                        view = targets.get(target, {})
                        state, reason = target_reference_evidence(view, target_id, definition=kind == "library")
                        if conflict:
                            state = "conflicting_observation"
                        result["references"].append({"persona": persona, "scope": scope_id, "device": label,
                            "source_scope_kind": kind, "source_view": source_view, "source_module": module,
                            "source": identity, "target_module": target, "target": target_id,
                            "path": list(path), "status": state, "target_evidence": reason, "source_evidence": "individual",
                            "collection_conflict": conflict,
                            **({"source_value_shape":reference_value_shape(profile_body(body),path)} if target_id is None else {})})
                        existing[key].add(target_id)

    # Qualify references against exact positive direct observations at
    # both ends. A collection-derived reference must not retain a positive
    # status when the individual source or target body contradicts it.
    from .dependency_evidence import qualify_reference_edges
    qualify_reference_edges(bundle, result["references"], persona_views)
    from .nac_dependency_references import nac_dependency_references
    result["references"].extend(nac_dependency_references(bundle))

    for module, view in sorted(library.get("modules", {}).items()):
        # Identity is semantic for numeric VLAN IDs and SSIDs. Report equivalent
        # named bodies only; never assume interchangeability.
        if module in ("layer2-vlan", "vlan-interfaces", "wlan-ssids", "ospfv2", "ospfv3", "bgp", "stp", "stp-gw") or module not in CONFIG_MODULES or view.get("status") != "list_parsed":
            continue
        key = CONFIG_MODULES[module][0]
        groups = defaultdict(list)
        for identity, raw in view["profiles"].items():
            ann = raw.get("@", {})
            if isinstance(ann, dict) and ann.get("aruba-annotation:is_default") is True:
                continue
            if not isinstance(raw.get(key), str) or raw[key] != identity:
                continue
            body = profile_body(raw)
            body.pop(key, None)
            if body:
                groups[canonical(body)].append(identity)
        duplicate_sets = [identities for identities in groups.values() if len(identities) > 1]
        if not duplicate_sets:
            continue
        all_usage = library_usage(bundle, module, [identity for identities in duplicate_sets for identity in identities], result["references"])
        unresolved_count = sum(r["target_module"] == module and r["status"] == "unresolved" for r in result["references"])
        for identities in duplicate_sets:
            usage = {identity: all_usage[identity] for identity in sorted(identities)}
            result["library_duplicates"].append({"module": module, "identities": sorted(identities),
                "usage": usage, "suggested_keep": preferred_duplicate(usage),
                "assignments": [a for identity in sorted(identities) for a in usage[identity]["assignments"]],
                "observed_references": [r for identity in sorted(identities) for r in usage[identity]["references"]],
                "unresolved_reference_count": unresolved_count,
                "recommendation": "Review identity-independent body match and all references before merging",
                "safe_to_apply": False})
    return result
