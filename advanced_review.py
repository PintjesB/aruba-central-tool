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
    assigned, referenced = defaultdict(list), defaultdict(list)
    for row in assignment_view.get("rows", []):
        if row.get("profile-type") == module and str(row.get("profile-instance")) in wanted:
            assigned[str(row["profile-instance"])].append(row)
    for ref in references:
        if ref["target_module"] == module and ref["target"] in wanted:
            referenced[ref["target"]].append(ref)
    result = {}
    for identity in sorted(wanted):
        rows = assigned[identity]
        unique = {(str(a.get("scope-id")), str(a.get("device-function"))) for a in rows
                  if a.get("scope-id") is not None and a.get("device-function") is not None}
        refs = referenced[identity]
        def consumer(r):
            return (r["persona"], r["scope"], r["source_module"], r["source"])
        consumers = {consumer(r) for r in refs}
        definitions = {consumer(r) for r in refs if r.get("source_view") in ("saved", "library")}
        effective = {consumer(r) for r in refs if r.get("source_view", "effective") == "effective"}
        result[identity] = {"identity": identity, "assignment_count": len(unique),
                            "assignment_status": assignment_view.get("status", "not_collected"),
                            "assignments": rows, "reference_count": len(consumers),
                            "definition_reference_count": len(definitions), "effective_reference_count": len(effective),
                            "reference_devices": len({(r["persona"], r["scope"]) for r in refs if r.get("source_scope_kind", "device") == "device" and r.get("source_view", "effective") == "effective"}),
                            "references": refs, "shared_devices": [], "matching_other_devices": [],
                            "different_devices": [], "unknown_devices": [], "absent_devices": [], "compared_devices": 0,
                            "coverage_complete": False}
    for persona, entry in sorted(bundle["results"].items()):
        if module not in entry["modules"]:
            continue
        views = {s["scope"]: s.get("effective_view", {}) for s in entry["modules"][module]["scope_results"]}
        for device in (s for s in entry["scopes"] if s["kind"] == "device"):
            sid = device["id"]
            record = {"persona": persona, "scope": sid, "name": device.get("name") or sid}
            actual = views.get(sid, {})
            for identity, usage in result.items():
                if actual.get("status") != "list_parsed":
                    usage["unknown_devices"].append(record)
                    continue
                usage["compared_devices"] += 1
                profile = actual["profiles"].get(identity)
                if profile is None:
                    usage["absent_devices" if actual.get("count_confirmed") is True else "unknown_devices"].append(record)
                    continue
                expected = view.get("profiles", {}).get(identity)
                if expected is None or canonical(profile_body(profile)) != canonical(profile_body(expected)):
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
    if not usage or any(u["assignment_status"] != "response_received" for u in usage.values()):
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
    from migration_review import migration_recipient_review
    recipients = migration_recipient_review(bundle, usage, keep, assignments, definitions, impacts)
    return {"module": module, "retain": keep, "assignments": assignments, "saved_references": definitions,
            "effective_references": impacts, **recipients,
            "target_conflicts": usage[keep]["different_devices"], "target_unknown_reads": usage[keep]["unknown_devices"],
            "blockers": ["Verify all assignments and reverse references, including unadapted modules.",
                         "Verify the retained profile is visible and equivalent on every affected device.",
                         "Do not delete the old names until fresh effective configuration and references are verified."],
            "safe_to_apply": False, "complete": False}


def advanced_analysis(bundle):
    result = {"port_groups": [], "shadowed": [], "library_duplicates": [],
              "references": [], "coverage": [], "reference_graph_complete": False,
              "safe_to_apply": False}
    library = bundle.get("library") or {}
    library_modules = library.get("modules", {})
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
                    "source_module": source_module, "source": source, "source_view": "effective", "source_scope_kind": "device", "target_module": target,
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
                    for target, ref, path in explicit_references(body, module=module):
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
                            "portable": portable, "unsupported": unsupported,
                            "before": body})
            for module in sorted(ADDITIVE & views.keys()):
                device_view = get(module)
                if device_view.get("status") != "list_parsed":
                    continue
                for identity, raw in device_view["profiles"].items():
                    annotation = raw.get("@", {})
                    if not isinstance(annotation, dict) or annotation.get("aruba-annotation:is_default") is True:
                        continue
                    # A direct winner must have explicit annotations at a known
                    # member scope, and agree exactly with the device effective body.
                    actual = profile_body(raw)
                    chain = [("device", sid)] + [(kind, members[sid][kind]) for kind in PRECEDENCE]
                    winner = None
                    unknown_higher = False
                    for index, (kind, scope_id) in enumerate(chain):
                        if scope_id is None:
                            # Optional absent membership is not proven by a missing ID.
                            if any(s["kind"] == kind for s in entry["scopes"]):
                                unknown_higher = True
                            continue
                        effective = views[module].get(scope_id, {})
                        if effective.get("status") != "list_parsed":
                            unknown_higher = True
                            continue
                        candidate = effective["profiles"].get(identity)
                        if candidate is None:
                            continue
                        ann = candidate.get("@", {})
                        if not isinstance(ann, dict) or ann.get("aruba-annotation:inherited") is not False or ann.get("aruba-annotation:object_type") not in ("LOCAL", "SHARED") or ann.get("aruba-annotation:is_default") is True:
                            continue
                        if canonical(profile_body(candidate)) == canonical(actual):
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
                        if upstream.get("status") != "list_parsed" or identity not in upstream["profiles"]:
                            continue
                        other = profile_body(upstream["profiles"][identity])
                        result["shadowed"].append({"persona": persona, "module": module,
                            "identity": identity, "device": names[sid], "scope": sid,
                            "winning_scope": names[winning_scope], "winning_scope_id": winning_scope,
                            "winning_scope_kind": winning_kind,
                            "higher_scope": names[ancestor], "higher_scope_id": ancestor,
                            "relationship": "same_body" if canonical(other) == canonical(actual) else "different_body",
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
            profile_view = library_modules.get("sw-port-profiles", {})
            library_matches = []
            if profile_view.get("status") == "list_parsed":
                for name, profile in sorted(profile_view["profiles"].items()):
                    body = profile_body(profile)
                    # A profile description describes the reusable object, not
                    # necessarily the physical port; do not ignore extra settings.
                    content = {k: v for k, v in body.items() if k not in ("profile-name", "description")}
                    if canonical(content) != canonical(settings):
                        continue
                    visibility = []
                    for sid in sorted({p["scope"] for p in ports}):
                        v = views.get("sw-port-profiles", {}).get(sid, {})
                        actual = v.get("profiles", {}).get(name) if v.get("status") == "list_parsed" else None
                        status = ("unknown" if v.get("status") != "list_parsed" else
                                  "not_observed" if actual is None else
                                  "matching" if canonical({k: val for k, val in profile_body(actual).items()
                                                           if k not in ("profile-name", "description")}) == canonical(settings)
                                  else "different")
                        visibility.append({"scope": sid, "device": names[sid], "status": status})
                    library_matches.append({"identity": name, "visibility": visibility})
            port_ids = {(p["scope"], p["port"]) for p in ports}
            dependencies = [r for key in sorted(port_ids) for r in port_reference_index[key]]
            from port_conversion_review import port_conversion_review
            result["port_groups"].append({"persona": persona, "ports": ports,
                "conversion_review": port_conversion_review(entry, ports, settings, library_matches),
                "portable_settings": settings, "unsupported_fields": ports[0]["unsupported"],
                "matching_library_profiles": library_matches, "library_status": profile_view.get("status", "not_collected"),
                "dependencies": dependencies,
                "recommendation": "Review existing matching Library profile" if library_matches else
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
            refs = list(explicit_references(body, module=module))
            if module != "layer2-vlan":
                vlan = reference_candidates(body, vlans)
                refs.extend(("layer2-vlan", vid, ref["path"]) for ref in vlan["references"] for vid in ref["vlan_ids"])
                refs.extend(("layer2-vlan", None, path) for path in vlan["unresolved_paths"])
            for target, target_id, path in refs:
                view = target_views.get(target, {})
                # Existence in Library is not proof of device applicability.
                state = ("unresolved" if target_id is None or view.get("status") != "list_parsed"
                         else "definition_observed" if target_id in view["profiles"] else "not_observed")
                result["references"].append({"persona": persona, "scope": sid, "device": name,
                    "source_scope_kind": kind, "source_view": "library" if kind == "library" else "saved", "source_module": module, "source": identity,
                    "target_module": target, "target": target_id, "path": list(path), "status": state})
    for persona, entry in sorted(bundle["results"].items()):
        views = effective_views(entry)
        scopes = {s["id"]: s for s in entry["scopes"]}
        for module, data in sorted(entry["modules"].items()):
            for scope in data["scope_results"]:
                sid = scope["scope"]
                meta = scopes.get(sid)
                local = scope.get("local_view", {})
                if not meta or local.get("status") != "list_parsed":
                    continue
                definition_refs(persona, sid, meta.get("name") or sid, meta["kind"], module,
                                local["profiles"], {m: v.get(sid, {}) for m, v in views.items()})
    for module, view in sorted(library_modules.items()):
        if view.get("status") == "list_parsed":
            definition_refs("Library", "Library", "Library", "library", module, view["profiles"], library_modules)

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
