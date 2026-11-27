"""Evidence-based device override fallback using documented Central precedence."""
from .central_tool import canonical, field_differences, profile_body
from .consolidation import scope_memberships

PRECEDENCE = ("group", "site", "collection", "global")
# Identity-preserving, additive profile families already reviewed by the advisor.
ADDITIVE = {"layer2-vlan", "roles", "wlan-ssids", "auth-servers"}
ATOMIC = {"dns", "ntp", "ospfv2", "ospfv3", "bgp", "stp", "stp-gw"}
# These topology-sensitive modules are observation-only, even when exact.
TOPOLOGY_REVIEW = {"ospfv2", "ospfv3", "bgp", "stp", "stp-gw"}
SUPPORTED = ADDITIVE | ATOMIC


def nearest_fallback(entry, module, device, identity, local, effective, annotations):
    """Find the first directly observed ancestor definition, not merely a Global match.

    Unknown membership, incomplete absence, conflicting source evidence and
    replacement/default semantics block an exact fallback prediction.
    This is a review candidate only, never a write authorization.
    """
    result = {"status": "unresolved", "source": None, "chain": [],
              "differences": None, "blockers": [], "safe_to_apply": False}
    atomic = module in ATOMIC
    result["mode"] = "atomic" if atomic else "additive" if module in ADDITIVE else "unqualified"
    if module not in SUPPORTED:
        result["blockers"].append("Module inheritance semantics not qualified")
        return result
    if module == "layer2-vlan" and identity == "1":
        result["blockers"].append("Protected default VLAN")
        return result
    if (not isinstance(local, dict) or not isinstance(effective, dict)
            or canonical(local) != canonical(effective)
            or not isinstance(annotations, dict)
            or annotations.get("aruba-annotation:inherited") is not False
            or annotations.get("aruba-annotation:object_type") != "LOCAL"):
        result["blockers"].append("Device-local source or saved/effective equality not confirmed")
        return result
    membership = scope_memberships(entry["scopes"]).get(device)
    if not membership:
        result["blockers"].append("Device membership unavailable")
        return result
    scopes = {s["id"]: s for s in entry["scopes"]}
    views = {s["scope"]: s for s in entry["modules"].get(module, {}).get("scope_results", [])}
    if atomic:
        for key in ("local_view", "effective_view"):
            view = views.get(device, {}).get(key, {})
            if (view.get("status") != "list_parsed" or view.get("count_confirmed") is not True
                    or set(view.get("profiles", {})) != {identity}):
                result["blockers"].append("Atomic device profile cardinality not confirmed")
                return result
    inherited_observations = []
    for kind in PRECEDENCE:
        sid = membership[kind]
        if sid is None:
            # Global and Site are mandatory; optional scopes cannot be skipped
            # just because the collector did not return an inventory entry.
            result["chain"].append({"kind": kind, "scope": None, "status": "membership_unknown"})
            result["blockers"].append(f"{kind} membership or absence not established")
            continue
        view = views.get(sid, {}).get("effective_view", {})
        step = {"kind": kind, "scope": sid, "name": scopes[sid].get("name") or sid}
        if view.get("status") != "list_parsed":
            result["chain"].append({**step, "status": "read_unqualified"})
            result["blockers"].append(f"{kind} effective configuration unavailable")
            continue
        profiles = view.get("profiles", {})
        source_identity = identity
        if atomic:
            if view.get("count_confirmed") is not True or len(profiles) > 1:
                result["chain"].append({**step, "status": "atomic_cardinality_unverified"})
                result["blockers"].append(f"{kind} atomic profile cardinality not confirmed")
                continue
            if profiles:
                source_identity = next(iter(profiles))
        raw = profiles.get(source_identity)
        if raw is None:
            confirmed = view.get("count_confirmed") is True
            result["chain"].append({**step, "status": "absent_count_confirmed" if confirmed else "absence_unverified"})
            if not confirmed:
                result["blockers"].append(f"{kind} absence not count-confirmed")
            continue
        ann = raw.get("@")
        direct = (isinstance(ann, dict) and ann.get("aruba-annotation:inherited") is False
                  and ann.get("aruba-annotation:object_type") in ("LOCAL", "SHARED")
                  and ann.get("aruba-annotation:is_default") is not True)
        if not direct:
            # An explicitly inherited object is not a direct definition at
            # this scope. Keep walking; unknown annotations block certainty.
            inherited = isinstance(ann, dict) and ann.get("aruba-annotation:inherited") is True
            result["chain"].append({**step, "status": "inherited" if inherited else "source_unverified"})
            if inherited:
                inherited_observations.append((step, source_identity, profile_body(raw)))
            else:
                result["blockers"].append(f"{kind} profile source not established")
            continue
        body = profile_body(raw)
        result["source"] = {**step, "body": body, "identity": source_identity, "object_type": ann["aruba-annotation:object_type"]}
        result["chain"].append({**step, "status": "direct_definition"})
        result["differences"] = field_differences(local, body)
        # Intermediate effective observations must agree with the proposed source.
        # An inheritance annotation alone does not establish that relationship.
        for observed_scope, observed_identity, observed_body in inherited_observations:
            if observed_identity != source_identity or canonical(observed_body) != canonical(body):
                result["blockers"].append(f"{observed_scope['kind']} inherited observation disagrees with candidate source")
        if atomic:
            result["setting_differences"] = field_differences(
                {k: v for k, v in local.items() if k != "name"},
                {k: v for k, v in body.items() if k != "name"})
        if result["blockers"]:
            result["status"] = "candidate_unverified"
        elif atomic and source_identity != identity and not result["setting_differences"]:
            result["status"] = "matching_settings_identity_changed"
            result["blockers"].append("Atomic fallback changes profile identity; verify references and assignment effects")
        else:
            result["status"] = "matching_fallback" if not result["differences"] else "different_fallback"
        if module in TOPOLOGY_REVIEW and result["status"] in ("matching_fallback", "matching_settings_identity_changed"):
            result["status"] = "candidate_unverified"
            result["blockers"].append("Topology-sensitive profile; verify per-VRF and operational behavior before any removal")
        break
    if result["source"] is None:
        result["blockers"].append("No directly observed higher-scope definition")
    return result
