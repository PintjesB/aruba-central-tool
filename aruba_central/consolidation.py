"""Conservative, offline consolidation recommendations from captured evidence."""
from collections import defaultdict
import hashlib

from .central_tool import canonical, field_differences, profile_body, assess_vlan_reference, PERSONAS

# Full device/system identity, physical interfaces and routed topology are
# deliberately excluded from generic reusable-profile promotion.
REUSABLE = {
    "layer2-vlan", "sw-port-profiles", "interface-profiles", "roles",
    "ap-port-profiles", "gw-port-profiles", "wlan-ssids", "dns", "ntp",
    "snmp", "snmp-trap", "logging", "auth-servers", "macauth", "qos-queues",
}
LABELS = {
    "remove_override": "Review redundant override",
    "promote_local": "Consolidate repeated local profiles",
    "reuse_library": "Reuse existing Library profile",
    "create_library": "Consider new Library profile",
    "conflict": "Review conflicting definitions",
    "default_review": "Review default / omitted settings",
    "unassigned_library": "Review Library assignments",
}
COMMON_BLOCKERS = (
    "Verify fresh configuration and actual inheritance precedence.",
    "Verify supported destination and all affected device functions and devices.",
    "Verify profile references, module-specific defaults and operational behavior.",
    "Approve a separate executable plan with validated rollback.",
)


def scope_memberships(scopes):
    """Correlate explicit IDs only, including the separate device-group path.

    Central's SDK correlates device siteId/deviceGroupId and site collectionId.
    A missing, ambiguous or unmatched ID remains unknown; no name matching.
    Scope IDs and entity IDs are separate selectors, so aliases must be unique.
    """
    by_kind = defaultdict(dict)
    for scope in scopes:
        kind = scope["kind"]
        sid = scope["id"]
        metadata = scope.get("metadata") or {}
        for key in {str(sid), str(metadata.get("id", ""))} - {""}:
            if key.isdigit():
                by_kind[kind].setdefault(str(int(key)), set()).add(sid)
    def resolve(kind, metadata, key):
        if key not in metadata:
            return None
        value = metadata[key]
        if type(value) not in (str, int) or not str(value).isdigit():
            return None
        matches = by_kind[kind].get(str(int(value)), set())
        return next(iter(matches)) if len(matches) == 1 else None
    globals_ = [s["id"] for s in scopes if s["kind"] == "global"]
    sites = {s["id"]: s for s in scopes if s["kind"] == "site"}
    membership = {}
    for scope in scopes:
        if scope["kind"] != "device":
            continue
        metadata = scope.get("metadata") or {}
        site = resolve("site", metadata, "siteId")
        group = resolve("group", metadata, "deviceGroupId")
        collection = resolve("collection", sites[site].get("metadata") or {}, "collectionId") if site else None
        membership[scope["id"]] = {
            "global": globals_[0] if len(globals_) == 1 else None,
            "site": site, "group": group, "collection": collection}
    return membership


def placement_index(scopes):
    """Build one immutable-in-use membership/recipient index per persona."""
    membership = scope_memberships(scopes)
    scope_by_id = {s["id"]: s for s in scopes}
    names = {s["id"]: s.get("name") or s["id"] for s in scopes}
    # Build the inverse membership map in one pass over devices. Unknown
    # membership sets are shared by scope kind rather than duplicated for
    # each possible destination. Callers only read these sets.
    known = defaultdict(set)
    unknown = defaultdict(set)
    for device, memberships in membership.items():
        for kind, sid in memberships.items():
            if sid is None:
                unknown[kind].add(device)
            else:
                known[kind, sid].add(device)
    all_devices = set(membership)
    empty = set()
    def recipients(sid):
        kind = scope_by_id[sid]["kind"]
        if kind == "device":
            return ({sid}, empty) if sid in membership else (empty, all_devices)
        if kind not in ("global", "site", "group", "collection"):
            return empty, all_devices
        return known.get((kind, sid), empty), unknown.get(kind, empty)
    return membership, scope_by_id, names, {sid: recipients(sid) for sid in scope_by_id}


def placement_evidence(scopes, sources, observed, references, *, index=None):
    """Preview known and unknown recipients, not a simulated deployment."""
    if index is None:
        index = placement_index(scopes)
    membership, scope_by_id, names, recipient_sets = index
    def recipients(sid):
        return recipient_sets[sid]
    intended, unknown_sources = set(), set()
    for source in sources:
        if source["scope"] not in scope_by_id:
            unknown_sources.update(membership)
            continue
        known, unknown = recipients(source["scope"])
        intended.update(known)
        unknown_sources.update(unknown)
    matching = {d["scope"] for d in observed.get("matching", [])}
    def describe(ids):
        return [{"scope": sid, "name": names.get(sid, sid)} for sid in sorted(ids)]
    proposals = []
    for ref in references:
        known, unknown = recipients(ref["scope"])
        if not intended or not intended <= known:
            continue
        extra = known - intended
        coverage = "exact_observed_recipient_set" if not extra and not unknown and not unknown_sources else "additional_or_unknown_recipients"
        proposals.append({**ref, "membership_status": coverage, "intended_devices": describe(intended),
                          "additional_devices": describe(extra),
                          "additional_already_matching": describe(extra & matching),
                          "additional_not_confirmed_matching": describe(extra - matching),
                          "unknown_membership": describe(unknown | unknown_sources),
                          "requires_precedence_validation": True, "safe_to_apply": False})
    preference = {"site": 0, "group": 1, "collection": 2, "global": 3}
    return sorted(proposals, key=lambda p: (p["membership_status"] != "exact_observed_recipient_set",
                         p["effective"] == "different", preference.get(p["kind"], 99),
                         len(p["additional_devices"]), p["scope"]))


def profile_recommendations(bundle):
    """Group exact local bodies; never equate observation with usage or safe removal."""
    findings = []
    library = bundle.get("library") or {}
    library_modules = library.get("modules", {})
    assignments = (library.get("assignments") or {}).get("rows", [])
    assigned = {(a.get("profile-type"), str(a["profile-instance"])) for a in assignments
                if isinstance(a, dict) and isinstance(a.get("profile-type"), str) and type(a.get("profile-instance")) in (str, int)}
    def add(action, persona, module, identity, sources, body, target, reference=None,
            observed=None, blockers=(), steps=(), scope_references=(), placement=(), fallbacks=(),
            individual_conflicts=(), blocked_destinations=()):
        payload = {"action": action, "persona": persona, "module": module,
                   "identity": identity, "sources": sources, "local": body,
                   "target": target, "reference": reference,
                   "differences": field_differences(body, reference)
                   if body is not None and reference is not None else None,
                   "observed_devices": observed or {}, "scope_references": list(scope_references),
                   "placement_options": list(placement), "fallbacks": list(fallbacks),
                   "preview_selectable": action != "remove_override" or bool(fallbacks) and all(
                       f["status"] == "matching_fallback" for f in fallbacks),
                   "blockers": list(dict.fromkeys([*blockers, *COMMON_BLOCKERS])),
                   "steps": list(steps), "safe_to_apply": False}
        if individual_conflicts:
            payload["individual_conflicts"] = list(individual_conflicts)
            payload["preview_selectable"] = False
        if blocked_destinations:
            payload["blocked_destinations"] = list(blocked_destinations)
            if any(d["destination"] == "library" for d in blocked_destinations) and not placement:
                payload["preview_selectable"] = False
        payload["id"] = hashlib.sha256(canonical(payload).encode()).hexdigest()[:24]
        findings.append(payload)
    for persona, entry in sorted(bundle["results"].items()):
        placement = placement_index(entry["scopes"])
        membership, scope_by_id, names, _ = placement
        for module, data in sorted(entry["modules"].items()):
            if module not in REUSABLE or data.get("device_scope_only"):
                continue
            scopes = data["scope_results"]
            by_scope = {s["scope"]: s for s in scopes}
            effective_signatures = {}
            qualified = [s for s in scopes if s.get("review", {}).get("qualified")]
            groups = defaultdict(list)
            variants = defaultdict(set)
            for scope in qualified:
                for row in scope["review"]["profiles"]:
                    if row["local"] is None or row["status"] in (
                            "default_profile", "source_conflict", "local_effective_mismatch"):
                        continue
                    if module == "layer2-vlan" and persona in PERSONAS and row["identity"] == "1":
                        continue  # Protected default VLAN; inspect separately, never recommend migration.
                    if scope["scope_kind"] == "global":
                        continue
                    if row["effective"] is None or canonical(row["local"]) != canonical(row["effective"]):
                        continue
                    identity = row["identity"]
                    sig = canonical(row["local"])
                    groups[identity, sig].append((scope, row))
                    variants[identity].add(sig)
            lib_view = library_modules.get(module, {})
            lib_profiles = lib_view.get("profiles", {}) if lib_view.get("status") == "list_parsed" else {}
            def effective_signature(sid, identity, evidence):
                key = (sid, identity)
                if key not in effective_signatures:
                    effective_signatures[key] = canonical(profile_body(evidence["profiles"][identity]))
                return effective_signatures[key]
            for (identity, signature), members in sorted(groups.items()):
                local = members[0][1]["local"]
                sources = [{"scope": s["scope"], "kind": s["scope_kind"],
                            "name": names.get(s["scope"], s["scope"]), "status": row["status"]}
                           for s, row in members]
                observed = {"matching": [], "different": [], "absent": [], "unknown": []}
                for device in (s for s in entry["scopes"] if s["kind"] == "device"):
                    sid = device["id"]
                    evidence = by_scope.get(sid, {}).get("effective_view", {})
                    if evidence.get("status") != "list_parsed":
                        state = "unknown"
                    elif identity not in evidence["profiles"]:
                        state = "absent" if evidence.get("count_confirmed") is True else "unknown"
                    elif effective_signature(sid, identity, evidence) == signature:
                        state = "matching"
                    else:
                        state = "different"
                    observed[state].append({"scope": sid, "name": names[sid]})
                scope_references = []
                for scope in entry["scopes"]:
                    if scope["kind"] == "device":
                        continue
                    evidence = by_scope.get(scope["id"], {}).get("effective_view", {})
                    if evidence.get("status") != "list_parsed":
                        state = "unknown"
                    elif identity not in evidence["profiles"]:
                        state = "absent" if evidence.get("count_confirmed") is True else "unknown"
                    elif effective_signature(scope["id"], identity, evidence) == signature:
                        state = "matching"
                    else:
                        state = "different"
                    scope_references.append({"scope": scope["id"], "kind": scope["kind"],
                                             "name": names[scope["id"]], "effective": state})
                global_ref = members[0][1].get("global_reference")
                exact_global = all(row["status"] == "local_matches_global" and
                                   row.get("global_reference") is not None and
                                   canonical(row["global_reference"]) == signature for _, row in members)
                lib_ref = profile_body(lib_profiles[identity]) if identity in lib_profiles else None
                exact_lib = lib_ref is not None and canonical(lib_ref) == signature
                conflicts = []
                if len(variants[identity]) > 1:
                    conflicts.append("Different local bodies exist for this identity.")
                if lib_ref is not None and not exact_lib:
                    conflicts.append("Existing Library identity has a different body.")
                if global_ref is not None and canonical(global_ref) != signature:
                    conflicts.append("Global identity has a different body.")
                if observed["unknown"]:
                    conflicts.append("Some device effective views are unqualified.")
                if any(s["effective"] == "unknown" for s in scope_references):
                    conflicts.append("Some higher-scope effective views are unqualified.")
                if any(s["effective"] == "different" for s in scope_references if s["kind"] != "global"):
                    conflicts.append("At least one intermediate scope has a different effective body; membership and precedence must be resolved.")
                if lib_view.get("status") != "list_parsed":
                    conflicts.append("Library inventory for this module is unqualified; an existing profile may be present.")
                if observed["different"] or observed["absent"]:
                    conflicts.append("Broader placement may change devices with a different or absent profile.")
                from .inheritance_review import nearest_fallback
                fallbacks = []
                for scope, row in members:
                    if scope["scope_kind"] == "device":
                        fallback = nearest_fallback(entry, module, scope["scope"], identity,
                                                   row["local"], row["effective"], row.get("annotations", {}),
                                                   index=(membership, scope_by_id, by_scope))
                    else:
                        fallback = {"status": "unresolved", "source": None, "blockers": [
                            "Higher-scope removal must be checked for every affected descendant device."],
                            "safe_to_apply": False}
                    fallbacks.append({"scope": scope["scope"], "name": names.get(scope["scope"], scope["scope"]), **fallback})
                exact_nearest = bool(fallbacks) and all(f["status"] == "matching_fallback" for f in fallbacks)
                atomic_match = bool(fallbacks) and all(f["status"] in ("matching_fallback", "matching_settings_identity_changed") for f in fallbacks)
                if exact_global or exact_nearest or atomic_match:
                    action = "remove_override"
                    if exact_nearest:
                        target, ref = "Nearest observed inherited definitions", local
                    elif atomic_match:
                        target, ref = "Review matching nearest settings; profile identity changes", None
                        conflicts.append("Atomic profile identity would change; removal preview is blocked until references and assignments are verified.")
                    elif any(f["status"] == "different_fallback" for f in fallbacks):
                        target, ref = "Retain: nearer scope differs", global_ref
                        conflicts.append("At least one device would inherit a different observed definition; removal preview is blocked.")
                    else:
                        target, ref = "Review Global match; fallback unverified", global_ref
                        conflicts.append("Nearest inherited definition is not established for every source; removal preview is blocked.")
                    steps = ("Review the observed fallback for each source and unresolved membership.",
                             "Confirm effective body and dependencies would remain unchanged.",
                             "Only preview removal after all source fallbacks match; validate each device.")
                elif exact_lib:
                    action, target, ref = "reuse_library", "Existing Library profile; exact source scopes", lib_ref
                    steps = ("Verify existing assignment state and compatibility.",
                             "Preview assignment of the matching Library profile at intended scopes.",
                             "Verify assignment behavior and remove redundant locals only when safe.")
                elif len({s["scope"] for s in sources}) > 1:
                    action, target, ref = "promote_local", "Common supported Site / Group scope, or Library", None
                    steps = ("Resolve membership and lowest common scope for intended recipients.",
                             "Preview creating the identical profile at that scope, or create and assign a Library profile.",
                             "Verify target and affected devices before removing redundant local definitions.")
                elif module == "layer2-vlan" and global_ref is not None and (
                        assess_vlan_reference(local, global_ref)["classification"] in
                        ("documented_defaults_only", "requires_validation")):
                    action, target, ref = "default_review", "Global reference (not equivalent yet)", global_ref
                    steps = ("Inspect omitted fields, SVI state and firmware-specific defaults.",
                             "Keep local configuration until operational equivalence is established.")
                elif conflicts and (len(variants[identity]) > 1 or lib_ref is not None or global_ref is not None):
                    action, target, ref = "conflict", "Retain / select approved canonical definition", global_ref if global_ref is not None else lib_ref
                    steps = ("Review intentional exceptions and all competing definitions.",
                             "Choose a desired configuration explicitly; do not automatically overwrite or delete.")
                else:
                    action, target, ref = "create_library", "Library, assigned only where intended", None
                    steps = ("Determine whether this profile is genuinely reusable.",
                             "If approved, create a Library profile and preview exact assignments.",
                             "Verify effective configuration before removing any local definition.")
                    conflicts.append("A unique local profile may be intentional; no reuse is proven.")
                placements = placement_evidence(entry["scopes"], sources, observed, scope_references, index=placement)
                blocked_destinations = []
                if action == "promote_local":
                    all_details = (bundle.get("keyed_profile_details") or {}).get("profiles", {})
                    def destination_conflicts(function, sid, views):
                        result = []
                        for kind, view in views:
                            evidence = all_details.get(function, {}).get(str(sid), {}).get(module, {}).get(identity, {}).get(kind, {})
                            body = evidence.get("profile")
                            if evidence.get("status") != "identity_observed" or not isinstance(body, dict) or view.get("status") != "list_parsed":
                                continue
                            stored = view.get("profiles", {}).get(identity)
                            if isinstance(stored, dict):
                                differences = field_differences(profile_body(stored), profile_body(body))
                            elif view.get("count_confirmed") is True:
                                differences = field_differences({}, profile_body(body))
                                if not differences:
                                    differences = [{"path": [], "kind": "missing_local", "local_type": "missing",
                                                    "reference_type": "dict", "reference_value": profile_body(body)}]
                            else:
                                continue
                            if differences:
                                result.append({"persona": function, "scope": sid, "identity": identity, "view": kind,
                                               "differences": differences, "collection_presence": "present" if stored is not None else "count_confirmed_absent"})
                        return result
                    def existing_definition_conflicts(function, sid, kind, view):
                        # A consolidation preview is not an overwrite request.
                        # Only a positive existing committed/Library definition
                        # qualifies as an overwrite collision. Effective inherited
                        # settings alone do not establish a committed definition.
                        if view.get("status") != "list_parsed":
                            return []
                        from .inheritance_review import ATOMIC
                        collisions = []
                        for name, stored in view.get("profiles", {}).items():
                            if name != identity and (module not in ATOMIC or kind == "library"):
                                continue
                            if not isinstance(stored, dict):
                                continue
                            existing = profile_body(stored)
                            if name != identity or canonical(existing) != signature:
                                collisions.append({"persona": function, "scope": sid, "view": kind,
                                                   "existing_identity": name, "proposed_identity": identity,
                                                   "differences": field_differences(existing, local)})
                        return collisions
                    eligible = []
                    for option in placements:
                        sid = option["scope"]
                        row = by_scope.get(sid, {})
                        discrepancies = destination_conflicts(persona, sid, [(k, row.get(k + "_view", {})) for k in ("local", "effective")])
                        collisions = existing_definition_conflicts(persona, sid, "local", row.get("local_view", {}))
                        if discrepancies or collisions:
                            blocked_destinations.append({"destination": sid, "name": option["name"], "kind": option["kind"],
                                                         "individual_conflicts": discrepancies, "existing_definition_conflicts": collisions})
                        else:
                            eligible.append(option)
                    placements = eligible
                    discrepancies = destination_conflicts("Library", "", [("library", lib_view)])
                    collisions = existing_definition_conflicts("Library", "", "library", lib_view)
                    if discrepancies or collisions:
                        blocked_destinations.append({"destination": "library", "name": "Library", "kind": "library",
                                                     "individual_conflicts": discrepancies, "existing_definition_conflicts": collisions})
                    if any(d["individual_conflicts"] for d in blocked_destinations):
                        conflicts.append("Some promotion destinations have contradictory individual configuration evidence and are excluded from review selection.")
                    if any(d.get("existing_definition_conflicts") for d in blocked_destinations):
                        conflicts.append("Some destinations contain an existing different committed definition; consolidation must not overwrite it.")
                    exact = next((p for p in placements if p["membership_status"] == "exact_observed_recipient_set"
                                  and p["effective"] in ("matching", "absent")), None)
                    library_blocked = any(d["destination"] == "library" for d in blocked_destinations)
                    if exact:
                        target = f"Review {exact['kind']} / {exact['name']}" + ("" if library_blocked else "; or Library")
                    elif library_blocked:
                        target = "Review remaining scoped destinations" if placements else "Retain: conflicting destination evidence"
                        conflicts.append("Library destination is blocked; review only remaining available choices.")
                    else:
                        conflicts.append("No common higher scope with exactly the intended observed device set is established; review exact-scope Library assignments instead.")
                individual_conflicts = []
                if action in ("promote_local", "reuse_library"):
                    # A contradiction in the actual source body (or retained
                    # Library definition) must not enter the review export.
                    # Sampled/absent individual reads are not contradictions.
                    all_details = (bundle.get("keyed_profile_details") or {}).get("profiles", {})
                    checks = [(persona, scope["scope"], kind, row[kind])
                              for scope, row in members for kind in ("local", "effective")]
                    if action == "reuse_library":
                        checks.append(("Library", "", "library", lib_ref))
                    for function, sid, kind, expected in checks:
                        evidence = all_details.get(function, {}).get(str(sid), {}).get(module, {}).get(identity, {}).get(kind, {})
                        body = evidence.get("profile")
                        if (evidence.get("status") == "identity_observed" and isinstance(body, dict)
                                and isinstance(expected, dict) and canonical(profile_body(body)) != canonical(expected)):
                            individual_conflicts.append({"persona": function, "scope": sid, "identity": identity,
                                                         "view": kind, "differences": field_differences(expected, profile_body(body))})
                    if individual_conflicts:
                        conflicts.append("Direct individual configuration differs from source or retained Library collection evidence; preview is blocked.")
                        target = "Retain: conflicting individual configuration evidence"
                if action == "remove_override":
                    # Do not offer a removal preview when a direct individual
                    # read contradicts the collection evidence used to qualify
                    # the fallback. Absence of detail is not a contradiction.
                    details = (bundle.get("keyed_profile_details") or {}).get("profiles", {}).get(persona, {})
                    for (scope, row), fallback in zip(members, fallbacks):
                        checks = [(scope["scope"], identity, "local", row["local"]),
                                  (scope["scope"], identity, "effective", row["effective"])]
                        source = fallback.get("source")
                        if source:
                            checks.append((source["scope"], source["identity"], "effective", source["body"]))
                        discrepancies = []
                        for sid, profile_id, kind, expected in checks:
                            evidence = details.get(str(sid), {}).get(module, {}).get(profile_id, {}).get(kind, {})
                            body = evidence.get("profile")
                            if (evidence.get("status") == "identity_observed" and isinstance(body, dict)
                                    and isinstance(expected, dict) and canonical(profile_body(body)) != canonical(expected)):
                                discrepancies.append({"scope": sid, "identity": profile_id, "view": kind,
                                                      "differences": field_differences(expected, profile_body(body))})
                        if discrepancies:
                            fallback["individual_conflicts"] = discrepancies
                            fallback["status"] = "individual_evidence_conflict"
                            fallback.setdefault("blockers", []).append(
                                "Direct individual configuration differs from the collection evidence.")
                    if any(f.get("individual_conflicts") for f in fallbacks):
                        conflicts.append("Individual profile evidence contradicts the configuration comparison; removal preview is blocked.")
                        target = "Retain: conflicting individual configuration evidence"
                add(action, persona, module, identity, sources, local, target, ref, observed, conflicts, steps, scope_references, placements, fallbacks if action == "remove_override" else (),
                    individual_conflicts=individual_conflicts, blocked_destinations=blocked_destinations)
    for module, view in sorted(library_modules.items()):
        if (library.get("assignments") or {}).get("status") != "response_received":
            continue
        if module not in REUSABLE or view.get("status") != "list_parsed":
            continue
        for identity, raw in sorted(view["profiles"].items()):
            if (module == "layer2-vlan" and identity == "1") or (isinstance(raw.get("@"), dict) and raw["@"].get("aruba-annotation:is_default") is True):
                continue
            if (module, identity) not in assigned:
                add("unassigned_library", "Library", module, identity, [], None,
                    "Review assignments and references; retain until verified", profile_body(raw),
                    blockers=("No matching assignment was observed; assignment completeness and reverse references are unverified.",),
                    steps=("Check all assignments, direct references and future provisioning requirements.",
                           "Retain the profile unless absence of dependencies and use is independently established."))
    rank = {"remove_override": 0, "reuse_library": 1, "promote_local": 2,
            "default_review": 3, "conflict": 4, "create_library": 5, "unassigned_library": 6}
    return sorted(findings, key=lambda f: (rank[f["action"]], f["persona"], f["module"], f["identity"], f["id"]))
