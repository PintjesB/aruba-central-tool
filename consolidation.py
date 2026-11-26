"""Conservative, offline consolidation recommendations from captured evidence."""
from collections import defaultdict
import hashlib

from central_tool import canonical, field_differences, profile_body, assess_vlan_reference, PERSONAS

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


def placement_evidence(scopes, sources, observed, references):
    """Preview known and unknown recipients, not a simulated deployment."""
    membership = scope_memberships(scopes)
    scope_by_id = {s["id"]: s for s in scopes}
    def recipients(sid):
        scope = scope_by_id[sid]
        kind = scope["kind"]
        if kind == "device":
            return ({sid}, set()) if sid in membership else (set(), set(membership))
        if kind not in ("global", "site", "group", "collection"):
            return set(), set(membership)
        return ({dev for dev, m in membership.items() if m[kind] == sid},
                {dev for dev, m in membership.items() if m[kind] is None})
    intended, unknown_sources = set(), set()
    for source in sources:
        if source["scope"] not in scope_by_id:
            unknown_sources.update(membership)
            continue
        known, unknown = recipients(source["scope"])
        intended.update(known)
        unknown_sources.update(unknown)
    matching = {d["scope"] for d in observed.get("matching", [])}
    names = {s["id"]: s.get("name") or s["id"] for s in scopes}
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
    def add(action, persona, module, identity, sources, body, target, reference=None,
            observed=None, blockers=(), steps=(), scope_references=(), placement=()):
        payload = {"action": action, "persona": persona, "module": module,
                   "identity": identity, "sources": sources, "local": body,
                   "target": target, "reference": reference,
                   "differences": field_differences(body, reference)
                   if body is not None and reference is not None else None,
                   "observed_devices": observed or {}, "scope_references": list(scope_references),
                   "placement_options": list(placement),
                   "blockers": list(dict.fromkeys([*blockers, *COMMON_BLOCKERS])),
                   "steps": list(steps), "safe_to_apply": False}
        payload["id"] = hashlib.sha256(canonical(payload).encode()).hexdigest()[:24]
        findings.append(payload)
    for persona, entry in sorted(bundle["results"].items()):
        names = {s["id"]: s.get("name") or s["id"] for s in entry["scopes"]}
        for module, data in sorted(entry["modules"].items()):
            if module not in REUSABLE or data.get("device_scope_only"):
                continue
            scopes = data["scope_results"]
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
            for (identity, signature), members in sorted(groups.items()):
                local = members[0][1]["local"]
                sources = [{"scope": s["scope"], "kind": s["scope_kind"],
                            "name": names.get(s["scope"], s["scope"]), "status": row["status"]}
                           for s, row in members]
                observed = {"matching": [], "different": [], "absent": [], "unknown": []}
                by_scope = {s["scope"]: s for s in scopes}
                for device in (s for s in entry["scopes"] if s["kind"] == "device"):
                    sid = device["id"]
                    evidence = by_scope.get(sid, {}).get("effective_view", {})
                    if evidence.get("status") != "list_parsed":
                        state = "unknown"
                    elif identity not in evidence["profiles"]:
                        state = "absent"
                    elif canonical(profile_body(evidence["profiles"][identity])) == signature:
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
                        state = "absent"
                    elif canonical(profile_body(evidence["profiles"][identity])) == signature:
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
                if exact_global:
                    action, target, ref = "remove_override", "Applicable inherited scope (verify)", global_ref
                    steps = ("Resolve nearest inherited profile, including site and group precedence.",
                             "Confirm effective body and dependencies would remain unchanged.",
                             "Preview removal of only the redundant local instances and verify each device.")
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
                placements = placement_evidence(entry["scopes"], sources, observed, scope_references)
                if action == "promote_local":
                    exact = next((p for p in placements if p["membership_status"] == "exact_observed_recipient_set"
                                  and p["effective"] in ("matching", "absent")), None)
                    if exact:
                        target = f"Review {exact['kind']} / {exact['name']}; or Library"
                    else:
                        conflicts.append("No common higher scope with exactly the intended observed device set is established; review exact-scope Library assignments instead.")
                add(action, persona, module, identity, sources, local, target, ref, observed, conflicts, steps, scope_references, placements)
    for module, view in sorted(library_modules.items()):
        if (library.get("assignments") or {}).get("status") != "response_received":
            continue
        if module not in REUSABLE or view.get("status") != "list_parsed":
            continue
        for identity, raw in sorted(view["profiles"].items()):
            if (module == "layer2-vlan" and identity == "1") or (isinstance(raw.get("@"), dict) and raw["@"].get("aruba-annotation:is_default") is True):
                continue
            matches = [a for a in assignments if a.get("profile-type") == module
                       and type(a.get("profile-instance")) in (str, int)
                       and str(a["profile-instance"]) == identity]
            if not matches:
                add("unassigned_library", "Library", module, identity, [], None,
                    "Review assignments and references; retain until verified", profile_body(raw),
                    blockers=("No matching assignment was observed; assignment completeness and reverse references are unverified.",),
                    steps=("Check all assignments, direct references and future provisioning requirements.",
                           "Retain the profile unless absence of dependencies and use is independently established."))
    rank = {"remove_override": 0, "reuse_library": 1, "promote_local": 2,
            "default_review": 3, "conflict": 4, "create_library": 5, "unassigned_library": 6}
    return sorted(findings, key=lambda f: (rank[f["action"]], f["persona"], f["module"], f["identity"], f["id"]))
