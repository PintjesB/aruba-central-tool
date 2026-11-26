"""Conservative, offline consolidation recommendations from captured evidence."""
from collections import defaultdict
import hashlib

from central_tool import canonical, field_differences, profile_body, assess_vlan_reference

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


def profile_recommendations(bundle):
    """Group exact local bodies; never equate observation with usage or safe removal."""
    findings = []
    library = bundle.get("library") or {}
    library_modules = library.get("modules", {})
    assignments = (library.get("assignments") or {}).get("rows", [])
    def add(action, persona, module, identity, sources, body, target, reference=None,
            observed=None, blockers=(), steps=()):
        payload = {"action": action, "persona": persona, "module": module,
                   "identity": identity, "sources": sources, "local": body,
                   "target": target, "reference": reference,
                   "differences": field_differences(body, reference)
                   if body is not None and reference is not None else None,
                   "observed_devices": observed or {},
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
                elif len(sources) > 1 and not (len(variants[identity]) > 1 or lib_ref is not None or global_ref is not None):
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
                add(action, persona, module, identity, sources, local, target, ref, observed, conflicts, steps)
    for module, view in sorted(library_modules.items()):
        if module not in REUSABLE or view.get("status") != "list_parsed":
            continue
        for identity, raw in sorted(view["profiles"].items()):
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
