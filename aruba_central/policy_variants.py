"""Group same-identity effective configuration variants without inferring intent."""
from collections import defaultdict
from .central_tool import canonical, field_differences, profile_body
from .configuration_history import STANDARD_MODULES
from .consolidation import scope_memberships
from .standard_evidence import conflicting_profiles


def policy_variants(bundle):
    findings = []
    for persona, entry in sorted(bundle["results"].items()):
        devices = {s["id"]: s.get("name") or s["id"] for s in entry["scopes"] if s["kind"] == "device"}
        memberships = scope_memberships(entry["scopes"])
        names = {s["id"]:s.get("name") or s["id"] for s in entry["scopes"]}
        for module, data in sorted(entry["modules"].items()):
            if module not in STANDARD_MODULES or data.get("device_scope_only"):
                continue
            views = {s["scope"]: s.get("effective_view", {}) for s in data["scope_results"] if s["scope"] in devices}
            identities = defaultdict(dict)
            conflicts = defaultdict(list)
            for sid, view in views.items():
                disputed = conflicting_profiles(bundle,persona,module,sid,view)
                for identity,evidence in disputed.items():
                    conflicts[identity].append({"scope":sid,"name":devices[sid],**evidence})
                if view.get("status") != "list_parsed":
                    continue
                for identity, raw in view["profiles"].items():
                    if not isinstance(raw, dict) or identity in disputed:
                        continue
                    body = profile_body(raw)
                    key = canonical(body)
                    groups = identities[identity]
                    group = groups.setdefault(key, {"body": body, "devices": []})
                    group["devices"].append({"scope": sid, "name": devices[sid], "annotations": raw.get("@")})
            for identity in sorted(identities.keys() | conflicts.keys()):
                groups = identities[identity]
                if len(groups) < 2 and not conflicts[identity]:
                    continue
                variants = sorted(groups.values(), key=lambda g: (-len(g["devices"]), canonical(g["body"])))
                majority = variants[0]["body"] if variants else None
                # Compare membership distributions, without declaring a
                # site/group exception intentional or approving a majority.
                distributions = {}
                for kind in ("site","group","collection"):
                    distribution = defaultdict(set)
                    for index,variant in enumerate(variants):
                        for device in variant["devices"]:
                            distribution[memberships[device["scope"]].get(kind)].add(index+1)
                    distributions[kind] = [{"scope":sid,"name":names.get(sid,sid) if sid is not None else "Membership unknown",
                                            "variant_numbers":sorted(numbers)}
                                           for sid,numbers in sorted(distribution.items(),key=lambda pair:(pair[0] is None,str(pair[0])))]
                explicit = False
                for group in variants:
                    group["differences"] = field_differences(majority, group["body"])
                    group["explicit_difference"] = any(d["kind"] not in ("missing_local", "missing_reference", "null_vs_value") for d in group["differences"])
                    explicit |= group["explicit_difference"]
                absent, unknown = [], []
                present = {d["scope"] for g in variants for d in g["devices"]}
                disputed_scopes = {d["scope"] for d in conflicts[identity]}
                for sid, name in devices.items():
                    if sid in present or sid in disputed_scopes:
                        continue
                    v = views.get(sid, {})
                    item = {"scope": sid, "name": name}
                    if v.get("status") == "list_parsed" and v.get("count_confirmed") is True:
                        absent.append(item)
                    else:
                        unknown.append(item)
                findings.append({"persona": persona, "module": module, "identity": identity, "variants": variants,
                                 "present_count": len(present), "absent": absent, "unknown": unknown,
                                 "individual_conflicts": conflicts[identity], "membership_distribution": distributions,
                                 "status": "explicit_differences" if explicit else "field_evidence_differs" if len(variants)>1 else "individual_evidence_conflict",
                                 "safe_to_apply": False})
    return sorted(findings, key=lambda r: (-r["present_count"], r["persona"], r["module"], r["identity"]))
