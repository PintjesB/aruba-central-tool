"""Group same-identity effective configuration variants without inferring intent."""
from collections import defaultdict
from central_tool import canonical, field_differences, profile_body
from configuration_history import STANDARD_MODULES


def policy_variants(bundle):
    findings = []
    for persona, entry in sorted(bundle["results"].items()):
        devices = {s["id"]: s.get("name") or s["id"] for s in entry["scopes"] if s["kind"] == "device"}
        for module, data in sorted(entry["modules"].items()):
            if module not in STANDARD_MODULES or data.get("device_scope_only"):
                continue
            views = {s["scope"]: s.get("effective_view", {}) for s in data["scope_results"] if s["scope"] in devices}
            identities = defaultdict(dict)
            for sid, view in views.items():
                if view.get("status") != "list_parsed":
                    continue
                for identity, raw in view["profiles"].items():
                    if not isinstance(raw, dict):
                        continue
                    body = profile_body(raw)
                    key = canonical(body)
                    groups = identities[identity]
                    group = groups.setdefault(key, {"body": body, "devices": []})
                    group["devices"].append({"scope": sid, "name": devices[sid], "annotations": raw.get("@")})
            for identity, groups in identities.items():
                if len(groups) < 2:
                    continue
                variants = sorted(groups.values(), key=lambda g: (-len(g["devices"]), canonical(g["body"])))
                majority = variants[0]["body"]
                explicit = False
                for group in variants:
                    group["differences"] = field_differences(majority, group["body"])
                    group["explicit_difference"] = any(d["kind"] not in ("missing_local", "missing_reference", "null_vs_value") for d in group["differences"])
                    explicit |= group["explicit_difference"]
                absent, unknown = [], []
                present = {d["scope"] for g in variants for d in g["devices"]}
                for sid, name in devices.items():
                    if sid in present:
                        continue
                    v = views.get(sid, {})
                    item = {"scope": sid, "name": name}
                    if v.get("status") == "list_parsed" and v.get("count_confirmed") is True:
                        absent.append(item)
                    else:
                        unknown.append(item)
                findings.append({"persona": persona, "module": module, "identity": identity, "variants": variants,
                                 "present_count": len(present), "absent": absent, "unknown": unknown,
                                 "status": "explicit_differences" if explicit else "field_evidence_differs",
                                 "safe_to_apply": False})
    return sorted(findings, key=lambda r: (-r["present_count"], r["persona"], r["module"], r["identity"]))
