"""Build offline optimization worklists without inventing a safety or risk score."""
import hashlib
from .central_tool import canonical
from .bulk_review import source_recipient_evidence, source_recipient_index


def engineering_group_id(workflow, record):
    if workflow == "duplicates":
        identity = [record["module"], sorted(record["identities"])]
    elif workflow == "ports":
        identity = [record["persona"], sorted((p["scope"], p["port"]) for p in record["ports"])]
    else:
        raise ValueError("Unknown engineering workflow")
    return hashlib.sha256(canonical([workflow, identity]).encode()).hexdigest()[:24]


def optimization_worklist(bundle, findings, engineering):
    rows = []
    indexes = {}
    for f in findings:
        action = f["action"]
        if action not in ("remove_override", "promote_local", "reuse_library"):
            continue
        persona = f["persona"]
        entry = bundle["results"][persona]
        if persona not in indexes:
            indexes[persona] = source_recipient_index(entry)
        recipients = source_recipient_evidence(entry, f["sources"], index=indexes[persona])
        rows.append({"category": action, "module": f["module"], "persona": persona,
                     "profile": f["identity"], "instances": len(f["sources"]), "unit": "local copies",
                     "known": len(recipients["known"]), "unknown": len(recipients["unknown"]),
                     "next_step": ("Evidence blocks preview" if not f["preview_selectable"] else
                                   "Choose destination and review" if action == "promote_local" else "Inspect change preview"),
                     "route": "advisor", "params": {"finding": action, "group": f["id"]}})
    for g in engineering["library_duplicates"]:
        devices = {(d["persona"], d["scope"]) for u in g["usage"].values() for d in u["shared_devices"]}
        unknown = {(d["persona"], d["scope"]) for u in g["usage"].values() for d in u["unknown_devices"]}
        rows.append({"category": "duplicates", "module": g["module"], "persona": "Library",
                     "profile": ", ".join(g["identities"]), "instances": len(g["identities"]), "unit": "Library names",
                     "known": len(devices), "unknown": len(unknown),
                     "next_step": "Choose retained name and review references",
                     "route": "advanced", "params": {"workflow": "duplicates", "group": engineering_group_id("duplicates", g)}})
    for g in engineering["port_groups"]:
        devices = {p["scope"] for p in g["ports"]}
        rows.append({"category": "ports", "module": "ethernet-interfaces", "persona": g["persona"],
                     "profile": "Repeated switchport settings", "instances": len(g["ports"]), "unit": "ports",
                     "known": len(devices), "unknown": None,
                     "next_step": "Review saved settings and profile mapping",
                     "route": "advanced", "params": {"workflow": "ports", "group": engineering_group_id("ports", g)}})
    return sorted(rows, key=lambda r: (r["category"], -r["instances"], -r["known"], r["persona"], r["module"], r["profile"]))
