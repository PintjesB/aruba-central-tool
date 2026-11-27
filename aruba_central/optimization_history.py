"""Compare observed optimization workload across two saved captures."""
from collections import Counter
from .configuration_history import snapshot_identity_checks
from .consolidation import profile_recommendations
from .advanced_review import advanced_analysis
from .workspace_ui import e, page, intro, table, tr, metrics
from .workspace_views import load, select, url


def workload(bundle, *, findings=None, engineering=None):
    findings = profile_recommendations(bundle) if findings is None else findings
    engineering = advanced_analysis(bundle) if engineering is None else engineering
    categories = Counter(f["action"] for f in findings)
    views = {}
    for persona, entry in bundle["results"].items():
        for module, data in entry["modules"].items():
            for row in data["scope_results"]:
                for side in ("local_view", "effective_view"):
                    read = row.get(side, {})
                    views[(persona, module, row["scope"], side)] = (read.get("status"), read.get("count_confirmed") is True)
    devices = {(persona, s["id"]) for persona, entry in bundle["results"].items() for s in entry["scopes"] if s["kind"] == "device"}
    return {"counts": {"remove_override": categories["remove_override"], "promote_local": categories["promote_local"],
                       "reuse_library": categories["reuse_library"], "duplicates": len(engineering["library_duplicates"]),
                       "ports": len(engineering["port_groups"]),
                       "preview_candidates": sum(f["action"] in ("remove_override", "promote_local", "reuse_library") and f["preview_selectable"] for f in findings)},
            "views": views, "devices": devices,
            "mixed_time": bool((bundle.get("collection_checkpoint") or {}).get("mixed_capture_times"))}


def compare_workload(previous, current, *, current_findings=None, current_engineering=None):
    identity = snapshot_identity_checks(previous, current)
    before = workload(previous)
    after = workload(current, findings=current_findings, engineering=current_engineering)
    common = before["views"].keys() & after["views"].keys()
    same_reads = before["views"] == after["views"]
    same_devices = before["devices"] == after["devices"]
    return {"identity": identity, "before": before["counts"], "after": after["counts"],
            "before_devices": len(before["devices"]), "after_devices": len(after["devices"]),
            "before_views": len(before["views"]), "after_views": len(after["views"]),
            "common_views": len(common), "same_structured_read_states": same_reads,
            "same_device_selectors": same_devices, "mixed_time": before["mixed_time"] or after["mixed_time"],
            "verified_removals": False}


def history_view(workspace, query):
    from .config_app import audit_files, read_audit
    from .central_tool import refresh_configuration_review
    loaded, empty = load(workspace, query, "Configuration assessment", "assessment")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    others = [(p.name, p.name) for p in audit_files(workspace.directory) if p.name != name]
    previous = query.get("previous", "")
    confirmed = query.get("confirmed") == "yes"
    body = intro("Optimization workload history", "Compare observed review workloads between two captures, not verified configuration removals.", picker)
    body += f'<p><a href="{url(root, "assessment", snapshot=name)}">Return to optimization worklist</a></p>'
    body += (f'<section><form method="get" class="filter-bar" action="{e(root + "assessment")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="mode" value="history">'
             + select("previous", [("", "Select baseline snapshot")] + others, previous, "Baseline")
             + '<label><input type="checkbox" name="confirmed" value="yes" required> Confirm same tenant</label>'
             + '<button type="submit">Compare workloads</button></form></section>')
    if previous and confirmed:
        if previous not in dict(others):
            raise ValueError("Invalid baseline")
        prior = refresh_configuration_review(read_audit(workspace.directory, previous))
        result = compare_workload(prior, bundle, current_findings=workspace.consolidation_snapshot(bundle),
                                  current_engineering=workspace.advanced_snapshot(bundle))
        body += metrics([("Baseline devices", result["before_devices"], "Device/function pairs"),
                         ("Current devices", result["after_devices"], "Device/function pairs"),
                         ("Common structured views", result["common_views"], "Same capture selectors")])
        body += '<section><h2>Comparability checks</h2>' + table(("Check", "Result"), [
            tr("Device selectors", "Same" if result["same_device_selectors"] else "Changed"),
            tr("Structured view selectors and read states", "Same" if result["same_structured_read_states"] else "Changed"),
            tr("Mixed-time checkpoint evidence", "Present" if result["mixed_time"] else "Not indicated")]) + '</section>'
        labels = {"remove_override": "Override review groups", "promote_local": "Repeated local profile groups",
                  "reuse_library": "Library reuse groups", "duplicates": "Duplicate Library groups",
                  "ports": "Repeated port groups", "preview_candidates": "Selectable consolidation previews"}
        rows = []
        for key, label in labels.items():
            old, new = result["before"][key], result["after"][key]
            rows.append(tr(e(label), str(old), str(new), f'{new-old:+d}'))
        body += '<section><h2>Observed workload change</h2>' + table(("Review category", "Baseline", "Current", "Count change"), rows) + '</section>'
        body += '<p class="note">A lower workload count does not establish successful remediation. Group boundaries, inventory, evidence availability and analysis logic can affect counts. Use Configuration drift and Remediation verification for exact changes. Same structured read states do not establish complete evidence equivalence.</p>'
        body += f'<p><a href="{url(root, "drift", snapshot=name, previous=previous, confirmed="yes")}">Review exact configuration drift</a></p>'
    return page("Configuration assessment", body, workspace.nav(name))
