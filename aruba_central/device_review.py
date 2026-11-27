"""Device-specific review hub for captured configuration and evidence."""
from collections import Counter
from .consolidation import scope_memberships
from .workspace_ui import e, page, intro, table, tr, metrics, module_label, persona_label, property_table
from .workspace_views import load, url
from .override_view import device_override_rows


def device_review(bundle, persona, device):
    entry = bundle["results"][persona]
    scopes = {s["id"]: s for s in entry["scopes"]}
    if device not in scopes or scopes[device]["kind"] != "device":
        raise ValueError("Unknown device")
    membership = scope_memberships(entry["scopes"])[device]
    overrides, incomplete = device_override_rows(bundle, persona, device=device)
    by_module = {}
    for finding in overrides:
        counts = by_module.setdefault(finding["module"], Counter())
        counts["local_review"] += 1
        if finding["review_candidate"]:
            counts[finding["removal"]] += 1
    modules = []
    for module, data in sorted(entry["modules"].items()):
        view = next((v for v in data["scope_results"] if v["scope"] == device), {})
        review = view.get("review", {})
        counts = Counter(p["status"] for p in review.get("profiles", [])) if review.get("qualified") else Counter()
        modules.append({"module": module, "local": view.get("local_view", {}).get("status", "not_collected"),
                        "effective": view.get("effective_view", {}).get("status", "not_collected"),
                        "qualified": bool(review.get("qualified")), "device_only": bool(data.get("device_scope_only")),
                        "profiles": sum(counts.values()), "states": dict(counts), "override_counts": dict(by_module.get(module, {}))})
    # Unfiltered requests describe the scope without selecting a device
    # function. Show those independently from typed observations.
    supplemental = []
    for module, data in sorted((bundle.get("unadapted_profiles") or {}).items()):
        for source in data.get("source_views", []):
            if str(source.get("scope")) != str(device) or source.get("persona") not in (persona, "UNFILTERED_SCOPE", "ALL_DEVICE_FUNCTIONS"):
                continue
            views = [source.get(side, {}) for side in ("committed", "effective")]
            supplemental.append({"module": module, "selector": source["persona"],
                                 "committed": views[0].get("status", "not_collected"),
                                 "effective": views[1].get("status", "not_collected"),
                                 "count_confirmed": sum(v.get("collection_count_verified") is True for v in views)})
    return {"device": scopes[device], "membership": {kind: scopes.get(sid) for kind, sid in membership.items()},
            "modules": modules, "supplemental": supplemental, "incomplete": len(incomplete), "safe_to_apply": False}


def device_view(workspace, query):
    loaded, empty = load(workspace, query, "Scopes", "scopes")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    persona, device = query["persona"], query["device"]
    report = device_review(bundle, persona, device)
    label = report["device"].get("name") or device
    params = {"snapshot": name, "persona": persona}
    modules = report["modules"]
    count = Counter()
    for row in modules:
        count.update(row["override_counts"])
    body = intro(label, persona_label(persona) + " · Captured device configuration review", picker)
    body += f'<p><a href="{url(root, "scopes", snapshot=name)}">Back to inventory</a></p>'
    body += metrics([("Qualified modules", f'{sum(r["qualified"] for r in modules)}/{len(modules)}', "Captured structured configuration"),
                     ("Matching fallback candidates", count["review_removal"], "Review only; not proven safe"),
                     ("Needs validation", count["verification_required"], "Removal candidates with evidence gaps"),
                     ("Higher-scope differences", count["higher_scope_differs"], "Potential removal changes")])
    body += '<section><h2>Device review actions</h2><div class="filter-bar">' + " ".join(
        f'<a class="button" href="{url(root, route, **params, **extra)}">{e(title)}</a>'
        for title, route, extra in (
            ("All captured configuration", "report", {"scope": device, "view": "all"}),
            ("Review local overrides", "overrides", {"device": device}),
            ("Incomplete evidence", "report", {"scope": device, "view": "diagnostics"}),
            ("Compare with another device", "compare", {"left": device}))) + '</div></section>'
    body += '<section><h2>Observed scope membership</h2>' + table(("Scope type", "Scope", ""), [
        tr(e(kind.title()), e((scope.get("name") or scope["id"]) if scope else "Not established"),
           f'<a href="{url(root, "report", **params, scope=scope["id"], view="all")}">Inspect configuration</a>' if scope else "")
        for kind, scope in report["membership"].items()]) + '</section>'
    rows = []
    for row in modules:
        module = row["module"]
        c = row["override_counts"]
        actions = f'<a href="{url(root, "report", **params, scope=device, module=module, view="all")}">Configuration</a>'
        if not row["device_only"]:
            actions += f' · <a href="{url(root, "overrides", **params, device=device, module=module, result="all")}">Overrides</a>'
        rows.append(tr(e(module_label(module)), e(row["local"]), e(row["effective"]),
                       "Qualified" if row["qualified"] else "Unqualified", str(row["profiles"]) if row["qualified"] else "Unknown",
                       str(c.get("local_review", 0)) if not row["device_only"] and row["qualified"] else "Not assessed",
                       str(c.get("review_removal", 0)) if not row["device_only"] and row["qualified"] else "Not assessed",
                       str(c.get("verification_required", 0)) if not row["device_only"] and row["qualified"] else "Not assessed",
                       actions))
    body += '<section><h2>Configuration by module</h2>' + table(("Module", "Saved read", "Effective read", "Comparison", "Profiles", "Local review", "Matching fallback", "Needs validation", ""), rows, search=True) + '</section>'
    supplemental = report["supplemental"]
    if supplemental:
        body += '<section><h2>Supplemental configuration evidence</h2><p>Additional raw observations at this exact device scope. Unfiltered reads do not establish device-function applicability.</p>'
        body += table(("Module", "Request selector", "Committed read", "Effective read", "Count-confirmed reads", ""), [
            tr(e(module_label(row["module"])), e(persona_label(row["selector"])), e(row["committed"]), e(row["effective"]),
               str(row["count_confirmed"]) + "/2",
               f'<a href="{url(root, "report", snapshot=name, mode="search", persona=row["selector"], module=row["module"], scope=device, q=device)}">Search captured settings</a>')
            for row in supplemental], search=True) + '</section>'
    body += '<p class="note">Structured module counts only. Unknown membership and unqualified reads are not evidence of absence. Device-only modules are not assessed for reusable profile cleanup. No live changes.</p>'
    body += '<details><summary>Captured device inventory metadata</summary>' + property_table(report["device"].get("metadata") or {}) + '</details>'
    return page("Scopes", body, workspace.nav(name))
