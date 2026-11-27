"""Device-specific review hub for captured configuration and evidence."""
from collections import Counter
from .consolidation import scope_memberships
from .workspace_ui import e, page, intro, table, tr, metrics, module_label, persona_label, property_table, status, badge
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
    from .keyed_evidence_view import keyed_observations
    keyed = []
    # Enumerate only the selected device and explicitly known request selectors.
    evidence = (bundle.get("keyed_profile_details") or {}).get("profiles", {})
    subset = {p: {str(device): evidence[p][str(device)]}
              for p in (persona, "ALL_DEVICE_FUNCTIONS", "UNFILTERED_SCOPE")
              if str(device) in evidence.get(p, {})}
    counts = {}
    for row in keyed_observations({"keyed_profile_details": {"profiles": subset}}):
        counts.setdefault(row["persona"], Counter())[row["category"]] += 1
    for selector, count in sorted(counts.items()):
        keyed.append({"selector": selector, "counts": dict(count)})
    return {"device": scopes[device], "membership": {kind: scopes.get(sid) for kind, sid in membership.items()},
            "modules": modules, "supplemental": supplemental, "keyed": keyed, "incomplete": len(incomplete), "safe_to_apply": False}


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
    missing_modules = sum(not row["qualified"] for row in modules)
    body += metrics([("Qualified modules", f'{sum(r["qualified"] for r in modules)}/{len(modules)}', "Captured structured configuration"),
                     ("Matching fallback candidates", count["review_removal"], "Review only; not proven safe"),
                     ("Needs validation", count["verification_required"], "Removal candidates with evidence gaps"),
                     ("Higher-scope differences", count["higher_scope_differs"], "Potential removal changes")])
    body += '<section><h2>Device review actions</h2>'
    if missing_modules:
        body += '<div class="review-decision"><div><strong>' + e(missing_modules) + ' structured modules need evidence review</strong><p>Saved or effective settings could not be fully compared. This is not a device fault or proof of missing configuration.</p></div>'
        body += f'<a class="button" href="{url(root, "report", **params, scope=device, view="diagnostics")}">Review incomplete evidence</a></div>'
    body += '<div class="filter-bar">' + " ".join(
        f'<a class="button" href="{url(root, route, **params, **extra)}">{e(title)}</a>'
        for title, route, extra in (
            ("Structured configuration", "report", {"scope": device, "view": "all"}),
            ("Review local overrides", "overrides", {"device": device}),
            ("Incomplete evidence", "report", {"scope": device, "view": "diagnostics"}),
            ("Compare with another device", "compare", {"left": device}))) + '</div></section>'
    body += '<section><h2>Observed scope membership</h2>' + table(("Scope type", "Scope", ""), [
        tr(e(kind.title()), e((scope.get("name") or scope["id"]) if scope else "Not established"),
           f'<a href="{url(root, "report", **params, scope=scope["id"], view="all")}">Inspect configuration</a>' if scope else "")
        for kind, scope in report["membership"].items()]) + '</section>'
    rows = []
    for row in sorted(modules, key=lambda row: (row["qualified"], row["module"])):
        module = row["module"]
        c = row["override_counts"]
        actions = f'<a href="{url(root, "report", **params, scope=device, module=module, view="all")}">Configuration</a>'
        if not row["qualified"]:
            actions += f' · <a href="{url(root, "report", **params, scope=device, module=module, view="diagnostics")}">Evidence gap</a>'
        if not row["device_only"]:
            actions += f' · <a href="{url(root, "overrides", **params, device=device, module=module, result="all")}">Overrides</a>'
        if row["qualified"] and not row["device_only"]:
            local_review = str(c.get("local_review", 0))
            cleanup = (f'<strong>{c.get("review_removal", 0)}</strong> matching fallback'
                       f'<small>{c.get("verification_required", 0)} need validation · {c.get("higher_scope_differs", 0)} higher-scope differences</small>')
        else:
            local_review = "Not assessed"
            cleanup = '<span class="muted">Not assessed</span>'
        reads = '<div class="device-read-pair"><small>Saved</small>' + status(row["local"]) + '<small>Effective</small>' + status(row["effective"]) + '</div>'
        comparison = badge("Comparable" if row["qualified"] else "Evidence gap", "good" if row["qualified"] else "warn")
        rows.append(tr(f'<strong>{e(module_label(module))}</strong><small>{e(module)}</small>', reads,
                       comparison, str(row["profiles"]) if row["qualified"] else "Unknown",
                       local_review, cleanup, actions))
    body += '<section><h2>Configuration by module</h2>' + table(("Module", "Collection evidence", "Comparison", "Profiles", "Local definitions", "Removal review", "Actions"), rows, search=True) + '</section>'
    supplemental = report["supplemental"]
    if supplemental:
        body += '<section><h2>Supplemental configuration evidence</h2><p>Additional raw observations at this exact device scope. Unfiltered reads do not establish device-function applicability.</p>'
        body += table(("Module", "Request selector", "Committed read", "Effective read", "Count-confirmed reads", ""), [
            tr(e(module_label(row["module"])), e(persona_label(row["selector"])), status(row["committed"]), status(row["effective"]),
               str(row["count_confirmed"]) + "/2",
               f'<a href="{url(root, "unadapted", snapshot=name, persona=row["selector"], module=row["module"], scope=device)}">Inspect complete response</a> · '
               f'<a href="{url(root, "report", snapshot=name, mode="search", persona=row["selector"], module=row["module"], scope=device, q=device)}">Search captured settings</a>')
            for row in supplemental], search=True) + '</section>'
    if report["keyed"]:
        body += '<section><h2>Individual profile evidence</h2><p>Individual reads and collection-only markers are separate. Review discrepancies in the exact device scope and request selector.</p>'
        rows = []
        for row in report["keyed"]:
            c = row["counts"]
            selector = row["selector"]
            links = f'<a href="{url(root, "assessment", snapshot=name, mode="keyed", persona=selector, scope=device)}">Review discrepancies</a>'
            links += f' · <a href="{url(root, "assessment", snapshot=name, mode="keyed", persona=selector, scope=device, category="all")}">All observations</a>'
            rows.append(tr(e(persona_label(selector)), str(c.get("unqualified", 0)), str(c.get("different", 0) + c.get("order_only", 0)),
                           str(c.get("not_compared", 0)), str(c.get("identical", 0)), str(c.get("sampled", 0)), links))
        body += table(("Request selector", "Unqualified", "Different", "Not compared", "Exact matches", "Collection-only", ""), rows) + '</section>'
    body += '<p class="note">Structured module counts only. Unknown membership and unqualified reads are not evidence of absence. Device-only modules are not assessed for reusable profile cleanup. No live changes.</p>'
    body += '<details><summary>Captured device inventory metadata</summary>' + property_table(report["device"].get("metadata") or {}) + '</details>'
    return page("Scopes", body, workspace.nav(name), extra_css=DEVICE_CSS)


DEVICE_CSS = """
.device-read-pair { display:grid; grid-template-columns:auto minmax(0,1fr); align-items:center; gap:5px 8px; }
.device-read-pair small { color:var(--muted); margin:0; }
.device-read-pair .tag { justify-self:start; white-space:normal; }
"""
