"""Aggregate captured configuration evidence by site, group and device."""
from collections import Counter, defaultdict
from .consolidation import scope_memberships
from .workspace_ui import e, page, intro, table, tr, metrics, persona_label
from .workspace_views import load, select, url


def configuration_health(bundle, *, persona="", group_by="site", device_ids=None):
    if group_by not in ("site", "group", "collection", "device"):
        raise ValueError("Unknown grouping")
    result = []
    for function, entry in sorted(bundle["results"].items()):
        if persona and persona != function:
            continue
        members = scope_memberships(entry["scopes"])
        scopes = {s["id"]: s for s in entry["scopes"]}
        if device_ids is not None:
            members = {sid: membership for sid, membership in members.items() if sid in device_ids}
        counts = {sid: Counter() for sid in members}
        for module, data in entry["modules"].items():
            views = {row["scope"]: row for row in data["scope_results"]}
            for sid, count in counts.items():
                row = views.get(sid, {})
                review = row.get("review", {})
                count["module_observations"] += 1
                if review.get("qualified") is True:
                    count["qualified_modules"] += 1
                for side in ("local_view", "effective_view"):
                    read = row.get(side, {})
                    count["expected_views"] += 1
                    if read.get("status") == "list_parsed":
                        count["parsed_views"] += 1
                        if read.get("count_confirmed") is True:
                            count["count_confirmed_views"] += 1
                if review.get("qualified") is True:
                    for profile in review.get("profiles", []):
                        if profile.get("local") is not None and profile.get("status") != "default_profile":
                            count["local_definitions"] += 1
                        if profile.get("status") in ("source_conflict", "local_effective_mismatch"):
                            count["source_disagreements"] += 1
                        if profile.get("status") == "local_matches_global":
                            count["global_matches"] += 1
        groups = defaultdict(list)
        for sid, membership in members.items():
            target = sid if group_by == "device" else membership[group_by]
            groups[target].append(sid)
        for target, ids in groups.items():
            aggregate = Counter()
            for sid in ids:
                aggregate.update(counts[sid])
            result.append({"persona": function, "scope": target,
                           "name": (scopes[target].get("name") or target) if target is not None else "Membership not established",
                           "devices": len(ids), "counts": dict(aggregate),
                           "device_ids": sorted(ids), "membership_unknown": target is None})
    return sorted(result, key=lambda row: (row["persona"], row["membership_unknown"], row["name"].casefold(), row["scope"] or ""))


def health_view(workspace, query):
    loaded, empty = load(workspace, query, "Configuration assessment", "assessment")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    persona, grouping = query.get("persona", ""), query.get("group_by", "site")
    if persona and persona not in bundle["results"]:
        raise ValueError("Unknown persona")
    drill = query.get("drill", "")
    parent_kind = query.get("parent_kind", "")
    selected = None
    allowed = None
    if drill or parent_kind:
        if not persona or grouping != "device" or parent_kind not in ("site", "group", "collection"):
            raise ValueError("Invalid scope drilldown")
        entry = bundle["results"][persona]
        members = scope_memberships(entry["scopes"])
        scopes = {s["id"]: s for s in entry["scopes"]}
        allowed = {sid for sid, membership in members.items()
                   if (drill == "unknown" and membership[parent_kind] is None)
                   or (membership[parent_kind] is not None and drill == "scope:" + str(membership[parent_kind]))}
        if not allowed:
            raise ValueError("Unknown parent scope")
        target = members[next(iter(allowed))][parent_kind]
        selected = {"name": (scopes[target].get("name") or target) if target is not None else "Membership not established"}
    records = configuration_health(bundle, persona=persona, group_by=grouping, device_ids=allowed)
    body = intro("Configuration health and evidence", "Review captured configuration consistency and evidence gaps by scope.", picker)
    body += f'<p><a href="{url(root, "assessment", snapshot=name)}">Return to optimization worklist</a></p>'
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "assessment")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="mode" value="health">'
             + select("persona", [("", "All functions")] + [(p, persona_label(p)) for p in sorted(bundle["results"])], persona, "Function")
             + select("group_by", [("site", "Site"), ("group", "Device group"), ("collection", "Site collection"), ("device", "Device")], grouping, "Group by")
             + '<button type="submit">Review evidence</button></form>'
             '<p class="note">Counts are observations within captured modules, not a health score or proof of compliance. A local copy matching Global is not a safe removal. Missing reads and unknown memberships are not defects. Device/function pairs remain separate.</p></section>')
    if selected is not None:
        body += '<section><h2>Devices in ' + e(selected["name"]) + '</h2><p>Only observed members of the selected scope are shown.</p>'
        body += f'<a href="{url(root, "assessment", snapshot=name, mode="health", persona=persona, group_by=parent_kind)}">Back to scope overview</a></section>'
    rows = []
    for row in records:
        count = row["counts"]
        params = {"persona": row["persona"]}
        if grouping == "device" and row["scope"]:
            params["scope"] = row["scope"]
        coverage = url(root, "report", snapshot=name, view="diagnostics", **params)
        override = url(root, "overrides", snapshot=name, persona=row["persona"], **({"device": row["scope"]} if grouping == "device" and row["scope"] else {}))
        if grouping == "device":
            links = f'<a href="{url(root, "scopes", snapshot=name, mode="device", persona=row["persona"], device=row["scope"])}">Review device</a> · <a href="{coverage}">Evidence</a> · <a href="{override}">Overrides</a>'
        else:
            target = "unknown" if row["membership_unknown"] else "scope:" + str(row["scope"])
            links = f'<a href="{url(root, "assessment", snapshot=name, mode="health", persona=row["persona"], group_by="device", parent_kind=grouping, drill=target)}">Review member devices</a>'
        rows.append(tr(e(row["name"]), e(persona_label(row["persona"])), str(row["devices"]),
                       f'{count.get("qualified_modules", 0)}/{count.get("module_observations", 0)}',
                       str(count.get("expected_views", 0) - count.get("parsed_views", 0)),
                       str(count.get("parsed_views", 0) - count.get("count_confirmed_views", 0)),
                       str(count.get("source_disagreements", 0)), str(count.get("global_matches", 0)),
                       str(count.get("local_definitions", 0)),
                       links))
    body += '<section><h2>Scope review</h2>' + table(("Scope", "Function", "Devices", "Qualified modules", "Unparsed views", "Unconfirmed counts", "Source disagreements", "Global matches", "Local definitions", ""), rows, search=True) + '</section>'
    if grouping != "device":
        body += '<p class="note">Open a scope to review its exact observed member devices. Unresolved membership is kept separate.</p>'
    return page("Configuration assessment", body, workspace.nav(name))
