"""Historical configuration compliance worklist."""
from .workspace_ui import e, page, intro, metrics, badge, table, tr, inspect, raw
from .workspace_views import load, select, url
from .history_view import private_export
from .local_standards import records, read_record
from .compliance_trends import compliance_trends


def trends_view(workspace, query):
    from .config_app import audit_files
    loaded, empty = load(workspace, query, "Compliance trends", "trends")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    standards = records(workspace.directory, "standard")
    standard_id = query.get("standard", "")
    confirmed = query.get("confirmed") == "yes"
    limit = query.get("limit", "10")
    if limit not in ("5", "10", "20"):
        raise ValueError("Invalid snapshot limit")
    body = intro("Compliance trends", "Compare historical observations against one frozen standard version.", picker)
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "trends")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}">'
             + select("standard", [("", "Select a saved standard")] + [(s["id"], s["name"] + " / " + s["id"][:8]) for s in standards], standard_id, "Standard version")
             + select("limit", [(n, n + " recent snapshots") for n in ("5", "10", "20")], limit, "Capture limit")
             + f'<label><span><input type="checkbox" name="confirmed" value="yes" {"checked" if confirmed else ""} required> Selected captures belong to the same tenant</span></label>'
             + '<button type="submit">Assess historical captures</button></form>'
             + '<p class="note">This retrospective comparison uses one frozen baseline and approvals effective at each capture time. Recent files are selected by file modification time, then displayed by capture timestamp.</p></section>')
    if not standard_id or not confirmed:
        return page("Compliance trends", body, workspace.nav(name))
    standard = read_record(workspace.directory, "standard", standard_id)
    names = [p.name for p in audit_files(workspace.directory)[:int(limit)]]
    result = compliance_trends(workspace.directory, standard, names, confirmed=True)
    entries = result["entries"]
    body += metrics([("Comparable captures", len(entries), "Frozen standard version"),
                     ("Skipped captures", len(result["skipped"]), "Identity, timestamp or evidence unavailable"),
                     ("Selected modules", len(standard["modules"]), "Fixed module set")])
    rows = []
    for row in entries:
        counts = row["counts"]
        rows.append(tr(e(row["captured_at"]), str(row["known_recipients"]), str(counts.get("matches_reference", 0)),
                       str(counts.get("approved_exceptions", 0)), str(counts.get("differences_observed", 0)),
                       str(row["devices_with_evidence_gaps"]), str(row["unknown_membership"]),
                       f'<a href="{url(root, "standards", snapshot=row["snapshot"], standard=standard_id, confirmed="yes")}">Current approval review</a>',
                       inspect("Historical evidence", raw(row), "Inspect")))
    body += '<section><h2>Historical compliance observations</h2>' + table(("Capture (UTC)", "Known recipients", "Matches", "Approved exceptions", "Differences", "Evidence gaps", "Unknown membership", "Review now", ""), rows, search=True)
    body += '<p class="note">Evidence gaps can overlap with observed differences. Device populations may change. The review link applies current approvals, while the historical counts apply approvals effective at capture time.</p></section>'
    body += '<section><h2>Skipped snapshots</h2>' + table(("Snapshot", "Reason"), [tr(e(row["snapshot"]), e(row["reason"])) for row in result["skipped"]]) + '</section>'
    body += '<section><h2>Export historical evidence</h2>' + private_export("compliance-trends", {"report": result}) + '</section>'
    return page("Compliance trends", body, workspace.nav(name))
