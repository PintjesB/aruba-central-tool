"""Printable aggregate assessment, separate from raw engineering evidence."""
from .assessment_review import assessment
from .workspace_ui import e, page, intro, metrics, table, tr
from .workspace_views import load, url


def report_view(workspace, query):
    loaded, empty = load(workspace, query, "Configuration assessment", "assessment")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    report = assessment(bundle, findings=workspace.consolidation_snapshot(bundle), engineering=workspace.advanced_snapshot(bundle))
    coverage = report["coverage"]
    expected, parsed, confirmed = (coverage.get(key, 0) for key in ("expected", "parsed", "count_confirmed"))
    actions, engineering, assignments = (report[k] for k in ("actions", "engineering", "assignments"))
    body = '<div class="report-actions">' + f'<a href="{url(root, "assessment", snapshot=name)}">Return to engineering assessment</a> <button type="button" id="print-assessment">Print / save PDF</button></div>'
    body += intro("Network configuration assessment", "Captured configuration and optimization review")
    body += '<p>Capture: ' + e(report.get("captured_at") or "Capture timestamp unavailable") + '</p>'
    body += '<section><h2>Executive overview</h2><p>This assessment identifies observed opportunities to simplify reusable configuration and evidence gaps that must be resolved before changes. It does not establish compliance, deployment safety or verified savings.</p>'
    body += metrics([("Device/function pairs", report["device_function_pairs"], "Captured inventory"),
                     ("Parsed scope views", f"{parsed}/{expected}", "Structured saved and effective reads"),
                     ("Count-confirmed views", f"{confirmed}/{expected}", "Structured reads only"),
                     ("Consolidation groups", report["consolidation"]["groups"], "Review candidates")]) + '</section>'
    body += '<section><h2>Optimization opportunities</h2>' + table(("Review opportunity", "Observed groups", "Recommended action"), [
        tr("Matching local overrides", str(actions.get("remove_override", 0)), "Confirm nearest inherited definitions and dependencies."),
        tr("Repeated local profiles", str(actions.get("promote_local", 0)), "Review a common scope or reusable Library profile."),
        tr("Matching Library profiles", str(actions.get("reuse_library", 0)), "Review assignments and effective configuration."),
        tr("Duplicate Library definitions", str(engineering["duplicate_groups"]), "Retain a canonical name based on observed usage."),
        tr("Repeated port settings", str(engineering["repeated_port_groups"]), "Review shared settings while retaining port identities."),
        tr("Divergent policy variants", str(report["variants"]["groups"]), "Distinguish intentional exceptions from inconsistent configuration.")]) + '</section>'
    body += '<section><h2>Evidence gaps and validation</h2>' + table(("Observation", "Count", "Required review"), [
        tr("Unparsed structured scope views", str(expected - parsed), "Resolve failed or unqualified reads."),
        tr("Parsed views without count confirmation", str(parsed - confirmed), "Validate collection completeness."),
        tr("Unresolved references", str(engineering["unresolved_references"]), "Establish target identity and dependency visibility."),
        tr("Assignments with unresolved scope", str(assignments["unknown_scopes"]), "Validate scope membership and intended recipients."),
        tr("Unsupported policy rule evidence", str(report["policy_rules"]["groups_with_unsupported_rules"]), "Qualify rule schema and predicate interpretation.")]) + '</section>'
    body += '<section><h2>Recommended execution approach</h2><ol><li>Resolve evidence gaps relevant to each proposed change.</li><li>Review intended recipients, inherited configuration and dependencies.</li><li>Approve the desired configuration and validate individual change previews.</li><li>Perform separately authorized changes and verify a fresh capture.</li></ol><p>Counts can overlap and must not be summed as unique defects or safe removals. This report contains aggregate observations only, not device names, profile bodies, addresses or credentials.</p>'
    if (report.get("checkpoint") or {}).get("mixed_capture_times"):
        body += '<p><strong>Evidence limitation:</strong> this capture reuses observations from different collection times. It is not valid for remediation verification.</p>'
    body += '</section><script>document.getElementById("print-assessment").addEventListener("click",()=>window.print());</script>'
    return page("Configuration assessment", body, workspace.nav(name), extra_css=PRINT_CSS)


PRINT_CSS = """
@media print {
 :root, :root[data-theme=dark], :root:not([data-theme=light]) { color-scheme: light !important; --bg: white !important; --surface: white !important; --text: #172334 !important; --muted: #455364 !important; --line: #c9cfd8 !important; }
 body.app-shell { display: block !important; background: white !important; color: #172334 !important; }
 .sidebar,.topbar,.skip-link,.report-actions,dialog { display:none !important; }
 .mobile-nav .app-body::before { display:none !important; }
 .app-body { width:100% !important; }
 .overview-metrics { grid-template-columns: repeat(2,minmax(0,1fr)) !important; }
 #main-content { padding: 0 !important; max-width: none !important; }
 .metric-card { break-inside: avoid; box-shadow:none; }
 section { box-shadow:none !important; break-inside:auto; }
 h1,h2 { break-after:avoid; }
 tr { break-inside:avoid; }
 .table-scroll { overflow:visible !important; }
 table { width:100%; table-layout:fixed; }
 th,td { overflow-wrap:anywhere; }
 section { padding:12px !important; }
 .metric-card { padding:12px !important; }
 @page { margin: 14mm; }
}
"""
