"""Compact navigation for the diagnostic coverage page."""
from collections import Counter
from .workspace_ui import e, icon
from .workspace_views import url


def coverage_navigation(bundle, transport, additional):
    groups = [
        ("Review gaps", [("coverage-gaps", "Collection gaps"),
                          ("coverage-health", "Deployment health"),
                          ("coverage-keyed", "Individual profile evidence")]),
        ("Configuration sources", [("coverage-structured", "Scoped configuration"),
                                   ("coverage-library", "Library collections"),
                                   ("coverage-visibility", "Library visibility"),
                                   ("coverage-assignments", "Assignments"),
                                   ("coverage-nac", "NAC configuration")]),
        ("API diagnostics", [("coverage-operations", "Documented GET operations")]),
    ]
    if additional:
        groups[1][1].append(("coverage-supplemental", "Supplemental scopes"))
    if bundle.get("nac_portal_assets"):
        groups[1][1].append(("coverage-assets", "Portal assets"))
    if bundle.get("scope_hierarchy_evidence") or bundle.get("keyed_assignment_details"):
        groups[1][1].append(("coverage-hierarchy", "Hierarchy and direct assignments"))
    if (bundle.get("profile_type_discovery") or {}).get("documented_catalog"):
        groups[2][1].append(("coverage-catalog", "Vendor catalog"))
    if isinstance(transport, dict):
        groups[2][1].append(("coverage-performance", "Request performance"))
    return '<nav class="coverage-nav" aria-label="Coverage sections">' + "".join(
        '<div><strong>' + e(label) + '</strong>' + "".join(
            f'<a href="#{e(target)}">{e(title)} {icon("chevron")}</a>' for target, title in links)
        + '</div>' for label, links in groups) + '</nav>'


def gap_summary(root, snapshot, gaps, selected):
    counts = Counter()
    for row in gaps:
        counts[row["reason"]] += row["observations"]
    def item(reason, label, count):
        href = url(root, "coverage", snapshot=snapshot, **({"gap_reason": reason} if reason else {})) + "#coverage-gaps"
        current = ' aria-current="true"' if reason == selected else ""
        return f'<a class="gap-filter"{current} href="{href}"><strong>{count}</strong><span>{e(label)}</span></a>'
    return '<div class="gap-filter-grid">' + item("", "All gap observations", sum(counts.values())) + "".join(
        item(reason, reason, count) for reason, count in sorted(counts.items(), key=lambda x: (-x[1], x[0]))) + '</div>'


COVERAGE_CSS = """
.coverage-nav { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin:0 0 18px; }
.coverage-nav > div { border:1px solid var(--line); border-radius:9px; padding:12px; background:var(--surface); }
.coverage-nav strong { display:block; margin-bottom:8px; }
.coverage-nav a { display:flex; justify-content:space-between; align-items:center; padding:4px 0; gap:5px; }
.coverage-nav a .ui-icon { width:14px; height:14px; }
.gap-filter-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:8px; margin:12px 0; }
.gap-filter { border:1px solid var(--line); border-radius:8px; padding:9px 12px; display:flex; gap:5px; flex-direction:column; color:var(--text); text-decoration:none; min-width:0; }
.gap-filter strong { font-size:21px; font-variant-numeric:tabular-nums; }
.gap-filter span { font-size:12px; overflow-wrap:anywhere; }
.gap-filter[aria-current=true],.gap-filter:hover { border-color:var(--accent); background:var(--soft); text-decoration:none; }
section[id^=coverage-] { scroll-margin-top:80px; }
"""
