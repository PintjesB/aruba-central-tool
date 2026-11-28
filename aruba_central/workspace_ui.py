"""Shared, self-contained UI for the local Central workspace.

All captured data is escaped. No third-party assets or network calls.\nOnly the color theme preference is stored in browser session storage.
"""
import json
from html import escape
from urllib.parse import urlencode


def e(value):
    return escape(str(value), quote=True)


MODULES = {
    "layer2-vlan": "VLANs", "vlan-interfaces": "VLAN interfaces",
    "ethernet-interfaces": "Ethernet ports", "portchannels": "Link aggregation",
    "sw-port-profiles": "Switch port profiles", "wlan-ssids": "Wireless networks",
    "roles": "Roles", "system-info": "Device identity", "ap-system": "AP system",
    "switch-system": "Switch system", "auth-profiles": "NAC authentication",
    "auth-servers": "Authentication servers", "ntp": "NTP", "dns": "DNS",
    "snmp": "SNMP", "snmp-trap": "SNMP traps", "qos-global": "Global QoS",
    "qos-queues": "QoS queues",
}
PERSONAS = {"ACCESS_SWITCH": "Access switches", "AGG_SWITCH": "Aggregation switches",
            "CORE_SWITCH": "Core switches", "CAMPUS_AP": "Campus APs",
            "MICROBRANCH_AP": "Microbranch APs", "Library": "Library"}
TITLES = {"Snapshots": "Overview", "Consolidation advisor": "Consolidation",
          "Engineering review": "Engineering", "Module coverage": "Coverage",
          "Library": "Library", "Scopes": "Inventory", "Compare devices": "Compare",
          "Configuration explorer": "Configuration", "Profile evidence": "Coverage",
          "Compare": "Compare"}


def module_label(value):
    return MODULES.get(value, str(value).replace("-", " ").capitalize())


def persona_label(value):
    return PERSONAS.get(value, str(value).replace("_", " ").capitalize())


def pretty(value):
    if value is None:
        return "Not available"
    return str(value).replace("_", " ").replace("-", " ").capitalize()


PROFILE_STATES = {
    "default_profile": "Central default profile",
    "local_matches_global": "Local copy matches Global",
    "local_differs_from_global": "Local settings differ from Global",
    "local_without_global_match": "No matching Global profile",
    "global_reference_unverified": "Global comparison unavailable",
    "device_local_profile": "Device-specific configuration",
    "global_local_profile": "Defined locally at Global",
    "inherited": "Inherited from a higher scope",
    "shared": "Shared Library profile",
    "source_conflict": "Source information disagrees",
    "local_effective_mismatch": "Saved and effective settings differ",
    "effective_source_unverified": "Effective source unknown",
    "effective_only_unverified": "Effective settings only",
}


def profile_state_label(value):
    return PROFILE_STATES.get(value, pretty(value))


def raw(value, label="Technical evidence"):
    return f'<details class="raw"><summary>{e(label)}</summary><pre>{e(json.dumps(value, indent=2, ensure_ascii=False))}</pre></details>'


def badge(label, tone="neutral"):
    return f'<span class="tag {e(tone)}">{e(label)}</span>'


def status(value):
    tone = ("good" if value in ("qualified", "list_parsed", "matching", "observed", "exact_match", "response_received")
            else "warn" if value in ("partial", "different", "not_observed", "different_body", "count_mismatch")
            else "neutral")
    labels = {"list_parsed": "Retrieved", "response_received": "Retrieved", "empty_object": "Unverified empty",
              "not_observed": "Not observed", "exact_match": "Identical", "different_body": "Different",
              "schema_unresolved": "Response format not recognized", "unqualified": "Not qualified",
              "qualified": "Complete", "partial": "Partial read", "absent": "Profile not returned",
              "unknown": "Cannot compare", "matching": "Identical settings", "different": "Different settings",
              "left_only": "Only on reference device", "right_only": "Only on compared device",
              "request_rejected": "API request rejected", "count_mismatch": "API counts disagree"}
    return badge(labels.get(value, pretty(value)), tone)


def table(headers, rows, *, search=False, label="Search", style=""):
    header = "".join(
        f'<th scope="col"><button type="button" class="table-sort" data-sort-column="{index}">{e(h)}<span aria-hidden="true" class="sort-indicator"></span></button></th>'
        if search and h else f'<th scope="col">{e(h)}</th>'
        for index, h in enumerate(headers))
    table_class = f' class="{e(style)}"' if style else ""
    controls = ""
    if search:
        controls = (f'<div class="table-toolbar"><label class="searchbox table-search"><span class="sr-only">{e(label)}</span>'
                    + icon("search") + '<input type="search" data-table-search placeholder="Search records"></label>'
                    '<div class="table-options"><span data-table-count class="muted" aria-live="polite"></span>'
                    '<label>Rows per page<select data-page-size><option>30</option><option>50</option><option>100</option></select></label>'
                    '<button type="button" data-export-csv title="Download all matching row summaries, not just the current page">Export filtered CSV</button></div></div>')
    pager = ('<div class="table-toolbar paging"><button type="button" data-prev aria-label="Previous page">Previous</button>'
             '<span data-page class="muted"></span><button type="button" data-next aria-label="Next page">Next</button></div>') if search else ""
    empty = '<p data-table-empty class="empty" hidden>No matching records.</p>' if search else ""
    return ('<div class="data-grid"' + (' data-paginated' if search else '') + '>' + controls
            + f'<div class="table-scroll"><table{table_class}><thead><tr>{header}</tr></thead><tbody>'
            + "".join(rows) + '</tbody></table></div>' + empty + pager + '</div>')


def tr(*cells, attrs=""):
    return f"<tr{attrs}>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"


def inspect(title, content, label="Inspect"):
    return (f'<button class="quiet inspect-trigger" type="button" data-inspect>{e(label)}{icon("chevron")}</button>'
            f'<template><div class="inspector-title"><h2>{e(title)}</h2></div>{content}</template>')


def setting_value(value):
    """Render typed configuration data without converting it to a JSON string.

    Keep exact field names and values; null, missing, false and empty
    containers remain distinct. All Central-controlled text is escaped.
    """
    if value is None:
        return '<span class="value-empty">Null</span>'
    if isinstance(value, bool):
        return '<span class="value-bool">' + ("True" if value else "False") + '</span>'
    if isinstance(value, dict):
        if not value:
            return '<span class="value-empty">Empty object</span>'
        return '<dl class="value-object">' + "".join(
            f'<div><dt>{e(key)}</dt><dd>{setting_value(item)}</dd></div>'
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))) + '</dl>'
    if isinstance(value, list):
        if not value:
            return '<span class="value-empty">Empty list</span>'
        return '<ul class="value-list">' + "".join(f'<li>{setting_value(item)}</li>' for item in value) + '</ul>'
    if isinstance(value, str) and value == "":
        return '<span class="value-empty">Empty string</span>'
    return '<span class="value-scalar">' + e(value) + '</span>'


def ordered_list_movement(left, right):
    """Map exact occurrences only; never infer semantic equivalence."""
    from collections import defaultdict, deque
    from .central_tool import canonical
    if not isinstance(left, list) or not isinstance(right, list) or len(left) != len(right):
        return None
    positions = defaultdict(deque)
    for index, value in enumerate(right, 1):
        positions[canonical(value)].append(index)
    moves = []
    for index, value in enumerate(left, 1):
        available = positions.get(canonical(value))
        if not available:
            return None
        destination = available.popleft()
        if index != destination:
            moves.append((index, destination))
    return moves


def diff_table(fields, left="Local", right="Reference"):
    if fields is None:
        return '<p class="empty">No comparable reference captured.</p>'
    if not fields:
        return '<p class="inline-good">Captured configuration bodies are identical.</p>'
    kinds = {"missing_local": "Missing from first observation", "missing_reference": "Missing from second observation",
             "null_vs_value": "Null vs explicit value", "type_difference": "Value types differ",
             "value_difference": "Values differ"}
    types = {"str": "String", "int": "Integer", "float": "Number", "bool": "Boolean",
             "dict": "Object", "list": "Ordered list", "NoneType": "Null"}
    def value(d, key, type_key):
        if key not in d:
            return '<span class="value-empty">Not returned</span>'
        kind = d.get(type_key, type(d[key]).__name__)
        value = d[key]
        if isinstance(value, list) and value:
            rendered = '<ol class="diff-ordered-list">' + "".join(
                '<li>' + setting_value(item) + '</li>' for item in value) + '</ol>'
        else:
            rendered = setting_value(value)
        return '<small class="diff-type">' + e(types.get(kind, pretty(kind))) + '</small>' + rendered
    def field(d):
        path = ".".join(map(str, d["path"])) or "(root)"
        kind = kinds.get(d.get("kind"), "Observed difference")
        movement = ordered_list_movement(d.get("local_value"), d.get("reference_value"))
        details = ""
        if movement:
            kind = "Same exact list members, different order"
            # Match repeated equal entries by occurrence, not inferred identity.
            details = '<small>' + e(f"{len(movement)} positions differ. Order may be significant.") + '</small>'
            details += '<details><summary>Position changes</summary><ol class="diff-moves">' + "".join(
                f'<li>Position {start} to {end}</li>' for start, end in movement) + '</ol></details>'
        return '<strong class="diff-path">' + e(path) + '</strong><small>' + e(kind) + '</small>' + details
    return table(("Setting", left, right), [tr(field(f), value(f, "local_value", "local_type"),
                value(f, "reference_value", "reference_type")) for f in fields], style="setting-table typed-diff")


def property_table(data):
    if not isinstance(data, dict) or not data:
        return '<p class="empty">No settings captured.</p>'
    return table(("Setting", "Value"), [tr(e(key), setting_value(value))
                                        for key, value in sorted(data.items())], style="setting-table")


def metrics(items):
    return '<div class="overview-metrics">' + "".join(
        f'<div class="metric-card"><span>{e(label)}</span><strong>{e(value)}</strong><small>{e(note)}</small></div>'
        for label, value, note in items) + '</div>'


def intro(title, subtitle="", action=""):
    return (f'<div class="page-intro"><div><h1>{e(title)}</h1>'
            + (f'<p class="muted">{e(subtitle)}</p>' if subtitle else "")
            + '</div>' + action + '</div>')


def snapshot_picker(root, route, files, selected):
    options = "".join(f'<option value="{e(p.name)}"{" selected" if p.name == selected else ""}>'
                      f'{e(p.name.removeprefix("config-audit-").removesuffix(".json"))}</option>' for p in files)
    return (f'<form class="snapshot-picker" method="get" action="{e(root + route)}">'
            f'<label>Snapshot<select name="snapshot">{options}</select></label>'
            '<noscript><button type="submit" class="quiet">Open</button></noscript></form>')


# Inline, monochrome SVGs keep the local workspace independent of external assets.
ICONS = {
    "overview": '<rect x="3" y="3" width="7" height="7" rx="1.3"/><rect x="14" y="3" width="7" height="7" rx="1.3"/><rect x="3" y="14" width="7" height="7" rx="1.3"/><rect x="14" y="14" width="7" height="7" rx="1.3"/>',
    "overrides": '<path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3" fill="currentColor" stroke="none"/><circle cx="15" cy="17" r="3" fill="currentColor" stroke="none"/>',
    "advisor": '<path d="M12 3 3 8l9 5 9-5-9-5ZM3 12l9 5 9-5M3 16l9 5 9-5"/>',
    "advanced": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
    "report": '<path d="M6 3h9l4 4v14H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2ZM14 3v5h5M8 12h7m-7 4h7"/>',
    "scopes": '<rect x="8" y="3" width="8" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>',
    "library": '<rect x="3" y="4" width="5" height="16" rx="1"/><rect x="10" y="4" width="4" height="16" rx="1"/><path d="m17 5 4 14-4 1-3-14 3-1Z"/>',
    "compare": '<path d="M4 7h15m-4-4 4 4-4 4M20 17H5m4-4-4 4 4 4"/>',
    "coverage": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    "search": '<circle cx="10.8" cy="10.8" r="6.3"/><path d="m16 16 4 4"/>',
    "arrow": '<path d="M5 12h14m-5-5 5 5-5 5"/>',
    "chevron": '<path d="m9 18 6-6-6-6"/>',
    "menu": '<path d="M4 6h16M4 12h16M4 18h16"/>',
    "shield": '<path d="m12 3 8 3v6c0 4-3 7-8 9-5-2-8-5-8-9V6l8-3Z"/><path d="m9 12 2 2 4-4"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
    "moon": '<path d="M20.5 14.2A9 9 0 0 1 9.8 3.5 9 9 0 1 0 20.5 14.2Z"/>',
    "database": '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    "close": '<path d="m6 6 12 12M18 6 6 18"/>',
    "brand": '<path d="M3 12 8 3h9l4 9-4 9H8L3 12Z"/><path d="m8 12 4-5 4 5-4 5-4-5Z"/>',
}


def icon(name):
    return ('<svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            'stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            + ICONS.get(name, ICONS["chevron"]) + '</svg>')


def navigation(root, snapshot=None):
    suffix = "?" + urlencode({"snapshot": snapshot}) if snapshot else ""
    links = []
    for group, items in (
        ("Analyze", (("", "Overview"), ("overrides", "Device overrides"), ("advisor", "Consolidation"),
                       ("assessment", "Configuration assessment"), ("advanced", "Engineering"), ("assignments", "Library assignments"), ("nac", "NAC identities"), ("sources", "Configuration sources"), ("impact", "Dependency impact"), ("drift", "Configuration drift"), ("remediation", "Remediation verification"), ("standards", "Standards compliance"), ("trends", "Compliance trends"))),
        ("Explore", (("find", "Find devices and profiles"), ("report", "Configuration"), ("scopes", "Inventory"), ("library", "Library"), ("compare", "Compare"))),
        ("System", (("filters", "Saved filters"), ("coverage", "Coverage")))):
        links.append(f'<div class="nav-group"><span>{e(group)}</span>')
        for route, label in items:
            target = (root + "report?" + urlencode({"mode": "entities", **({"snapshot": snapshot} if snapshot else {})})
                      if route == "find" else root + route + suffix)
            links.append(f'<a data-nav="{e(label)}" aria-label="{e(label)}" title="{e(label)}" href="{e(target)}">'
                         f'{icon("search" if route == "find" else route or "overview")}<span class="nav-label">{e(label)}</span></a>')
        links.append('</div>')
    return "".join(links)


def page(title, content, nav="", extra_css=""):
    active = TITLES.get(title, title)
    # The navigation is generated by navigation(), not supplied by the API.
    nav = nav.replace(f'data-nav="{e(active)}"', f'data-nav="{e(active)}" aria-current="page"')
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{e(active)} · Central Workspace</title><style>{extra_css}\n{CSS}</style></head>'
            '<body class="app-shell"><a class="skip-link" href="#main-content">Skip to content</a>'
            '<aside class="sidebar" id="workspace-sidebar"><div class="brand"><span class="brand-mark">' + icon("brand") + '</span>'
            '<div><strong>Central<span class="brand-accent">.</span></strong><small>Configuration intelligence</small></div>'
            '<button class="nav-close icon-button" id="workspace-nav-close" type="button" aria-label="Close navigation">' + icon("close") + '</button></div>'
            f'<nav aria-label="Main navigation">{nav}</nav>'
            '<div class="nav-footer">' + icon("shield") + '<div><strong>Read-only workspace</strong><small>Private local data</small></div></div></aside>'
            '<div class="app-body"><header class="topbar"><div class="topbar-left">'
            '<button id="workspace-menu" class="icon-button" type="button" aria-label="Toggle navigation" aria-controls="workspace-sidebar" aria-expanded="false">' + icon("menu") + '</button>'
            '<span class="breadcrumb">Workspace</span>' + icon("chevron") + f'<strong>{e(active)}</strong></div>'
            '<div class="topbar-actions"><div id="snapshot-slot"></div>'
            '<button id="workspace-command" class="command-trigger" type="button" aria-label="Quick navigation" aria-haspopup="dialog">' + icon("search") + '<span>Quick navigation</span><kbd>Ctrl K</kbd></button>'
            '<button id="workspace-theme" class="icon-button" type="button" aria-label="Switch color theme" aria-pressed="false">' + '<span class="theme-moon">' + icon("moon") + '</span><span class="theme-sun">' + icon("sun") + '</span></button></div></header>'
            f'<main id="main-content">{content}</main></div>'
            '<dialog class="inspector" id="workspace-inspector" aria-labelledby="workspace-inspector-title"><div class="inspector-head">'
            '<div><small>Configuration review</small><h2 id="workspace-inspector-title"></h2></div>'
            '<div class="inspector-actions"><button type="button" class="quiet" id="workspace-inspector-back" hidden>Back</button>'
            '<button type="button" class="icon-button" id="workspace-close" autofocus aria-label="Close inspector">' + icon("close") + '</button></div></div>'
            '<div id="workspace-inspector-body"></div></dialog>'
            '<dialog id="workspace-palette" class="command-palette" aria-label="Quick navigation"><div class="command-input">' + icon("search")
            + '<input id="command-query" type="search" placeholder="Find a workspace page..." aria-label="Find a workspace page"><kbd>Esc</kbd></div>'
            '<div id="command-results" class="command-results"></div><p id="command-empty" class="empty" hidden>No matching pages.</p>'
            '<div class="command-footer">Navigate <kbd>↑</kbd> <kbd>↓</kbd><span>Open <kbd>Enter</kbd></span></div></dialog>'
            f'<script>{SCRIPT}</script></body></html>')



CSS = """
:root {
  font: 14px/1.5 "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
  color-scheme: light;
  --bg: #f6f7f9; --surface: #fff; --text: #192334; --muted: #657184;
  --line: #e3e7ed; --accent: #176b5b; --primary: #147a66; --primary-hover: #0c6554;
  --soft: #edf6f2; --green: #176c50; --green-bg: #e7f5ee;
  --warn: #94601d; --warn-bg: #fdf3df; --nav: #142622; --nav-text: #afc2b9;
  --nav-muted: #8aa49a; --nav-active: #26433a; --nav-line: #31453d;
  --radius: 12px; --shadow: 0 1px 2px #14262209;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme=light]) {
    color-scheme: dark; --bg: #111815; --surface: #1b2420; --text: #e6eee9;
    --muted: #a0b1a8; --line: #34423b; --accent: #7bdfbe; --primary: #147a66;
    --primary-hover: #0c6554; --soft: #243c32; --green: #8be0b3;
    --green-bg: #203d30; --warn: #efc47d; --warn-bg: #403522; --shadow: none;
  }
}
:root[data-theme=dark] {
  color-scheme: dark; --bg: #111815; --surface: #1b2420; --text: #e6eee9;
  --muted: #a0b1a8; --line: #34423b; --accent: #7bdfbe; --primary: #147a66;
  --primary-hover: #0c6554; --soft: #243c32; --green: #8be0b3;
  --green-bg: #203d30; --warn: #efc47d; --warn-bg: #403522; --shadow: none;
}
* { box-sizing: border-box; }
body.app-shell { margin: 0; background: var(--bg); color: var(--text);
  display: grid; grid-template-columns: 236px minmax(0,1fr); min-height: 100vh; }
.ui-icon { width: 18px; height: 18px; flex: none; vertical-align: middle; }
.app-shell .sidebar { position: sticky; top: 0; height: 100vh; height: 100dvh;
  background: var(--nav); color: var(--nav-text); padding: 26px 14px 16px;
  display: flex; flex-direction: column; overflow: auto; }
.brand { display: flex; gap: 11px; align-items: center; padding: 0 8px 35px; color: #f0f8f4; }
.brand strong { font-size: 22px; line-height: 1.1; display: block; letter-spacing: -.8px; font-weight: 750; }
.brand-accent { color: #7de0bb; }
.brand small { font-size: 10px; color: var(--nav-muted); display: block; margin-top: 4px; white-space: nowrap; }
.brand-mark { display: grid; place-items: center; width: 36px; height: 36px; border-radius: 11px;
  background: #2b5346; color: #a6f3d4; flex: none; }
.brand-mark .ui-icon { width: 25px; height: 25px; }
.nav-close { display: none !important; }
.theme-sun { display: none; } #workspace-theme[data-mode=dark] .theme-sun { display: inline-flex; }
#workspace-theme[data-mode=dark] .theme-moon { display: none; }
.nav-group { margin: 0 0 24px; }
.nav-group > span { display: block; font-size: 10px; font-weight: 650; letter-spacing: .1em;
  text-transform: uppercase; padding: 0 12px 7px; color: var(--nav-muted); }
.sidebar nav a { position: relative; display: flex; gap: 11px; align-items: center; color: var(--nav-text);
  padding: 10px 11px; border-radius: 7px; text-decoration: none; margin: 2px 0; font-weight: 500; }
.sidebar nav a:hover { background: #203a31; color: #eefbf5; }
.sidebar nav a[aria-current=page] { background: var(--nav-active); color: #dcfaed; font-weight: 650; }
.sidebar nav a[aria-current=page]::before { content: ""; position: absolute; left: 0; width: 3px;
  height: 21px; border-radius: 2px; background: #81e1bf; }
.nav-footer { margin-top: auto; padding: 14px 8px 0; display: flex; align-items: center; gap: 10px;
  border-top: 1px solid var(--nav-line); font-size: 11px; color: var(--nav-text); }
.nav-footer .ui-icon { color: #8bdbb6; width: 20px; height: 20px; }
.nav-footer small { display: block; color: var(--nav-muted); font-size: 10px; }
.lock-dot { display: inline-block; background: var(--green); width: 7px; height: 7px; border-radius: 50%; margin-right: 6px; }
.app-body { min-width: 0; }
.app-shell .topbar { position: sticky; top: 0; z-index: 4; background: var(--surface);
  border-bottom: 1px solid var(--line); color: var(--text); padding: 11px 26px; min-height: 65px;
  display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.topbar-left,.topbar-actions { display: flex; align-items: center; gap: 12px; min-width: 0; }
.topbar-left .ui-icon { width: 15px; height: 15px; color: var(--muted); }
.topbar-left strong { font-size: 13px; white-space: nowrap; }
.breadcrumb { font-size: 12px; color: var(--muted); white-space: nowrap; }
.topbar-actions { justify-content: flex-end; flex: 1; }
#snapshot-slot:empty { display: none; }
#snapshot-slot { min-width: 0; }
.snapshot-picker { margin: 0; }
.snapshot-picker label { display: flex; align-items: center; gap: 9px; font-size: 11px; white-space: nowrap; }
.snapshot-picker select { max-width: 210px; min-width: 0; font-weight: 600; font-size: 12px; }
.command-trigger { gap: 8px; color: var(--muted); background: var(--bg); }
.command-trigger .ui-icon { width: 15px; height: 15px; }
kbd { font: 10px/1.4 system-ui,sans-serif; border: 1px solid var(--line);
  border-radius: 4px; padding: 2px 4px; color: var(--muted); background: var(--surface); }
.icon-button { width: 36px; height: 36px; padding: 8px; background: transparent; }
.icon-button .ui-icon { width: 18px; height: 18px; }
.compact-nav body.app-shell { grid-template-columns: 66px minmax(0,1fr); }
.compact-nav .sidebar { padding-left: 9px; padding-right: 9px; }
.compact-nav .brand { padding: 0 6px 31px; }
.compact-nav .brand > div,.compact-nav .nav-label,.compact-nav .nav-group > span,.compact-nav .nav-footer > div { display: none; }
.compact-nav .sidebar nav a { justify-content: center; padding: 12px 0; }
.compact-nav .nav-footer { justify-content: center; padding: 14px 0 0; }
.app-shell main { max-width: 1720px; margin: 0 auto; padding: 32px 32px 42px; min-width: 0; }
.page-intro { display: flex; align-items: center; justify-content: space-between; gap: 18px; flex-wrap: wrap; margin-bottom: 27px; }
h1 { font-size: clamp(27px,2.4vw,34px); font-weight: 720; letter-spacing: -1.2px; line-height: 1.16; margin: 0 0 7px; }
h2 { font-size: 18px; letter-spacing: -.4px; font-weight: 670; margin: 0 0 12px; }
h3 { font-size: 14px; font-weight: 680; margin: 0 0 8px; }
h4 { font-size: 13px; margin: 0 0 6px; }
p { margin: 0 0 12px; }
.muted,small { color: var(--muted); } small { font-size: 12px; }
.muted { font-size: 13px; } .page-intro p { margin: 0; font-size: 14px; max-width: 760px; }
.app-shell section { background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); box-shadow: var(--shadow); padding: 20px; margin: 0 0 18px; min-width: 0; }
.section-head { display: flex; align-items: center; justify-content: space-between;
  gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
.section-head h2 { margin: 0; }
a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
button,input,select { font: inherit; color: var(--text); }
button,.button { display: inline-flex; align-items: center; justify-content: center; gap: 7px;
  padding: 8px 13px; min-height: 36px; border: 1px solid var(--line); border-radius: 7px;
  background: var(--surface); cursor: pointer; text-decoration: none; color: var(--text);
  font-weight: 600; font-size: 12px; white-space: nowrap; transition: background .12s,border-color .12s; }
button:hover,.button:hover { background: var(--soft); border-color: var(--accent); text-decoration: none; }
button.primary,.button.primary,button[type=submit]:not(.quiet) { background: var(--primary); color: #fff; border-color: var(--primary); }
button.primary:hover,.button.primary:hover,button[type=submit]:not(.quiet):hover { background: var(--primary-hover); }
button.quiet { background: transparent; }
.inspect-trigger { color: var(--accent); border-color: transparent; padding: 5px 7px; min-height: 32px; }
.inspect-trigger .ui-icon { width: 13px; height: 13px; }
.inspect-trigger:hover { background: var(--soft); border-color: transparent; }
.reset-link { border: 0; background: transparent; color: var(--muted); }
button:disabled { opacity: .45; cursor: default; }
button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
input:not([type=checkbox]):not([type=radio]),select { border: 1px solid var(--line); border-radius: 7px;
  background: var(--surface); padding: 8px 10px; min-height: 36px; max-width: 100%; }
input[type=checkbox] { accent-color: var(--primary); width: 16px; height: 16px; vertical-align: middle; margin: 0; }
label { display: grid; gap: 5px; color: var(--muted); font-weight: 600; font-size: 11px; }
form,.toolbar,.table-toolbar,.snapshot-picker { display: flex; flex-wrap: wrap; align-items: end; gap: 10px; }
.worklist { padding: 20px; }
.worklist-controls { padding: 0 0 18px; border-bottom: 1px solid var(--line); margin-bottom: 18px; }
.worklist-summary { display: flex; align-items: baseline; justify-content: space-between; gap: 14px; flex-wrap: wrap; margin-bottom: 16px; }
.worklist-summary h2,.worklist-summary .result-summary { margin: 0; }
.worklist .filter-bar label { flex-basis: 135px; }
.override-table th:first-child { width: 23%; }
.override-table th:nth-child(2) { width: 30%; }
.override-table th:nth-child(3) { width: 33%; }
.override-table td:last-child { text-align: right; }
.override-table td small { line-height: 1.4; }
.setting-table th:first-child { width: 28%; }
.setting-table td { vertical-align: top; }
.typed-diff .diff-type { font-weight:600; color:var(--muted); margin:0 0 4px; }
.typed-diff .diff-path { overflow-wrap:anywhere; }
.diff-ordered-list,.diff-moves { padding-left:24px; margin:6px 0; }
.diff-ordered-list > li { padding:4px 0; }
.diff-ordered-list > li::marker { font-weight:600; color:var(--muted); }
.diff-moves { list-style:none; padding-left:0; font-variant-numeric:tabular-nums; }
.typed-diff td:first-child small { color:var(--muted); }
.value-scalar { white-space: pre-wrap; overflow-wrap: anywhere; }
.value-empty { color: var(--muted); font-style: italic; }
.value-bool { font-weight: 600; }
.value-object { margin: 0; min-width: 0; }
.value-object > div { display: grid; grid-template-columns: minmax(70px,1fr) minmax(0,1.5fr); gap: 10px; padding: 5px 0; border-bottom: 1px solid var(--line); }
.value-object > div:last-child { border-bottom: 0; }
.value-object dt { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
.value-object dd { margin: 0; min-width: 0; }
.value-list { margin: 0; padding-left: 17px; }
.value-list li + li { margin-top: 6px; }
@media(max-width: 680px) { .override-table { min-width: 560px; } .worklist-summary { align-items: flex-start; flex-direction: column; } .value-object > div { grid-template-columns: 1fr; gap: 3px; } }
.filter-section { padding: 15px 18px !important; }
.filter-bar { display: flex; gap: 10px; align-items: flex-end; flex-wrap: wrap; }
.filter-bar label { flex: 1 1 145px; min-width: 0; }
.filter-bar select,.filter-bar input { width: 100%; min-width: 0; }
.filter-bar .searchbox { max-width: none; }
.filter-bar button { min-height: 36px; }
.filter-hint { font-size: 12px; color: var(--muted); margin: 12px 0 0; }
.collection-nav { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin: 0 0 16px; flex-wrap: wrap; }
.collection-nav select { max-width: 250px; }
.overview-metrics { display: grid; grid-template-columns: repeat(auto-fit,minmax(155px,1fr)); gap: 12px; margin: 0 0 18px; }
.metric-card { padding: 18px 20px; background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); display: grid; gap: 5px; box-shadow: var(--shadow); }
.metric-card span { color: var(--muted); font-weight: 600; font-size: 12px; }
.metric-card strong { font-size: 32px; font-variant-numeric: tabular-nums; line-height: 1.15; letter-spacing: -1.3px; font-weight: 680; }
.metric-card small { font-size: 11px; }
.overview-layout { display: grid; grid-template-columns: minmax(0,2fr) minmax(245px,1fr); gap: 16px; align-items: stretch; }
.overview-layout > section { min-width: 0; }
.app-shell .overview-focus { display: grid; grid-template-columns: minmax(0,1.15fr) minmax(0,1fr); align-items: center; gap: 20px; padding: 26px; background: #16382f; color: #f0faf5; border: 1px solid #234a3e; }
.focus-kicker { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 11px; letter-spacing: .015em; }
.focus-kicker .ui-icon { width: 16px; height: 16px; }
.overview-focus .focus-kicker { color: #a5d9c7; }
.focus-number { font-size: 70px; line-height: 1; font-weight: 690; letter-spacing: -4px; margin: 18px 0 10px; font-variant-numeric: tabular-nums; }
.overview-focus h2 { font-size: 23px; letter-spacing: -.7px; line-height: 1.22; margin: 0 0 8px; color: #f3faf7; }
.overview-focus p { color: #bbd7cd; font-size: 13px; max-width: 335px; margin-bottom: 18px; }
.overview-focus .button.primary { background: #a9ebd2; color: #143c30; border-color: #a9ebd2; white-space: normal; }
.overview-focus .button.primary:hover { background: #caf5e5; }
.overview-focus .button .ui-icon { width: 14px; height: 14px; }
.overview-breakdown { border-left: 1px solid #416057; padding-left: 19px; min-width: 0; }
.overview-breakdown h3 { font-size: 12px; color: #c0dcd1; font-weight: 600; margin-bottom: 10px; }
.opportunity-row { display: grid; grid-template-columns: minmax(0,1fr) auto 13px; gap: 5px 9px; align-items: center; padding: 11px 0; border-bottom: 1px solid #416057; color: #f3faf7; }
.opportunity-row:last-child { border-bottom: 0; }
.opportunity-row:hover { text-decoration: none; color: #a9ebd2; }
.opportunity-row strong { font-size: 12px; display: block; }
.opportunity-row small { font-size: 10px; color: #a7c6ba; display: block; }
.opportunity-row b { font-size: 20px; font-weight: 650; grid-column: 2; grid-row: 1; font-variant-numeric: tabular-nums; }
.opportunity-row .ui-icon { width: 13px; height: 13px; grid-column: 3; grid-row: 1; }
.opportunity-meter { grid-column: 1/-1; height: 4px; background: #416057; border-radius: 4px; overflow: hidden; }
.opportunity-meter span { display: block; height: 100%; border-radius: 4px; background: #82e1bc; }
.app-shell .coverage-focus { display: flex; flex-direction: column; align-items: flex-start; padding: 24px; }
.coverage-focus .focus-kicker { color: var(--muted); }
.coverage-number { font-size: 42px; line-height: 1.15; font-weight: 690; letter-spacing: -1.5px; margin: 24px 0 5px; font-variant-numeric: tabular-nums; }
.coverage-number small { font-size: 18px; letter-spacing: -.4px; font-weight: 500; }
.coverage-focus h3 { font-size: 13px; }
.coverage-meter { width: 100%; height: 9px; background: var(--bg); border-radius: 5px; margin: 12px 0; overflow: hidden; }
.coverage-meter span { height: 100%; display: block; background: var(--primary); border-radius: 5px; }
.coverage-focus p { color: var(--muted); font-size: 12px; margin-bottom: 16px; }
.coverage-focus > a { margin-top: auto; font-size: 13px; font-weight: 600; display: inline-flex; align-items: center; gap: 8px; }
.coverage-focus > a .ui-icon,.overview-links a .ui-icon { width: 14px; height: 14px; }
.overview-links { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
.overview-links p { color: var(--muted); font-size: 13px; }
.overview-links a { display: inline-flex; align-items: center; gap: 7px; font-weight: 600; font-size: 12px; }
.overview-links > div + div { border-left: 1px solid var(--line); padding-left: 24px; }
@media(max-width: 1260px) { .overview-layout { grid-template-columns: 1fr; } .coverage-focus { min-height: 180px; } }
@media(max-width: 650px) { .app-shell .overview-focus { grid-template-columns: 1fr; padding: 20px; } .focus-number { font-size: 58px; } }
.connection-details > summary { font-weight: 650; font-size: 15px; color: var(--text); margin: 0; }
.connection-details[open] > summary { margin-bottom: 14px; }
.result-summary { display: flex; gap: 10px 18px; flex-wrap: wrap; align-items: center; margin: 0 0 16px; color: var(--muted); font-size: 12px; }
.result-summary strong { font-size: 17px; color: var(--text); font-variant-numeric: tabular-nums; }
.workflow-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(210px,1fr)); gap: 12px; margin-bottom: 20px; }
.workflow-card { display: block; color: var(--text); padding: 17px; background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); }
.workflow-card:hover { border-color: var(--accent); text-decoration: none; }
.workflow-card strong { display: block; margin-bottom: 6px; } .workflow-card span { display: block; color: var(--muted); font-size: 13px; }
.workflow-card .arrow { color: var(--accent); margin-top: 10px; }
.data-grid { min-width: 0; }
.table-scroll { overflow-x: auto; max-width: 100%; border: 1px solid var(--line); border-radius: 8px; }
table { width: 100%; border-collapse: separate; border-spacing: 0; text-align: left; font-variant-numeric: tabular-nums; font-size: 13px; }
th { font-size: 11px; font-weight: 650; color: var(--muted); background: var(--bg); white-space: normal; }
td,th { padding: 12px 13px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: middle; }
td { overflow-wrap: anywhere; } tbody tr:hover { background: var(--soft); }
tbody tr:last-child td { border-bottom: 0; } td strong { font-weight: 650; } td small { display: block; margin-top: 3px; }
.group-usage { font-size: 12px; min-width: 350px; }
.group-usage th,.group-usage td { padding: 6px 9px; vertical-align: middle; }
.group-usage th { font-size: 11px; background: transparent; } .group-usage tr:hover { background: transparent; }
.group-usage td:first-child { min-width: 100px; } .retain-mark { font-size: 10px; color: var(--accent); font-weight: 650; }
.table-toolbar { align-items: center; justify-content: space-between; margin: 0 0 12px; }
.paging { margin: 12px 0 0; justify-content: flex-end; }
.table-options { display:flex;align-items:center;gap:12px;flex-wrap:wrap; }
.table-options label { display:flex;align-items:center;gap:6px;font-size:12px; }
.table-options select { min-width:0;width:auto; }
.table-sort { display:inline-flex;align-items:center;gap:6px;background:transparent;border:0;padding:0;color:inherit;font:inherit;text-align:left;cursor:pointer; }
.table-sort:hover { color:var(--accent);background:transparent; }
.sort-indicator { opacity:.55; }
.sort-indicator::after { content:"↕"; }
th[aria-sort=ascending] .sort-indicator::after { content:"↑";opacity:1; }
th[aria-sort=descending] .sort-indicator::after { content:"↓";opacity:1; }

.searchbox { flex: 1; max-width: 340px; } .searchbox input { width: 100%; }
.table-search { position: relative; display: block; }
.table-search .ui-icon { position: absolute; left: 10px; top: 9px; color: var(--muted); width: 16px; height: 16px; }
.table-search input { padding-left: 34px !important; font-size: 12px; }
.tag { display: inline-flex; align-items: center; gap: 5px; border-radius: 5px; padding: 4px 7px; font-size: 11px; font-weight: 600; white-space: normal; }
.tag.neutral { background: var(--bg); color: var(--muted); }
.tag.good,.inline-good { background: var(--green-bg); color: var(--green); }
.tag.warn,.pill { background: var(--warn-bg); color: var(--warn); }
.tag.info { background: var(--soft); color: var(--accent); }
.tag.good::before,.tag.warn::before { content: ""; width: 6px; height: 6px; flex: none; border-radius: 50%; background: currentColor; }
.inline-good { padding: 10px 12px; border-radius: 7px; }
.empty { color: var(--muted); padding: 20px 0; }
.note { font-size: 12px; color: var(--muted); padding: 10px 12px; border-left: 3px solid var(--line); margin: 8px 0 12px; }
.raw { border-top: 1px solid var(--line); margin-top: 16px; padding-top: 8px; }
.raw summary { font-size: 12px; color: var(--muted); }
summary { cursor: pointer; color: var(--accent); font-weight: 600; margin: 8px 0; }
pre,code { font: 12px/1.55 ui-monospace,Consolas,monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
pre { background: var(--bg); border: 1px solid var(--line); padding: 12px; max-height: 420px; overflow: auto; border-radius: 7px; margin: 8px 0; }
html:has(.inspector[open]),html:has(.command-palette[open]),html.inspector-open { overflow: hidden; scrollbar-gutter: stable; }
.inspector { position: fixed; inset: 0; margin: auto; width: min(1320px,calc(100vw - 64px)); height: calc(100vh - 64px); height: calc(100dvh - 64px);
  max-height: none; max-width: none; border: 1px solid var(--line); border-radius: 16px; background: var(--surface); color: var(--text);
  padding: 0; overflow: hidden; box-shadow: 0 20px 80px #0004; }
.inspector[open] { display: flex; flex-direction: column; }
.inspector::backdrop,.command-palette::backdrop { background: #0b1918a0; backdrop-filter: blur(2px); }
.inspector-head { flex: none; display: flex; justify-content: space-between; align-items: center; gap: 16px; background: var(--surface); padding: 20px 28px; border-bottom: 1px solid var(--line); }
.inspector-head small { display: block; font-size: 11px; margin-bottom: 3px; }
.inspector-head h2 { font-size: 24px; line-height: 1.3; margin: 0; overflow-wrap: anywhere; letter-spacing: -.6px; }
.inspector-actions { display: flex; align-items: center; gap: 8px; }
#workspace-inspector-body { flex: 1; min-height: 0; min-width: 0; padding: 24px 28px 32px; overflow-y: auto; overflow-x: hidden; overscroll-behavior: contain; scrollbar-gutter: stable; }
.inspector h3 { margin: 24px 0 10px; }
.inspector .table-scroll { max-height: none; overflow-x: auto; overflow-y: hidden; }
.inspector .data-grid { min-width: 0; }
.inspector th { white-space: normal; } .inspector td { vertical-align: top; }
.inspector pre { max-height: none; overflow: visible; }
.inspector ul,.inspector ol { padding-left: 22px; margin: 8px 0 16px; }
.inspector .note { border: 0; background: var(--bg); border-radius: 6px; padding: 10px 12px; }
.inspector details:not(.raw) { border-top: 1px solid var(--line); padding: 5px 0; }
.review-decision { display: flex; justify-content: space-between; align-items: flex-start; gap: 20px;
  padding: 18px 20px; margin: 0 0 22px; background: var(--bg); border: 1px solid var(--line); border-radius: 10px; }
.review-decision p { margin: 8px 0 0; } .review-context { min-width: 0; text-align: right; }
.review-context strong { display: block; overflow-wrap: anywhere; }
.comparison-summary { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 0 0 12px; }
.comparison-summary .tag { font-size: 12px; padding: 5px 9px; }
.comparison-table { table-layout: fixed; } .comparison-table th,.comparison-table td { padding: 10px 12px; }
.comparison-table th:nth-child(1) { width: 23%; } .comparison-table th:nth-child(2) { width: 15%; }
.comparison-table th:nth-child(3) { width: 25%; } .comparison-table th:nth-child(4) { width: 20%; }
.comparison-table th:nth-child(5) { width: 17%; } .comparison-table td:first-child { font-weight: 600; }
.comparison-table td small { font-size: 11px; line-height: 1.3; } .comparison-table td .tag { white-space: normal; }
.comparison-table tbody tr[data-comparison=different] { background: var(--warn-bg); }
.inspector li { margin-bottom: 5px; }
.workflow-tabs { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 18px; }
.workflow-tabs a { display: inline-flex; align-items: center; gap: 8px; padding: 10px 13px; color: var(--muted);
  border: 1px solid var(--line); border-radius: 8px; background: var(--surface); font-size: 12px; font-weight: 600; }
.workflow-tabs a span { font-variant-numeric: tabular-nums; color: var(--muted); font-size: 11px; }
.workflow-tabs a[aria-current=true] { color: var(--accent); border-color: var(--accent); background: var(--soft); }
.workflow-tabs a:hover { text-decoration: none; border-color: var(--accent); }
[data-port-review] label { max-width: 400px; margin-bottom: 12px; }
[data-port-target] { color: var(--accent); font-weight: 600; }
.tabs { display: flex; gap: 5px; flex-wrap: wrap; border-bottom: 1px solid var(--line); margin-bottom: 16px; }
.tabs button { border: 0; border-radius: 0; border-bottom: 2px solid transparent; background: transparent; font-size: 13px; padding: 10px 13px; color: var(--muted); }
.tabs button[aria-selected=true] { border-bottom-color: var(--accent); color: var(--accent); font-weight: 650; }
.tabs button span { font-size: 11px; color: var(--muted); margin-left: 4px; }
.audit-state { border-left: 3px solid var(--accent); background: var(--bg); padding: 12px 15px; border-radius: 6px; margin: 0 0 16px; }
.audit-state[data-state=complete] { border-color: var(--green); } .audit-state[data-state=failed] { border-color: #cc5246; }
.audit-state p { margin: 5px 0; } progress { width: 100%; height: 13px; accent-color: var(--primary); }
.connection-form { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.connection-form button,.connection-form label:first-of-type { grid-column: 1/-1; }
.split { display: grid; grid-template-columns: minmax(0,1fr) minmax(280px,.7fr); gap: 18px; align-items: start; }
.command-palette { position: fixed; inset: 12vh 0 auto; margin: 0 auto; width: min(520px,calc(100vw - 28px)); max-width: none; max-height: 76vh;
  background: var(--surface); border: 1px solid var(--line); border-radius: 14px; padding: 0; color: var(--text); box-shadow: 0 20px 80px #0005; overflow: hidden; }
.command-palette[open] { display: flex; flex-direction: column; }
.command-input { display: flex; align-items: center; gap: 12px; padding: 15px 18px; border-bottom: 1px solid var(--line); }
.command-input .ui-icon { color: var(--muted); }
.command-input input { flex: 1; min-width: 0; border: 0 !important; background: transparent !important; font-size: 15px; outline: none; }
.command-results { padding: 7px; overflow-y: auto; min-height: 0; }
.command-result { display: flex; gap: 12px; padding: 11px 12px; color: var(--text); border-radius: 6px; align-items: center; text-decoration: none; }
.command-result:hover,.command-result.selected { background: var(--soft); color: var(--accent); text-decoration: none; }
.command-result .ui-icon { color: var(--muted); }
.command-footer { display: flex; align-items: center; gap: 5px; padding: 10px 16px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--line); }
.command-footer span { margin-left: auto; } #command-empty { padding: 20px; margin: 0; }
[hidden] { display: none !important; }
.skip-link,.sr-only { position: absolute; left: -10000px; }
.skip-link:focus { left: 12px; top: 12px; background: var(--surface); padding: 12px; z-index: 50; }
@media(max-width: 1100px) {
  .app-shell main { padding: 25px; } .app-shell .topbar { padding: 10px 18px; }
  .breadcrumb,.topbar-left > .ui-icon,.command-trigger kbd,.command-trigger span { display: none; }
  .command-trigger { width: 36px; height: 36px; padding: 8px; }
  .split { grid-template-columns: 1fr; }
}
@media(max-width: 820px) {
  body.app-shell,.compact-nav body.app-shell { display: block; }
  .app-shell .sidebar { position: fixed; top: 0; left: 0; width: 236px; height: 100dvh; transform: translateX(-100%); visibility: hidden; z-index: 20; box-shadow: 0 0 40px #0004; }
  .mobile-nav .sidebar { transform: none; visibility: visible; }
  .mobile-nav .brand { padding-left: 0; padding-right: 0; gap: 7px; }
  .mobile-nav .nav-close { display: inline-flex !important; width: 28px; min-height: 28px; height: 28px; margin-left: auto; color: #d8e9e0; border-color: var(--nav-line); }
  .mobile-nav .nav-close:hover { background: var(--nav-active); }
  .mobile-nav .sidebar .brand > div,.mobile-nav .sidebar .nav-label,.mobile-nav .sidebar .nav-group > span,.mobile-nav .sidebar .nav-footer > div { display: block; }
  .mobile-nav .sidebar nav a { justify-content: flex-start; padding: 10px 11px; }
  .mobile-nav .sidebar .nav-footer { justify-content: flex-start; }
  .mobile-nav .app-body::before { content: ""; position: fixed; inset: 0; z-index: 10; background: #14262265; pointer-events: none; }
  .app-shell .topbar { padding: 9px 14px; min-height: 58px; gap: 8px; }
  .topbar-left,.topbar-actions { gap: 6px; } .topbar-left strong { display: none; }
  #snapshot-slot label { font-size: 0; gap: 0; } .snapshot-picker select { max-width: 165px; }
  .overview-layout,.app-shell .overview-focus,.overview-links { grid-template-columns: 1fr; gap: 16px; }
  .overview-breakdown,.overview-links > div + div { border-left: 0; padding-left: 0; border-top: 1px solid var(--line); padding-top: 12px; }
  .overview-breakdown { border-top-color: #416057; }
  .app-shell main { padding: 20px 15px; } .app-shell section { padding: 15px; }
  .filter-bar label { flex-basis: calc(50% - 10px); } .filter-section { padding: 14px !important; }
  .connection-form { grid-template-columns: 1fr; }
}
@media(max-width: 760px) {
  .inspector { width: 100vw; height: 100vh; height: 100dvh; border-radius: 0; border: 0; }
  .inspector-head { padding: 12px 16px; } #workspace-inspector-body { padding: 16px; }
  .comparison-table { min-width: 560px; } .review-decision { flex-wrap: wrap; } .review-context { text-align: left; }
}
@media(prefers-reduced-motion: reduce) { * { transition: none !important; } }
"""

SCRIPT = r"""
(()=>{
'use strict';
const dialog=document.getElementById('workspace-inspector');
const body=document.getElementById('workspace-inspector-body');
const title=document.getElementById('workspace-inspector-title');
const closeButton=document.getElementById('workspace-close');
const backButton=document.getElementById('workspace-inspector-back');
const history=[];
let opener=null,inspectionRequest=0;
function rememberInspector(button){
 if(!dialog.open||!body.contains(button))return;
 // Move existing nodes, preserving initialized grids, filters and handlers.
 history.push({nodes:Array.from(body.childNodes),title:title.textContent,scroll:body.scrollTop,focus:button});
 // Bound memory retained by repeated nested navigation.
 if(history.length>8)history.shift();
 backButton.hidden=false;
}
backButton.addEventListener('click',()=>{
 if(!history.length)return;
 inspectionRequest++;
 const prior=history.pop();
 title.textContent=prior.title;
 body.replaceChildren(...prior.nodes);
 backButton.hidden=!history.length;
 body.scrollTop=prior.scroll;
 if(prior.focus.isConnected)prior.focus.focus({preventScroll:true});
});
function openInspector(button){
 if(!dialog.open){
  opener=button;
  dialog.showModal();
  document.documentElement.classList.add('inspector-open');
 }
 body.scrollTop=0;closeButton.focus({preventScroll:true});
}
function renderInspector(template,button){
 const content=template.content.cloneNode(true);
 const heading=content.querySelector('.inspector-title');
 title.textContent=heading?heading.textContent.trim():'Configuration review';
 if(heading)heading.remove();
 body.replaceChildren(content);
 for(const grid of body.querySelectorAll('[data-paginated]'))initGrid(grid);
 openInspector(button);
 document.dispatchEvent(new Event('workspace-inspector-loaded'));
}
document.addEventListener('click',async event=>{
 const button=event.target.closest('[data-inspect]');
 if(!button)return;
 const request=++inspectionRequest;
 if(button.dataset.inspectUrl){
  const endpoint=new URL(button.dataset.inspectUrl,location.href);
  if(endpoint.origin!==location.origin)return;
  rememberInspector(button);
  title.textContent='Configuration review';
  const loading=document.createElement('p');loading.textContent='Loading captured evidence…';loading.setAttribute('role','status');
  body.replaceChildren(loading);openInspector(button);
  try{
   const response=await fetch(endpoint,{credentials:'same-origin',cache:'no-store',redirect:'error'});
   if(!response.ok)throw Error('Evidence unavailable');
   const documentCopy=new DOMParser().parseFromString(await response.text(),'text/html');
   const template=documentCopy.querySelector('template[data-advisor-evidence]');
   if(!template)throw Error('Evidence unavailable');
   if(request!==inspectionRequest||!dialog.open)return;
   renderInspector(template,button);
  }catch(error){
   if(request!==inspectionRequest||!dialog.open)return;
   const message=document.createElement('p');
   message.textContent='Unable to load the exact finding. Reopen the worklist if the snapshot changed, or close and retry.';
   message.setAttribute('role','alert');body.replaceChildren(message);
  }
  return;
 }
 const template=button.nextElementSibling;
 if(!template||template.tagName!=='TEMPLATE')return;
 rememberInspector(button);
 renderInspector(template,button);
});
closeButton.addEventListener('click',()=>dialog.close());
dialog.addEventListener('close',()=>{
 inspectionRequest++;
 document.documentElement.classList.remove('inspector-open');
 body.replaceChildren();title.textContent='';
 history.length=0;backButton.hidden=true;
 if(opener&&opener.isConnected)opener.focus({preventScroll:true});
 opener=null;
});
const theme=document.getElementById('workspace-theme');
const menu=document.getElementById('workspace-menu');
const shell=document.documentElement;
const mobile=matchMedia('(max-width: 820px)');
function syncMenu(){
 menu.setAttribute('aria-expanded',String(mobile.matches?shell.classList.contains('mobile-nav'):!shell.classList.contains('compact-nav')));
}
menu.addEventListener('click',()=>{
 shell.classList.toggle(mobile.matches?'mobile-nav':'compact-nav');
 syncMenu();
});
document.getElementById('workspace-nav-close').addEventListener('click',()=>{shell.classList.remove('mobile-nav');syncMenu();menu.focus();});
mobile.addEventListener('change',()=>{shell.classList.remove('mobile-nav');syncMenu();});
syncMenu();
const picker=document.querySelector('.page-intro .snapshot-picker');
if(picker)document.getElementById('snapshot-slot').append(picker);
const palette=document.getElementById('workspace-palette');
const query=document.getElementById('command-query');
const results=document.getElementById('command-results');
const commandButton=document.getElementById('workspace-command');
const pages=Array.from(document.querySelectorAll('.sidebar a[data-nav]'));
let selected=0, matching=[], paletteOpener=null;
function highlight(){
 matching.forEach((link,index)=>link.classList.toggle('selected',index===selected));
 if(matching[selected])matching[selected].scrollIntoView({block:'nearest'});
}
function renderCommands(){
 const terms=query.value.trim().toLowerCase().split(/\s+/);
 matching=pages.filter(a=>terms.every(term=>a.dataset.nav.toLowerCase().includes(term))).map(a=>{
  const item=a.cloneNode(true);
  item.removeAttribute('aria-current');
  item.removeAttribute('data-nav');
  item.className='command-result';
  return item;
 });
 results.replaceChildren(...matching);selected=0;
 document.getElementById('command-empty').hidden=matching.length>0;
 highlight();
}
function openPalette(){
 if(palette.open||document.querySelector('.inspector[open]'))return;
 paletteOpener=document.activeElement;query.value='';renderCommands();palette.showModal();query.focus();
}
commandButton.addEventListener('click',openPalette);
query.addEventListener('input',renderCommands);
query.addEventListener('keydown',event=>{
 if(event.key==='Escape'){event.preventDefault();event.stopPropagation();palette.close();return;}
 if(event.key==='ArrowDown'||event.key==='ArrowUp'){
  event.preventDefault();if(matching.length){selected=(selected+(event.key==='ArrowDown'?1:-1)+matching.length)%matching.length;highlight();}
 }else if(event.key==='Enter'&&matching[selected]){
  event.preventDefault();matching[selected].click();
 }
});
document.addEventListener('keydown',event=>{
 if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){
  if(document.querySelector('.inspector[open]'))return;
  event.preventDefault();if(palette.open)palette.close();else openPalette();
 }else if(event.key==='Escape'&&!palette.open&&shell.classList.contains('mobile-nav')){
  shell.classList.remove('mobile-nav');syncMenu();
 }
});
palette.addEventListener('click',event=>{if(event.target===palette)palette.close();});
palette.addEventListener('close',()=>{if(paletteOpener&&paletteOpener.isConnected)paletteOpener.focus({preventScroll:true});});

function updateThemeLabel(){
 const dark=getComputedStyle(document.documentElement).colorScheme==='dark';
 theme.title=dark?'Switch to light mode':'Switch to dark mode';
 theme.setAttribute('aria-label',theme.title);
 theme.dataset.mode=dark?'dark':'light';
 theme.setAttribute('aria-pressed',String(dark));
}
theme.addEventListener('click',()=>{
 const dark=getComputedStyle(document.documentElement).colorScheme==='dark';
 document.documentElement.dataset.theme=dark?'light':'dark';
 try{sessionStorage.setItem('central-theme',document.documentElement.dataset.theme);}catch{}
 updateThemeLabel();
});
try{const saved=sessionStorage.getItem('central-theme');if(saved==='dark'||saved==='light')shell.dataset.theme=saved;}catch{}
updateThemeLabel();
for(const picker of document.querySelectorAll('.snapshot-picker, .auto-select')){
 picker.querySelector('select').addEventListener('change',()=>picker.requestSubmit());
}
for(const form of document.querySelectorAll('[data-scope-filters]')){
 const options=JSON.parse(form.dataset.scopeFilters);
 const persona=form.elements.namedItem('persona');
 persona.addEventListener('change',()=>{
  const fields=options[persona.value];
  if(!fields)return;
  for(const [name,choices] of Object.entries(fields)){
   const select=form.elements.namedItem(name);
   const previous=select.value;
   select.replaceChildren(...choices.map(([value,label])=>new Option(label,value)));
   if(choices.some(([value])=>String(value)===previous))select.value=previous;
  }
 });
}
function initGrid(grid){
 const rows=Array.from(grid.querySelectorAll(':scope > .table-scroll > table > tbody > tr'));
 const tbody=grid.querySelector(':scope > .table-scroll > table > tbody');
 const paging=grid.querySelector(':scope > .paging');
 const search=grid.querySelector('[data-table-search]');
 const count=grid.querySelector('[data-table-count]');
 const prev=grid.querySelector('[data-prev]'),next=grid.querySelector('[data-next]');
 const pageLabel=grid.querySelector('[data-page]'),empty=grid.querySelector('[data-table-empty]');
 const sizeControl=grid.querySelector('[data-page-size]');
 const headers=Array.from(grid.querySelectorAll(':scope > .table-scroll > table > thead [data-sort-column]'));
 const indexed=rows.map((row,index)=>({row,index,search:row.textContent.toLowerCase(),values:Array.from(row.cells,c=>c.textContent.trim())}));
 const collator=new Intl.Collator(undefined,{numeric:true,sensitivity:'base'});
 let page=0,size=30,ordered=indexed,filtered=indexed,sortColumn=-1,direction=1;
 let lastTerms=null,lastVisible=new Set(rows.filter(row=>!row.hidden));
 function update(reset=false,reorder=false){
  if(reset)page=0;
  const terms=search.value.toLowerCase().trim().split(/\s+/).filter(Boolean);
  const termKey=terms.join(' ');
  if(reorder||termKey!==lastTerms){
   filtered=terms.length?ordered.filter(record=>terms.every(term=>record.search.includes(term))):ordered;
   lastTerms=termKey;
  }
  grid.querySelector('[data-export-csv]').disabled=filtered.length===0;
  const pages=Math.max(1,Math.ceil(filtered.length/size));page=Math.min(page,pages-1);
  const visible=new Set(filtered.slice(page*size,(page+1)*size).map(record=>record.row));
  // Change only rows entering or leaving the displayed page. Preserve DOM
  // nodes (including checkbox selections and inspector templates).
  for(const row of lastVisible)if(!visible.has(row))row.hidden=true;
  for(const row of visible)if(!lastVisible.has(row))row.hidden=false;
  lastVisible=visible;
  count.textContent=filtered.length.toLocaleString()+' of '+rows.length.toLocaleString()+' records';pageLabel.textContent='Page '+(page+1)+' / '+pages;
  if(paging)paging.hidden=pages<=1;
  prev.disabled=page===0;next.disabled=page+1>=pages;empty.hidden=filtered.length!==0;
 }
 for(const button of headers)button.addEventListener('click',()=>{
  const column=Number(button.dataset.sortColumn);
  if(sortColumn===column)direction=-direction;else{sortColumn=column;direction=1;}
  for(const header of headers)header.closest('th').removeAttribute('aria-sort');
  button.closest('th').setAttribute('aria-sort',direction===1?'ascending':'descending');
  ordered=indexed.slice().sort((a,b)=>{
   const left=a.values[column]||'',right=b.values[column]||'';
   if(!left||!right)return left? -1:right?1:a.index-b.index;
   return direction*collator.compare(left,right)||a.index-b.index;
  });
  const fragment=document.createDocumentFragment();
  for(const record of ordered)fragment.append(record.row);
  tbody.append(fragment);update(true,true);
 });
 const exportButton=grid.querySelector('[data-export-csv]');
 exportButton.addEventListener('click',()=>{
  const columns=headers.map(button=>({index:Number(button.dataset.sortColumn),label:button.textContent.trim()}));
  function csvCell(value){
   let text=String(value??'');
   // Spreadsheet programs may execute captured configuration as a formula.
   // Prefix formula-like and leading control characters as literal text.
   if(/^[\s\u0000-\u001f]*[=+\-@]/.test(text)||/^[\t\r\n]/.test(text))text="'"+text;
   return '"'+text.replaceAll('"','""')+'"';
  }
  const records=[columns.map(c=>c.label),...filtered.map(record=>columns.map(c=>record.values[c.index]??''))];
  const content='\uFEFF'+records.map(row=>row.map(csvCell).join(',')).join('\r\n');
  const link=document.createElement('a');
  const objectUrl=URL.createObjectURL(new Blob([content],{type:'text/csv;charset=utf-8'}));
  link.href=objectUrl;link.download='central-worklist.csv';link.click();
  setTimeout(()=>URL.revokeObjectURL(objectUrl),1000);
 });
 sizeControl.addEventListener('change',()=>{size=Number(sizeControl.value);update(true);});
 search.addEventListener('input',()=>update(true));prev.addEventListener('click',()=>{page--;update();});
 next.addEventListener('click',()=>{page++;update();});update();
}
for(const grid of document.querySelectorAll('[data-paginated]'))initGrid(grid);
for(const tabs of document.querySelectorAll('[data-tabs]')){
 const buttons=Array.from(tabs.querySelectorAll('[data-tab]'));
 const panels=Array.from(document.querySelectorAll('[data-panel]')).filter(p=>p.dataset.group===tabs.dataset.tabs);
 function select(name){for(const button of buttons)button.setAttribute('aria-selected',String(button.dataset.tab===name));
  for(const panel of panels)panel.hidden=panel.dataset.panel!==name;}
 for(const button of buttons)button.addEventListener('click',()=>select(button.dataset.tab));
 if(buttons.length)select(buttons[0].dataset.tab);
}
})();
"""
