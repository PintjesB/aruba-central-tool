"""Shared, self-contained UI for the local Central workspace.

All captured data is escaped. No third-party assets, storage, or network calls.
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
    header = "".join(f"<th scope=\"col\">{e(h)}</th>" for h in headers)
    table_class = f' class="{e(style)}"' if style else ""
    controls = ""
    if search:
        controls = (f'<div class="table-toolbar"><label class="searchbox">{e(label)}'
                    '<input type="search" data-table-search placeholder="Filter results"></label>'
                    '<span data-table-count class="muted" aria-live="polite"></span></div>')
    pager = ('<div class="table-toolbar paging"><button type="button" data-prev>Previous</button>'
             '<span data-page class="muted"></span><button type="button" data-next>Next</button></div>') if search else ""
    empty = '<p data-table-empty class="empty" hidden>No matching records.</p>' if search else ""
    return ('<div class="data-grid"' + (' data-paginated' if search else '') + '>' + controls
            + f'<div class="table-scroll"><table{table_class}><thead><tr>{header}</tr></thead><tbody>'
            + "".join(rows) + '</tbody></table></div>' + empty + pager + '</div>')


def tr(*cells, attrs=""):
    return f"<tr{attrs}>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"


def inspect(title, content, label="Inspect"):
    return (f'<button class="quiet inspect-trigger" type="button" data-inspect>{e(label)}</button>'
            f'<template><div class="inspector-title"><h2>{e(title)}</h2></div>{content}</template>')


def diff_table(fields, left="Local", right="Reference"):
    if fields is None:
        return '<p class="empty">No comparable reference captured.</p>'
    if not fields:
        return '<p class="inline-good">Captured configuration bodies are identical.</p>'
    def value(d, key):
        return '<code>' + e(json.dumps(d[key], ensure_ascii=False)) + '</code>' if key in d else '<span class="muted">Not returned</span>'
    return table(("Setting", left, right), [tr(e(".".join(map(str, f["path"])) or "(root)"),
                value(f, "local_value"), value(f, "reference_value")) for f in fields])


def property_table(data):
    if not isinstance(data, dict) or not data:
        return '<p class="empty">No settings captured.</p>'
    return table(("Setting", "Value"), [tr(e(key), '<code>' + e(json.dumps(value, ensure_ascii=False)) + '</code>')
                                        for key, value in sorted(data.items())])


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


def navigation(root, snapshot=None):
    suffix = "?" + urlencode({"snapshot": snapshot}) if snapshot else ""
    links = []
    for group, items in (
        ("Workspace", (("", "Overview", "⌂"), ("overrides", "Device overrides", "⇅"), ("advisor", "Consolidation", "◈"),
                       ("advanced", "Engineering", "▤"))),
        ("Explore", (("report", "Configuration", "▦"), ("scopes", "Inventory", "▥"),
                     ("library", "Library", "▣"), ("compare", "Compare", "⇄"))),
        ("Diagnostics", (("coverage", "Coverage", "◉"),))):
        links.append(f'<div class="nav-group"><span>{e(group)}</span>')
        for route, label, icon in items:
            links.append(f'<a data-nav="{e(label)}" href="{e(root + route + suffix)}">'
                         f'<span class="nav-icon" aria-hidden="true">{icon}</span>{e(label)}</a>')
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
            '<aside class="sidebar"><div class="brand"><span class="brand-mark">C</span>'
            '<div><strong>Central</strong><small>Configuration workspace</small></div></div>'
            f'<nav aria-label="Main navigation">{nav}</nav>'
            '<div class="nav-footer"><span class="lock-dot"></span>Local · read-only</div></aside>'
            '<div class="app-body"><header class="topbar"><span class="workspace-context"><span class="lock-dot"></span> Local audit workspace</span>'
            '<button id="workspace-theme" class="quiet" type="button" aria-label="Switch color theme" aria-pressed="false">Theme</button></header>'
            f'<main id="main-content">{content}</main></div>'
            '<dialog class="inspector" id="workspace-inspector" aria-labelledby="workspace-inspector-title"><div class="inspector-head">'
            '<div><small>Configuration review</small><h2 id="workspace-inspector-title"></h2></div>'
            '<button type="button" id="workspace-close" autofocus>Close <span aria-hidden="true">×</span></button></div>'
            '<div id="workspace-inspector-body"></div></dialog>'
            f'<script>{SCRIPT}</script></body></html>')


CSS = """
:root{font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color-scheme:light;
--bg:#f5f6f9;--surface:#fff;--text:#182236;--muted:#647086;--line:#e2e6ee;--accent:#2459bc;
--soft:#eaf3ff;--green:#176b4a;--green-bg:#e8f5ed;--warn:#935b12;--warn-bg:#fff3df;
--nav:#fff;--nav-text:#56637a;--shadow:0 1px 2px #10182808}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;
--bg:#101925;--surface:#182535;--text:#e5edf8;--muted:#a0b2ca;--line:#334357;--accent:#8fc5ff;
--soft:#203c59;--green:#9bdfbb;--green-bg:#193e33;--warn:#ffd18a;--warn-bg:#493720;--nav:#142031;--nav-text:#b5c2d5;--shadow:none}}
:root[data-theme=dark]{color-scheme:dark;--bg:#101925;--surface:#182535;--text:#e5edf8;--muted:#a0b2ca;
--line:#334357;--accent:#8fc5ff;--soft:#203c59;--green:#9bdfbb;--green-bg:#193e33;--warn:#ffd18a;--warn-bg:#493720;--nav:#142031;--nav-text:#b5c2d5;--shadow:none}
*{box-sizing:border-box}body.app-shell{margin:0;background:var(--bg);color:var(--text);display:grid;grid-template-columns:224px minmax(0,1fr);min-height:100vh}
.app-shell .sidebar{position:sticky;top:0;height:100vh;background:var(--nav);color:var(--nav-text);padding:24px 14px;display:flex;flex-direction:column;overflow:auto;border-right:1px solid var(--line)}
.brand{display:flex;gap:12px;align-items:center;padding:0 8px 30px;color:var(--text)}.brand strong{font-size:18px;display:block;letter-spacing:-.5px}
.brand small{font-size:11px;color:var(--nav-text);display:block}.brand-mark{display:grid;place-items:center;width:36px;height:36px;border-radius:10px;background:var(--accent);color:var(--surface);font-weight:800;font-size:21px;flex-shrink:0}
.nav-group{margin:0 0 21px}.nav-group>span{display:block;text-transform:uppercase;font-size:10px;font-weight:700;letter-spacing:1px;padding:0 12px 7px;color:var(--muted)}
.sidebar nav a{display:flex;gap:11px;align-items:center;color:var(--nav-text);padding:9px 12px;border-radius:7px;text-decoration:none;margin:2px 0;font-weight:550}
.sidebar nav a:hover{background:var(--bg);color:var(--text)}.sidebar nav a[aria-current=page]{background:var(--soft);color:var(--accent);font-weight:650}
.nav-icon{font-size:17px;width:21px;text-align:center;color:inherit}.nav-footer{margin-top:auto;padding:14px 8px 0;border-top:1px solid var(--line);font-size:12px}
.lock-dot{display:inline-block;background:#7bd1a2;width:7px;height:7px;border-radius:50%;margin-right:6px}.app-body{min-width:0}
.app-shell .topbar{position:sticky;top:0;z-index:4;background:var(--surface);border-bottom:1px solid var(--line);color:var(--text);padding:12px 28px;display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:13px}
.app-shell main{max-width:1680px;margin:0 auto;padding:30px 32px;min-width:0}.page-intro{display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap;margin-bottom:22px}
h1{font-size:30px;font-weight:700;letter-spacing:-1px;line-height:1.2;margin:0 0 6px}h2{font-size:18px;letter-spacing:-.25px;margin:0 0 12px}h3{font-size:15px;margin:0 0 8px}h4{font-size:13px;margin:0 0 6px}
p{margin:0 0 12px}.muted,small{color:var(--muted)}small{font-size:12px}.muted{font-size:13px}.page-intro p{margin:0}
.app-shell section{background:var(--surface);border:1px solid var(--line);border-radius:11px;box-shadow:var(--shadow);padding:22px;margin:0 0 20px}
.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px}.section-head h2{margin:0}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}button,input,select{font:inherit;color:var(--text)}
button,.button{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 12px;border:1px solid var(--line);border-radius:7px;background:var(--surface);cursor:pointer;text-decoration:none;color:var(--text);font-weight:550;white-space:nowrap}
button:hover,.button:hover{border-color:var(--accent);text-decoration:none}button.primary,.button.primary,button[type=submit]:not(.quiet){background:#176bc1;color:white;border-color:#176bc1}
button.quiet{background:transparent}.inspect-trigger{color:var(--accent);border-color:transparent;padding:6px 9px}.inspect-trigger:hover{background:var(--soft);border-color:transparent}.reset-link{border:0;background:transparent;color:var(--muted)}button:disabled{opacity:.5;cursor:default}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
input:not([type=checkbox]):not([type=radio]),select{border:1px solid var(--line);border-radius:7px;background:var(--surface);padding:8px 10px;min-height:37px;max-width:100%}
input[type=checkbox]{accent-color:#176bc1;width:16px;height:16px;vertical-align:middle;margin:0}label{display:grid;gap:4px;color:var(--muted);font-weight:600;font-size:12px}
form,.toolbar,.table-toolbar,.snapshot-picker{display:flex;flex-wrap:wrap;align-items:end;gap:10px}.snapshot-picker select{max-width:260px}.snapshot-picker{margin:0}.snapshot-picker label{font-size:11px}.snapshot-picker select{font-weight:600}
.filter-section{padding:16px 20px!important}.filter-bar{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}.filter-bar label{flex:1 1 155px;min-width:0}.filter-bar select,.filter-bar input{width:100%;min-width:0}.filter-bar .searchbox{max-width:none}.filter-bar button{min-height:38px}.filter-hint{font-size:12px;color:var(--muted);margin:12px 0 0}
.collection-nav{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 16px;flex-wrap:wrap}.collection-nav select{max-width:250px}
.usage-stack{display:grid;gap:0}.usage-stack>div{min-height:40px;display:flex;align-items:center;gap:6px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.usage-stack>div:last-child{border-bottom:0}.retain-mark{font-size:10px;color:var(--accent);font-weight:650}
.overview-focus{display:grid;grid-template-columns:1.2fr minmax(0,1fr);align-items:center;gap:32px;padding:28px!important}.overview-focus h2{font-size:24px;margin:6px 0 10px;letter-spacing:-.5px}.overview-focus p,.overview-links p{color:var(--muted)}.overview-breakdown{border-left:1px solid var(--line);padding-left:24px}.overview-breakdown>div{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:11px 0;border-bottom:1px solid var(--line)}.overview-breakdown>div:last-child{border:0}.overview-breakdown strong{font-size:22px;font-variant-numeric:tabular-nums}.overview-links{display:grid;grid-template-columns:1fr 1fr;gap:24px}.overview-links>div+div{border-left:1px solid var(--line);padding-left:24px}.connection-details>summary{font-weight:650;font-size:15px;color:var(--text);margin:0}.connection-details[open]>summary{margin-bottom:14px}
@media(max-width:800px){.overview-focus,.overview-links{grid-template-columns:1fr;gap:16px}.overview-breakdown,.overview-links>div+div{border-left:0;padding-left:0;border-top:1px solid var(--line);padding-top:12px}}
.result-summary{display:flex;gap:8px 18px;flex-wrap:wrap;align-items:center;margin:0 0 16px;color:var(--muted);font-size:13px}.result-summary strong{font-size:17px;color:var(--text);font-variant-numeric:tabular-nums}
.workspace-context{color:var(--muted);font-size:12px}.workspace-context .lock-dot{background:var(--green)}
@media(max-width:680px){.filter-bar label{flex-basis:calc(50% - 12px)}.filter-bar{gap:10px}.filter-section{padding:14px!important}}
.overview-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin:0 0 20px}
.metric-card{padding:17px;background:var(--surface);border:1px solid var(--line);border-radius:10px;display:grid;gap:5px;box-shadow:var(--shadow)}
.metric-card span{color:var(--muted);font-weight:600;font-size:12px}.metric-card strong{font-size:27px;font-variant-numeric:tabular-nums;line-height:1.2}
.metric-card small{font-size:11px}.workflow-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin-bottom:20px}
.workflow-card{display:block;color:var(--text);padding:17px;background:var(--surface);border:1px solid var(--line);border-radius:10px}
.workflow-card:hover{border-color:var(--accent);text-decoration:none}.workflow-card strong{display:block;margin-bottom:6px}.workflow-card span{display:block;color:var(--muted);font-size:13px}.workflow-card .arrow{color:var(--accent);margin-top:10px}
.table-scroll{overflow-x:auto;max-width:100%}table{width:100%;border-collapse:separate;border-spacing:0;text-align:left;font-variant-numeric:tabular-nums}
th{font-size:12px;letter-spacing:0;font-weight:650;color:var(--muted);background:var(--bg);white-space:normal}th:first-child{border-radius:6px 0 0 6px}th:last-child{border-radius:0 6px 6px 0}
td,th{padding:12px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}td{overflow-wrap:anywhere}
tbody tr:hover{background:var(--soft)}tbody tr:last-child td{border-bottom:0}td strong{font-weight:650}td small{display:block;margin-top:2px}
.table-toolbar{align-items:center;justify-content:space-between;margin:0 0 12px}.paging{margin:12px 0 0;justify-content:flex-end}
.searchbox{flex:1;max-width:360px}.searchbox input{width:100%}.tag{display:inline-block;border-radius:5px;padding:3px 7px;font-size:11px;font-weight:650;white-space:normal}
.tag.neutral{background:var(--bg);color:var(--muted)}.tag.good,.inline-good{background:var(--green-bg);color:var(--green)}.tag.warn,.pill{background:var(--warn-bg);color:var(--warn)}
.tag.info{background:var(--soft);color:var(--accent)}.inline-good{padding:10px 12px;border-radius:7px}
.empty{color:var(--muted);padding:16px 0}.note{font-size:12px;color:var(--muted);padding:10px 12px;border-left:3px solid var(--line);margin:8px 0 12px}
.raw{border-top:1px solid var(--line);margin-top:16px;padding-top:8px}.raw summary{font-size:12px;color:var(--muted)}
summary{cursor:pointer;color:var(--accent);font-weight:550;margin:8px 0}pre,code{font:12px/1.55 ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
pre{background:var(--bg);border:1px solid var(--line);padding:12px;max-height:420px;overflow:auto;border-radius:7px;margin:8px 0}
html:has(.inspector[open]),html.inspector-open{overflow:hidden;scrollbar-gutter:stable}
.inspector{position:fixed;inset:0;margin:auto;width:min(1240px,calc(100vw - 48px));height:calc(100vh - 48px);height:calc(100dvh - 48px);max-height:none;max-width:none;border:1px solid var(--line);border-radius:12px;background:var(--surface);color:var(--text);padding:0;overflow:hidden;box-shadow:0 18px 70px #0005}
.inspector[open]{display:flex;flex-direction:column}
.inspector::backdrop{background:#07132288}
.inspector-head{flex:none;display:flex;justify-content:space-between;align-items:center;gap:16px;background:var(--surface);padding:16px 24px;border-bottom:1px solid var(--line)}
.inspector-head small{display:block;font-size:11px;margin-bottom:3px}.inspector-head h2{font-size:21px;line-height:1.3;margin:0;overflow-wrap:anywhere}
#workspace-inspector-body{flex:1;min-height:0;min-width:0;padding:20px 24px 28px;overflow-y:auto;overflow-x:hidden;overscroll-behavior:contain;scrollbar-gutter:stable}
.inspector h3{margin:20px 0 8px}.inspector .table-scroll{max-height:none;overflow-x:auto;overflow-y:hidden}
.inspector .data-grid{min-width:0}.inspector th{white-space:normal}.inspector td{vertical-align:top}
.inspector pre{max-height:none;overflow:visible}.inspector ul,.inspector ol{padding-left:22px;margin:8px 0 16px}
.inspector .note{border:0;background:var(--bg);border-radius:6px;padding:10px 12px}
.inspector details:not(.raw){border-top:1px solid var(--line);padding:5px 0}
.review-decision{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;padding:14px 16px;margin:0 0 18px;background:var(--bg);border-radius:8px}
.review-decision p{margin:8px 0 0}.review-context{min-width:0;text-align:right}.review-context strong{display:block;overflow-wrap:anywhere}
.comparison-summary{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:0 0 12px}
.comparison-summary .tag{font-size:12px;padding:5px 9px}
.comparison-table{table-layout:fixed}.comparison-table th,.comparison-table td{padding:9px 10px}
.comparison-table th:nth-child(1){width:23%}.comparison-table th:nth-child(2){width:15%}.comparison-table th:nth-child(3){width:25%}.comparison-table th:nth-child(4){width:20%}.comparison-table th:nth-child(5){width:17%}
.comparison-table td:first-child{font-weight:600}.comparison-table td small{font-size:11px;line-height:1.3}
.comparison-table td .tag{white-space:normal}.comparison-table tbody tr[data-comparison=different]{background:var(--warn-bg)}
@media(max-width:760px){.inspector{width:100vw;height:100vh;height:100dvh;border-radius:0;border:0}.inspector-head{padding:12px 16px}#workspace-inspector-body{padding:16px}.comparison-table{min-width:560px}}
.inspector li{margin-bottom:5px}.tabs{display:flex;gap:5px;flex-wrap:wrap;border-bottom:1px solid var(--line);margin-bottom:16px}
.tabs button{border:0;border-radius:0;border-bottom:3px solid transparent;background:transparent;font-size:13px;padding:9px 11px;color:var(--muted)}
.tabs button[aria-selected=true]{border-bottom-color:var(--accent);color:var(--accent);font-weight:700}.tabs button span{font-size:11px;color:var(--muted);margin-left:4px}
.audit-state{border-left:3px solid var(--accent);background:var(--bg);padding:12px 15px;border-radius:6px;margin:0 0 16px}
.audit-state[data-state=complete]{border-color:var(--green)}.audit-state[data-state=failed]{border-color:#cc5246}.audit-state p{margin:5px 0}
progress{width:100%;height:13px;accent-color:#2683d6}.connection-form{display:grid;grid-template-columns:1fr 1fr;gap:12px}.connection-form button{grid-column:1/-1}
.connection-form label:first-of-type{grid-column:1/-1}.split{display:grid;grid-template-columns:minmax(0,1fr) minmax(280px,.7fr);gap:18px;align-items:start}
[hidden]{display:none!important}.skip-link{position:absolute;left:-10000px}.skip-link:focus{left:12px;top:12px;background:var(--surface);padding:12px;z-index:50}
@media(max-width:1000px){body.app-shell{grid-template-columns:184px minmax(0,1fr)}.app-shell main{padding:20px}.split{grid-template-columns:1fr}.app-shell .topbar{padding:12px 20px}}
@media(max-width:680px){body.app-shell{display:block}.app-shell .sidebar{position:static;height:auto;padding:10px}.brand{padding:0 6px 12px}.sidebar nav{display:flex;flex-wrap:wrap;gap:5px}.nav-group{display:contents}.nav-group>span,.nav-icon,.nav-footer{display:none}.sidebar nav a{padding:6px 9px;font-size:12px}.app-shell main{padding:14px}.connection-form{grid-template-columns:1fr}.app-shell section{padding:14px}.app-shell .topbar{position:static}}
"""

SCRIPT = r"""
(()=>{
'use strict';
const dialog=document.getElementById('workspace-inspector');
const body=document.getElementById('workspace-inspector-body');
const title=document.getElementById('workspace-inspector-title');
const closeButton=document.getElementById('workspace-close');
let opener=null;
document.addEventListener('click',event=>{
 const button=event.target.closest('[data-inspect]');
 if(!button)return;
 const template=button.nextElementSibling;
 if(!template||template.tagName!=='TEMPLATE')return;
 const content=template.content.cloneNode(true);
 const heading=content.querySelector('.inspector-title');
 title.textContent=heading?heading.textContent.trim():'Configuration review';
 if(heading)heading.remove();
 body.replaceChildren(content);
 for(const grid of body.querySelectorAll('[data-paginated]'))initGrid(grid);
 if(!dialog.open){
  opener=button;
  dialog.showModal();
  document.documentElement.classList.add('inspector-open');
 }
 body.scrollTop=0;closeButton.focus({preventScroll:true});
});
closeButton.addEventListener('click',()=>dialog.close());
dialog.addEventListener('close',()=>{
 document.documentElement.classList.remove('inspector-open');
 body.replaceChildren();title.textContent='';
 if(opener&&opener.isConnected)opener.focus({preventScroll:true});
 opener=null;
});
const theme=document.getElementById('workspace-theme');
function updateThemeLabel(){
 const dark=getComputedStyle(document.documentElement).colorScheme==='dark';
 theme.textContent=dark?'Light mode':'Dark mode';
 theme.setAttribute('aria-pressed',String(dark));
}
theme.addEventListener('click',()=>{
 const dark=getComputedStyle(document.documentElement).colorScheme==='dark';
 document.documentElement.dataset.theme=dark?'light':'dark';
 updateThemeLabel();
});
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
 const paging=grid.querySelector('.paging');
 const search=grid.querySelector('[data-table-search]');
 const count=grid.querySelector('[data-table-count]');
 const prev=grid.querySelector('[data-prev]'),next=grid.querySelector('[data-next]');
 const pageLabel=grid.querySelector('[data-page]'),empty=grid.querySelector('[data-table-empty]');
 let page=0;const size=30;
 function update(reset=false){
  if(reset)page=0;
  const term=search.value.toLowerCase().trim();
  const filtered=rows.filter(r=>r.textContent.toLowerCase().includes(term));
  const pages=Math.max(1,Math.ceil(filtered.length/size));page=Math.min(page,pages-1);
  const visible=new Set(filtered.slice(page*size,(page+1)*size));
  for(const row of rows)row.hidden=!visible.has(row);
  count.textContent=filtered.length.toLocaleString()+' of '+rows.length.toLocaleString()+' records';pageLabel.textContent='Page '+(page+1)+' / '+pages;
  if(paging)paging.hidden=pages<=1;
  prev.disabled=page===0;next.disabled=page+1>=pages;empty.hidden=filtered.length!==0;
 }
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
