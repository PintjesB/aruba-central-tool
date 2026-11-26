"""Loopback-only configuration workspace backed by private audit files."""
import json
import os
import re
import secrets
import threading
import time
import webbrowser
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit


CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'")


def e(value):
    return escape(str(value), quote=True)


def audit_files(directory):
    """Use only direct, non-symlink audit files in the selected workspace."""
    return sorted((p for p in directory.glob("config-audit-*.json")
                   if p.is_file() and not p.is_symlink()
                   and re.fullmatch(r"config-audit-[A-Za-z0-9-]+\.json", p.name)),
                  key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)


def read_audit(directory, name):
    path = next((p for p in audit_files(directory) if p.name == name), None)
    if path is None:
        raise ValueError("Unknown snapshot")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or data.get("kind") != "configuration_audit":
        raise ValueError("Not a configuration audit")
    return data


def page(title, content, nav=""):
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>""" + e(title) + """</title>
<style>
:root{font:14px/1.5 system-ui,sans-serif;color-scheme:light dark;--surface:#fff;--text:#19304a;--line:#d8e1ee;--bg:#f3f6fb}
@media(prefers-color-scheme:dark){:root{--surface:#182538;--text:#e8effa;--line:#3b4b62;--bg:#101a2a}}
body{margin:0;background:var(--bg);color:var(--text)}header{padding:18px 30px;background:#18304c;color:white}
header a{color:#b8dcff;margin-right:20px}main{max-width:1250px;margin:auto;padding:25px}
h1{font-size:23px;margin:0 0 10px}h2{font-size:18px}section{background:var(--surface);border:1px solid var(--line);border-radius:10px;margin:18px 0;padding:20px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
button,select,input{font:inherit;padding:8px 12px;margin:4px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:inherit}
a{color:#1674c8}@media(prefers-color-scheme:dark){a{color:#8dc2ff}}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}
progress{width:100%;height:18px;accent-color:#1683dc}.audit-state{border-left:4px solid #1683dc;padding:12px 16px;background:var(--bg);border-radius:7px}.audit-state[data-state=complete]{border-color:#249761}.audit-state[data-state=failed]{border-color:#cc5246}.audit-state h3{margin:0 0 6px}.audit-state p{margin:6px 0}label{display:inline-block;margin:6px}small{opacity:.8}.pill{padding:4px 8px;border-radius:6px;background:#fff0d7;color:#804a0b}
</style></head><body><header><h1>Central Configuration Workspace</h1>""" + nav + "</header><main>" + content + "</main></body></html>"


def options(items, selected=None):
    return "".join(f'<option value="{e(key)}"{" selected" if key == selected else ""}>{e(label)}</option>'
                   for key, label in items)


def module_coverage(bundle):
    """Count actual qualified scopes, not merely successful API requests."""
    result = []
    for persona, entry in sorted(bundle["results"].items()):
        for module, data in sorted(entry["modules"].items()):
            scopes = data["scope_results"]
            qualified = sum(s.get("review", {}).get("qualified") is True for s in scopes)
            result.append({"persona": persona, "module": module, "qualified": qualified,
                           "total": len(scopes), "status": "qualified" if scopes and qualified == len(scopes)
                           else "partial" if qualified else "unqualified"})
    return result


def credential_refresh(client_id, client_secret, region):
    """One-shot credentials captured in a worker closure, not a workspace or file."""
    from central_tool import Central, EU_REGIONS, detect_region, configuration_audit, audit_progress
    if region and region not in EU_REGIONS:
        raise ValueError("Choose an official EU region")
    if not client_id.strip() or not client_secret or len(client_id) > 1024 or len(client_secret) > 4096:
        raise ValueError("Invalid credentials")
    client = Central(region or EU_REGIONS[0], None, client_id, client_secret)
    def run(progress=None):
        try:
            audit_progress(progress, "Connection", 0, 0, "Authenticating and detecting region")
            detect_region(client, region or None)
            return configuration_audit(client, progress=progress)
        finally:
            client.client_id = None
            client.client_secret = None
            client.token = None
    return run


def library_profile_comparison(bundle, module):
    """Join only exact profile identities; absence of assignments proves nothing."""
    from central_tool import canonical, field_differences, profile_body
    library = bundle.get("library", {})
    view = library.get("modules", {}).get(module, {})
    if view.get("status") != "list_parsed":
        return {}
    assignments = library.get("assignments", {})
    by_identity = {}
    for identity, profile in view["profiles"].items():
        matches = [r for r in assignments.get("rows", [])
                   if r.get("profile-type") == module and type(r.get("profile-instance")) in (str, int)
                   and str(r["profile-instance"]) == identity]
        by_identity[identity] = {"profile": profile_body(profile), "assignments": matches,
                                 "assignment_completeness_verified": False, "local_variants": []}
    for persona, data in bundle["results"].items():
        scope_names = {s["id"]: s.get("name") or s["id"] for s in data["scopes"]}
        for scope in data["modules"].get(module, {}).get("scope_results", []):
            if not scope["review"]["qualified"]:
                continue
            for row in scope["review"]["profiles"]:
                identity = row["identity"]
                if identity not in by_identity or row.get("local") is None:
                    continue
                target = by_identity[identity]
                differences = field_differences(row["local"], target["profile"])
                target["local_variants"].append({"persona": persona, "scope": scope["scope"],
                                                 "scope_name": scope_names.get(scope["scope"], scope["scope"]),
                                                 "classification": "exact_match" if canonical(row["local"]) == canonical(target["profile"])
                                                 else "different_body", "differences": differences})
    return by_identity


def compare_devices(bundle, persona, left, right, module=None):
    """Compare captured effective bodies only, within one persona and capture."""
    from central_tool import field_differences, profile_body
    entry = bundle["results"].get(persona)
    if entry is None or left == right:
        raise ValueError("Select two distinct devices of the same function")
    devices = {s["id"] for s in entry["scopes"] if s["kind"] == "device"}
    if left not in devices or right not in devices:
        raise ValueError("Unknown device")
    results = []
    for name, data in sorted(entry["modules"].items()):
        if module and name != module:
            continue
        # Port IDs are device-specific. Expose them only on explicit selection.
        if not module and name in {"ethernet-interfaces", "vlan-interfaces", "portchannels"}:
            continue
        by_scope = {s["scope"]: s["effective_view"] for s in data["scope_results"]}
        a, b = by_scope.get(left, {}), by_scope.get(right, {})
        if a.get("status") != "list_parsed" or b.get("status") != "list_parsed":
            results.append({"module": name, "status": "unqualified", "differences": []})
            continue
        pa, pb = a["profiles"], b["profiles"]
        diffs = []
        for identity in sorted(pa.keys() | pb.keys()):
            if identity not in pa or identity not in pb:
                diffs.append({"identity": identity, "status": "left_only" if identity in pa else "right_only",
                              "left": profile_body(pa[identity]) if identity in pa else None,
                              "right": profile_body(pb[identity]) if identity in pb else None})
                continue
            fields = field_differences(profile_body(pa[identity]), profile_body(pb[identity]))
            if fields:
                diffs.append({"identity": identity, "status": "different", "fields": fields})
        results.append({"module": name, "status": "different" if diffs else "exact_match",
                        "differences": diffs})
    return results


class Workspace:
    def __init__(self, directory, refresh=None):
        self.directory = Path(directory).resolve(strict=True)
        if not self.directory.is_dir():
            raise ValueError("Workspace must be a directory")
        self.token = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.refresh = refresh
        self.lock = threading.Lock()
        self.state = "idle"
        self.phase = ""
        self.detail = ""
        self.done = 0
        self.total = 0
        self.started = None
        self.finished = None
        self.snapshot = None

    def update_progress(self, phase, done, total, detail):
        with self.lock:
            self.phase = phase
            self.done = done
            self.total = total
            self.detail = detail

    def status(self):
        with self.lock:
            elapsed = (self.finished or time.monotonic()) - self.started if self.started is not None else 0
            return {"state": "failed" if self.state.startswith("failed") else self.state,
                    "message": self.state, "phase": self.phase, "detail": self.detail,
                    "done": self.done, "total": self.total, "elapsed": int(elapsed),
                    "snapshot": self.snapshot}

    def start_refresh(self, one_shot=None):
        with self.lock:
            refresh = one_shot if one_shot is not None else self.refresh
            if refresh is None or self.state == "running":
                return False
            self.state = "running"
            self.phase = "Connection"
            self.detail = "Starting read-only audit"
            self.done = self.total = 0
            self.started = time.monotonic()
            self.finished = None
            self.snapshot = None
        def run():
            try:
                from central_tool import write_private
                bundle = refresh(progress=self.update_progress)
                self.update_progress("Saving snapshot", 0, 0, "Publishing the completed audit")
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
                target = self.directory / f"config-audit-{stamp}.json"
                temporary = target.with_suffix(".partial")
                try:
                    write_private(temporary, bundle)
                    os.replace(temporary, target)
                finally:
                    temporary.unlink(missing_ok=True)
                state = "complete"
                snapshot = target.name
            except Exception as exc:
                snapshot = None
                # Expose only a known HTTP status, never arbitrary exception data.
                from central_tool import APIError
                if isinstance(exc, APIError):
                    stage = "OAuth" if str(exc).startswith("OAuth:") else "Central API"
                    state = f"failed; {stage} returned HTTP {exc.status}"
                else:
                    state = "failed; check local configuration and API access"
            with self.lock:
                self.state = state
                self.finished = time.monotonic()
                self.snapshot = snapshot
                self.phase = "Complete" if state == "complete" else "Failed"
                self.detail = "Snapshot saved" if state == "complete" else state
                self.done = self.total = 0
        threading.Thread(target=run, daemon=True).start()
        return True

    def nav(self):
        root = "/" + self.token + "/"
        return f'<a href="{root}">Snapshots</a><a href="{root}advisor">Consolidation advisor</a><a href="{root}coverage">Module coverage</a><a href="{root}library">Library</a><a href="{root}scopes">Scopes</a><a href="{root}compare">Compare devices</a>'

    def home(self):
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        status = self.status()
        state = status["state"]
        from central_tool import EU_REGIONS
        disabled = " disabled" if state == "running" else ""
        hidden = f'<input type="hidden" name="csrf" value="{e(self.csrf)}">'
        refresh = (f'<form method="post" action="{root}credentials" autocomplete="off">' + hidden +
                   '<label>API region<select name="region">'
                   + options([("", "Detect EU region")] + [(r, urlsplit(r).hostname.split(".")[0].upper()) for r in EU_REGIONS])
                   + '</select></label><label>Client ID<input name="client_id" type="text" required maxlength="1024" autocomplete="off"></label>'
                   '<label>Client secret<input name="client_secret" type="password" required maxlength="4096" autocomplete="new-password"></label>'
                   f'<button type="submit"{disabled}>Connect and refresh</button></form>'
                   '<p><small>Credentials are used only for this audit, in process memory. '
                   'They are not saved or returned by the application. Decline browser password-saving prompts.</small></p>')
        if self.refresh is not None:
            refresh += (f'<form method="post" action="{root}refresh">' + hidden + '<button type="submit"'
                       + (" disabled" if state == "running" else "")
                       + ">Refresh using environment credentials</button></form>")
        title = {"idle": "Ready to connect", "running": "Audit in progress",
                 "complete": "Audit complete", "failed": "Audit failed"}[state]
        snapshot_link = ""
        if status["snapshot"]:
            href = root + "report?" + urlencode({"snapshot": status["snapshot"]})
            advisor = root + "advisor?" + urlencode({"snapshot": status["snapshot"]})
            snapshot_link = f'<p><a href="{e(advisor)}">Review consolidation recommendations</a> · <a href="{e(href)}">Open new configuration snapshot</a></p>'
        progress_html = (
            f'<div class="audit-state" id="audit-state" data-state="{e(state)}" data-status-url="{root}status">'
            f'<h3 id="audit-title" role="status">{e(title)}</h3>'
            f'<p id="audit-detail">{e(status["phase"])} {e(status["detail"])}</p>'
            f'<progress id="audit-progress" max="{max(1, status["total"])}"'
            + (f' value="{status["done"]}"' if status["total"] else "")
            + ("" if state == "running" else " hidden")
            + f'></progress><p id="audit-count">{status["done"]}/{status["total"]} · {status["elapsed"]}s</p>'
            + snapshot_link + '</div>')
        script = """
<script>
const panel=document.getElementById('audit-state');
const title=document.getElementById('audit-title');
const detail=document.getElementById('audit-detail');
const bar=document.getElementById('audit-progress');
const count=document.getElementById('audit-count');
for(const form of document.querySelectorAll('form[method=post]')){
  form.addEventListener('submit',()=>{
    title.textContent='Connecting to Central…';
    detail.textContent='Starting audit. Please keep the local application open.';
    panel.dataset.state='running';
    bar.hidden=false;bar.removeAttribute('value');
    for(const button of document.querySelectorAll('form[method=post] button'))button.disabled=true;
  });
}
async function poll(){
  try {
    const response=await fetch(panel.dataset.statusUrl,{cache:'no-store',credentials:'same-origin'});
    if(!response.ok)throw Error('Status unavailable');
    const state=await response.json();
    if(state.state!=='running'){location.reload();return;}
    title.textContent='Audit in progress';
    detail.textContent=[state.phase,state.detail].filter(Boolean).join(' · ');
    bar.hidden=false;
    if(state.total>0){bar.max=state.total;bar.value=state.done;}
    else{bar.removeAttribute('value');}
    count.textContent=(state.total>0?state.done+'/'+state.total+' · ':'')+state.elapsed+'s elapsed';
  } catch(error) {
    detail.textContent='Unable to reach the local status endpoint. Retrying…';
  }
  setTimeout(poll,1000);
}
if(panel.dataset.state==='running')poll();
</script>"""
        return page("Snapshots", '<p>Private local workspace. Select a saved configuration capture. '
                    'Use a separate directory for each customer; tenant identity is not independently verified.</p>'
                    f'<section><h2>Audit refresh</h2>{progress_html}{refresh}'
                    f'<p><a href="{root}">Reload status</a></p></section><section><h2>Saved snapshots ({len(files)})</h2>'
                    '<table><thead><tr><th>Capture file</th><th>Action</th></tr></thead><tbody>' +
                    "".join(f'<tr><td>{e(p.name)}</td><td><a href="{root}report?{e(urlencode({"snapshot": p.name}))}">Open explorer</a>'
                            f' · <a href="{root}advisor?{e(urlencode({"snapshot": p.name}))}">Consolidation advisor</a>'
                            f' · <a href="{root}coverage?{e(urlencode({"snapshot": p.name}))}">Module coverage</a>'
                            f' · <a href="{root}scopes?{e(urlencode({"snapshot": p.name}))}">Browse scopes</a>' 
                            f' · <a href="{root}compare?{e(urlencode({"snapshot": p.name}))}">Compare devices</a></td></tr>'
                            for p in files) + '</tbody></table></section>' + script, self.nav())

    def advisor(self, query):
        from central_tool import refresh_configuration_review
        from consolidation import LABELS, profile_recommendations
        from collections import Counter
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        if not files:
            return page("Consolidation advisor", "<p>No snapshots available.</p>", self.nav())
        name = query.get("snapshot", files[0].name)
        bundle = refresh_configuration_review(read_audit(self.directory, name))
        findings = profile_recommendations(bundle)
        counts = Counter(f["action"] for f in findings)
        cards = "".join(
            f'<button type="button" class="advisor-card" data-action="{e(k)}"><strong>{counts[k]}</strong><span>{e(v)}</span></button>'
            for k, v in LABELS.items())
        modules = sorted({f["module"] for f in findings})
        people = sorted({f["persona"] for f in findings})
        rows = []
        for f in findings:
            sources = ", ".join(s["name"] for s in f["sources"]) or "Library"
            observed = f["observed_devices"]
            coverage = " / ".join(f"{len(observed.get(k, []))} {k}" for k in
                                  ("matching", "different", "absent", "unknown")) if observed else "Not assessed"
            details = {"source_profiles": f["sources"], "local": f["local"], "reference": f["reference"],
                       "differences": f["differences"], "observed_devices": observed}
            rows.append(
                f'<tr data-action="{e(f["action"])}" data-module="{e(f["module"])}" data-persona="{e(f["persona"])}">'
                f'<td><input type="checkbox" class="choose" aria-label="Select recommendation" data-plan="{e(json.dumps(f, ensure_ascii=False))}"></td>'
                f'<td><strong>{e(LABELS[f["action"]])}</strong><br><small>{e(f["persona"])}</small></td>'
                f'<td>{e(f["module"])}<br><strong>{e(f["identity"])}</strong></td>'
                f'<td>{len(f["sources"])} local scopes<br>{e(sources)}</td>'
                f'<td>{e(f["target"])}</td><td>{e(coverage)}</td>'
                '<td><span class="pill">Review required</span>'
                '<details><summary>Evidence and steps</summary>'
                + '<ol>' + "".join(f'<li>{e(step)}</li>' for step in f["steps"]) + '</ol>'
                + '<ul>' + "".join(f'<li>{e(b)}</li>' for b in f["blockers"]) + '</ul>'
                + f'<pre>{e(json.dumps(details, indent=2, ensure_ascii=False))}</pre></details></td></tr>')
        controls = (
            f'<form method="get" action="{root}advisor"><label>Snapshot<select name="snapshot">'
            + options([(p.name, p.name) for p in files], name)
            + '</select></label><button>Open</button></form>'
            '<div class="advisor-cards">' + cards + '</div>'
            '<div class="advisor-filters"><label>Action<select id="action">'
            + options([("", "All recommendations")] + list(LABELS.items()))
            + '</select></label><label>Module<select id="module">'
            + options([("", "All modules")] + [(m, m) for m in modules])
            + '</select></label><label>Device function<select id="persona">'
            + options([("", "All functions")] + [(p, p) for p in people])
            + '</select></label><label>Search<input id="search" type="search" placeholder="Profile or device"></label>'
            '<button type="button" id="clear">Clear filters</button></div>')
        plan = (
            '<section><h2>Selected change preview</h2><p id="selected" aria-live="polite">0 selected</p>'
            '<p>Review-only. These steps are not executable API operations. Unknown inheritance, destination scope, '
            'dependencies and rollback must be resolved before any write.</p>'
            '<button id="select-visible" type="button">Select visible</button>'
            '<button id="clear-selection" type="button">Clear selection</button>'
            '<button id="export-plan" type="button" disabled>Export private preview JSON</button>'
            '<pre id="preview">Select recommendations to inspect the proposed workflow.</pre></section>')
        script = """
<style>
.advisor-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin:12px 0}
.advisor-card{display:grid;text-align:left;gap:5px;padding:14px;margin:0;border-top:3px solid #1683dc;cursor:pointer}
.advisor-card strong{font-size:25px}.advisor-card span{font-size:12px}
.advisor-filters{display:flex;flex-wrap:wrap;align-items:center}.advisor-table{overflow:auto}
.advisor-table td{min-width:90px}.advisor-table td:first-child{min-width:30px}.advisor-table details pre{max-width:450px;max-height:320px;overflow:auto}
.advisor-table tr[hidden]{display:none}.advisor-table summary{cursor:pointer;color:#1683dc;margin:8px 0}
#preview{max-height:500px;overflow:auto;background:var(--bg);padding:12px}
</style>
<script>
'use strict';
const $=id=>document.getElementById(id);
const rows=Array.from(document.querySelectorAll('.advisor-table tbody tr'));
const checks=rows.map(r=>r.querySelector('.choose'));
const keys=['action','module','persona'];
function filter(){
 const q=$('search').value.trim().toLowerCase();
 for(const row of rows)row.hidden=!keys.every(k=>!$(k).value||row.dataset[k]===$(k).value)||!row.textContent.toLowerCase().includes(q);
 $('visible-count').textContent=rows.filter(r=>!r.hidden).length+' of '+rows.length+' recommendations';
}
function selection(){
 const chosen=checks.filter(c=>c.checked).map(c=>JSON.parse(c.dataset.plan));
 $('selected').textContent=chosen.length+' selected (including any hidden by filters)';
 $('export-plan').disabled=!chosen.length;
 $('preview').textContent=chosen.length?chosen.map(f=>f.module+' / '+f.identity+' — '+f.action+'\\nTarget: '+f.target+'\\n'+f.steps.map((s,i)=>(i+1)+'. '+s).join('\\n')+'\\nBlocked: '+f.blockers.join(' ')).join('\\n\\n'):'Select recommendations to inspect the proposed workflow.';
 return chosen;
}
for(const k of keys)$(k).addEventListener('change',filter);
$('search').addEventListener('input',filter);
$('clear').addEventListener('click',()=>{for(const k of keys)$(k).value='';$('search').value='';filter();});
for(const b of document.querySelectorAll('.advisor-card'))b.addEventListener('click',()=>{$('action').value=b.dataset.action;filter();});
for(const c of checks)c.addEventListener('change',selection);
$('select-visible').addEventListener('click',()=>{for(const r of rows)if(!r.hidden)r.querySelector('.choose').checked=true;selection();});
$('clear-selection').addEventListener('click',()=>{for(const c of checks)c.checked=false;selection();});
$('export-plan').addEventListener('click',()=>{
 const content=JSON.stringify({schema:1,kind:'consolidation_preview',safe_to_apply:false,snapshot:$('snapshot-label').dataset.snapshot,recommendations:selection()},null,2);
 const url=URL.createObjectURL(new Blob([content],{type:'application/json'}));
 const a=document.createElement('a');a.href=url;a.download='consolidation-preview.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
filter();selection();
</script>"""
        return page("Consolidation advisor",
                    f'<section><h2>Consolidation advisor</h2><p id="snapshot-label" data-snapshot="{e(name)}">Captured: {e(bundle.get("captured_at", "unknown"))}</p>'
                    '<p>Qualified reusable profiles only. Repeated profiles are grouped by exact identity and body. '
                    'Device counts are observed effective configuration, not traffic usage or a verified blast radius. '
                    'Device-specific system settings and physical/routed topology are excluded from generic promotion.</p>'
                    + controls + '<p id="visible-count" aria-live="polite"></p>'
                    '<div class="advisor-table"><table><thead><tr><th>Select</th><th>Recommendation</th><th>Profile</th>'
                    '<th>Local scopes</th><th>Proposed placement</th><th>Observed devices</th><th>Review</th></tr></thead><tbody>'
                    + "".join(rows) + '</tbody></table></div></section>' + plan + script, self.nav())

    def library(self, query):
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        if not files:
            return page("Library", "<p>No snapshots available.</p>", self.nav())
        name = query.get("snapshot", files[0].name)
        from central_tool import refresh_configuration_review
        bundle = refresh_configuration_review(read_audit(self.directory, name))
        library = bundle.get("library")
        select = (f'<form method="get" action="{root}library"><label>Snapshot<select name="snapshot">'
                  + options([(p.name, p.name) for p in files], name)
                  + '</select></label><button>Open</button></form>')
        if not library:
            return page("Library", select + "<p>This capture predates Library discovery. Refresh from Central to collect it.</p>", self.nav())
        module = query.get("module", "")
        modules = library.get("modules", {})
        if module and module not in modules:
            raise ValueError("Unknown Library module")
        assignments = library.get("assignments", {})
        assignment_rows = assignments.get("rows", [])
        body = ""
        for key, view in sorted(modules.items()):
            if module and key != module:
                continue
            link = root + "library?" + urlencode({"snapshot": name, "module": key})
            body += (f'<tr><td><a href="{e(link)}">{e(key)}</a></td><td>{e(view["status"])}</td>'
                     f'<td>{len(view["profiles"])}</td></tr>')
        detail = ""
        if module:
            view = modules[module]
            detail = f'<section><h2>{e(module)}</h2><p>Observed profiles: {len(view["profiles"])}</p>'
            comparison = library_profile_comparison(bundle, module)
            for identity, profile in sorted(view["profiles"].items()):
                review = comparison.get(identity, {})
                matches = review.get("assignments", [])
                variants = review.get("local_variants", [])
                conflicts = sum(v["classification"] == "different_body" for v in variants)
                detail += (f'<details><summary>{e(identity)} · {len(matches)} observed assignments · '
                           f'{len(variants)} local instances · {conflicts} different bodies</summary>'
                           '<p>Zero observed assignments does not establish that a profile is unused.</p>'
                           f'<pre>{e(json.dumps({"profile": profile, **review}, indent=2, ensure_ascii=False))}</pre></details>')
            detail += "</section>"
        assignment_detail = (f'<section><h2>Observed assignment response</h2><p>{e(assignments.get("status", "unknown"))} · '
                             f'{len(assignment_rows)} records. Assignment completeness is not verified.</p>'
                             f'<details><summary>Inspect raw assignment records</summary><pre>{e(json.dumps(assignment_rows, indent=2, ensure_ascii=False))}</pre></details></section>')
        return page("Library", select + '<section><h2>Tenant Library</h2><p>Read-only shared profile inventory; counts are observed, not proof of completeness.</p>'
                    '<table><thead><tr><th>Module</th><th>Response status</th><th>Observed profiles</th></tr></thead><tbody>'
                    + body + '</tbody></table></section>' + detail + assignment_detail, self.nav())

    def unadapted(self, query):
        root = "/" + self.token + "/"
        bundle = read_audit(self.directory, query["snapshot"])
        module = query["module"]
        evidence = bundle.get("unadapted_profiles", {}).get(module)
        if evidence is None:
            return page("Profile evidence", "<p>No captured evidence for this profile type. Collect a fresh audit.</p>", self.nav())
        body = f'<section><h2>{e(module)}</h2><p>Raw read-only evidence. This profile type has no qualified identity adapter.</p>'
        from central_tool import qualify_observed_identities
        identities = qualify_observed_identities(evidence)
        for persona, result in identities.items():
            body += (f'<details><summary>{e(persona)} · {e(result["status"])} · '
                     f'{result.get("comparable_source_scopes", 0)}/{result["source_scopes"]} comparable source scopes</summary>'
                     '<p>Inventory-derived identity evidence only. Full hierarchy and migration safety are not verified.</p>'
                     f'<pre>{e(json.dumps(result, indent=2, ensure_ascii=False))}</pre></details>')
        library = evidence["library"]
        body += (f'<details><summary>Library · {e(library["status"])}</summary>'
                 f'<pre>{e(json.dumps(library, indent=2, ensure_ascii=False))}</pre></details>')
        for view in evidence["source_views"]:
            body += (f'<details><summary>{e(view["persona"])} / Scope {e(view["scope"])} · '
                     f'{len(view["observed_instances"])} observed instances</summary>'
                     f'<pre>{e(json.dumps(view, indent=2, ensure_ascii=False))}</pre></details>')
        return page("Profile evidence", body + "</section>", self.nav())

    def coverage(self, query):
        from central_tool import refresh_configuration_review
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        if not files:
            return page("Module coverage", "<p>No snapshots available.</p>", self.nav())
        name = query.get("snapshot", files[0].name)
        bundle = refresh_configuration_review(read_audit(self.directory, name))
        rows = module_coverage(bundle)
        order = {"qualified": 0, "partial": 1, "unqualified": 2}
        rows.sort(key=lambda r: (order[r["status"]], r["persona"], r["module"]))
        body = ""
        for row in rows:
            href = root + "report?" + urlencode({"snapshot": name, "persona": row["persona"], "module": row["module"]})
            body += (f'<tr><td>{e(row["persona"])}</td><td>{e(row["module"])}</td>'
                     f'<td>{row["qualified"]}/{row["total"]}</td><td>{e(row["status"])}</td>'
                     f'<td><a href="{e(href)}">Inspect evidence</a></td></tr>')
        observed = bundle.get("profile_type_discovery")
        discovery = ""
        if observed is not None:
            library = bundle.get("library", {})
            unknown = set(observed["unknown_adapter_modules"])
            observed_rows = "".join(
                f'<tr><td>{e(module)}</td><td>{e(", ".join(personas))}</td>'
                f'<td>{e("Adapter needed" if module in unknown else "Adapter available")}'
                + (f' · <a href="{e(root + "unadapted?" + urlencode({"snapshot": name, "module": module}))}">Raw evidence</a>'
                   if module in unknown else "") + '</td></tr>'
                for module, personas in observed["modules"].items())
            assignments = library.get("assignments") or {}
            maps = library.get("scope_maps") or {}
            discovery = (f'<section><h2>Observed tenant profile types</h2>'
                         f'<p>Assignments: {e(assignments.get("status", "unknown"))}. '
                         f'Scope maps: {e(maps.get("status", "unknown"))}. '
                         f'{len(unknown)} observed types need adapters; '
                         f'{observed["unresolved_records"]} records could not be classified. '
                         'These inventories do not establish complete coverage.</p>'
                         '<table><thead><tr><th>Profile type</th><th>Observed device functions</th>'
                         '<th>Adapter</th></tr></thead><tbody>' + observed_rows + '</tbody></table></section>')
        return page("Module coverage", '<section><h2>Configuration module qualification</h2>'
                    '<p>Fully qualified modules first. Partial modules retain their valid scope evidence; '
                    'unqualified scopes are diagnostics only. Qualification is not permission to modify configuration.</p>'
                    f'<form method="get" action="{root}coverage"><label>Snapshot<select name="snapshot">'
                    + options([(p.name, p.name) for p in files], name)
                    + '</select></label><button>Open</button></form><table><thead><tr><th>Function</th><th>Module</th>'
                    '<th>Qualified scopes</th><th>Status</th><th>Evidence</th></tr></thead><tbody>'
                    + body + '</tbody></table></section>' + discovery, self.nav())

    def report(self, query):
        from central_tool import configuration_html, refresh_configuration_review
        bundle = refresh_configuration_review(read_audit(self.directory, query["snapshot"]))
        if "scope" in query or "module" in query:
            from central_tool import config_review_rows, configuration_view_shape
            from config_dashboard import render_dashboard
            records = [r for r in config_review_rows(bundle) if r[0] == query.get("persona")
                       and ("scope" not in query or r[3]["scope"] == query["scope"])
                       and ("module" not in query or r[1] == query["module"])]
            if not records:
                raise ValueError("Unknown scope")
            html = render_dashboard(bundle, records, configuration_view_shape)
            html = html.replace("<main>", "<main><p>Filtered evidence. Counts and repeat groups are limited to this selection.</p>", 1)
        else:
            html = configuration_html(bundle)
        # Static report remains standalone; add a local navigation link only here.
        return html.replace("<main>", f'<main><p><a href="/{self.token}/">Back to workspace</a></p>', 1)

    def scopes(self, query):
        from central_tool import refresh_configuration_review
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        if not files:
            return page("Scopes", "<p>No snapshots available.</p>", self.nav())
        name = query.get("snapshot", files[0].name)
        bundle = refresh_configuration_review(read_audit(self.directory, name))
        select = (f'<form method="get" action="{root}scopes"><label>Snapshot<select name="snapshot">'
                  + options([(p.name, p.name) for p in files], name)
                  + '</select></label><button>Open</button></form>')
        sections = []
        order = {"global": 0, "collection": 1, "site": 2, "group": 3, "device": 4}
        for persona, entry in sorted(bundle["results"].items()):
            rows = []
            for scope in sorted(entry["scopes"], key=lambda s: (order.get(s["kind"], 99), s.get("name") or "", s["id"])):
                sid = scope["id"]
                views = [s for m in entry["modules"].values() for s in m["scope_results"] if s["scope"] == sid]
                qualified = sum(s["review"]["qualified"] for s in views)
                href = root + "report?" + urlencode({"snapshot": name, "persona": persona, "scope": sid})
                rows.append(f'<tr><td>{e(scope["kind"])}</td><td>{e(scope.get("name") or sid)}</td>'
                            f'<td>{qualified}/{len(views)}</td><td><a href="{e(href)}">Inspect scope</a></td></tr>')
            sections.append(f'<section><h2>{e(persona)}</h2><table><thead><tr><th>Scope type</th>'
                            '<th>Name</th><th>Qualified modules</th><th>Action</th></tr></thead><tbody>'
                            + "".join(rows) + '</tbody></table></section>')
        return page("Scopes", '<p>Scope inventory grouped by device function and level. '
                    'Parent relationships are not inferred from the order.</p>' + select + "".join(sections), self.nav())

    def comparison(self, query):
        from central_tool import refresh_configuration_review
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        if not files:
            return page("Compare", "<p>No snapshots available.</p>", self.nav())
        name = query.get("snapshot", files[0].name)
        bundle = refresh_configuration_review(read_audit(self.directory, name))
        personas = sorted(bundle["results"])
        if not personas:
            return page("Compare", "<p>No qualified personas in capture.</p>", self.nav())
        persona = query.get("persona", personas[0])
        if persona not in personas:
            raise ValueError("Unknown persona")
        entry = bundle["results"][persona]
        devices = [(s["id"], s.get("name") or s["id"]) for s in entry["scopes"] if s["kind"] == "device"]
        left, right = query.get("left", ""), query.get("right", "")
        module = query.get("module", "")
        if module and module not in entry["modules"]:
            raise ValueError("Unknown module")
        choose = (f'<form method="get" action="{root}compare">'
                  f'<label>Snapshot<select name="snapshot">{options([(p.name,p.name) for p in files], name)}</select></label>'
                  f'<label>Function<select name="persona">{options([(p,p) for p in personas], persona)}</select></label>'
                  '<button>Load devices</button></form>')
        controls = (f'<form method="get" action="{root}compare">'
                    f'<input type="hidden" name="snapshot" value="{e(name)}">'
                    f'<input type="hidden" name="persona" value="{e(persona)}">'
                    f'<label>Reference device<select name="left">{options([("", "Select")] + devices, left)}</select></label>'
                    f'<label>Compare device<select name="right">{options([("", "Select")] + devices, right)}</select></label>'
                    f'<label>Module<select name="module">{options([("", "Reusable modules")] + [(m,m) for m in sorted(entry["modules"])], module)}</select></label>'
                    '<button>Compare</button></form>')
        result = ""
        if left and right:
            comparison = compare_devices(bundle, persona, left, right, module or None)
            result = "".join(f'<section><h2>{e(r["module"])}</h2><p class="pill">{e(r["status"])} · '
                             f'{len(r["differences"])} differing profiles</p>'
                             + "".join(f'<details><summary>{e(d["identity"])} · {e(d["status"])}</summary>'
                                       f'<pre>{e(json.dumps(d,indent=2,ensure_ascii=False))}</pre></details>'
                                       for d in r["differences"]) + "</section>" for r in comparison)
        return page("Compare devices", '<section><h2>Compare captured effective configuration</h2>'
                    '<p>Same snapshot and device function only. Infrastructure is excluded by default; '
                    'select a specific module to compare it. Exact body differences do not prove operational equivalence.</p>'
                    + choose + controls + "</section>" + result, self.nav())


def handler_for(workspace):
    root = "/" + workspace.token + "/"
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def valid_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def reply(self, body, status=200, content_type="text/html; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            # no-referrer can cause an opaque Origin on browser form POSTs.
            # Never send the private session URL to a different origin.
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if not self.valid_host() or not parsed.path.startswith(root):
                self.reply("Not found", 404)
                return
            try:
                query = {k: v[-1] for k, v in parse_qs(parsed.query, max_num_fields=12).items()}
                if parsed.path == root + "status":
                    self.reply(json.dumps(workspace.status()), content_type="application/json; charset=utf-8")
                    return
                if parsed.path == root:
                    body = workspace.home()
                elif parsed.path == root + "report":
                    body = workspace.report(query)
                elif parsed.path == root + "advisor":
                    body = workspace.advisor(query)
                elif parsed.path == root + "library":
                    body = workspace.library(query)
                elif parsed.path == root + "unadapted":
                    body = workspace.unadapted(query)
                elif parsed.path == root + "coverage":
                    body = workspace.coverage(query)
                elif parsed.path == root + "scopes":
                    body = workspace.scopes(query)
                elif parsed.path == root + "compare":
                    body = workspace.comparison(query)
                else:
                    self.reply("Not found", 404)
                    return
                self.reply(body)
            except (ValueError, KeyError, OSError, TypeError):
                self.reply(page("Invalid request", "<p>Invalid snapshot or selection.</p>", workspace.nav()), 400)

        def do_POST(self):
            expected = f"http://127.0.0.1:{self.server.server_port}"
            origin = self.headers.get("Origin")
            fetch_site = self.headers.get("Sec-Fetch-Site")
            # Explicit cross-origin requests are always rejected. Older cached
            # form pages or privacy settings may send an opaque/null Origin;
            # permit that only with same-origin fetch metadata and a CSRF token.
            origin_ok = origin == expected or (origin in (None, "null") and fetch_site == "same-origin")
            if (not self.valid_host() or self.path not in (root + "refresh", root + "credentials")
                    or not origin_ok or fetch_site not in (None, "same-origin")):
                self.reply("Forbidden: local session or origin check failed. Reopen the application.", 403)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 24576 or self.headers.get_content_type() != "application/x-www-form-urlencoded":
                    raise ValueError("Invalid form")
                self.connection.settimeout(10)
                values = parse_qs(self.rfile.read(length).decode("utf-8"),
                                  keep_blank_values=True, strict_parsing=True, max_num_fields=4)
                if any(len(v) != 1 for v in values.values()):
                    raise ValueError("Invalid form")
                token = values.pop("csrf", [""])[0]
                if not secrets.compare_digest(token.encode("utf-8"), workspace.csrf.encode("utf-8")):
                    self.reply("Forbidden: stale or invalid form token. Reopen the application.", 403)
                    return
                if self.path == root + "credentials":
                    if set(values) != {"client_id", "client_secret", "region"}:
                        raise ValueError("Invalid credential form")
                    refresh = credential_refresh(values["client_id"][0], values["client_secret"][0], values["region"][0])
                    values.clear()
                    started = workspace.start_refresh(refresh)
                else:
                    if values:
                        raise ValueError("Invalid refresh form")
                    started = workspace.start_refresh()
            except (ValueError, OSError, UnicodeError):
                self.reply("Invalid refresh form", 400)
                return
            if not started:
                self.reply(page("Refresh unavailable", "<p>Refresh unavailable or already running.</p>",
                                workspace.nav()), 409)
                return
            self.send_response(303)
            self.send_header("Location", root)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
    return Handler


def serve(directory, refresh=None, port=0, open_browser=True):
    workspace = Workspace(directory, refresh)
    with ThreadingHTTPServer(("127.0.0.1", port), handler_for(workspace)) as server:
        url = f"http://127.0.0.1:{server.server_port}/{workspace.token}/"
        print("Local configuration workspace started on loopback. Press Ctrl+C to stop.", flush=True)
        if open_browser:
            webbrowser.open(url)
        else:
            print(url, flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
