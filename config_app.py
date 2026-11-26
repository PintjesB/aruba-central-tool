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


from workspace_ui import page, navigation, intro, snapshot_picker, metrics


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


def credential_refresh(client_id, client_secret, region, *, deep_catalog=False):
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
            return configuration_audit(client, progress=progress, deep_catalog=deep_catalog)
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

    def nav(self, snapshot=None):
        return navigation("/" + self.token + "/", snapshot)

    def home(self, query=None):
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        name = (query or {}).get("snapshot", files[0].name if files else None)
        bundle = read_audit(self.directory, name) if name else None
        status = self.status()
        state = status["state"]
        from central_tool import EU_REGIONS
        disabled = " disabled" if state == "running" else ""
        hidden = f'<input type="hidden" name="csrf" value="{e(self.csrf)}">'
        refresh = (f'<form class="connection-form" method="post" action="{root}credentials" autocomplete="off">' + hidden +
                   '<label>API region<select name="region">'
                   + options([("", "Detect EU region")] + [(r, urlsplit(r).hostname.split(".")[0].upper()) for r in EU_REGIONS])
                   + '</select></label><label>Client ID<input name="client_id" type="text" required maxlength="1024" autocomplete="off"></label>'
                   '<label>Client secret<input name="client_secret" type="password" required maxlength="4096" autocomplete="new-password"></label>'
                   '<label>Collection depth<select name="depth"><option value="deep">Deep catalog (all discovered scopes)</option><option value="standard">Standard (observed functions and Global)</option></select></label>'
                   f'<button type="submit"{disabled}>Connect and refresh</button></form>'
                   '<p><small>Deep collection can take substantially longer on large tenants. API coverage gaps and rejected reads remain visible.</small></p>'
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
        summary = ""
        if bundle:
            coverage = module_coverage(bundle)
            devices = {s["id"] for entry in bundle["results"].values() for s in entry["scopes"] if s["kind"] == "device"}
            qualified = sum(r["status"] == "qualified" for r in coverage)
            library = (bundle.get("library") or {}).get("modules", {})
            observed = sum(len(v["profiles"]) for v in library.values() if v["status"] == "list_parsed")
            scopes = {s["id"] for entry in bundle["results"].values() for s in entry["scopes"] if s["kind"] != "device"}
            summary = metrics([("Devices", len(devices), "Captured inventory"),
                               ("Configuration scopes", len(scopes), "Non-device scopes"),
                               ("Library profiles", observed, "Observed definitions")])
            from consolidation import profile_recommendations
            from collections import Counter
            from central_tool import refresh_configuration_review
            complete_structure = all(
                {"scope_kind", "local_view", "effective_view"} <= scope.keys()
                for entry in bundle["results"].values() for data in entry["modules"].values()
                for scope in data["scope_results"])
            findings = profile_recommendations(refresh_configuration_review(bundle)) if complete_structure else None
            counts = Counter(f["action"] for f in findings or [])
            opportunities = counts["remove_override"] + counts["promote_local"] + counts["reuse_library"]
            advisor_href = root + "advisor?" + urlencode({"snapshot": name})
            overrides_href = root + "overrides?" + urlencode({"snapshot": name})
            coverage_href = root + "coverage?" + urlencode({"snapshot": name})
            if findings is None:
                summary += '<section><h2>Consolidation analysis unavailable</h2><p>This snapshot lacks the saved configuration evidence needed for review. Collect a new snapshot to calculate recommendations.</p></section>'
            else:
                from workspace_ui import icon
                categories = (("remove_override", "Matching Global profiles", "Review lower-scope copies"),
                              ("promote_local", "Repeated local profiles", "Consolidate repeated definitions"),
                              ("reuse_library", "Matching Library profiles", "Reuse an existing definition"))
                breakdown = "".join(
                    f'<a class="opportunity-row" href="{e(advisor_href + "&finding=" + key)}">'
                    f'<div><strong>{e(label)}</strong><small>{e(description)}</small></div>'
                    f'<div class="opportunity-meter"><span style="width:{100 * counts[key] / max(1, opportunities):.2f}%"></span></div>'
                    f'<b>{counts[key]}</b>{icon("chevron")}</a>'
                    for key, label, description in categories)
                gap = len(coverage) - qualified
                summary = (f'<div class="overview-layout"><section class="overview-focus"><div class="focus-lead">'
                           '<div class="focus-kicker">' + icon("advisor") + ' Consolidation opportunities</div>'
                           f'<div class="focus-number">{opportunities}</div>'
                           '<h2>Reduce configuration duplication.</h2>'
                           '<p>Review the captured evidence and prepare a change preview. No changes are sent to Central.</p>'
                           f'<a class="button primary" href="{e(advisor_href)}">Review opportunities {icon("arrow")}</a></div>'
                           '<div class="overview-breakdown"><h3>Review by recommendation</h3>' + breakdown + '</div></section>'
                           '<section class="coverage-focus"><div class="focus-kicker">' + icon("coverage") + ' Data readiness</div>'
                           f'<div class="coverage-number">{qualified}<small> / {len(coverage)}</small></div>'
                           '<h3>Fully qualified module reads</h3>'
                           f'<div class="coverage-meter" role="img" aria-label="{qualified} of {len(coverage)} module reads fully qualified">'
                           f'<span style="width:{100 * qualified / max(1, len(coverage)):.2f}%"></span></div>'
                           f'<p>{gap} incomplete or unavailable module reads.</p><a href="{e(coverage_href)}">Inspect coverage {icon("arrow")}</a></section></div>'
                           + summary
                           + '<section class="overview-links"><div><h3>Review device overrides</h3><p>Inspect the actual differences between a device and Global before removing local definitions.</p>'
                           f'<a href="{e(overrides_href + "&result=cleanup")}">Review potential cleanup {icon("arrow")}</a></div>'
                           '<div><h3>Library engineering</h3><p>Find duplicate definitions, compare individual usage and inspect configuration dependencies.</p>'
                           f'<a href="{e(root + "advanced?" + urlencode({"snapshot": name}))}">Review engineering {icon("arrow")}</a></div></section>')
        else:
            summary = '<section><h2>Saved snapshots</h2><p>No snapshots yet. Connect to Central to start a read-only configuration audit.</p></section>'
        picker = snapshot_picker(root, "", files, name) if files else ""
        capture_note = (f'<p class="muted">Captured: {e(bundle.get("captured_at", "unknown"))} · Saved snapshots: {len(files)}</p>' if bundle else "")
        # The connection form is secondary once an audit is available. Keep
        # active/failed progress visible and never store credentials.
        connection = (f'<section><details class="connection-details"{" open" if not bundle or state in ("running", "failed", "complete") else ""}>'
                      f'<summary>Collect a new snapshot</summary>{progress_html}{refresh}'
                      '<p class="note">Use a separate workspace directory for each customer. Tenant identity is not independently verified.</p></details></section>')
        return page("Snapshots", intro("Overview", "Review captured configuration and plan improvements.", picker)
                    + capture_note + summary + connection + script, self.nav(name))

    def overrides(self, query):
        from override_view import overrides_view
        return overrides_view(self, query)

    def advisor(self, query):
        from workspace_views import advisor_view
        return advisor_view(self, query)

    def advanced(self, query):
        from workspace_views import engineering_view
        return engineering_view(self, query)

    def library(self, query):
        from workspace_views import library_view
        return library_view(self, query)

    def unadapted(self, query):
        from workspace_ui import property_table, table, tr, status, raw, module_label, persona_label, badge
        from central_tool import qualify_observed_identities
        root = "/" + self.token + "/"
        name, module = query["snapshot"], query["module"]
        bundle = read_audit(self.directory, name)
        evidence = bundle.get("unadapted_profiles", {}).get(module)
        if evidence is None:
            return page("Profile evidence", "<p>No captured evidence for this profile type. Collect a fresh audit.</p>", self.nav(name))
        def link(**params):
            return e(root + "unadapted?" + urlencode({"snapshot": name, "module": module, **params}))
        def settings(read):
            payload = read.get("raw")
            if isinstance(payload, dict):
                fields = {k: v for k, v in payload.items() if k != "metadata"}
                display = property_table(fields) if fields else '<p class="empty">No configuration values returned.</p>'
            else:
                display = '<p class="empty">Structured settings unavailable.</p>'
            return status(read["status"]) + display + raw(read, "Complete captured response")
        names = {(persona, str(s["id"])): s.get("name") or s["id"]
                 for persona, entry in bundle["results"].items() for s in entry["scopes"]}
        identities = qualify_observed_identities(evidence)
        selected_persona, selected_scope = query.get("persona"), query.get("scope")
        body = intro(module_label(module), "Captured configuration without a qualified comparison adapter.")
        body += f'<div class="collection-nav"><a href="{e(root + "coverage?" + urlencode({"snapshot": name}))}">← Collection coverage</a></div>'
        body += '<p class="note">Read-only evidence. A captured value does not establish profile identity, source precedence or safe removal.</p>'
        if selected_persona is not None or selected_scope is not None:
            matches = [v for v in evidence["source_views"] if v["persona"] == selected_persona and v["scope"] == selected_scope]
            if len(matches) != 1:
                raise ValueError("Unknown source scope")
            view = matches[0]
            label = names.get((selected_persona, selected_scope), selected_scope)
            body += f'<section><a href="{link()}">← All captured scopes</a><h2>{e(label)} · {e(persona_label(selected_persona))}</h2>'
            body += '<h3>Committed configuration</h3>' + settings(view["committed"])
            body += '<h3>Effective configuration</h3>' + settings(view["effective"]) + '</section>'
        else:
            library = evidence["library"]
            body += '<section><h2>Library</h2>' + settings(library) + '</section>'
            views = evidence["source_views"]
            if identities:
                body += '<section><h2>Identity evidence</h2>' + table(("Device function", "Identity field", "Comparable observed source scopes"),
                    [tr(e(persona_label(p)), e(v.get("identity_field", "Unavailable")),
                        f'{v.get("comparable_source_scopes", 0)}/{v["source_scopes"]}')
                     for p, v in identities.items()]) + '</section>'
            body += '<section><h2>Captured scopes</h2>' + table(("Device function", "Scope", "Committed", "Effective", ""),
                    [tr(e(persona_label(v["persona"])), e(names.get((v["persona"], v["scope"]), v["scope"])),
                        status(v["committed"]["status"]), status(v["effective"]["status"]),
                        f'<a href="{link(persona=v["persona"], scope=v["scope"])}">Inspect settings</a>')
                     for v in views], search=True) + '</section>'
        return page("Profile evidence", body, self.nav(name))

    def coverage(self, query):
        from workspace_views import coverage_view
        return coverage_view(self, query)

    def report(self, query):
        from workspace_views import explorer_view
        return explorer_view(self, query)

    def scopes(self, query):
        from workspace_views import inventory_view
        return inventory_view(self, query)

    def impact(self, query):
        from impact_view import impact_view
        return impact_view(self, query)

    def comparison(self, query):
        from workspace_views import comparison_view
        return comparison_view(self, query)

    def drift(self, query):
        from history_view import drift_view
        return drift_view(self, query)

    def standards(self, query):
        from history_view import standards_view
        return standards_view(self, query)


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
                    body = workspace.home(query)
                elif parsed.path == root + "report":
                    body = workspace.report(query)
                elif parsed.path == root + "legacy-report":
                    from central_tool import configuration_html, refresh_configuration_review
                    bundle = refresh_configuration_review(read_audit(workspace.directory, query["snapshot"]))
                    body = configuration_html(bundle).replace("<main>", f'<main><p><a href="{root}report?{e(urlencode({"snapshot": query["snapshot"]}))}">Back to workspace</a></p>', 1)
                elif parsed.path == root + "overrides":
                    body = workspace.overrides(query)
                elif parsed.path == root + "advisor":
                    body = workspace.advisor(query)
                elif parsed.path == root + "impact":
                    body = workspace.impact(query)
                elif parsed.path == root + "advanced":
                    body = workspace.advanced(query)
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
                elif parsed.path == root + "drift":
                    body = workspace.drift(query)
                elif parsed.path == root + "standards":
                    body = workspace.standards(query)
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
                                  keep_blank_values=True, strict_parsing=True, max_num_fields=5)
                if any(len(v) != 1 for v in values.values()):
                    raise ValueError("Invalid form")
                token = values.pop("csrf", [""])[0]
                if not secrets.compare_digest(token.encode("utf-8"), workspace.csrf.encode("utf-8")):
                    self.reply("Forbidden: stale or invalid form token. Reopen the application.", 403)
                    return
                if self.path == root + "credentials":
                    depth = values.pop("depth", ["standard"])[0]
                    if set(values) != {"client_id", "client_secret", "region"} or depth not in ("standard", "deep"):
                        raise ValueError("Invalid credential form")
                    refresh = credential_refresh(values["client_id"][0], values["client_secret"][0], values["region"][0],
                                                 deep_catalog=depth == "deep")
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
