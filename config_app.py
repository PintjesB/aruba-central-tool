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


from workspace_ui import page, navigation, intro, snapshot_picker, metrics, e as ui_escape


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
        summary = ""
        if bundle:
            coverage = module_coverage(bundle)
            devices = {s["id"] for entry in bundle["results"].values() for s in entry["scopes"] if s["kind"] == "device"}
            qualified = sum(r["status"] == "qualified" for r in coverage)
            partial = sum(r["status"] == "partial" for r in coverage)
            library = (bundle.get("library") or {}).get("modules", {})
            observed = sum(len(v["profiles"]) for v in library.values() if v["status"] == "list_parsed")
            summary = metrics([("Devices", len(devices), "Captured inventory"),
                               ("Qualified module views", qualified, f"{partial} partially qualified"),
                               ("Library profiles", observed, "Observed definitions")])
            cards = []
            for route, title, desc in (
                ("advisor", "Consolidate configuration", "Find repeated profiles, compare overrides and choose destinations."),
                ("advanced", "Review engineering findings", "Find reusable ports, shadowed settings and duplicate Library profiles."),
                ("report", "Explore configuration", "Inspect individual scope settings and their sources."),
                ("compare", "Compare devices", "Review exact configuration differences between devices.")):
                href = root + route + "?" + urlencode({"snapshot": name})
                cards.append(f'<a class="workflow-card" href="{e(href)}"><strong>{e(title)}</strong><span>{e(desc)}</span><span class="arrow">Open workspace →</span></a>')
            summary += '<h2>Workflows</h2><div class="workflow-grid">' + "".join(cards) + '</div>'
        else:
            summary = '<section><h2>Collect your first snapshot</h2><p>Connect to Central to start a read-only configuration audit.</p></section>'
        picker = snapshot_picker(root, "", files, name) if files else ""
        captures = (f'<section><div class="section-head"><h2>Saved snapshots ({len(files)})</h2></div>'
                    + picker + (f'<p class="muted">Captured: {e(bundle.get("captured_at", "unknown"))}</p>' if bundle else "")
                    + '<p class="note">Use a separate workspace directory for each customer. Tenant identity is not independently verified.</p></section>')
        return page("Snapshots", intro("Overview", "Review captured configuration and plan improvements.")
                    + summary + '<div class="split">' + captures
                    + f'<section><h2>Connect to Central</h2>{progress_html}{refresh}</section></div>'
                    + script, self.nav(name))

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
        return page("Profile evidence", intro("Profile evidence", "Raw diagnostic capture.") + body + "</section>", self.nav(query["snapshot"]))

    def coverage(self, query):
        from workspace_views import coverage_view
        return coverage_view(self, query)

    def report(self, query):
        from workspace_views import explorer_view
        return explorer_view(self, query)

    def scopes(self, query):
        from workspace_views import inventory_view
        return inventory_view(self, query)

    def comparison(self, query):
        from workspace_views import comparison_view
        return comparison_view(self, query)


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
                elif parsed.path == root + "advisor":
                    body = workspace.advisor(query)
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
