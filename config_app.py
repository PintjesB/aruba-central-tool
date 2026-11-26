"""Loopback-only configuration workspace backed by private audit files."""
import json
import os
import re
import secrets
import threading
import webbrowser
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit


CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


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
label{display:inline-block;margin:6px}small{opacity:.8}.pill{padding:4px 8px;border-radius:6px;background:#fff0d7;color:#804a0b}
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
    from central_tool import Central, EU_REGIONS, detect_region, configuration_audit
    if region and region not in EU_REGIONS:
        raise ValueError("Choose an official EU region")
    if not client_id.strip() or not client_secret or len(client_id) > 1024 or len(client_secret) > 4096:
        raise ValueError("Invalid credentials")
    client = Central(region or EU_REGIONS[0], None, client_id, client_secret)
    def run():
        try:
            detect_region(client, region or None)
            return configuration_audit(client)
        finally:
            client.client_id = None
            client.client_secret = None
            client.token = None
    return run


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
        self.refresh = refresh
        self.lock = threading.Lock()
        self.state = "idle"

    def start_refresh(self, one_shot=None):
        with self.lock:
            refresh = one_shot if one_shot is not None else self.refresh
            if refresh is None or self.state == "running":
                return False
            self.state = "running"
        def run():
            try:
                from central_tool import write_private
                bundle = refresh()
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
                target = self.directory / f"config-audit-{stamp}.json"
                temporary = target.with_suffix(".partial")
                try:
                    write_private(temporary, bundle)
                    os.replace(temporary, target)
                finally:
                    temporary.unlink(missing_ok=True)
                state = "complete"
            except Exception:
                # No exception payloads or credentials in browser output.
                state = "failed; check local configuration and API access"
            with self.lock:
                self.state = state
        threading.Thread(target=run, daemon=True).start()
        return True

    def nav(self):
        root = "/" + self.token + "/"
        return f'<a href="{root}">Snapshots</a><a href="{root}coverage">Module coverage</a><a href="{root}library">Library</a><a href="{root}scopes">Scopes</a><a href="{root}compare">Compare devices</a>'

    def home(self):
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        with self.lock:
            state = self.state
        from central_tool import EU_REGIONS
        disabled = " disabled" if state == "running" else ""
        refresh = (f'<form method="post" action="{root}credentials" autocomplete="off">'
                   '<label>API region<select name="region">'
                   + options([("", "Detect EU region")] + [(r, urlsplit(r).hostname.split(".")[0].upper()) for r in EU_REGIONS])
                   + '</select></label><label>Client ID<input name="client_id" type="text" required maxlength="1024" autocomplete="off"></label>'
                   '<label>Client secret<input name="client_secret" type="password" required maxlength="4096" autocomplete="new-password"></label>'
                   f'<button type="submit"{disabled}>Connect and refresh</button></form>'
                   '<p><small>Credentials are used only for this audit, in process memory. '
                   'They are not saved or returned by the application. Decline browser password-saving prompts.</small></p>')
        if self.refresh is not None:
            refresh += (f'<form method="post" action="{root}refresh"><button type="submit"'
                       + (" disabled" if state == "running" else "")
                       + ">Refresh using environment credentials</button></form>")
        return page("Snapshots", '<p>Private local workspace. Select a saved configuration capture. '
                    'Use a separate directory for each customer; tenant identity is not independently verified.</p>'
                    f'<section><h2>Audit refresh</h2><p>Status: {e(state)}</p>{refresh}'
                    f'<p><a href="{root}">Reload status</a></p></section><section><h2>Saved snapshots ({len(files)})</h2>'
                    '<table><thead><tr><th>Capture file</th><th>Action</th></tr></thead><tbody>' +
                    "".join(f'<tr><td>{e(p.name)}</td><td><a href="{root}report?{e(urlencode({"snapshot": p.name}))}">Open explorer</a>'
                            f' · <a href="{root}coverage?{e(urlencode({"snapshot": p.name}))}">Module coverage</a>'
                            f' · <a href="{root}scopes?{e(urlencode({"snapshot": p.name}))}">Browse scopes</a>' 
                            f' · <a href="{root}compare?{e(urlencode({"snapshot": p.name}))}">Compare devices</a></td></tr>'
                            for p in files) + '</tbody></table></section>', self.nav())

    def library(self, query):
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        if not files:
            return page("Library", "<p>No snapshots available.</p>", self.nav())
        name = query.get("snapshot", files[0].name)
        bundle = read_audit(self.directory, name)
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
            for identity, profile in sorted(view["profiles"].items()):
                detail += (f'<details><summary>{e(identity)}</summary>'
                           f'<pre>{e(json.dumps(profile, indent=2, ensure_ascii=False))}</pre></details>')
            detail += "</section>"
        assignment_detail = (f'<section><h2>Observed assignment response</h2><p>{e(assignments.get("status", "unknown"))} · '
                             f'{len(assignment_rows)} records. Assignment completeness is not verified.</p>'
                             f'<details><summary>Inspect raw assignment records</summary><pre>{e(json.dumps(assignment_rows, indent=2, ensure_ascii=False))}</pre></details></section>')
        return page("Library", select + '<section><h2>Tenant Library</h2><p>Read-only shared profile inventory; counts are observed, not proof of completeness.</p>'
                    '<table><thead><tr><th>Module</th><th>Response status</th><th>Observed profiles</th></tr></thead><tbody>'
                    + body + '</tbody></table></section>' + detail + assignment_detail, self.nav())

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
        return page("Module coverage", '<section><h2>Configuration module qualification</h2>'
                    '<p>Fully qualified modules first. Partial modules retain their valid scope evidence; '
                    'unqualified scopes are diagnostics only. Qualification is not permission to modify configuration.</p>'
                    f'<form method="get" action="{root}coverage"><label>Snapshot<select name="snapshot">'
                    + options([(p.name, p.name) for p in files], name)
                    + '</select></label><button>Open</button></form><table><thead><tr><th>Function</th><th>Module</th>'
                    '<th>Qualified scopes</th><th>Status</th><th>Evidence</th></tr></thead><tbody>'
                    + body + '</tbody></table></section>', self.nav())

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

        def reply(self, body, status=200):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
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
                if parsed.path == root:
                    body = workspace.home()
                elif parsed.path == root + "report":
                    body = workspace.report(query)
                elif parsed.path == root + "library":
                    body = workspace.library(query)
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
            if (not self.valid_host() or self.path not in (root + "refresh", root + "credentials")
                    or self.headers.get("Origin") != expected):
                self.reply("Forbidden", 403)
                return
            if self.path == root + "credentials":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 24576 or self.headers.get_content_type() != "application/x-www-form-urlencoded":
                        raise ValueError("Invalid credential form")
                    self.connection.settimeout(10)
                    values = parse_qs(self.rfile.read(length).decode("utf-8"),
                                      keep_blank_values=True, strict_parsing=True, max_num_fields=3)
                    if set(values) != {"client_id", "client_secret", "region"} or any(len(v) != 1 for v in values.values()):
                        raise ValueError("Invalid credential form")
                    refresh = credential_refresh(values["client_id"][0], values["client_secret"][0], values["region"][0])
                    values.clear()
                    started = workspace.start_refresh(refresh)
                except (ValueError, OSError, UnicodeError):
                    self.reply("Invalid credential form", 400)
                    return
            else:
                if self.headers.get("Content-Length", "0") != "0":
                    self.reply("Unexpected request body", 400)
                    return
                started = workspace.start_refresh()
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
