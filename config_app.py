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
button,select{font:inherit;padding:8px 12px;margin:4px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:inherit}
a{color:#1674c8}@media(prefers-color-scheme:dark){a{color:#8dc2ff}}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}
label{display:inline-block;margin:6px}small{opacity:.8}.pill{padding:4px 8px;border-radius:6px;background:#fff0d7;color:#804a0b}
</style></head><body><header><h1>Central Configuration Workspace</h1>""" + nav + "</header><main>" + content + "</main></body></html>"


def options(items, selected=None):
    return "".join(f'<option value="{e(key)}"{" selected" if key == selected else ""}>{e(label)}</option>'
                   for key, label in items)


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

    def start_refresh(self):
        with self.lock:
            if self.refresh is None or self.state == "running":
                return False
            self.state = "running"
        def run():
            try:
                from central_tool import write_private
                bundle = self.refresh()
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
                write_private(self.directory / f"config-audit-{stamp}.json", bundle)
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
        return f'<a href="{root}">Snapshots</a><a href="{root}compare">Compare devices</a>'

    def home(self):
        root = "/" + self.token + "/"
        files = audit_files(self.directory)
        with self.lock:
            state = self.state
        refresh = ""
        if self.refresh is not None:
            refresh = (f'<form method="post" action="{root}refresh"><button type="submit"'
                       + (" disabled" if state == "running" else "")
                       + ">Refresh from Central</button></form>")
        return page("Snapshots", '<p>Private local workspace. Select a saved configuration capture. '
                    'Use a separate directory for each customer; tenant identity is not independently verified.</p>'
                    f'<section><h2>Audit refresh</h2><p>Status: {e(state)}</p>{refresh}'
                    f'<p><a href="{root}">Reload status</a></p></section><section><h2>Saved snapshots ({len(files)})</h2>'
                    '<table><thead><tr><th>Capture file</th><th>Action</th></tr></thead><tbody>' +
                    "".join(f'<tr><td>{e(p.name)}</td><td><a href="{root}report?{e(urlencode({"snapshot": p.name}))}">Open explorer</a>'
                            f' · <a href="{root}compare?{e(urlencode({"snapshot": p.name}))}">Compare devices</a></td></tr>'
                            for p in files) + '</tbody></table></section>', self.nav())

    def report(self, query):
        from central_tool import configuration_html, refresh_configuration_review
        bundle = refresh_configuration_review(read_audit(self.directory, query["snapshot"]))
        html = configuration_html(bundle)
        # Static report remains standalone; add a local navigation link only here.
        return html.replace("<main>", f'<main><p><a href="/{self.token}/">Back to workspace</a></p>', 1)

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
            query = {k: v[-1] for k, v in parse_qs(parsed.query, max_num_fields=12).items()}
            try:
                if parsed.path == root:
                    body = workspace.home()
                elif parsed.path == root + "report":
                    body = workspace.report(query)
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
            if (not self.valid_host() or self.path != root + "refresh"
                    or self.headers.get("Origin") != expected):
                self.reply("Forbidden", 403)
                return
            if self.headers.get("Content-Length", "0") != "0":
                self.reply("Unexpected request body", 400)
                return
            if not workspace.start_refresh():
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
