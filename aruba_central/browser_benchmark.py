"""Measure local browser navigation and inspector latency without exporting tenant data."""
import argparse
from http.server import ThreadingHTTPServer
from pathlib import Path
from statistics import median
from threading import Thread
from time import perf_counter
from urllib.parse import urlencode, urlsplit

from .central_tool import write_private
from .config_app import Workspace, audit_files, handler_for


def browser_benchmark(directory, snapshot, *, repeat=3, executable=None):
    if type(repeat) is not int or not 1 <= repeat <= 5:
        raise ValueError("Repeat must be between 1 and 5")
    from playwright.sync_api import sync_playwright
    workspace = Workspace(directory)
    bundle = workspace.reviewed_snapshot(snapshot)
    # Use a warm reviewed snapshot to isolate browser navigation/interaction.
    # Browser/HTTP timings still include normal server-side request processing.
    workspace.advanced_snapshot(bundle)
    routes = [
        ("assessment", "assessment", {}), ("coverage", "coverage", {}),
        ("advisor", "advisor", {}), ("overrides", "overrides", {"result": "all"}),
        ("keyed_evidence", "assessment", {"mode": "keyed"}),
        ("nac", "nac", {}), ("field_search", "report", {"mode": "search", "q": "vlan"}),
        ("object_search", "report", {"mode": "entities", "q": "vlan"}),
        ("port_mapping", "advanced", {"workflow": "ports"}),
        ("duplicates", "advanced", {"workflow": "duplicates"}),
    ]
    samples = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(workspace))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    root = origin + "/" + workspace.token + "/"
    try:
        with sync_playwright() as playwright:
            options = {"headless": True}
            if executable:
                options["executable_path"] = str(executable)
            browser = playwright.chromium.launch(**options)
            try:
                context = browser.new_context(viewport={"width": 1440, "height": 900},
                                              service_workers="block")
                # No requests to Central, external fonts, links or third-party sites.
                def local_only(route):
                    target = urlsplit(route.request.url)
                    if target.scheme == "http" and target.netloc == f"127.0.0.1:{server.server_port}":
                        route.continue_()
                    else:
                        route.abort()
                context.route("**/*", local_only)
                tab = context.new_page()
                tab.set_default_timeout(30000)
                errors = []
                tab.on("pageerror", lambda _: errors.append(True))
                for _ in range(repeat):
                    for label, route, params in routes:
                        start = perf_counter()
                        response = tab.goto(root + route + "?" + urlencode({"snapshot": snapshot, **params}), wait_until="load")
                        if response is None or response.status != 200:
                            raise ValueError("Local page unavailable: " + label)
                        # Two animation frames give synchronous grid initialization and
                        # the next render opportunity; not an actual paint measurement.
                        tab.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
                        elapsed = perf_counter() - start
                        nav = tab.evaluate("""() => {const n=performance.getEntriesByType('navigation')[0];
                            return {response_ms:n.responseEnd,dom_ready_ms:n.domContentLoadedEventEnd,
                                    load_ms:n.loadEventEnd,dom_nodes:document.getElementsByTagName('*').length};}""")
                        samples.setdefault(label, []).append({"navigation_seconds": elapsed, **nav,
                                                              "html_bytes": len(response.body())})
                        button = tab.locator("[data-inspect-url]:visible").first
                        if button.count():
                            start = perf_counter()
                            button.click()
                            tab.locator("#workspace-inspector-body").wait_for(state="visible")
                            tab.wait_for_function("""() => {
                                const b=document.querySelector('#workspace-inspector-body');
                                return b && !b.querySelector('[role=status]') && b.childElementCount>0;
                            }""")
                            if tab.locator("#workspace-inspector-body [role=alert]").count():
                                raise ValueError("Local evidence unavailable: " + label)
                            tab.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
                            samples.setdefault(label + "_inspector", []).append({"navigation_seconds": perf_counter()-start})
                            tab.locator("#workspace-close").click()
                        if errors:
                            raise ValueError("Browser script failed: " + label)
                    if workspace.reviewed_snapshot(snapshot) is not bundle:
                        raise ValueError("Snapshot changed during benchmark")
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    return {"schema": 1, "kind": "anonymous_browser_benchmark", "repeat": repeat,
            "viewport": {"width": 1440, "height": 900}, "warm_reviewed_snapshot": True,
            "central_api_requests": 0,
            "stages": {name: {"samples": values, "median_navigation_seconds": median(v["navigation_seconds"] for v in values)}
                       for name, values in samples.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--snapshot")
    parser.add_argument("--repeat", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--browser", type=Path, help="Existing Chromium/Chrome/Edge executable; otherwise use Playwright Chromium")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output already exists; choose a new filename")
    files = audit_files(args.directory)
    if not files:
        parser.error("No configuration audit snapshots found")
    try:
        report = browser_benchmark(args.directory, args.snapshot or files[0].name, repeat=args.repeat, executable=args.browser)
    except ImportError:
        parser.error("Optional Playwright dependency not installed")
    except Exception:
        # Browser exceptions may contain URLs, selectors or tenant data.
        parser.error("Browser benchmark failed; verify local browser availability and saved capture")
    write_private(args.output, report)
    print("Anonymous browser benchmark saved.")


if __name__ == "__main__":
    main()
