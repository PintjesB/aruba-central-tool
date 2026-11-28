"""Run anonymous offline acceptance reports against one unchanged capture."""
import argparse
from pathlib import Path

from .config_app import audit_files, read_audit
from .central_tool import write_private
from .local_benchmark import benchmark
from .keyed_qualification import keyed_qualification
from .browser_benchmark import browser_benchmark
from .planner_qualification import planner_qualification


def qualification_suite(directory, snapshot=None, *, repeat=3, executable=None, previous=None, confirm_history_same_tenant=False):
    files = audit_files(Path(directory))
    if not files:
        raise ValueError("No configuration audit snapshots found")
    selected = snapshot or files[0].name
    path = next((p for p in files if p.name == selected), None)
    if path is None:
        raise ValueError("Unknown snapshot")

    if previous is not None and not confirm_history_same_tenant:
        raise ValueError("Confirm both history captures belong to the same tenant")
    historical = None
    if confirm_history_same_tenant:
        historical = (next((p for p in files if p.name == previous), None) if previous is not None
                      else next((p for p in files[files.index(path)+1:]), None))
        if historical is None or historical == path:
            raise ValueError("Choose a different saved history capture")
    def fingerprint(p):
        if p.is_symlink():
            raise ValueError("Snapshot changed during qualification")
        stat = p.stat()
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)

    selected_paths = [path] + ([historical] if historical is not None else [])
    initial = [fingerprint(p) for p in selected_paths]

    def unchanged():
        if [fingerprint(p) for p in selected_paths] != initial:
            raise ValueError("Snapshot changed during qualification")

    performance = benchmark(directory, selected, repeat=repeat, ui=True)
    unchanged()
    from .engineering_qualification import engineering_qualification
    capture=read_audit(Path(directory),selected)
    qualification = keyed_qualification(capture)
    engineering=engineering_qualification(capture,include_reference_patterns=True)
    del capture
    unchanged()
    planner = planner_qualification(directory, selected)
    unchanged()
    history = None
    if historical is not None:
        from .history_qualification import history_qualification
        history = history_qualification(directory, selected, historical.name, repeat=repeat)
        unchanged()
    browser = browser_benchmark(directory, selected, repeat=repeat, executable=executable,
                                **({"previous": historical.name} if historical is not None else {}))
    unchanged()
    # Export fixed report names, not the selected filename, filesystem identity
    # or customer data. Do not publish a partial suite when any stage fails.
    return {"schema": 1, "kind": "anonymous_offline_qualification_suite",
            "central_api_requests": 0, "same_capture_verified": True,
            "performance": performance, "qualification": qualification, "planner": planner, "browser": browser,
            "engineering":engineering,
            **({"history": history, "same_capture_pair_verified": True} if history is not None else {})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--snapshot", help="Saved snapshot filename; default is latest at start")
    parser.add_argument("--repeat", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--browser", type=Path, help="Existing Chromium/Chrome/Edge executable")
    parser.add_argument("--previous", help="Exact prior saved snapshot filename for optional history qualification")
    parser.add_argument("--confirm-history-same-tenant", action="store_true",
                        help="Include historical comparison; confirm both saved captures belong to the same tenant")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output already exists; choose a new filename")
    try:
        report = qualification_suite(args.directory, args.snapshot, repeat=args.repeat, executable=args.browser,
                                     previous=args.previous, confirm_history_same_tenant=args.confirm_history_same_tenant)
    except ImportError:
        parser.error("Optional Playwright dependency not installed")
    except Exception:
        # Browser and filesystem exceptions can contain private information.
        parser.error("Qualification suite failed; verify the unchanged saved capture and local browser availability")
    write_private(args.output, report)
    print("Anonymous offline qualification suite saved.")


if __name__ == "__main__":
    main()
