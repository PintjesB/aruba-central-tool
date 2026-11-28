"""Run anonymous offline acceptance reports against one unchanged capture."""
import argparse
from contextlib import contextmanager
from pathlib import Path

from .config_app import audit_files, read_audit
from .central_tool import write_private
from .local_benchmark import benchmark
from .keyed_qualification import keyed_qualification
from .browser_benchmark import browser_benchmark
from .planner_qualification import planner_qualification


class QualificationStageError(ValueError):
    """Public diagnostic with a fixed stage and no captured data."""


@contextmanager
def qualification_stage(stage):
    try:
        yield
    except Exception as exc:
        hint = "Check local capture and qualification dependencies."
        if stage == "browser benchmark":
            if isinstance(exc, ImportError):
                hint = "Install the optional Playwright dependency using the same Python interpreter."
            elif "Executable doesn't exist at" in str(exc) and "BrowserType.launch" in str(exc):
                hint = "Run python -m playwright install chromium using the same Python interpreter, or supply --browser."
            else:
                hint = "Check local browser availability and browser benchmark execution."
        elif stage == "capture verification":
            hint = "Verify that the saved capture is unchanged."
        # Do not expose exception text: it may contain tenant data, local paths
        # or the workspace URL/token. The original cause remains available to
        # local Python callers for explicit debugging.
        raise QualificationStageError(f"Qualification failed during {stage}. {hint}") from exc


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

    with qualification_stage("local performance"):
        performance = benchmark(directory, selected, repeat=repeat, ui=True)
    with qualification_stage("capture verification"):
        unchanged()
    with qualification_stage("capture loading"):
        from .engineering_qualification import engineering_qualification
        capture=read_audit(Path(directory),selected)
    with qualification_stage("keyed evidence"):
        qualification = keyed_qualification(capture)
    with qualification_stage("engineering evidence"):
        engineering=engineering_qualification(capture,include_reference_patterns=True)
    del capture
    with qualification_stage("capture verification"):
        unchanged()
    with qualification_stage("planner validation"):
        planner = planner_qualification(directory, selected)
    with qualification_stage("capture verification"):
        unchanged()
    history = None
    if historical is not None:
        with qualification_stage("history comparison"):
            from .history_qualification import history_qualification
            history = history_qualification(directory, selected, historical.name, repeat=repeat)
        with qualification_stage("capture verification"):
            unchanged()
    with qualification_stage("browser benchmark"):
        browser = browser_benchmark(directory, selected, repeat=repeat, executable=executable,
                                    **({"previous": historical.name} if historical is not None else {}))
    with qualification_stage("capture verification"):
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
    except QualificationStageError as exc:
        parser.error(str(exc))
    except Exception:
        # Capture selection and filesystem errors can contain private information.
        parser.error("Qualification failed during capture selection or initialization. Verify the saved capture and requested options.")
    write_private(args.output, report)
    print("Anonymous offline qualification suite saved.")


if __name__ == "__main__":
    main()
