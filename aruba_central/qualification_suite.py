"""Run the three anonymous offline acceptance reports against one unchanged capture."""
import argparse
from pathlib import Path

from .config_app import audit_files, read_audit
from .central_tool import write_private
from .local_benchmark import benchmark
from .keyed_qualification import keyed_qualification
from .browser_benchmark import browser_benchmark


def qualification_suite(directory, snapshot=None, *, repeat=3, executable=None):
    files = audit_files(Path(directory))
    if not files:
        raise ValueError("No configuration audit snapshots found")
    selected = snapshot or files[0].name
    path = next((p for p in files if p.name == selected), None)
    if path is None:
        raise ValueError("Unknown snapshot")

    def fingerprint():
        if path.is_symlink():
            raise ValueError("Snapshot changed during qualification")
        stat = path.stat()
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)

    initial = fingerprint()

    def unchanged():
        if fingerprint() != initial:
            raise ValueError("Snapshot changed during qualification")

    performance = benchmark(directory, selected, repeat=repeat, ui=True)
    unchanged()
    qualification = keyed_qualification(read_audit(directory, selected))
    unchanged()
    browser = browser_benchmark(directory, selected, repeat=repeat, executable=executable)
    unchanged()
    # Export fixed report names, not the selected filename, filesystem identity
    # or customer data. Do not publish a partial suite when any stage fails.
    return {"schema": 1, "kind": "anonymous_offline_qualification_suite",
            "central_api_requests": 0, "same_capture_verified": True,
            "performance": performance, "qualification": qualification, "browser": browser}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--snapshot", help="Saved snapshot filename; default is latest at start")
    parser.add_argument("--repeat", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--browser", type=Path, help="Existing Chromium/Chrome/Edge executable")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output already exists; choose a new filename")
    try:
        report = qualification_suite(args.directory, args.snapshot, repeat=args.repeat, executable=args.browser)
    except ImportError:
        parser.error("Optional Playwright dependency not installed")
    except Exception:
        # Browser and filesystem exceptions can contain private information.
        parser.error("Qualification suite failed; verify the unchanged saved capture and local browser availability")
    write_private(args.output, report)
    print("Anonymous offline qualification suite saved.")


if __name__ == "__main__":
    main()
