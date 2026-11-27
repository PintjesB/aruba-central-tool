"""Measure local snapshot analysis without contacting Central or exporting tenant data."""
import argparse
import json
from pathlib import Path
from statistics import median
from time import perf_counter, process_time

from .assignment_review import assignment_review
from .config_app import Workspace, audit_files
from .consolidation import profile_recommendations
from .override_view import device_override_rows
from .central_tool import write_private


def benchmark(directory, snapshot, *, repeat=3):
    """Measure the same saved capture with a fresh workspace cache each trial.

    Timings include normal Python allocation and OS filesystem caching; they
    are not network timings or a claim of cold physical disk performance.
    Only fixed stage names, aggregate counts and timing values are returned.
    """
    if type(repeat) is not int or not 1 <= repeat <= 5:
        raise ValueError("Repeat must be between 1 and 5")
    samples = {}
    counts = None
    for _ in range(repeat):
        workspace = Workspace(directory)
        def measure(label, action):
            wall, cpu = perf_counter(), process_time()
            result = action()
            samples.setdefault(label, []).append({
                "wall_seconds": perf_counter() - wall,
                "cpu_seconds": process_time() - cpu})
            return result

        bundle = measure("load_and_refresh_review", lambda: workspace.reviewed_snapshot(snapshot))
        measure("review_cache_hit", lambda: workspace.reviewed_snapshot(snapshot))
        overview = measure("dashboard_summary", lambda: workspace.snapshot_overview(snapshot))
        measure("dashboard_cache_hit", lambda: workspace.snapshot_overview(snapshot))
        findings = measure("consolidation", lambda: profile_recommendations(bundle))
        engineering = measure("engineering", lambda: workspace.advanced_snapshot(bundle))
        measure("engineering_cache_hit", lambda: workspace.advanced_snapshot(bundle))
        measure("vlan_evidence_summary", lambda: workspace.vlan_summary(bundle))
        measure("vlan_evidence_cache_hit", lambda: workspace.vlan_summary(bundle))
        assignments = measure("assignment_review", lambda: assignment_review(bundle))

        def overrides():
            rows, missing = 0, 0
            for persona in sorted(bundle["results"]):
                findings, incomplete = device_override_rows(bundle, persona)
                rows += len(findings)
                missing += len(incomplete)
            return rows, missing

        override_count, incomplete_count = measure("device_overrides", overrides)
        trial_counts = {"devices": overview["device_count"], "scopes": overview["scope_count"],
                        "consolidation_findings": len(findings), "references": len(engineering["references"]),
                        "assignments": len(assignments["rows"]), "device_overrides": override_count,
                        "incomplete_override_reads": incomplete_count}
        if counts is not None and counts != trial_counts:
            raise ValueError("Aggregate results changed during benchmark")
        counts = trial_counts
        if workspace.reviewed_snapshot(snapshot) is not bundle:
            raise ValueError("Snapshot changed during benchmark")
        # Drop references before the next trial loads another large snapshot.
        del workspace, bundle, overview, findings, engineering, assignments
    return {"schema": 1, "repeat": repeat, "counts": counts,
            "stages": {label: {"samples": values,
                               "median_wall_seconds": median(v["wall_seconds"] for v in values),
                               "median_cpu_seconds": median(v["cpu_seconds"] for v in values)}
                       for label, values in samples.items()},
            "central_api_requests": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--snapshot", help="Saved snapshot filename; default is latest")
    parser.add_argument("--repeat", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--output", type=Path, help="Write aggregate JSON to a new private file")
    args = parser.parse_args()
    if args.output is not None and (args.output.exists() or args.output.is_symlink()):
        parser.error("Output already exists; choose a new filename")
    files = audit_files(args.directory)
    if not files:
        parser.error("No configuration audit snapshots found")
    result = benchmark(args.directory, args.snapshot or files[0].name, repeat=args.repeat)
    if args.output is None:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        write_private(args.output, result)
        print("Local benchmark saved to the requested file.")


if __name__ == "__main__":
    main()
