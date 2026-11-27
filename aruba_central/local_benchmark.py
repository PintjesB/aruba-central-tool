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


def benchmark(directory, snapshot, *, repeat=3, ui=False):
    """Measure the same saved capture with a fresh workspace cache each trial.

    Timings include normal Python allocation and OS filesystem caching; they
    are not network timings or a claim of cold physical disk performance.
    Only fixed stage names, aggregate counts and timing values are returned.
    """
    if type(repeat) is not int or not 1 <= repeat <= 5:
        raise ValueError("Repeat must be between 1 and 5")
    path = next((p for p in audit_files(Path(directory)) if p.name == snapshot), None)
    if path is None:
        raise ValueError("Unknown snapshot")
    def fingerprint():
        if path.is_symlink():
            raise ValueError("Snapshot changed during benchmark")
        stat = path.stat()
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    initial = fingerprint()
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
        cached_findings = measure("consolidation_workspace_lookup", lambda: workspace.consolidation_snapshot(bundle))
        if cached_findings != findings:
            raise ValueError("Cached recommendations differ from direct analysis")
        measure("consolidation_cache_hit", lambda: workspace.consolidation_snapshot(bundle))
        del cached_findings
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
        if ui:
            from .configuration_search import search_configuration, grouped_search
            from .configuration_health import configuration_health
            from .optimization_worklist import optimization_worklist
            worklist = measure("optimization_worklist", lambda: optimization_worklist(bundle, findings, engineering))
            health = measure("configuration_health", lambda: configuration_health(bundle))
            # Fixed non-private search term; only aggregate counts leave the workspace.
            matches = measure("configuration_search", lambda: search_configuration(bundle, "vlan"))
            grouped = measure("configuration_search_grouped", lambda: grouped_search(bundle, "vlan"))
            trial_counts.update(optimization_worklist_rows=len(worklist), health_rows=len(health),
                                search_observations=matches["total"], search_groups=grouped["total_groups"])
            cached_worklist = measure("optimization_worklist_lookup", lambda: workspace.optimization_worklist(bundle))
            if cached_worklist != worklist:
                raise ValueError("Cached worklist differs from direct analysis")
            measure("optimization_worklist_cache_hit", lambda: workspace.optimization_worklist(bundle))
            del worklist, cached_worklist, health, matches, grouped
            def render(label, action):
                html = measure(label, action)
                trial_counts[label + "_bytes"] = len(html.encode("utf-8"))
            for label, action in (
                ("render_inventory", lambda: workspace.scopes({"snapshot": snapshot})),
                ("render_advisor", lambda: workspace.advisor({"snapshot": snapshot})),
                ("render_advisor_repeat", lambda: workspace.advisor({"snapshot": snapshot})),
                ("render_engineering_ports", lambda: workspace.advanced({"snapshot": snapshot, "workflow": "ports"})),
                ("render_engineering_duplicates", lambda: workspace.advanced({"snapshot": snapshot, "workflow": "duplicates"})),
                ("render_coverage", lambda: workspace.coverage({"snapshot": snapshot})),
                ("render_entity_search", lambda: workspace.report({"snapshot": snapshot, "mode": "entities", "q": "vlan"})),
                ("render_field_search", lambda: workspace.report({"snapshot": snapshot, "mode": "search", "q": "vlan"})),
            ):
                render(label, action)
            from .optimization_worklist import engineering_group_id
            from .review_dispositions import snapshot_binding
            binding = snapshot_binding(workspace, snapshot, bundle)
            for workflow, key in (("ports", "port_groups"), ("duplicates", "library_duplicates")):
                if engineering[key]:
                    group = engineering_group_id(workflow, engineering[key][0])
                    render("render_engineering_" + workflow + "_detail",
                           lambda: workspace.advanced({"snapshot": snapshot, "workflow": workflow,
                                                      "group": group, "detail": "1", "binding": binding}))
            if findings:
                group = findings[0]["id"]
                render("render_advisor_detail", lambda: workspace.advisor({"snapshot": snapshot, "group": group,
                                                                          "detail": "1", "binding": binding}))
            first_library = next(((module, sorted(view["profiles"])[0])
                                  for module, view in sorted((bundle.get("library") or {}).get("modules", {}).items())
                                  if view.get("status") == "list_parsed" and view.get("profiles")), None)
            if first_library is not None:
                module, identity = first_library
                render("render_library_collection", lambda: workspace.library({"snapshot": snapshot, "module": module}))
                render("render_library_profile", lambda: workspace.library({"snapshot": snapshot, "module": module, "profile": identity}))
            if bundle.get("results"):
                persona = sorted(bundle["results"])[0]
                render("render_overrides", lambda: workspace.overrides({"snapshot": snapshot, "persona": persona, "result": "all"}))
            if bundle.get("nac_registrations") or bundle.get("nac_configuration"):
                render("render_nac", lambda: workspace.nac({"snapshot": snapshot}))
            for label, query in (("render_assessment", {}),
                                 ("render_health", {"mode": "health"}),
                                 ("render_customer_report", {"mode": "customer-report"}),
                                 ("render_keyed_evidence", {"mode": "keyed"}),
                                 ("render_assessment_repeat", {})):
                html = measure(label, lambda: workspace.assessment({"snapshot": snapshot, **query}))
                trial_counts[label + "_bytes"] = len(html.encode("utf-8"))
                # Page tokens have a fixed length. Do not retain HTML or expose it.
                del html
            first_device = next(((persona, scope["id"]) for persona, entry in sorted(bundle["results"].items())
                                 for scope in entry["scopes"] if scope["kind"] == "device"), None)
            if first_device is not None:
                persona, device = first_device
                html = measure("render_device_review", lambda: workspace.scopes({"snapshot": snapshot, "mode": "device", "persona": persona, "device": device}))
                trial_counts["render_device_review_bytes"] = len(html.encode("utf-8"))
                del html
        if counts is not None and counts != trial_counts:
            raise ValueError("Aggregate results changed during benchmark")
        counts = trial_counts
        if fingerprint() != initial or workspace.reviewed_snapshot(snapshot) is not bundle:
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
    parser.add_argument("--ui", action="store_true", help="Include new review analysis and server-side page rendering")
    parser.add_argument("--output", type=Path, help="Write aggregate JSON to a new private file")
    args = parser.parse_args()
    if args.output is not None and (args.output.exists() or args.output.is_symlink()):
        parser.error("Output already exists; choose a new filename")
    files = audit_files(args.directory)
    if not files:
        parser.error("No configuration audit snapshots found")
    result = benchmark(args.directory, args.snapshot or files[0].name, repeat=args.repeat, ui=args.ui)
    if args.output is None:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        write_private(args.output, result)
        print("Local benchmark saved to the requested file.")


if __name__ == "__main__":
    main()
