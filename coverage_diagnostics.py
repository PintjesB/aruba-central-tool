"""Export allowlisted, aggregate collection diagnostics without customer identities."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re


def count(value):
    return value if type(value) is int and value >= 0 else 0


def safe_status(value):
    allowed = {
        "list_parsed", "empty_object", "schema_unresolved", "identity_unresolved",
        "count_mismatch", "request_rejected", "read_failed", "response_received",
        "not_collected", "not_attempted", "no_response", "mixed_outcomes",
        "unqualified_adapter", "qualified", "partial", "unqualified",
        "identity_observed", "scope_only_observed", "pagination_unresolved", "cursor_unresolved",
        "complete", "incomplete", "unknown", "count_confirmed", "pagination_exhausted",
        "page_limit_reached", "schema_unqualified", "ambiguous_registration_envelope",
        "duplicate_or_unqualified_registration_identity", "cursor_unqualified", "cursor_repeated_or_empty",
        "empty_response", "partial_response", "permission_denied", "invalid_selector",
        "selector_mismatch", "empty_correlated", "empty_contradictory_local_profile",
        "empty_effective_source_unverified", "not_attempted",
        "supplemental_raw", "settings_observed", "tenant_scope_disagreement",
    }
    return value if isinstance(value, str) and value in allowed else "other"


def view_summary(view):
    return {
        "status": safe_status(view.get("status")),
        "count_confirmed": view.get("count_confirmed") is True or view.get("collection_count_verified") is True,
        "profiles": len(view["profiles"]) if isinstance(view.get("profiles"), dict) else None,
        "http_error": view.get("http_error") if type(view.get("http_error")) is int and 400 <= view["http_error"] <= 599 else None,
    }


def raw_shape(payload, identity_keys=()):
    """Aggregate response structure without emitting tenant keys or values."""
    if not isinstance(payload, dict):
        return "non_object", 0, 0
    if not payload:
        return "empty_object", 0, 0
    fields = {k: v for k, v in payload.items() if k not in ("metadata", "@")}
    if not fields:
        return "metadata_only", 0, 0
    lists = [v for v in fields.values() if isinstance(v, list)]
    if len(fields) == 1 and len(lists) == 1:
        records = lists[0]
        if not records:
            return "empty_list", 0, 0
        if not all(isinstance(r, dict) for r in records):
            return "non_record_list", 0, 0
        shape = "record_list"
    elif len(fields) == 1 and isinstance(next(iter(fields.values())), dict):
        records = [next(iter(fields.values()))]
        shape = "object_envelope"
    elif any(k in fields for k in identity_keys):
        records = [fields]
        shape = "direct_object"
    else:
        return "other_object", 0, 0
    matched = sum(any(type(row.get(key)) in (str, int) and str(row[key]).strip()
                      for key in identity_keys) for row in records)
    return shape, len(records), matched


def raw_profile_shapes(bundle, catalog, modules):
    keys = {}
    for request in catalog["get_requests"]:
        match = re.fullmatch(r"/network-config/v1alpha1/([a-z][a-z0-9-]*)/:([a-z][a-z0-9-]*)",
                             request["path"])
        if request["method"] == "GET" and match:
            module, key = match.groups()
            keys.setdefault(module, set()).add(key)
    counts = Counter()
    records = Counter()
    matches = Counter()
    for module, entry in (bundle.get("unadapted_profiles") or {}).items():
        if module not in modules:
            continue
        views = [("library", entry.get("library", {}))]
        for source in entry.get("source_views", []):
            views.extend((side, source.get(side, {})) for side in ("committed", "effective"))
        for side, view in views:
            if "raw" not in view:
                continue
            shape, n, m = raw_shape(view["raw"], keys.get(module, ()))
            if shape == "empty_object":
                continue
            group = (module, side, shape)
            counts[group] += 1
            records[group] += n
            matches[group] += m
    return [{"module": m, "view": v, "shape": s, "responses": n,
             "records": records[(m, v, s)], "records_with_documented_key": matches[(m, v, s)]}
            for (m, v, s), n in sorted(counts.items())]


def pagination_evidence(bundle, modules):
    """Aggregate only allowlisted reasons and counts, never request selectors."""
    allowed = {"complete", "pagination_exhausted", "request_failed", "read_failed",
               "schema_changed", "count_or_offset_changed", "count_changed",
               "initial_response_changed", "duplicate_records", "repeated_page",
               "duplicate_or_invalid_identity", "page_limit_reached",
               "library_pagination_unavailable", "offset_behavior_unverified"}
    counts, pages, empty_last = Counter(), Counter(), Counter()

    def add(module, source, view):
        if "pagination_status" not in view:
            return
        reason = view["pagination_status"]
        reason = reason if isinstance(reason, str) and reason in allowed else "other"
        key = (module if module in modules else "other", source, reason)
        counts[key] += 1
        raw_pages = view.get("raw_pages", [])
        if isinstance(raw_pages, list):
            pages[key] += len(raw_pages)
            empty_last[key] += bool(raw_pages and raw_pages[-1] == {})

    library = bundle.get("library") or {}
    for module, view in library.get("modules", {}).items():
        add(module, "library", view)
    for module, view in (bundle.get("nac_configuration") or {}).items():
        add(module, "tenant", view)
    for entry in bundle.get("results", {}).values():
        for module, data in entry.get("modules", {}).items():
            for scope in data.get("scope_results", []):
                for side in ("local", "effective"):
                    add(module, side, scope.get(side + "_view", {}))
    for module, entry in (bundle.get("unadapted_profiles") or {}).items():
        add(module, "raw_library", entry.get("library", {}))
        for scope in entry.get("source_views", []):
            for side in ("committed", "effective"):
                add(module, "raw_" + side, scope.get(side, {}))
    assignments = library.get("assignments") or {}
    add("config-assignments", "tenant", assignments)
    for scopes in assignments.get("scope_reads", {}).values():
        for view in scopes.values():
            add("config-assignments", "scoped", view)
    add("scope-maps", "tenant", library.get("scope_maps") or {})
    return [{"module": m, "source": s, "reason": r, "views": n,
             "pages": pages[(m, s, r)], "last_page_empty_object": empty_last[(m, s, r)]}
            for (m, s, r), n in sorted(counts.items())]


def specialized_response_shapes(entry, name):
    """Expose response structure without exporting arbitrary keys or values."""
    known = {
        "hierarchy": ("items", "Hierarchy", "hierarchy", "id", "type", "metadata", "scopeId"),
        "assignments": ("config-assignment", "config-assignments", "items", "metadata", "@",
                        "scope-id", "device-function", "profile-type", "profile-instance",
                        "scope-name", "scope-type", "persona", "resource", "httpStatusCode", "errorCode", "message", "debugId"),
        "portal-assets": ("items", "count", "imageID", "imageId", "image-id", "id",
                          "fileName", "referencedBy", "metadata", "httpStatusCode", "errorCode", "message")
    }[name]
    def shape(raw):
        if not isinstance(raw, dict):
            return {"type": "list" if isinstance(raw, list) else "other",
                    "size": len(raw) if isinstance(raw, list) else 0}
        result = {"type": "object", "known_fields": {}, "other_fields": len(set(raw) - set(known))}
        for key in known:
            if key not in raw:
                continue
            value = raw[key]
            result["known_fields"][key] = ("list" if isinstance(value, list) else "object"
                                           if isinstance(value, dict) else "string" if isinstance(value, str)
                                           else "integer" if type(value) is int else "other")
            if isinstance(value, list):
                result.setdefault("list_sizes", {})[key] = len(value)
                observed = Counter()
                for row in value:
                    if isinstance(row, dict):
                        for field in known:
                            if field in row:
                                observed[field] += 1
                result.setdefault("record_fields", {})[key] = dict(observed)
        return result
    records = ([entry.get("list_read", {}), *entry.get("details", {}).values()]
               if name == "portal-assets" else entry.get("records", []))
    counts = Counter(json.dumps(shape(record["raw"]), sort_keys=True)
                     for record in records if isinstance(record, dict) and "raw" in record)
    return [{"shape": json.loads(key), "responses": n} for key, n in sorted(counts.items())]


def diagnostics(bundle):
    if bundle.get("schema") != 1 or bundle.get("kind") != "configuration_audit":
        raise ValueError("Expected a configuration audit")
    from central_tool import CONFIG_MODULES, NETWORK_PERSONAS
    catalog = json.loads(Path(__file__).with_name("central_api_catalog.json").read_text(encoding="utf-8"))
    paths = {r["path"] for r in catalog["get_requests"] if r["method"] == "GET"}
    paths.update(r["path"] for r in catalog.get("release_note_collections", []))
    modules = set(CONFIG_MODULES) | {"auth-profiles", "authz-policies", "identity-stores", "static-tag"}
    modules.update(path.rsplit("/", 1)[-1] for path in paths
                   if re.fullmatch(r"/network-config/v1alpha1/[a-z][a-z0-9-]*", path))
    scoped = Counter()
    for persona, entry in bundle.get("results", {}).items():
        for module, data in entry.get("modules", {}).items():
            for row in data.get("scope_results", []):
                kind = row.get("scope_kind")
                kind = kind if kind in ("global", "collection", "site", "group", "device", "library") else "other"
                for side in ("local", "effective"):
                    summary = view_summary(row.get(side + "_view", {}))
                    key = (persona if persona in NETWORK_PERSONAS else "other",
                           module if module in modules else "other", kind, side,
                           summary["status"], summary["count_confirmed"], summary["http_error"])
                    scoped[key] += 1
    operations = []
    for row in bundle.get("api_read_coverage", {}).get("operations", []):
        if row.get("path") not in paths or not count(row.get("attempted")):
            continue
        outcomes = {k: count(v) for k, v in row.get("outcomes", {}).items()
                    if k in ("response_received", "read_failed") or re.fullmatch(r"http_[45][0-9]{2}", k)}
        operations.append({"path": row["path"], "attempted": count(row["attempted"]),
                           "received": count(row.get("received")), "outcomes": outcomes,
                           **({"elapsed_ms_sum": count(row.get("elapsed_ms_sum")),
                               "elapsed_ms_max": count(row.get("elapsed_ms_max"))}
                              if type(row.get("elapsed_ms_sum")) is int and type(row.get("elapsed_ms_max")) is int else {})})
    # Only use pinned vendor templates. Never export observed URL selectors.
    # A missing operation is not necessarily applicable to this tenant.
    groups = {}
    for request in catalog["get_requests"]:
        if request["method"] == "GET":
            groups.setdefault(request["path"], set()).add(request["group"])
    for request in catalog.get("release_note_collections", []):
        groups.setdefault(request["path"], set()).add("Additional documented profiles")
    attempted = {row["path"] for row in operations}
    gaps = []
    operation_groups = {}
    for path in sorted(paths):
        group = " / ".join(sorted(groups.get(path, {"Other"})))
        totals = operation_groups.setdefault(group, {"documented": 0, "attempted": 0, "not_attempted": 0})
        totals["documented"] += 1
        if path in attempted:
            totals["attempted"] += 1
            continue
        totals["not_attempted"] += 1
        gaps.append({"path": path, "group": group,
                     "selector_required": any(part.startswith((":", "{")) for part in path.split("/"))})
    from nac_authorization import nac_collection
    nac = {module: view_summary(nac_collection(bundle, module))
           for module in ("auth-profiles", "authz-policies", "identity-stores", "static-tag")}
    registration = bundle.get("nac_registrations", {})
    nac["mac-registrations"] = {
        "status": safe_status(registration.get("status")),
        "count_confirmed": registration.get("count_confirmed") is True,
        "records": len(registration.get("rows", [])),
    }
    raw = Counter()
    for module, entry in bundle.get("unadapted_profiles", {}).items():
        name = module if module in modules else "other"
        for status, n in entry.get("scope_read_outcomes", {}).items():
            raw[(name, safe_status(status))] += count(n)
    # Use the original snapshot evidence, not current adapter assumptions.
    # The keys below are allowlisted; resource identities are never exported.
    keyed = Counter()
    keyed_differences = Counter()
    keyed_skipped = Counter()
    selector_shapes = Counter()
    for persona, scopes in (bundle.get("keyed_profile_details") or {}).get("profiles", {}).items():
        function = persona if persona in NETWORK_PERSONAS or persona in ("Library", "NAC", "ALL_DEVICE_FUNCTIONS", "UNFILTERED_SCOPE") else "other"
        for scope in scopes.values():
            for module, identities in scope.items():
                name = module if module in modules else "other"
                for identity, views in identities.items():
                    for kind, result in views.items():
                        side = kind if kind in ("local", "effective", "library", "tenant") else "other"
                        if result.get("status") == "collection_only_sampled":
                            keyed_skipped[(name, side)] += 1
                            continue
                        state = safe_status(result.get("status"))
                        keyed[(function, name, side, state)] += 1
                        differences = result.get("differences")
                        if state == "identity_observed":
                            comparison = "not_compared" if not isinstance(differences, list) else "different" if differences else "identical"
                            keyed_differences[(name, side, comparison)] += 1
                            if isinstance(differences, list) and any(isinstance(d, dict) and d.get("kind") == "missing_local" for d in differences):
                                keyed_differences[(name, side, "additional_fields_in_detail")] += 1
                        if state == "invalid_selector":
                            shape = ("numeric_port" if re.fullmatch(r"[0-9]{1,4}/[0-9]{1,4}/[0-9]{1,4}", identity)
                                     else "contains_separator" if "/" in identity or "\\" in identity
                                     else "contains_percent" if "%" in identity else "other")
                            selector_shapes[(name, shape)] += 1
    library = bundle.get("library") or {}
    library_summary = [{"module": module if module in modules else "other", **view_summary(view)}
                       for module, view in sorted(library.get("modules", {}).items())]
    from library_visibility import visibility_summary
    visibility = []
    for row in visibility_summary(bundle):
        if row["module"] in modules:
            visibility.append({**row, "assignment_capture_status": safe_status(row["assignment_capture_status"])})
    scope_totals = Counter()
    for key, n in scoped.items():
        scope_totals[key[4]] += n
    registration = bundle.get("nac_registrations") or {}
    nac["mac-registrations"]["status"] = safe_status(registration.get("status", "not_collected"))
    specialized = {}
    for name, key in (("hierarchy", "scope_hierarchy_evidence"), ("assignments", "keyed_assignment_details"),
                      ("portal-assets", "nac_portal_assets")):
        entry = bundle.get(key) or {}
        outcomes = Counter()
        for state, number in entry.get("outcomes", {}).items():
            outcomes[safe_status(state)] += count(number)
        specialized[name] = {"collected": bool(entry), "outcomes": dict(outcomes),
                             "response_shapes": specialized_response_shapes(entry, name)}
        if name == "assignments":
            from scope_evidence import assignment_selector_rejection, assignment_identity, legacy_assignment_status
            rows = ((bundle.get("library") or {}).get("assignments") or {}).get("rows", [])
            rejected = Counter()
            for row in rows:
                reason = assignment_selector_rejection(row)
                if reason:
                    rejected[reason] += 1
            specialized[name]["selector_rejection_reasons"] = dict(rejected)
            # Offline qualification of retained legacy responses. Does not
            # modify the capture or establish that new requests will succeed.
            legacy = Counter()
            for record in entry.get("records", []):
                identity = assignment_identity(record.get("selector"))
                response_body = record.get("raw")
                if identity and isinstance(response_body, dict) and "persona" in response_body and "resource" in response_body:
                    legacy[legacy_assignment_status(response_body, identity)] += 1
            specialized[name]["retained_legacy_identity_matches"] = dict(legacy)
        if name == "hierarchy":
            by_kind = Counter()
            for record in entry.get("records", []):
                kind = record.get("kind")
                kind = kind if kind in ("global", "collection", "site", "group", "device") else "other"
                version = record.get("endpoint_version", "v1")
                version = version if version in ("v1", "v1alpha1") else "other"
                error = record.get("http_error")
                error = error if type(error) is int and 400 <= error <= 599 else None
                by_kind[(kind, version, safe_status(record.get("status")), error)] += 1
            specialized[name]["scope_outcomes"] = [
                {"kind": kind, "version": version, "status": status, "http_error": error, "reads": n}
                for (kind, version, status, error), n in sorted(by_kind.items(), key=lambda item: str(item[0]))]
        if name == "portal-assets":
            specialized[name].update(status=safe_status(entry.get("status", "not_collected")),
                                     images=len(entry.get("images", [])), count_confirmed=entry.get("count_confirmed") is True)
    timing = bundle.get("collection_timing") or {}
    # Only known phase names are exported. Never retain progress descriptions,
    # which may contain a device function or an observed identifier.
    phase_names = {"Connection", "Discovery", "Configuration scopes", "Library",
                   "Additional profile types", "NAC registrations", "Profile details",
                   "Profile detail expansion", "VLAN details", "Configuration health",
                   "Scope hierarchy", "Individual assignments", "NAC portal assets",
                   "Saving snapshot", "Assignment coverage", "NAC configuration", "Operational VLANs",
                   "Switch VLAN verification", "Switch VLAN features"}
    def seconds(value):
        return round(value, 1) if type(value) in (int, float) and 0 <= value <= 864000 else None
    phase_timing = [{"phase": row["phase"] if row.get("phase") in phase_names else "other",
                     "done": count(row.get("done")), "total": count(row.get("total")),
                     "seconds": seconds(row.get("seconds"))}
                    for row in timing.get("phases", []) if isinstance(row, dict)]
    strategy = bundle.get("collection_strategy")
    details = bundle.get("keyed_profile_details") or {}
    detail_strategy = details.get("detail_strategy")
    transport = bundle.get("http_get_transport")
    transport_fields = ("http_get_attempts", "http_get_retries", "http_get_429",
                        "http_get_5xx", "custom_500_retry_sequences_suppressed", "http_get_transient_errors")
    return {
        "schema": 1, "kind": "anonymous_collection_diagnostics",
        "collection_performance": {
            "strategy": strategy if strategy in ("standard", "deep", "targeted") else "unknown",
            "detail_strategy": detail_strategy if detail_strategy in ("adaptive", "exhaustive") else "unknown",
            "logical_gets": sum(row["attempted"] for row in operations),
            "slowest_operations": [{"path": row["path"], "requests": row["attempted"],
                                    "cumulative_seconds": round(row["elapsed_ms_sum"] / 1000, 2),
                                    "mean_seconds": round(row["elapsed_ms_sum"] / row["attempted"] / 1000, 3),
                                    "max_seconds": round(row["elapsed_ms_max"] / 1000, 3)}
                                   for row in sorted((r for r in operations if "elapsed_ms_sum" in r),
                                                     key=lambda r: (-r["elapsed_ms_sum"], r["path"]))[:20]],
            "exact_collection_gets_reused": count((bundle.get("api_read_coverage") or {}).get("exact_collection_gets_reused")),
            "detail_read_plan": [{"module": m,
                                  "candidates": count((details.get("candidate_reads_by_module") or {}).get(m)),
                                  "initial_reads": count((details.get("initial_reads_by_module") or {}).get(m)),
                                  "expanded_reads": count((details.get("expanded_reads_by_module") or {}).get(m))}
                                 for m in sorted(modules & set(details.get("candidate_reads_by_module") or {}))],
            "http_get_transport": ({key: count(transport.get(key)) for key in transport_fields}
                                   if isinstance(transport, dict) else None),
            "http_get_performance": ({
                **{key: count(bundle["http_get_performance"].get(key))
                   for key in ("rate_wait_ms", "successful_get_ms", "successful_gets")},
                "phase_worker_budgets": {
                    key: count(bundle["http_get_performance"].get("phase_worker_budgets", {}).get(key))
                    for key in ("assignments", "configuration_scopes", "library", "supplemental",
                                "nac_assets", "health", "keyed_details", "hierarchy",
                                "assignment_details", "vlan_details", "operational", "switch_cli")
                    if key in bundle["http_get_performance"].get("phase_worker_budgets", {})}}
                if isinstance(bundle.get("http_get_performance"), dict) else None),
            "http_config_validators": ({kind + "_" + field: count(bundle["http_config_validators"].get(kind + "_" + field))
                                        for kind in ("collection", "keyed")
                                        for field in ("responses", "strong_etag", "weak_etag", "last_modified")}
                                       if isinstance(bundle.get("http_config_validators"), dict) else None),
            "elapsed_before_save_seconds": seconds(timing.get("elapsed_before_save_seconds")),
            "phases": phase_timing,
            "individual_reads": sum(keyed.values()),
            "collection_only": sum(keyed_skipped.values()),
            "collection_only_by_module": [{"module": m, "view": v, "observations": n}
                                          for (m, v), n in sorted(keyed_skipped.items())],
        },
        "specialized_reads": specialized,
        "pagination_evidence": pagination_evidence(bundle, modules | {"config-assignments", "scope-maps"}),
        "keyed_comparison_counts": [{"module": m, "view": v, "comparison": c, "reads": n}
                                    for (m, v, c), n in sorted(keyed_differences.items())],
        "scoped_status_totals": dict(scope_totals),
        "library_views": library_summary,
        "library_visibility": visibility,
        "keyed_read_outcomes": [{"persona": p, "module": m, "view": v, "status": s, "reads": n}
                                for (p, m, v, s), n in sorted(keyed.items())],
        "invalid_selector_shapes": [{"module": m, "shape": shape, "reads": n}
                                    for (m, shape), n in sorted(selector_shapes.items())],
        "mixed_capture_times": bundle.get("collection_checkpoint", {}).get("mixed_capture_times") is True,
        "scoped_views": [{"persona": p, "module": m, "scope_kind": k, "view": v, "status": s,
                          "count_confirmed": c, "http_error": h, "views": n}
                         for (p, m, k, v, s, c, h), n in sorted(scoped.items(), key=lambda row: str(row[0]))],
        "raw_profile_shapes": raw_profile_shapes(bundle, catalog, modules),
        "raw_scope_outcomes": [{"module": m, "status": s, "views": n}
                               for (m, s), n in sorted(raw.items())],
        "nac": nac, "attempted_operations": sorted(operations, key=lambda row: row["path"]),
        "catalog_operations": len(paths), "operation_groups": operation_groups,
        "unattempted_operations": gaps, "complete": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--snapshot", help="Specific snapshot filename; default is latest")
    parser.add_argument("--output", type=Path, help="Write JSON to a new private file instead of standard output")
    args = parser.parse_args()
    if args.output is not None and (args.output.exists() or args.output.is_symlink()):
        parser.error("Output already exists; choose a new filename")
    from config_app import audit_files, read_audit
    files = audit_files(args.directory)
    if not files:
        parser.error("No configuration audit snapshots found")
    result = diagnostics(read_audit(args.directory, args.snapshot or files[0].name))
    if args.output is None:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        from central_tool import write_private
        write_private(args.output, result)
        print("Diagnostics saved to the requested file.")


if __name__ == "__main__":
    main()
