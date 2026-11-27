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
        "identity_observed", "pagination_unresolved", "cursor_unresolved",
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
                           "received": count(row.get("received")), "outcomes": outcomes})
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
    selector_shapes = Counter()
    for persona, scopes in (bundle.get("keyed_profile_details") or {}).get("profiles", {}).items():
        function = persona if persona in NETWORK_PERSONAS or persona in ("Library", "NAC", "ALL_DEVICE_FUNCTIONS", "UNFILTERED_SCOPE") else "other"
        for scope in scopes.values():
            for module, identities in scope.items():
                name = module if module in modules else "other"
                for identity, views in identities.items():
                    for kind, result in views.items():
                        side = kind if kind in ("local", "effective", "library", "tenant") else "other"
                        state = safe_status(result.get("status"))
                        keyed[(function, name, side, state)] += 1
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
        specialized[name] = {"collected": bool(entry), "outcomes": dict(outcomes)}
        if name == "portal-assets":
            specialized[name].update(status=safe_status(entry.get("status", "not_collected")),
                                     images=len(entry.get("images", [])), count_confirmed=entry.get("count_confirmed") is True)
    return {
        "schema": 1, "kind": "anonymous_collection_diagnostics",
        "specialized_reads": specialized,
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
    args = parser.parse_args()
    from config_app import audit_files, read_audit
    files = audit_files(args.directory)
    if not files:
        parser.error("No configuration audit snapshots found")
    result = diagnostics(read_audit(args.directory, args.snapshot or files[0].name))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
