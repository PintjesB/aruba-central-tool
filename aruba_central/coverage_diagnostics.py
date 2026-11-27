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


def supplemental_survey_footprint(bundle, modules):
    """Anonymous actual footprint, not a proof of selector applicability."""
    from .central_tool import NETWORK_PERSONAS
    kinds = {}
    valid_kinds = {"global", "site", "collection", "group", "device"}
    for entry in bundle.get("results", {}).values():
        for scope in entry.get("scopes", []):
            kind = scope.get("kind")
            if kind in valid_kinds:
                kinds.setdefault(str(scope.get("id")), set()).add(kind)
        for module in entry.get("modules", {}).values():
            for scope in module.get("scope_results", []):
                kind = scope.get("scope_kind")
                if kind in valid_kinds:
                    kinds.setdefault(str(scope.get("scope")), set()).add(kind)
    counts = {}
    def classify(view):
        raw = view.get("raw")
        status = view.get("status")
        if status not in ("response_received", "empty_response"):
            return "unqualified"
        if not isinstance(raw, dict):
            return "unqualified"
        if view.get("collection_count_verified") is True:
            # A verified count is not a declaration of applicability.
            return "counted_positive" if any(isinstance(v, list) and v for k, v in raw.items() if k != "metadata") else "counted_empty"
        if not raw:
            return "empty_object"
        if any(k not in ("metadata", "@") and v not in (None, {}, []) for k, v in raw.items()):
            return "positive_uncounted"
        return "metadata_or_empty_collection"
    for module, data in (bundle.get("unadapted_profiles") or {}).items():
        name = module if module in modules else "other"
        for source in data.get("source_views", []):
            known = kinds.get(str(source.get("scope")), set())
            kind = next(iter(known)) if len(known) == 1 else "unknown"
            persona = source.get("persona")
            selector = persona if persona in NETWORK_PERSONAS else (
                "unfiltered" if persona in ("ALL_DEVICE_FUNCTIONS", "UNFILTERED_SCOPE") else "other")
            key = (name, kind, selector)
            row = counts.setdefault(key, Counter())
            for side in ("committed", "effective"):
                view = source.get(side, {})
                row["views"] += 1
                row[classify(view)] += 1
                row["reused_views"] += view.get("reused_exact_collection") is True
                pages = view.get("raw_pages")
                if isinstance(pages, list):
                    row["pagination_responses"] += len(pages)
                if view.get("pagination_status") in ("request_failed", "read_failed"):
                    row["pagination_failures"] += 1
                if view.get("http_error") in (400, 403, 404, 500):
                    row["http_" + str(view["http_error"])] += 1
    return [{"module": name, "scope_kind": kind, "selector": selector, **dict(row)}
            for (name, kind, selector), row in sorted(counts.items())]


def committed_effective_projection_evidence(bundle, modules):
    """Offline candidate measurement only; never substitutes an effective read.

    Compare explicit LOCAL counts and non-inherited annotations against the
    independently observed committed view. Effective results can hide
    overridden objects, so even exact historical agreement is not proof of
    equivalence for future requests.
    """
    from .central_tool import NETWORK_PERSONAS, canonical
    totals = {}
    def complete_rows(view, object_type):
        raw = view.get("raw")
        if (view.get("status") not in ("list_parsed", "response_received")
                or view.get("pagination_status") not in (None, "complete")
                or view.get("http_error") is not None or not isinstance(raw, dict)):
            return None
        meta = raw.get("metadata")
        if not isinstance(meta, dict):
            return None
        counts = meta.get("count_objects_in_module", {})
        if not isinstance(counts, dict):
            return None
        expected = counts.get(object_type)
        total = meta.get("total", expected)
        lists = [(k, v) for k, v in raw.items() if k != "metadata" and isinstance(v, list)]
        if (len(lists) == 1 and set(raw) == {"metadata", lists[0][0]}):
            rows = lists[0][1]
        elif type(expected) is int and expected == 0 and (
                set(raw) == {"metadata"} or len(raw) == 2 and any(
                    k != "metadata" and v is None for k, v in raw.items())):
            rows = []
        else:
            return None
        if (type(total) is not int or total != len(rows)
                or expected is not None and (type(expected) is not int or expected != total)
                or type(meta.get("count", total)) is not int or meta.get("count", total) != total
                or type(meta.get("offset", 0)) is not int or meta.get("offset", 0) not in (0, total)
                or not all(isinstance(v, dict) for v in rows)
                or len({canonical(v) for v in rows}) != total):
            return None
        return rows, counts

    def body(row):
        return canonical({k: v for k, v in row.items() if k != "@"})

    def examine(module, kind, selector, source, committed, effective, local_only):
        key = (module if module in modules else "other", kind, selector, source)
        row = totals.setdefault(key, Counter())
        row["pairs"] += 1
        if committed.get("raw") == {} and effective.get("raw") == {}:
            row["both_empty_unqualified"] += 1
        c = complete_rows(committed, "LOCAL" if local_only else "ANY")
        e = complete_rows(effective, "ANY")
        if c is None or e is None:
            row["unqualified_pair"] += 1
            return
        row["count_qualified_pair"] += 1
        crows, _ = c
        erows, counts = e
        if Counter(map(canonical, crows)) == Counter(map(canonical, erows)):
            row["identical_full_records"] += 1
        expected = counts.get("LOCAL")
        if type(expected) is not int or expected < 0:
            row["effective_local_count_missing"] += 1
            return
        def local(rows):
            result = []
            for profile in rows:
                ann = profile.get("@")
                if (not isinstance(ann, dict)
                        or ann.get("aruba-annotation:object_type") not in ("LOCAL", "SHARED")
                        or type(ann.get("aruba-annotation:inherited")) is not bool):
                    return None
                if ann["aruba-annotation:object_type"] == "LOCAL" and not ann["aruba-annotation:inherited"]:
                    result.append(body(profile))
            return result
        projected = local(erows)
        actual = list(map(body, crows)) if local_only else local(crows)
        if projected is None or actual is None:
            row["source_annotations_missing"] += 1
        elif len(projected) != expected:
            row["effective_local_count_disagrees"] += 1
        elif Counter(projected) != Counter(actual):
            row["local_projection_differs"] += 1
        else:
            row["local_projection_matches"] += 1
            row["local_projection_positive" if actual else "local_projection_empty"] += 1
    valid_kinds = {"global", "site", "collection", "group", "device"}
    kinds = {}
    for persona, entry in bundle.get("results", {}).items():
        for scope in entry.get("scopes", []):
            if scope.get("kind") in valid_kinds:
                kinds.setdefault(str(scope["id"]), set()).add(scope["kind"])
        for module, data in entry.get("modules", {}).items():
            for scope in data.get("scope_results", []):
                kind = scope.get("scope_kind")
                if kind in valid_kinds:
                    kinds.setdefault(str(scope["scope"]), set()).add(kind)
                examine(module, kind if kind in valid_kinds else "unknown",
                        persona if persona in NETWORK_PERSONAS else "other", "structured",
                        scope.get("local_view", {}), scope.get("effective_view", {}), True)
    for module, entry in (bundle.get("unadapted_profiles") or {}).items():
        for scope in entry.get("source_views", []):
            known = kinds.get(str(scope.get("scope")), set())
            kind = next(iter(known)) if len(known) == 1 else "unknown"
            persona = scope.get("persona")
            selector = persona if persona in NETWORK_PERSONAS else (
                "unfiltered" if persona in ("ALL_DEVICE_FUNCTIONS", "UNFILTERED_SCOPE") else "other")
            examine(module, kind, selector, "supplemental",
                    scope.get("committed", {}), scope.get("effective", {}), False)
    return {"groups": [{"module": m, "scope_kind": k, "selector": p, "source": s, **dict(v)}
                       for (m, k, p, s), v in sorted(totals.items())],
            "projection_qualified": False, "complete": False}


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
    from .central_tool import CONFIG_MODULES, NETWORK_PERSONAS
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
    from .nac_authorization import nac_collection
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
    from .library_visibility import visibility_summary
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
            from .scope_evidence import assignment_selector_rejection, assignment_identity, legacy_assignment_status
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
            "exact_counted_empty_gets_reused": count((bundle.get("api_read_coverage") or {}).get("exact_counted_empty_gets_reused")),
            "duplicate_config_get_attempts": [
                {"path": row["path"], "duplicates": count(row.get("duplicates"))}
                for row in (bundle.get("api_read_coverage") or {}).get("duplicate_config_get_attempts", [])
                if row.get("path") in paths],
            "duplicate_accounting_truncated": (bundle.get("api_read_coverage") or {}).get("duplicate_accounting_truncated") is True,
            "supplemental_exact_reuse": [
                {"module": module, "scope_views": sum(
                    read.get("reused_exact_collection") is True
                    for view in entry.get("source_views", [])
                    for read in (view.get("committed", {}), view.get("effective", {}))),
                 "library_view": entry.get("library", {}).get("reused_exact_collection") is True}
                for module, entry in sorted((bundle.get("unadapted_profiles") or {}).items())
                if module in modules],
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
        "supplemental_survey_footprint": supplemental_survey_footprint(bundle, modules),
        "committed_effective_projection": committed_effective_projection_evidence(bundle, modules),
        "raw_scope_outcomes": [{"module": m, "status": s, "views": n}
                               for (m, s), n in sorted(raw.items())],
        "nac": nac, "attempted_operations": sorted(operations, key=lambda row: row["path"]),
        "catalog_operations": len(paths), "operation_groups": operation_groups,
        "unattempted_operations": gaps, "complete": False,
    }


def compare_coverage(previous, current):
    """Compare exact private selectors locally; export only aggregate counts.

    A changed or missing observation may reflect tenant drift, not lost
    coverage. Never infer that equal counts prove equal configuration.
    """
    def index(bundle):
        if bundle.get("schema") != 1 or bundle.get("kind") != "configuration_audit":
            raise ValueError("Expected configuration audit")
        selectors = {}
        duplicate = Counter()
        def add(kind, key, view, positive, counted=False):
            full = (kind, *key)
            if full in selectors:
                duplicate[kind] += 1
            selectors[full] = (positive, counted, view.get("status"))
        for persona, entry in bundle.get("results", {}).items():
            for module, data in entry.get("modules", {}).items():
                for scope in data.get("scope_results", []):
                    for side in ("local", "effective"):
                        view = scope.get(side + "_view", {})
                        add("structured", (persona, module, str(scope["scope"]), side), view,
                            view.get("status") == "list_parsed",
                            view.get("count_confirmed") is True)
        for module, data in (bundle.get("unadapted_profiles") or {}).items():
            for scope in data.get("source_views", []):
                for side in ("committed", "effective"):
                    view = scope.get(side, {})
                    add("supplemental", (scope.get("persona"), module, str(scope.get("scope")), side),
                        view, view.get("status") == "response_received",
                        view.get("collection_count_verified") is True)
            view = data.get("library", {})
            add("supplemental_library", (module,), view,
                view.get("status") == "response_received",
                view.get("collection_count_verified") is True)
        for module, view in (bundle.get("library") or {}).get("modules", {}).items():
            add("library", (module,), view, view.get("status") == "list_parsed",
                view.get("count_confirmed") is True)
        for persona, scopes in (bundle.get("keyed_profile_details") or {}).get("profiles", {}).items():
            for scope, modules in scopes.items():
                for module, identities in modules.items():
                    for identity, views in identities.items():
                        for side, view in views.items():
                            add("keyed", (persona, str(scope), module, identity, side), view,
                                view.get("status") in ("identity_observed", "collection_only_sampled"))
        return selectors, duplicate

    old, old_duplicates = index(previous)
    new, new_duplicates = index(current)
    result = {}
    for kind in ("structured", "supplemental", "supplemental_library", "library", "keyed"):
        a = {key for key in old if key[0] == kind}
        b = {key for key in new if key[0] == kind}
        common = a & b
        result[kind] = {
            "previous": len(a), "current": len(b), "matched": len(common),
            "previous_only": len(a - b), "current_only": len(b - a),
            "previous_duplicate_selectors": old_duplicates[kind],
            "current_duplicate_selectors": new_duplicates[kind],
            "previous_positive_now_missing": sum(old[key][0] for key in a - b),
            "previous_positive_now_unqualified": sum(old[key][0] and not new[key][0] for key in common),
            "previous_count_confirmed_now_unqualified": sum(old[key][1] and not new[key][1] for key in common),
            "status_changed": sum(old[key][2] != new[key][2] for key in common),
        }
        if kind == "keyed":
            result[kind]["direct_to_sampled"] = sum(
                old[key][2] == "identity_observed" and new[key][2] == "collection_only_sampled" for key in common)
            result[kind]["sampled_to_direct"] = sum(
                old[key][2] == "collection_only_sampled" and new[key][2] == "identity_observed" for key in common)
    return {"same_region": bool(previous.get("region") and previous.get("region") == current.get("region")),
            "same_collection_strategy": bool(previous.get("collection_strategy") and previous.get("collection_strategy") == current.get("collection_strategy")),
            "mixed_capture_times": any((b.get("collection_checkpoint") or {}).get("mixed_capture_times") is True for b in (previous, current)),
            "selectors": result, "complete": False, "safe_to_apply": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--snapshot", help="Specific snapshot filename; default is latest")
    parser.add_argument("--compare-previous", action="store_true", help="Compare exact selector coverage with the preceding saved audit, offline")
    parser.add_argument("--output", type=Path, help="Write JSON to a new private file instead of standard output")
    args = parser.parse_args()
    if args.output is not None and (args.output.exists() or args.output.is_symlink()):
        parser.error("Output already exists; choose a new filename")
    from .config_app import audit_files, read_audit
    files = audit_files(args.directory)
    if not files:
        parser.error("No configuration audit snapshots found")
    selected = args.snapshot or files[0].name
    bundle = read_audit(args.directory, selected)
    result = diagnostics(bundle)
    if args.compare_previous:
        index = next((i for i, path in enumerate(files) if path.name == selected), None)
        if index is None or index + 1 >= len(files):
            parser.error("No preceding saved configuration audit")
        result["coverage_comparison"] = compare_coverage(
            read_audit(args.directory, files[index + 1].name), bundle)
    if args.output is None:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        from .central_tool import write_private
        write_private(args.output, result)
        print("Diagnostics saved to the requested file.")


if __name__ == "__main__":
    main()
