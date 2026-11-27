"""Read-only, bounded live verification of collection and keyed response contracts.

No private names, serials, scopes, identities, raw values or credentials are printed.
The original workspace is not modified. This is a diagnostic, not a new snapshot.
"""
import argparse
from collections import Counter
import getpass
import json
import os
from pathlib import Path

from central_tool import (
    APIError, Central, CONFIG_MODULES, NETWORK_PERSONAS, discover_scopes,
    health_serial, inventory, inventory_capabilities, keyed_profile_read,
    keyed_profile_contracts, read_module_view,
)
from configuration_history import snapshot_identity_checks
from coverage_diagnostics import safe_status, view_summary


PROBE_MODULES = ("ethernet-interfaces", "dns", "ntp", "snmp", "snmp-trap",
                 "net-groups", "role-acls", "portchannels", "logging")


def qualified_scopes(client, previous):
    devices = inventory(client)
    records = inventory_capabilities(devices)
    present = {record["identity"]["persona"] for record in records}
    results = {}
    for persona in sorted(set(previous["results"]) & present & NETWORK_PERSONAS):
        scopes, _ = discover_scopes(client, persona, devices)
        results[persona] = {"scopes": scopes}
    snapshot_identity_checks(previous, {"region": client.base, "results": results, "inventory": records})
    # Do not sample a device merely because its scope ID was reused.
    old_serials = {health_serial(r.get("inventory")) for r in previous.get("inventory", [])} - {None}
    for entry in results.values():
        entry["scopes"] = [s for s in entry["scopes"] if s["kind"] != "device"
                           or health_serial(s.get("metadata")) in old_serials]
    return results


def observed_read(read):
    try:
        return read()
    except APIError as exc:
        if exc.status in (401, 429):
            raise
        return {"status": "request_rejected", "http_error": exc.status}
    except (RuntimeError, OSError, ValueError):
        return {"status": "read_failed"}


def assignment_context(client, module, scopes, library, sample):
    """Read exact documented module assignments, then sample their actual scopes.

    No absence claim follows from an empty assignment response. Distinguish
    directly observed matching definitions from unknown effective visibility.
    """
    from central_tool import profile_inventory_view, canonical, profile_body
    reads = []
    identities = set()
    contexts = {}
    unknown = 0

    def inspect(source, params, persona=None, sid=None):
        nonlocal unknown
        result = observed_read(lambda: profile_inventory_view(
            client, "config-assignments", "config-assignment", **params))
        raw = result.get("raw")
        records = result.get("rows", [])
        matched, invalid, unrelated, other_types = set(), 0, 0, 0
        for row in records:
            if (not isinstance(row, dict)
                    or not isinstance(row.get("profile-type"), str)
                    or type(row.get("profile-instance")) not in (str, int)
                    or type(row.get("scope-id")) not in (str, int)
                    or not isinstance(row.get("device-function"), str)):
                invalid += 1
                continue
            row_persona, row_sid = row["device-function"], str(row["scope-id"])
            if ((persona is not None and row_persona != persona)
                    or (sid is not None and row_sid != sid)
                    or ("profile-type" in params and row["profile-type"] != module)):
                unrelated += 1
                continue
            if row["profile-type"] != module:
                other_types += 1
                continue
            matched.add((str(row["profile-instance"]), row_persona, row_sid))
        unknown += invalid + unrelated
        identities.update(matched)
        shape = ("missing" if raw is None else "non_object" if not isinstance(raw, dict)
                 else "empty_object" if not raw else
                 "expected_list" if isinstance(raw.get("config-assignment"), list)
                 else "unexpected_envelope")
        reads.append({"source": source, "status": safe_status(result.get("status")),
                      "http_error": result.get("http_error"), "response_shape": shape,
                      "rows": len(records), "matching_assignments": len(matched),
                      "other_type_rows": other_types, "invalid_rows": invalid,
                      "selector_mismatches": unrelated,
                      "count_confirmed": result.get("collection_count_verified") is True
                                         and not invalid and not unrelated})
        return result, matched

    result, filtered = inspect("profile_type", {"profile-type": module})
    _, tenant = inspect("tenant", {})
    # Sample every known scope kind rather than only scopes returned by a
    # potentially incomplete profile-type query. Keep the request count bounded.
    for persona, entry in sorted(scopes.items()):
        by_kind = {}
        for scope in sorted(entry["scopes"], key=lambda s: str(s["id"])):
            if str(scope["id"]).isdigit():
                by_kind.setdefault(scope["kind"], []).append(scope)
        for kind, candidates in sorted(by_kind.items()):
            for scope in candidates[:sample]:
                sid = str(scope["id"])
                inspect("scope_" + kind, {"scope-id": sid, "device-function": persona},
                        persona, sid)
    for identity, persona, sid in identities:
        scope = next((s for s in scopes.get(persona, {}).get("scopes", [])
                      if str(s["id"]) == sid), None)
        if scope:
            contexts.setdefault((persona, sid, scope["kind"]), set()).add(identity)
    expected = library.get("profiles", {}) if library.get("status") == "list_parsed" else {}
    visibility = Counter()
    for (persona, sid, kind), assigned in sorted(contexts.items())[:sample * 2]:
        params = {"view-type": "LOCAL", "scope-id": sid, "device-function": persona, "detailed": "true"}
        identity_key = CONFIG_MODULES[module][0]
        for side, filters in (
                ("committed_shared", {"effective": "false", "object-type": "SHARED"}),
                ("effective_any", {"effective": "true"}),
                ("effective_shared", {"effective": "true", "object-type": "SHARED"})):
            view = observed_read(lambda: read_module_view(client, module, identity_key, {**params, **filters}))
            profiles = view.get("profiles", {}) if view.get("status") == "list_parsed" else {}
            for identity in assigned:
                actual = profiles.get(identity)
                if actual is None:
                    outcome = "count_confirmed_absence" if view.get("status") == "list_parsed" and view.get("count_confirmed") else "visibility_unverified"
                elif identity not in expected:
                    outcome = "library_definition_unverified"
                elif canonical(profile_body(actual)) != canonical(profile_body(expected[identity])):
                    outcome = "different_body"
                else:
                    ann = actual.get("@")
                    outcome = "matching_shared" if isinstance(ann, dict) and ann.get("aruba-annotation:object_type") == "SHARED" else "matching_source_unverified"
                visibility[(persona, kind, side, safe_status(view.get("status")), outcome)] += 1
    return {"module": module, "assignment_read": safe_status(result.get("status")),
            "assignment_count_confirmed": reads[0]["count_confirmed"] and identities == filtered,
            "assignment_reads": reads,
            "tenant_only_assignments": len(tenant - filtered),
            "additional_assignments": len(identities - filtered),
            "observed_assignments": len(identities), "invalid_or_unrelated_rows": unknown,
            "library_profiles_with_observed_assignment": len({i for i, _, _ in identities} & set(expected)),
            "library_profiles_without_observed_assignment": len(set(expected) - {i for i, _, _ in identities}),
            "known_assignment_contexts": len(contexts), "sampled_assignment_contexts": min(len(contexts), sample * 2),
            "visibility": [{"persona": p, "scope_kind": k, "view": v, "read_status": s, "observation": o, "profiles": n}
                           for (p, k, v, s, o), n in sorted(visibility.items())],
            "complete": False}


def probe(client, previous, modules, sample=2):
    if type(sample) is not int or not 1 <= sample <= 4:
        raise ValueError("Sample must be between 1 and 4")
    if not modules or any(module not in PROBE_MODULES for module in modules):
        raise ValueError("Unsupported probe module")
    modules = tuple(dict.fromkeys(modules))
    scopes = qualified_scopes(client, previous)
    contracts = keyed_profile_contracts()
    collections, keyed, assignments = [], Counter(), []
    for module in modules:
        identity, functions, device_only = CONFIG_MODULES[module]
        if not device_only:
            view = observed_read(lambda: read_module_view(client, module, identity,
                                                          {"view-type": "LIBRARY", "detailed": "true"}))
            collections.append({"module": module, "persona": "Library", "scope_kind": "library",
                                "view": "library", **view_summary(view)})
            if contracts.get(module) == identity and view.get("status") == "list_parsed":
                for key, profile in sorted(view["profiles"].items())[:sample]:
                    result = observed_read(lambda: keyed_profile_read(client, module, identity, key,
                                           {"view-type": "LIBRARY", "detailed": "true"}, profile))
                    keyed[(module, "Library", "library", safe_status(result.get("status")), result.get("http_error"))] += 1
            assignments.append(assignment_context(client, module, scopes, view, sample))
        for persona, entry in scopes.items():
            if persona not in functions:
                continue
            device_scopes = sorted((s for s in entry["scopes"] if s["kind"] == "device"), key=lambda s: s["id"])[:sample]
            global_scopes = [s for s in entry["scopes"] if s["kind"] == "global"] if not device_only else []
            for scope in [*global_scopes, *device_scopes]:
                base = {"view-type": "LOCAL", "scope-id": scope["id"],
                        "device-function": persona, "detailed": "true"}
                for side, params in (("local", {**base, "effective": "false", "object-type": "LOCAL"}),
                                     ("effective", {**base, "effective": "true"})):
                    view = observed_read(lambda: read_module_view(client, module, identity, params))
                    collections.append({"module": module, "persona": persona, "scope_kind": scope["kind"],
                                        "view": side, **view_summary(view)})
                    if contracts.get(module) != identity or view.get("status") != "list_parsed":
                        continue
                    for key, profile in sorted(view["profiles"].items())[:sample]:
                        result = observed_read(lambda: keyed_profile_read(client, module, identity, key, params, profile))
                        keyed[(module, persona, side, safe_status(result.get("status")),
                               result.get("http_error"))] += 1
    return {"schema": 1, "kind": "anonymous_live_probe", "sample_limit": sample,
            "collections": collections, "assignments": assignments,
            "keyed": [{"module": m, "persona": p, "view": v, "status": s, "http_error": h, "reads": n}
                      for (m, p, v, s, h), n in sorted(keyed.items(), key=lambda item: str(item[0]))],
            "complete": False, "safe_to_apply": False}


def specialized_probe(client, previous):
    """Bound live verification of outstanding API contracts to observed scopes.

    No additional audit or persisted capture. Exports counts/status only;
    never returns private selectors, field values, error text or credentials.
    """
    from central_tool import read_raw_profile_collection
    from scope_evidence import (hierarchy_capture, keyed_assignment_capture, assignment_identity,
                                assignment_selector_rejection, legacy_assignment_status)
    from nac_assets import capture_portal_assets
    scopes = qualified_scopes(client, previous)
    selected = {}
    for persona, entry in sorted(scopes.items()):
        # One current scope per kind; no arbitrary guessed scope IDs.
        by_kind = {}
        for scope in sorted(entry["scopes"], key=lambda s: str(s["id"])):
            if scope["kind"] in ("global", "device"):
                by_kind.setdefault(scope["kind"], scope)
        selected[persona] = list(by_kind.values())
    # Check both documented endpoints at Library and representative scopes.
    # A response on one scope never establishes absence on another.
    collections = []
    seen = set()
    def collection(module, persona, kind, mode, params):
        signature = (module, json.dumps(params, sort_keys=True))
        if signature in seen:
            return
        seen.add(signature)
        view = observed_read(lambda: read_raw_profile_collection(client, module, params))
        raw = view.get("raw")
        collections.append({"module": module, "persona": persona, "scope_kind": kind,
                            "view": mode, "status": safe_status(view.get("status")),
                            "http_error": view.get("http_error"),
                            "count_confirmed": view.get("collection_count_verified") is True,
                            "record_lists": sum(isinstance(v, list) for k, v in raw.items() if k != "metadata") if isinstance(raw, dict) else 0,
                            "record_count": sum(len(v) for k, v in raw.items() if k != "metadata" and isinstance(v, list)) if isinstance(raw, dict) else 0})
    for module in ("management-server", "custom-get-api"):
        collection(module, "Library", "library", "library", {"view-type": "LIBRARY", "detailed": "true"})
        for persona, entries in sorted(selected.items()):
            for scope in entries:
                for effective in ("false", "true"):
                    base = {"view-type": "LOCAL", "scope-id": str(scope["id"]),
                            "effective": effective, "detailed": "true"}
                    side = "effective" if effective == "true" else "committed"
                    collection(module, "ALL_DEVICE_FUNCTIONS", scope["kind"], side, base)
                    collection(module, persona, scope["kind"], side, {**base, "device-function": persona})
    # Recheck only previously failed hierarchy scopes which still exist in
    # the independently qualified current inventory, at most four.
    live = {(str(s["id"]), s["kind"]): s for entry in scopes.values() for s in entry["scopes"]}
    failed = sorted({(str(r.get("scope")), r.get("kind"))
                     for r in (previous.get("scope_hierarchy_evidence") or {}).get("records", [])
                     if r.get("status") == "request_rejected"
                     and (str(r.get("scope")), r.get("kind")) in live})[:4]
    hierarchy = hierarchy_capture(client, {"sample": [live[k] for k in failed]})
    hierarchy_rows = [{"kind": r["kind"], "status": r["status"],
                       "version": r.get("endpoint_version"), "http_error": r.get("http_error"),
                       "primary_http_error": r.get("primary_read", {}).get("http_error")}
                      for r in hierarchy["records"]]
    # Select at most two observed assignments per currently qualified persona.
    # The live keyed response must still match every selector field.
    live_pairs = {(persona, str(s["id"])) for persona, entry in scopes.items() for s in entry["scopes"]}
    rows = ((previous.get("library") or {}).get("assignments") or {}).get("rows", [])
    sampled, used = [], Counter()
    unique = set()
    rejected = Counter()
    for row in rows:
        reason = assignment_selector_rejection(row)
        if reason:
            rejected[reason] += 1
            continue
        identity = assignment_identity(row)
        sid, persona, _, _ = identity
        if (persona, sid) not in live_pairs or used[persona] >= 2 or identity in unique:
            continue
        unique.add(identity)
        used[persona] += 1
        sampled.append(row)
    assignments = keyed_assignment_capture(client, {"rows": sampled})
    retained = Counter()
    for record in (previous.get("keyed_assignment_details") or {}).get("records", []):
        identity = assignment_identity(record.get("selector"))
        raw = record.get("raw")
        if identity and isinstance(raw, dict) and "persona" in raw and "resource" in raw:
            retained[legacy_assignment_status(raw, identity)] += 1
    assets = capture_portal_assets(client, detail_limit=2)
    return {"schema": 1, "kind": "anonymous_specialized_live_probe",
            "collections": collections, "hierarchy": hierarchy_rows,
            "assignments": {"sampled": len(sampled), "outcomes": assignments["outcomes"],
                            "retained_legacy_identity_matches": dict(retained),
                            "selector_rejection_reasons": dict(rejected)},
            "portal_assets": {"status": assets.get("status"), "count_confirmed": assets["count_confirmed"],
                              "images": len(assets["images"]), "outcomes": assets.get("outcomes", {})},
            "complete": False, "safe_to_apply": False}


PERFORMANCE_MODULES = ("net-services", "role-gpids", "aaa-profile", "device-persona-mapping",
                       "ethernet-interfaces", "dns")


def performance_probe(client, previous, sample=1):
    """Bounded read-only selector and page-size experiments.

    Compare exact source-annotated bodies only within current qualified scopes.
    No inference of absence or universal applicability from a sample.
    One initial, two explicit page-size and one typed GET per context at most.
    """
    from central_tool import ALPHA, canonical, documented_offset_collections
    if type(sample) is not int or not 1 <= sample <= 4:
        raise ValueError("Invalid sample")
    scopes = qualified_scopes(client, previous)
    measurements = []
    validators_before = client.get_validator_metrics() if isinstance(client, Central) else {}
    def fetch(module, params):
        try:
            raw = client.get(ALPHA + "/" + module, **params)
        except APIError as exc:
            if exc.status in (401, 429):
                raise
            return {"status": "request_rejected", "http_error": exc.status}, None, None
        except (RuntimeError, OSError, ValueError):
            return {"status": "read_failed"}, None, None
        if not isinstance(raw, dict):
            return {"status": "schema_unresolved"}, None, None
        lists = [(k, v) for k, v in raw.items() if k != "metadata" and isinstance(v, list)]
        meta = raw.get("metadata", {})
        if (len(lists) != 1 or set(raw) - {"metadata", lists[0][0]}
                or not isinstance(meta, dict) or not all(isinstance(v, dict) for v in lists[0][1])):
            return {"status": "schema_unresolved"}, None, None
        rows = lists[0][1]
        counts = meta.get("count_objects_in_module", {})
        expected = counts.get("ANY") if isinstance(counts, dict) else None
        total = meta.get("total", expected)
        consistent = (isinstance(counts, dict) and
                      (expected is None or type(expected) is int and expected == total) and
                      type(meta.get("count", len(rows))) is int and meta.get("count", len(rows)) == len(rows) and
                      type(meta.get("offset", 0)) is int and meta.get("offset", 0) in (0, len(rows)))
        unique = len({canonical(row) for row in rows}) == len(rows)
        confirmed = consistent and unique and type(total) is int and total == len(rows)
        return {"status": "response_received", "records": len(rows), "count_confirmed": confirmed,
                "declared_total": total if type(total) is int and total >= 0 else None,
                "advertised_limit": meta["limit"] if type(meta.get("limit")) is int and 0 <= meta["limit"] <= 100000 else None,
                "offset": meta["offset"] if type(meta.get("offset")) is int and 0 <= meta["offset"] <= 100000 else None}, rows, lists[0][0]

    for persona, entry in sorted(scopes.items()):
        by_kind = {}
        for scope in sorted(entry["scopes"], key=lambda s: str(s["id"])):
            if scope["kind"] in ("global", "device"):
                by_kind.setdefault(scope["kind"], []).append(scope)
        for module in PERFORMANCE_MODULES:
            if module not in documented_offset_collections():
                continue
            spec = CONFIG_MODULES.get(module)
            if spec and (persona not in spec[1]):
                continue
            for kind, candidates in sorted(by_kind.items()):
                if spec and spec[2] and kind != "device":
                    continue
                for scope in candidates[:sample]:
                    params = {"view-type": "LOCAL", "scope-id": str(scope["id"]),
                              "effective": "true", "detailed": "true"}
                    raw_summary, raw_rows, envelope = fetch(module, params)
                    typed_summary, typed_rows, typed_envelope = fetch(module, {**params, "device-function": persona})
                    comparison = "unqualified"
                    if (raw_summary.get("count_confirmed") and typed_summary.get("count_confirmed")
                            and envelope == typed_envelope):
                        def function(row):
                            annotation = row.get("@")
                            return annotation.get("aruba-annotation:device_function") if isinstance(annotation, dict) else None
                        if all(function(row) in NETWORK_PERSONAS for row in raw_rows) and all(
                                function(row) == persona for row in typed_rows):
                            expected = Counter(canonical(row) for row in raw_rows if function(row) == persona)
                            comparison = "exact_projection" if expected == Counter(map(canonical, typed_rows)) else "different"
                    pages = []
                    for limit in (100, 500):
                        page, page_rows, page_envelope = fetch(module, {**params, "limit": limit, "offset": 0})
                        prefix = None
                        if raw_rows is not None and page_rows is not None and envelope == page_envelope:
                            overlap = min(len(raw_rows), len(page_rows))
                            prefix = overlap > 0 and [canonical(r) for r in raw_rows[:overlap]] == [canonical(r) for r in page_rows[:overlap]]
                        pages.append({"requested_limit": limit, **page, "matching_initial_prefix": prefix})
                    measurements.append({"module": module, "persona": persona, "scope_kind": kind,
                                         "unfiltered": raw_summary, "typed": typed_summary,
                                         "projection": comparison, "pages": pages})
    validators_after = client.get_validator_metrics() if isinstance(client, Central) else {}
    return {"schema": 1, "kind": "anonymous_performance_probe", "sample_limit": sample,
            "contexts": measurements, "http_config_validators": {
                key: validators_after.get(key, 0) - validators_before.get(key, 0)
                for kind in ("collection", "keyed")
                for field in ("responses", "strong_etag", "weak_etag", "last_modified")
                for key in (kind + "_" + field,)},
            "complete": False, "safe_to_apply": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--snapshot")
    parser.add_argument("--module", choices=PROBE_MODULES, action="append")
    parser.add_argument("--sample", type=int, choices=range(1, 5), default=2)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--specialized", action="store_true", help="Bounded probe of management-server, custom-get-api, failed hierarchy scopes, assignment identities and portal assets")
    modes.add_argument("--performance", action="store_true", help="Bounded selector and page-size qualification")
    args = parser.parse_args()
    from config_app import audit_files, read_audit
    try:
        files = audit_files(args.directory)
        if not files:
            raise ValueError("No saved configuration audit")
        previous = read_audit(args.directory, args.snapshot or files[0].name)
        token = os.environ.get("CENTRAL_ACCESS_TOKEN")
        client_id = os.environ.get("CENTRAL_CLIENT_ID")
        secret = os.environ.get("CENTRAL_CLIENT_SECRET")
        if not token and not (client_id and secret):
            client_id = client_id or getpass.getpass("Central client ID: ")
            secret = secret or getpass.getpass("Central client secret: ")
        client = Central(previous["region"], token, client_id, secret)
        if args.performance:
            report = performance_probe(client, previous, args.sample)
        elif args.specialized:
            report = specialized_probe(client, previous)
        else:
            report = probe(client, previous, args.module or ["ethernet-interfaces", "snmp", "net-groups"], args.sample)
        print(json.dumps(report, indent=2, sort_keys=True))
    except APIError as exc:
        parser.exit(1, f"Probe stopped: Central HTTP {exc.status}.\n")
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        parser.exit(1, "Probe stopped: connection, snapshot or workspace continuity could not be qualified.\n")


if __name__ == "__main__":
    main()
