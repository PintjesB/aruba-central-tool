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
    result = observed_read(lambda: profile_inventory_view(
        client, "config-assignments", "config-assignment", **{"profile-type": module}))
    records = result.get("rows", [])
    identities = set()
    contexts = {}
    unknown = 0
    for row in records:
        if (not isinstance(row, dict) or row.get("profile-type") != module
                or type(row.get("profile-instance")) not in (str, int)
                or type(row.get("scope-id")) not in (str, int)
                or not isinstance(row.get("device-function"), str)):
            unknown += 1
            continue
        identity = str(row["profile-instance"])
        persona, sid = row["device-function"], str(row["scope-id"])
        identities.add((identity, persona, sid))
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
            "assignment_count_confirmed": result.get("collection_count_verified") is True and not unknown,
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--snapshot")
    parser.add_argument("--module", choices=PROBE_MODULES, action="append")
    parser.add_argument("--sample", type=int, choices=range(1, 5), default=2)
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
        report = probe(client, previous, args.module or ["ethernet-interfaces", "snmp", "net-groups"], args.sample)
        print(json.dumps(report, indent=2, sort_keys=True))
    except APIError as exc:
        parser.exit(1, f"Probe stopped: Central HTTP {exc.status}.\n")
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        parser.exit(1, "Probe stopped: connection, snapshot or workspace continuity could not be qualified.\n")


if __name__ == "__main__":
    main()
