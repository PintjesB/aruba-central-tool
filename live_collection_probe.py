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


def probe(client, previous, modules, sample=2):
    if type(sample) is not int or not 1 <= sample <= 4:
        raise ValueError("Sample must be between 1 and 4")
    if not modules or any(module not in PROBE_MODULES for module in modules):
        raise ValueError("Unsupported probe module")
    modules = tuple(dict.fromkeys(modules))
    scopes = qualified_scopes(client, previous)
    contracts = keyed_profile_contracts()
    collections, keyed = [], Counter()
    for module in modules:
        identity, functions, device_only = CONFIG_MODULES[module]
        if not device_only:
            view = observed_read(lambda: read_module_view(client, module, identity,
                                                          {"view-type": "LIBRARY", "detailed": "true"}))
            collections.append({"module": module, "persona": "Library", "scope_kind": "library",
                                "view": "library", **view_summary(view)})
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
            "collections": collections,
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
