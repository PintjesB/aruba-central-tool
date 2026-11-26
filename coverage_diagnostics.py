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
        "complete", "incomplete", "unknown",
    }
    return value if isinstance(value, str) and value in allowed else "other"


def view_summary(view):
    return {
        "status": safe_status(view.get("status")),
        "count_confirmed": view.get("count_confirmed") is True or view.get("collection_count_verified") is True,
        "profiles": len(view["profiles"]) if isinstance(view.get("profiles"), dict) else None,
        "http_error": view.get("http_error") if type(view.get("http_error")) is int and 400 <= view["http_error"] <= 599 else None,
    }


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
    from nac_authorization import nac_collection
    nac = {module: view_summary(nac_collection(bundle, module))
           for module in ("auth-profiles", "authz-policies", "identity-stores", "static-tag")}
    registration = bundle.get("nac_registrations", {})
    nac["mac-registrations"] = {
        "status": safe_status(registration.get("status")),
        "count_confirmed": registration.get("count_confirmed") is True,
        "records": len(registration.get("records", [])),
    }
    raw = Counter()
    for module, entry in bundle.get("unadapted_profiles", {}).items():
        name = module if module in modules else "other"
        for status, n in entry.get("scope_read_outcomes", {}).items():
            raw[(name, safe_status(status))] += count(n)
    return {
        "schema": 1, "kind": "anonymous_collection_diagnostics",
        "mixed_capture_times": bundle.get("collection_checkpoint", {}).get("mixed_capture_times") is True,
        "scoped_views": [{"persona": p, "module": m, "scope_kind": k, "view": v, "status": s,
                          "count_confirmed": c, "http_error": h, "views": n}
                         for (p, m, k, v, s, c, h), n in sorted(scoped.items(), key=lambda row: str(row[0]))],
        "raw_scope_outcomes": [{"module": m, "status": s, "views": n}
                               for (m, s), n in sorted(raw.items())],
        "nac": nac, "attempted_operations": sorted(operations, key=lambda row: row["path"]),
        "catalog_operations": len(paths), "complete": False,
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
