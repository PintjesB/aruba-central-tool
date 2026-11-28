"""Bounded, anonymous NAC service capability probe.

Documentation: vendor DPP list/detail and job list/status contracts.
No registration URI, job identifier, account, secret or job file is exported.
Do not use CSV export or download endpoints to qualify configuration coverage.
"""
import re
from collections import Counter
from urllib.parse import quote

from .central_tool import ALPHA, APIError


# Explicitly distinguish query selectors from path selectors and policy exclusions.
# https://www.postman.com/hpe-aruba-networking/new-hpe-aruba-networking-central/request/32717089-d1b52c8a-8b18-4376-9091-1d509eecbc10
# https://developer.arubanetworks.com/new-central-config/reference/exportnamedmpskcsvfile
ENDPOINTS = {
    "cnac-dpp-reg": "bounded_list",
    "cnac-dpp-reg/:id": "observed_id_only",
    "cnac-job": "bounded_list",
    "cnac-job/:job-id/status": "observed_id_only",
    "cnac-certificate": "requires_user_principal_name",
    "cnac-named-mpsk-reg": "excluded_credential_bearing_registration",
    "cnac-visitor": "excluded_personal_account_data",
    "cnac-mac-reg/export": "excluded_duplicate_sensitive_export",
    "cnac-named-mpsk-reg/export": "requires_identity_store_and_excluded_secret_export",
    "cnac-visitor/export": "excluded_personal_account_export",
    "cnac-job/:job-id": "excluded_job_file_download",
    "cnac-job/:job-id/error": "excluded_job_file_download",
    "cnac-job/:job-id/input": "excluded_job_file_download",
    "cnac-image/download/:image-id": "excluded_binary_asset_download",
}


def safe_id(value):
    return isinstance(value, str) and value not in (".", "..") and re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", value) is not None


def read(client, path, **params):
    try:
        return "response_received", client.get(ALPHA + "/" + path, **params)
    except APIError as exc:
        if exc.status in (401, 429):
            raise
        return "http_" + str(exc.status), None
    except (OSError, RuntimeError, ValueError):
        return "read_failed", None


def list_sample(client, endpoint, limit=10):
    status, raw = read(client, endpoint, limit=limit)
    result = {"status": status, "rows": 0, "identity_count": 0, "count": None,
              "total": None, "next_cursor_present": False}
    if status != "response_received":
        return result, []
    if not isinstance(raw, dict) or not isinstance(raw.get("items"), list):
        result["status"] = "schema_unqualified"
        return result, []
    rows = raw["items"]
    result["rows"] = len(rows)
    for field in ("count", "total"):
        value = raw.get(field)
        if type(value) is int and value >= 0:
            result[field] = value
    result["next_cursor_present"] = bool(isinstance(raw.get("next"), str) and raw["next"])
    ids = [row.get("id") for row in rows if isinstance(row, dict)]
    if len(rows) > limit or len(ids) != len(rows) or not all(safe_id(v) for v in ids) or len(set(ids)) != len(ids):
        result["status"] = "identity_or_page_unqualified"
        return result, []
    result["identity_count"] = len(ids)
    result["status"] = "list_observed"
    return result, ids[:2]


def nac_service_probe(client):
    results = []
    for endpoint, suffix, template in (("cnac-dpp-reg", "", "cnac-dpp-reg/:id"),
                                       ("cnac-job", "/status", "cnac-job/:job-id/status")):
        summary, ids = list_sample(client, endpoint)
        results.append({"operation": endpoint, **summary})
        outcomes = Counter()
        for identity in ids:
            status, raw = read(client, endpoint + "/" + quote(identity, safe="") + suffix)
            if status == "response_received":
                status = "identity_observed" if isinstance(raw, dict) and raw.get("id") == identity else "identity_unqualified"
            outcomes[status] += 1
        results.append({"operation": template, "attempted": len(ids), "outcomes": dict(outcomes)})
    return {"schema": 1, "kind": "anonymous_nac_service_probe", "operations": results,
            "endpoint_policy": dict(ENDPOINTS), "complete": False, "safe_to_apply": False}


def service_count_confirmed(summary):
    """A bounded page count alone does not establish total inventory size."""
    return (summary.get("status") == "list_observed"
            and type(summary.get("total")) is int
            and type(summary.get("rows")) is int
            and summary["total"] == summary["rows"]
            and summary.get("count") in (None, summary["rows"])
            and summary.get("next_cursor_present") is False
            and summary.get("identity_count") == summary["rows"])


def capture_service_inventory(client):
    """Capture bounded service coverage, never raw credential/job payloads."""
    report = nac_service_probe(client)
    for row in report["operations"]:
        if row["operation"] in ("cnac-dpp-reg", "cnac-job"):
            row["count_confirmed"] = service_count_confirmed(row)
    return report
