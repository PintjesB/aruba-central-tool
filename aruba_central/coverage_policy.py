"""Separate observed API coverage from current endpoint handling policy."""
from .nac_service_probe import ENDPOINTS
from .central_tool import ALPHA, keyed_profile_contracts, observed_profile_candidates
import re

NAC_CAPTURE = {"cnac-mac-reg": "MAC registration inventory",
               "cnac-image": "Portal image inventory",
               "cnac-image/:image-id": "Observed image metadata"}
NAC_HANDLING = {
    "bounded_list": "Bounded diagnostic available",
    "observed_id_only": "Diagnostic uses observed identities only",
    "requires_user_principal_name": "Requires an observed user principal name",
    "excluded_credential_bearing_registration": "Excluded: credential-bearing registrations",
    "excluded_personal_account_data": "Excluded: personal account data",
    "excluded_duplicate_sensitive_export": "Excluded: duplicate sensitive export",
    "requires_identity_store_and_excluded_secret_export": "Excluded: secret export requires identity store",
    "excluded_personal_account_export": "Excluded: personal account export",
    "excluded_job_file_download": "Excluded: job file download",
    "excluded_binary_asset_download": "Excluded: binary asset download",
}


def operation_handling(path):
    prefix = ALPHA + "/"
    if path.startswith(prefix):
        endpoint = path[len(prefix):]
        if endpoint in NAC_CAPTURE:
            return "Capture adapter: " + NAC_CAPTURE[endpoint]
        if endpoint in ENDPOINTS:
            return NAC_HANDLING[ENDPOINTS[endpoint]]
    if any(part.startswith((":", "{")) for part in path.split("/")):
        return "Path selector required; verify resource applicability"
    return "Review query selectors and resource applicability"


def coverage_action(row):
    """Current handling guidance, not proof of applicability or a historical read."""
    return {"handling": operation_handling(row["path"]),
            "read_state": row.get("status", "not_attempted")}


def keyed_gap_context(bundle):
    """Use the actual saved detail plan, not a guessed reason for absence."""
    return {"contracts": keyed_profile_contracts(include_raw=True),
            "plan": bundle.get("keyed_profile_details") or {},
            "raw": bundle.get("unadapted_profiles") or {}}


def gap_handling(row, context):
    path = row["path"]
    base = operation_handling(path)
    if row.get("attempted"):
        return base
    match = re.fullmatch(re.escape(ALPHA) + r"/([a-z][a-z0-9-]*)/:([a-z][a-z0-9-]*)", path)
    if not match or context["contracts"].get(match[1]) != match[2]:
        return base
    plan = context["plan"]
    if not plan:
        return "Single-key adapter available; detail plan not recorded"
    if match[1] not in plan.get("supported_modules", []):
        return "Single-key adapter available now; not in saved supported modules"
    candidates = plan.get("candidate_reads_by_module")
    if not isinstance(candidates, dict):
        return "Single-key adapter available; candidate counts not recorded"
    count = candidates.get(match[1], 0)
    if type(count) is not int or count < 0:
        return "Single-key adapter available; candidate count unqualified"
    if count == 0:
        module = match[1]
        if module in {"airpass-approval", "message-providers", "skins", "overrides"}:
            entry = context.get("raw", {}).get(module)
            if isinstance(entry, dict):
                reads = [entry.get("library", {})]
                reads.extend(v.get(side, {}) for v in entry.get("source_views", [])
                             for side in ("committed", "effective"))
                empty = sum(v.get("status") in ("empty_response", "empty_object") for v in reads)
                positives = sum(bool(observed_profile_candidates(v, match[2])) for v in reads)
                if positives:
                    return f"{positives} collection views contain candidate identities; saved detail plan omitted them; review selectors"
                if empty == len(reads) and empty:
                    return f"No individual candidates planned; {empty} empty collection responses, absence not established"
                return f"No individual candidates planned; {empty}/{len(reads)} unverified empty collection responses, other views require review; absence not established"
        return "No individual candidates planned; absence not established"
    return f"{count} individual candidates planned; no matching GET attempt recorded"
