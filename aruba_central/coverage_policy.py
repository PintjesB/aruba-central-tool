"""Separate observed API coverage from current endpoint handling policy."""
from .nac_service_probe import ENDPOINTS
from .central_tool import ALPHA

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
