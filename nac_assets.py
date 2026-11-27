"""Read-only Central NAC portal asset metadata.

Published HPE collection: List images and Get image details.
https://www.postman.com/hpe-aruba-networking/new-hpe-aruba-networking-central/request/32717089-5281e8f4-89b8-440d-9606-d6b3ecd72149
No binary downloads, registrations containing credentials or export jobs.
"""
from collections import Counter
from urllib.parse import quote
from central_tool import ALPHA, ordered_parallel, audit_progress, field_differences
from scope_evidence import evidence_read


def safe_image_id(value):
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= 512
            and value not in (".", "..") and not any(c in value for c in ("/", "\\", "%"))
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def image_identity(row):
    """Accept the live camelCase identity and documented legacy spelling."""
    if not isinstance(row, dict):
        return None
    values = [row[key] for key in ("imageId", "imageID") if key in row]
    if not values or any(not safe_image_id(value) for value in values):
        return None
    return values[0] if all(value == values[0] for value in values) else None


def image_comparison_body(row):
    identity = image_identity(row)
    return {**{key: value for key, value in row.items() if key not in ("imageId", "imageID")},
            "imageId": identity}


def capture_portal_assets(client, workers=1, progress=None):
    result = {"list_read": evidence_read(client, ALPHA + "/cnac-image"),
              "images": [], "details": {}, "count_confirmed": False,
              "complete": False, "safe_to_apply": False}
    read = result["list_read"]
    raw = read.get("raw")
    if read["status"] != "response_received":
        result["status"] = read["status"]
        return result
    if not isinstance(raw, dict) or not isinstance(raw.get("items"), list):
        result["status"] = "schema_unresolved"
        return result
    images = raw["items"]
    observed = {}
    invalid = duplicates = 0
    for row in images:
        identity = image_identity(row)
        if not safe_image_id(identity):
            invalid += 1
        elif identity in observed:
            duplicates += 1
        else:
            observed[identity] = row
    result["images"] = list(observed.values())
    count = raw.get("count")
    result["count_confirmed"] = (type(count) is int and count == len(images)
                                 and not invalid and not duplicates)
    result["status"] = ("identity_unresolved" if invalid or duplicates else
                        "count_mismatch" if count is not None and not result["count_confirmed"] else
                        "list_parsed")
    def detail(identity):
        item = evidence_read(client, ALPHA + "/cnac-image/" + quote(identity, safe=""))
        if item["status"] == "response_received":
            body = item["raw"]
            # The published individual endpoint also documents the same
            # items envelope as the inventory. Require exactly one matching
            # identity and a consistent count, never pick an arbitrary row.
            if isinstance(body, dict) and "items" in body:
                items = body["items"]
                count = body.get("count", 1)
                body = items[0] if (isinstance(items, list) and len(items) == 1
                                    and type(count) is int and count == 1) else None
            if image_identity(body) == identity:
                item["status"] = "identity_observed"
                item["differences"] = field_differences(image_comparison_body(observed[identity]), image_comparison_body(body))
            else:
                item["status"] = "identity_unresolved"
        return identity, item
    result["details"] = dict(ordered_parallel(sorted(observed), detail, workers,
        completed=lambda done, total: audit_progress(progress, "NAC portal assets", done, total,
                                                    "Reading observed image metadata")))
    result["outcomes"] = dict(Counter(item["status"] for item in result["details"].values()))
    result["invalid_records"] = invalid
    result["duplicate_records"] = duplicates
    return result
