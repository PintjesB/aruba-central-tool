"""Read-only Central NAC MAC registration evidence and static tag review.

Documented contract:
https://developer.arubanetworks.com/new-central-config/reference/getmacregistrations
https://www.postman.com/hpe-aruba-networking/new-hpe-aruba-networking-central/request/32717089-04524f76-bc04-44a7-a49e-dd0dbf2b7a38
Never collect named MPSK secrets or infer authorization from registration.
"""
from collections import Counter, defaultdict
import re


def normalized_mac(value):
    if not isinstance(value, str):
        return None
    if re.fullmatch(r"[0-9a-fA-F]{12}", value):
        return value.lower()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", value):
        return value.replace(":", "").replace("-", "").lower()
    if re.fullmatch(r"(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}", value):
        return value.replace(".", "").lower()
    return None


def read_mac_registrations(client, progress=None, limit=200, max_pages=10000):
    from central_tool import ALPHA, APIError, audit_progress, canonical
    output = {"status": "page_limit_reached", "rows": [], "pages": [], "count_confirmed": False,
              "safe_to_apply": False}
    seen_ids, seen_cursors = set(), set()
    total = None
    cursor = None
    for _ in range(max_pages):
        params = {"limit": limit, "sort": "macAddress asc"}
        params.update({"next": cursor} if cursor is not None else {"offset": len(output["rows"])})
        try:
            raw = client.get(ALPHA + "/cnac-mac-reg", **params)
        except APIError as exc:
            if exc.status in (401, 429):
                raise
            output.update(status="request_rejected", http_error=exc.status)
            return output
        except (OSError, RuntimeError, ValueError):
            output["status"] = "read_failed"
            return output
        output["pages"].append(raw)
        if not isinstance(raw, dict):
            output["status"] = "schema_unqualified"
            return output
        lists = [raw[k] for k in ("items", "macs") if k in raw]
        if (not lists or any(not isinstance(v, list) for v in lists)
                or len({canonical(v) for v in lists}) != 1):
            output["status"] = "ambiguous_registration_envelope"
            return output
        rows = lists[0]
        page_total = raw.get("total")
        if page_total is not None:
            if type(page_total) is not int or page_total < 0 or total is not None and total != page_total:
                output["status"] = "count_mismatch"
                return output
            total = page_total
        page = raw.get("page", {})
        count = raw.get("count")
        if (not isinstance(page, dict) or len(rows) > limit
                or "count" in page and (type(page["count"]) is not int or page["count"] != len(rows))
                or count is not None and (type(count) is not int or count not in (len(rows), total))):
            output["status"] = "count_mismatch"
            return output
        ids = [row.get("id") if isinstance(row, dict) else None for row in rows]
        if any(not isinstance(v, str) or not v for v in ids) or len(set(ids)) != len(ids) or seen_ids.intersection(ids):
            output["status"] = "duplicate_or_unqualified_registration_identity"
            return output
        if total is not None and len(output["rows"]) + len(rows) > total:
            output["status"] = "count_mismatch"
            return output
        output["rows"].extend(rows)
        seen_ids.update(ids)
        next_cursor = raw.get("next")
        if next_cursor is not None and not isinstance(next_cursor, str):
            output["status"] = "cursor_unqualified"
            return output
        if next_cursor and (next_cursor in seen_cursors or not rows):
            output["status"] = "cursor_repeated_or_empty"
            return output
        audit_progress(progress, "NAC registrations", len(output["rows"]), total or 0, "Reading registered MAC identities")
        if total is not None and len(output["rows"]) == total:
            output["status"] = "count_confirmed" if not next_cursor else "count_mismatch"
            output["count_confirmed"] = not bool(next_cursor)
            return output
        if not rows:
            output["status"] = "pagination_exhausted" if total is None else "count_mismatch"
            return output
        if next_cursor:
            seen_cursors.add(next_cursor)
        cursor = next_cursor or None
    return output


def nac_review(bundle):
    from nac_authorization import nac_collection
    source = bundle.get("nac_registrations") or {}
    tags = nac_collection(bundle, "static-tag")
    definitions = tags.get("profiles", {}) if tags.get("status") == "list_parsed" else {}
    names = defaultdict(set)
    for identity, profile in definitions.items():
        if isinstance(profile.get("name"), str):
            names[profile["name"]].add(identity)
    macs, usage = defaultdict(list), Counter()
    rows = []
    for row in source.get("rows", []):
        if not isinstance(row, dict):
            continue
        mac = normalized_mac(row.get("macAddress"))
        if mac is not None:
            macs[mac].append(row["id"])
        observed = row.get("staticTags")
        references = []
        if isinstance(observed, list):
            for token in observed:
                matches = set()
                if isinstance(token, str):
                    matches = set(names[token])
                    if token in definitions:
                        matches.add(token)
                    usage[token] += 1
                status = ("observed_id" if len(matches) == 1 and token in definitions else
                          "observed_name_only" if len(matches) == 1 else
                          "ambiguous" if matches else "unresolved")
                references.append({"value": token, "status": status, "candidates": sorted(matches)})
        rows.append({"id": row.get("id"), "mac": mac, "display_name": row.get("displayName"),
                     "enabled": row.get("enable") if type(row.get("enable")) is bool else None,
                     "tags_observed": isinstance(observed, list), "references": references, "record": row})
    return {"capture_status": source.get("status", "not_collected"), "count_confirmed": source.get("count_confirmed") is True,
            "rows": rows, "duplicate_mac_groups": [{"mac": k, "ids": v} for k, v in macs.items() if len(v) > 1],
            "tag_definition_status": tags.get("status", "not_collected"),
            "tag_definitions": definitions, "tag_usage": dict(usage), "safe_to_apply": False}
