"""Read-only audit-log window retrieval. Completeness is limited to reported events."""
from datetime import datetime, timedelta, timezone
from .central_tool import APIError, canonical

AUDIT_LOG_PATH = "/network-services/v1/audits"


def _stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def read_audit_window(client, lo, hi):
    try:
        raw = client.get(AUDIT_LOG_PATH, **{"start-at": _stamp(lo), "end-at": _stamp(hi),
                                           "limit": 1000, "offset": 1})
    except APIError as exc:
        if exc.status in (401, 429):
            raise
        return {"status": "request_rejected", "http_error": exc.status}, {}
    except (RuntimeError, OSError, ValueError):
        return {"status": "read_failed"}, {}
    if not isinstance(raw, dict) or not isinstance(raw.get("items"), list):
        return {"status": "schema_unresolved"}, {}
    rows = raw["items"]
    total = raw.get("total")
    count = raw.get("count")
    offset = raw.get("offset")
    # The API may echo the requested page size as count, even for a
    # short page. Never use count as evidence of the number of events.
    # A complete window still requires total == actual unique rows and
    # independent reconciliation with a stable broader read.
    count_kind = ("returned_records" if type(count) is int and count == len(rows)
                  else "requested_limit" if type(count) is int and count == 1000
                  else "unqualified")
    metadata_ok = (type(total) is int and total >= len(rows)
                   and count_kind != "unqualified"
                   and type(offset) is int and offset == 1
                   and len(rows) <= 1000)
    observed, invalid, duplicates, outside, conflicts, impact = {}, 0, 0, 0, 0, 0
    for row in rows:
        if not isinstance(row, dict):
            invalid += 1
            continue
        event_id, when = row.get("id"), row.get("occurredOn")
        if type(event_id) not in (str, int) or not str(event_id).strip() or not isinstance(when, str):
            invalid += 1
            continue
        try:
            instant = datetime.fromisoformat(when.replace("Z", "+00:00"))
            if instant.tzinfo is None:
                raise ValueError("timestamp has no timezone")
            if not lo <= instant <= hi:
                outside += 1
        except (ValueError, OverflowError):
            invalid += 1
            continue
        details = row.get("logDetails")
        if isinstance(details, dict) and details.get("impactRadius"):
            impact += 1
        key = str(event_id)
        signature = canonical(row)
        if key in observed:
            duplicates += 1
            conflicts += observed[key] != signature
        observed[key] = signature
    qualified = metadata_ok and not (invalid or duplicates or outside or conflicts)
    return {"status": "response_received", "records": len(rows),
            "declared_total": total if type(total) is int and total >= 0 else None,
            "metadata_consistent": metadata_ok, "count_interpretation": count_kind,
            "reported_count": count if type(count) is int and 0 <= count <= 1000 else None,
            "reported_offset": offset if type(offset) is int and 0 <= offset <= 1000 else None,
            "invalid_records": invalid,
            "duplicate_ids": duplicates, "conflicting_ids": conflicts,
            "outside_window": outside, "impact_radius_present": impact,
            "complete_window": bool(qualified and total == len(rows)),
            "valid_page": bool(qualified)}, observed



def collect_audit_window(client, lo, hi, *, max_requests=31):
    """Reconcile a busy interval using bounded subdivision and stable parent reads.

    Return only observed events internally. A failed or incomplete child,
    conflicting identity, changed parent or exhausted budget never qualifies.
    This does not prove that Central logs every configuration change.
    """
    if (lo.tzinfo is None or hi.tzinfo is None or not lo < hi
            or hi - lo >= timedelta(days=90)
            or type(max_requests) is not int or not 1 <= max_requests <= 127):
        raise ValueError("Invalid audit window or request budget")
    attempts = 0

    def read(start, end):
        nonlocal attempts
        if attempts >= max_requests:
            return {"status": "request_budget_exhausted"}, {}
        attempts += 1
        return read_audit_window(client, start, end)

    def visit(start, end):
        summary, observed = read(start, end)
        if summary.get("complete_window"):
            return summary, observed
        if (not summary.get("valid_page") or summary.get("declared_total", 0) <= len(observed)
                or end - start <= timedelta(seconds=2) or max_requests - attempts < 3):
            return summary, observed
        midpoint = start + (end - start) / 2
        midpoint = midpoint.replace(microsecond=(midpoint.microsecond // 1000) * 1000)
        left, a = visit(start, midpoint)
        right, b = visit(midpoint, end)
        repeated, final = read(start, end)
        conflicts = sum(a[key] != b[key] for key in a.keys() & b.keys())
        merged = {**a, **b}
        stable = (repeated.get("valid_page") is True
                  and repeated.get("declared_total") == summary.get("declared_total")
                  and observed == final)
        qualified = (left.get("complete_window") is True and right.get("complete_window") is True
                     and stable and not conflicts
                     and all(merged.get(key) == value for key, value in observed.items())
                     and len(merged) == summary["declared_total"])
        return {**summary, "complete_window": bool(qualified),
                "subdivision_reconciled": bool(qualified),
                "subdivision_conflicts": conflicts,
                "parent_stable": stable,
                "unique_subdivision_events": len(merged)}, merged

    summary, observed = visit(lo, hi)
    return {**summary, "window_requests": attempts}, observed
