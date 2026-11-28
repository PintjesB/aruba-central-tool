"""Bounded same-selector A/B measurement of read-only pacing.

Both modes retain the rolling cap, normal retry rules and cooldown.
This is a short transport experiment, not a complete configuration audit.
"""
from collections import Counter
from time import perf_counter
from .central_tool import ALPHA, CONFIG_MODULES, APIError, ordered_parallel, canonical
import hashlib

MODULES = ("dns", "ntp", "logging", "layer2-vlan", "aaa-profile", "named-vlan")


def selectors(previous, qualified, limit=72):
    live = {(persona, str(scope["id"])) for persona, entry in qualified.items()
            for scope in entry["scopes"] if scope["kind"] == "device"}
    buckets = []
    for module in MODULES:
        if module not in CONFIG_MODULES:
            continue
        rows = []
        for persona, entry in sorted(previous["results"].items()):
            for row in entry.get("modules", {}).get(module, {}).get("scope_results", []):
                sid = str(row["scope"])
                if (persona, sid) in live and row.get("effective_view", {}).get("status") == "list_parsed":
                    rows.append((module, persona, sid))
        buckets.append(iter(sorted(set(rows))))
    result = []
    while buckets and len(result) < limit:
        for bucket in list(buckets):
            if len(result) == limit:
                break
            item = next(bucket, None)
            if item is None:
                buckets.remove(bucket)
            else:
                result.append(item)
    return result


def pacing_probe(client, previous, qualified, *, limit=72):
    if type(limit) is not int or not 12 <= limit <= 72:
        raise ValueError("Invalid pacing probe limit")
    tasks = selectors(previous, qualified, limit)
    if len(tasks) < 36:
        return {"schema": 1, "kind": "anonymous_pacing_probe", "status": "insufficient_observed_selectors",
                "selectors": len(tasks), "complete": False, "safe_to_apply": False}
    def read(task):
        module, persona, scope = task
        try:
            raw = client.get(ALPHA + "/" + module, **{"view-type": "LOCAL", "scope-id": scope,
                "effective": "true", "detailed": "true", "device-function": persona})
        except APIError as exc:
            if exc.status in (401, 429):
                raise
            return ("http_" + str(exc.status), None)
        except (OSError, RuntimeError, ValueError):
            return ("read_failed", None)
        # Compare transient digests internally only; never output identifiers or bodies.
        return ("response_received", hashlib.sha256(canonical(raw).encode()).digest())

    phases, observations = [], []
    original = client._pacing_compensation_enabled
    try:
        for enabled in (False, True):
            client._pacing_compensation_enabled = enabled
            before = client.get_transport_metrics()
            net_before = client.get_network_metrics()
            started = perf_counter()
            results = ordered_parallel(tasks, read, workers=12)
            elapsed = perf_counter() - started
            after, net_after = client.get_transport_metrics(), client.get_network_metrics()
            transport = {key: after.get(key, 0) - before.get(key, 0) for key in
                         ("http_get_attempts", "http_get_retries", "http_get_429", "http_get_5xx", "http_get_transient_errors")}
            network = {key: net_after.get(key, 0) - net_before.get(key, 0) for key in
                       ("pacing_admissions", "pacing_waited_admissions", "pacing_lateness_us",
                        "pacing_compensation_us", "pacing_gap_samples", "pacing_gap_us",
                        "rate_wait_ms", "successful_get_ms", "successful_gets")}
            phases.append({"mode": "compensated" if enabled else "strict_spacing",
                           "seconds": round(elapsed, 3),
                           "attempts_per_second": round(transport["http_get_attempts"] / elapsed, 3) if elapsed else None,
                           "transport": transport, "network": network,
                           "outcomes": dict(Counter(status for status, _ in results))})
            observations.append(results)
            # Do not continue a comparison after observed throttling, even
            # if the normal request retry mechanism recovered successfully.
            if transport["http_get_429"]:
                break
    finally:
        client._pacing_compensation_enabled = original
    comparison = Counter()
    if len(observations) == 2:
        for (status_a, a), (status_b, b) in zip(*observations):
            comparison["exact_response_match" if a is not None and a == b else
                       "response_changed" if a is not None and b is not None else
                       "unqualified"] += 1
    return {"schema": 1, "kind": "anonymous_pacing_probe", "status": "measured" if len(phases) == 2 else "throttled",
            "selectors": len(tasks), "workers": 12, "phases": phases, "response_comparison": dict(comparison),
            "complete": False, "safe_to_apply": False}
