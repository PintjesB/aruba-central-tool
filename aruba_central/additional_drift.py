"""Historical comparison of supplemental, individual and NAC configuration evidence.

Keep request selectors exact and never infer profile removal from missing or
sampled observations. Raw response changes are not semantic configuration changes.
"""
from collections import Counter, defaultdict
from .central_tool import canonical, field_differences, health_serial
from .configuration_history import view_changes

UNFILTERED = {"ALL_DEVICE_FUNCTIONS", "UNFILTERED_SCOPE"}


def additional_evidence_drift(before, after):
    def scopes(bundle):
        result = defaultdict(list)
        for persona, entry in bundle["results"].items():
            for scope in entry["scopes"]:
                result[persona, str(scope["id"])].append(scope)
                for function in UNFILTERED:
                    result[function, str(scope["id"])].append(scope)
        return result
    aa, bb = scopes(before), scopes(after)
    def context(index, persona, sid):
        rows = index.get((persona, sid), [])
        signatures = {(s["kind"], health_serial(s.get("metadata")) if s["kind"] == "device" else None) for s in rows}
        if len(signatures) != 1:
            return None
        kind, serial = next(iter(signatures))
        if kind == "device" and not serial:
            return None
        return kind, serial
    def stable(persona, sid):
        if persona in ("Library", "NAC") and not sid:
            return True
        a, b = context(aa, persona, sid), context(bb, persona, sid)
        return a is not None and a == b
    def name(persona, sid):
        rows = bb.get((persona, sid)) or aa.get((persona, sid)) or []
        names = {str(s.get("name") or sid) for s in rows}
        return next(iter(names)) if len(names) == 1 else sid or persona
    def index(bundle):
        result = defaultdict(list)
        for module, entry in (bundle.get("unadapted_profiles") or {}).items():
            for row in entry.get("source_views", []):
                for side in ("committed", "effective"):
                    if isinstance(row.get(side), dict):
                        result["supplemental", row["persona"], str(row["scope"]), module, side, ""].append(row[side])
            if isinstance(entry.get("library"), dict):
                result["supplemental", "Library", "", module, "library", ""].append(entry["library"])
        for persona, scopes_ in ((bundle.get("keyed_profile_details") or {}).get("profiles") or {}).items():
            for sid, modules in scopes_.items():
                for module, profiles in modules.items():
                    for identity, reads in profiles.items():
                        for side, read in reads.items():
                            result["individual", persona, str(sid), module, side, identity].append(read)
        for module, view in (bundle.get("nac_configuration") or {}).items():
            result["nac_configuration", "NAC", "", module, "tenant", ""].append(view)
        return result
    a, b = index(before), index(after)
    counts = defaultdict(Counter)
    records = []
    for key in sorted(a.keys() | b.keys()):
        family, persona, sid, module, side, identity = key
        totals = counts[family]
        totals["selectors"] += 1
        common = {"family": family, "persona": persona, "scope": sid, "scope_name": name(persona,sid),
                  "module": module, "view": side, "identity": identity}
        left, right = a.get(key, []), b.get(key, [])
        x, y = left[0] if len(left) == 1 else {}, right[0] if len(right) == 1 else {}
        states = {"before_status": x.get("status", "not_observed"), "after_status": y.get("status", "not_observed")}
        def record(status, **details):
            records.append({**common, **states, "status": status, **details})
        if len(left) > 1 or len(right) > 1:
            totals["ambiguous_selector"] += 1
            record("ambiguous_selector", before_observations=len(left), after_observations=len(right))
            continue
        if not stable(persona,sid):
            totals["scope_identity_unverified"] += 1
            record("scope_identity_unverified")
            continue
        if not left or not right:
            totals["selector_observation_changed"] += 1
            record("selector_observation_changed")
            continue
        if family == "supplemental":
            # Compare only same-selector raw completed responses. Preserve
            # metadata and list order; never interpret raw equality as
            # equivalent deployment or complete profile inventory.
            def qualified(view):
                return (view.get("status") in ("response_received","empty_response") and "raw" in view
                        and view.get("pagination_status") in (None,"complete","pagination_exhausted"))
            if not qualified(x) or not qualified(y):
                totals["not_comparable"] += 1
                if states["before_status"] != states["after_status"]:
                    record("read_status_changed")
                continue
            old, new = x["raw"], y["raw"]
            if x.get("collection_count_verified") is not True or y.get("collection_count_verified") is not True:
                totals["count_unverified_pairs"] += 1
            if canonical(old) == canonical(new):
                totals["exact_match"] += 1
            else:
                totals["response_changed"] += 1
                record("supplemental_response_changed", before=old, after=new, fields=field_differences(old,new))
        elif family == "individual":
            if not all(z.get("status") == "identity_observed" and isinstance(z.get("profile"),dict) for z in (x,y)):
                totals["not_comparable"] += 1
                if states["before_status"] != states["after_status"]:
                    record("read_status_changed")
                continue
            old, new = x["profile"], y["profile"]
            fields = field_differences(old,new) if canonical(old) != canonical(new) else []
            annotations = field_differences(x.get("annotations"),y.get("annotations"))
            if fields or annotations:
                totals["response_changed"] += 1
                record("individual_observation_changed",before=old,after=new,fields=fields,source_fields=annotations)
            else:
                totals["exact_match"] += 1
        else:
            changes = view_changes(x,y)
            if changes:
                totals["selectors_with_observations"] += 1
                for row in changes:
                    records.append({**common, **states, **row})
            else:
                totals["exact_match"] += 1
    return {"counts": {family:dict(values) for family,values in sorted(counts.items())},
            "records": records, "complete": False, "safe_to_apply": False}
