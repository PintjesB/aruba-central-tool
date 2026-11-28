"""Independent effective-module comparison beyond the explicitly reviewed profiles."""
from collections import Counter
from .central_tool import health_serial
from .configuration_history import view_changes


def collateral_review(before, after, module, covered):
    """Compare effective views across observed functions and device scopes.

    covered maps (persona, scope) to profile identities already independently
    checked by the selected remediation workflow. No other identities are
    excluded. Missing evidence or uncertain device identity is never equality.
    """
    records, counts = [], Counter()
    for persona in sorted(before["results"].keys() | after["results"].keys()):
        def index(bundle):
            entry = bundle["results"].get(persona, {})
            devices = {s["id"]: s for s in entry.get("scopes", []) if s["kind"] == "device"}
            views = {}
            for row in entry.get("modules", {}).get(module, {}).get("scope_results", []):
                views.setdefault(row["scope"], row.get("effective_view", {}))
            return devices, views, module in entry.get("modules", {})
        a, av, a_has = index(before)
        b, bv, b_has = index(after)
        if not (a_has or b_has):
            continue
        for sid in sorted(a.keys() | b.keys()):
            name = (b.get(sid) or a[sid]).get("name") or sid
            counts["device_function_pairs"] += 1
            serial_a = health_serial(a.get(sid, {}).get("metadata"))
            serial_b = health_serial(b.get(sid, {}).get("metadata"))
            common = {"persona": persona, "scope": sid, "device": name}
            if not serial_a or serial_a != serial_b:
                counts["unverified_device_pairs"] += 1
                records.append({**common, "identity": "", "status": "device_identity_unverified"})
                continue
            x, y = av.get(sid, {}), bv.get(sid, {})
            excluded = covered.get((persona, sid), set())
            def filtered(view):
                if view.get("status") != "list_parsed":
                    return view
                return {**view, "profiles": {k: body for k, body in view["profiles"].items() if k not in excluded}}
            if not all(z.get("status") == "list_parsed" and z.get("count_confirmed") is True for z in (x, y)):
                counts["unverified_view_pairs"] += 1
            # Inspect direct positive observations even when collections
            # match exactly or claim count-confirmed absence. Exclude only
            # identities already checked by the primary remediation.
            from .remediation_review import captured_observation
            conflicts = set()
            for label, bundle in (("before", before), ("after", after)):
                profiles = (bundle.get("keyed_profile_details") or {}).get("profiles", {}).get(
                    persona, {}).get(str(sid), {}).get(module, {})
                for identity in sorted(set(profiles) - excluded):
                    observed = captured_observation(bundle, persona, module, sid, "effective", identity)
                    if observed["state"] == "individual_evidence_conflict":
                        conflicts.add(identity)
                        records.append({**common, "identity": identity, "status": "individual_evidence_conflict",
                                        "capture": label, "observation": observed})
            changes = view_changes(filtered(x), filtered(y))
            if not changes and not conflicts:
                counts["unchanged_count_confirmed_pairs"] += 1
            for change in changes:
                records.append({**common, **change})
    return {"module": module, "counts": dict(counts),
            "outcomes": dict(Counter(r["status"] for r in records)),
            "records": records, "complete": False, "safe_to_apply": False}
