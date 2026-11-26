"""Consolidated read-only configuration assessment with actionable worklists."""
from collections import Counter
from advanced_review import advanced_analysis
from assignment_review import assignment_review
from consolidation import profile_recommendations
from policy_variants import policy_variants


def assessment(bundle):
    devices = {(p, s["id"]) for p, e in bundle["results"].items()
               for s in e["scopes"] if s["kind"] == "device"}
    findings = profile_recommendations(bundle)
    engineering = advanced_analysis(bundle)
    assignments = assignment_review(bundle)
    variants = policy_variants(bundle)
    coverage = Counter()
    for entry in bundle["results"].values():
        for module in entry["modules"].values():
            for row in module["scope_results"]:
                for kind in ("local_view", "effective_view"):
                    view = row.get(kind, {})
                    coverage["expected"] += 1
                    if view.get("status") == "list_parsed":
                        coverage["parsed"] += 1
                        if view.get("count_confirmed") is True:
                            coverage["count_confirmed"] += 1
    actions = Counter(f["action"] for f in findings)
    review = [f for f in findings if f["action"] in ("remove_override", "promote_local", "reuse_library")]
    return {"device_function_pairs": len(devices), "coverage": dict(coverage),
            "actions": dict(actions), "consolidation": {"groups": len(review),
                "reviewable": sum(f.get("preview_selectable") is True for f in review),
                "source_definitions": sum(len(f["sources"]) for f in review)},
            "engineering": {"duplicate_groups": len(engineering["library_duplicates"]),
                "repeated_port_groups": len(engineering["port_groups"]),
                "ports_in_groups": sum(len(g["ports"]) for g in engineering["port_groups"]),
                "scope_observations": len(engineering["shadowed"]),
                "unresolved_references": sum(ref["status"] not in ("observed", "definition_observed") for ref in engineering["references"])},
            "assignments": {"observed": len(assignments["rows"]), "overlaps": len(assignments["overlaps"]),
                "unknown_scopes": sum(not row["scope_resolved"] for row in assignments["rows"]),
                "invalid": len(assignments["invalid_rows"])},
            "variants": {"groups": len(variants), "explicit": sum(v["status"] == "explicit_differences" for v in variants)},
            "checkpoint": bundle.get("collection_checkpoint", {}), "captured_at": bundle.get("captured_at"),
            "complete": False, "safe_to_apply": False}
