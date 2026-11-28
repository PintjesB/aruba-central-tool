"""Explain existing duplicate retention suggestions without changing their policy."""
from .advanced_review import preferred_duplicate


def retention_comparison(usage, suggested):
    labels = ("saved referring objects", "observed assignments", "all referring objects", "matching shared deployments")
    def values(u):
        return (u.get("definition_reference_count", 0), u["assignment_count"],
                u["reference_count"], len(u["shared_devices"]))
    ordered = sorted(usage.values(), key=values, reverse=True)
    rows = [{"identity": u["identity"], "saved_references": values(u)[0],
             "assignments": str(u["assignment_count"]) if u["assignment_status"] == "response_received" else "Unknown",
             "referencing_objects": u["reference_count"], "shared_devices": len(u["shared_devices"]),
             "different_devices": len(u["different_devices"]), "unknown_devices": len(u["unknown_devices"]),
             "suggested": u["identity"] == suggested} for u in ordered]
    if suggested is not None and preferred_duplicate(usage) == suggested and len(ordered) > 1:
        first, second = values(ordered[0]), values(ordered[1])
        index = next(i for i, pair in enumerate(zip(first, second)) if pair[0] != pair[1])
        short = "More " + labels[index]
        explanation = f"Suggested because it has more {labels[index]} than the next candidate ({first[index]} vs {second[index]}). Earlier criteria are tied."
    elif any(u["assignment_status"] != "response_received" for u in usage.values()):
        short = "Assignment evidence unavailable"
        explanation = "No automatic suggestion because assignment evidence is unavailable."
    elif any(u.get("library_individual_conflict") or u.get("individual_conflict_devices") for u in usage.values()):
        short = "Conflicting profile evidence"
        explanation = "No automatic suggestion because individual profile evidence contradicts a Library or effective collection."
    elif any(u.get("conflicting_reference_count", 0) for u in usage.values()):
        short = "Conflicting reference evidence"
        explanation = "No automatic suggestion because individual and collection reference evidence conflicts."
    else:
        short = "No unique usage leader"
        explanation = "No unique usage leader was established. Choose using naming standards and observed dependencies."
    return {"rows": rows, "short_reason": short,
            "explanation": explanation + " Counts are captured observations, not complete migration cost or permission to delete."}
