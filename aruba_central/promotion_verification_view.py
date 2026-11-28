"""Private observed before/after promotion review presentation."""
from .workspace_ui import e, metrics, table, tr, badge, inspect, pretty
from .remediation_presentation import observation_comparison


def promotion_outcome(result):
    good = {"observed_intended_effective_match", "observed_outside_unchanged"}
    rows = result["rows"]
    body = metrics([("Intended effective matches", sum(r["status"] == "observed_intended_effective_match" for r in rows),
                     "Captured settings only"),
                    ("Outside effective settings unchanged", sum(r["status"] == "observed_outside_unchanged" for r in rows),
                     "Selected profile only"),
                    ("Unresolved or changed devices", sum(r["status"] not in good for r in rows), "Review first"),
                    ("Destination evidence", "Observed" if result["destination_and_assignments_observed"] else "Unverified",
                     "Definition and required Library assignment observations")])
    if result["workflow"] == "library_reuse":
        body += '<p class="note">Existing Library reuse: the retained Library definition must match in both captures; exact source-scope assignments and local cleanup are checked separately.</p>'
    body += '<section><h2>Destination definition</h2>' + observation_comparison(
        "Saved destination profile", result["before_destination"], result["after_destination"])
    if result["assignment_observations"]:
        body += table(("Original source scope", "Exact Library assignment observed"), [
            tr(e(r["scope"]), "Yes" if r["observed"] else "Unverified") for r in result["assignment_observations"]])
    body += '</section><section><h2>Local definition cleanup</h2>'
    body += table(("Source", "Observed outcome", "Evidence"), [
        tr(e(r["name"]), badge(pretty(r["status"])), inspect(r["name"], observation_comparison(
            "Saved local definition", r["before_local"], r["after_local"])))
        for r in result["source_rows"]]) + '</section>'
    body += '<section><h2>Intended and outside recipient comparison</h2><p>All observed device scopes for the selected function are checked, including new or missing devices. This is a comparison of the selected profile, not full configuration or operational verification.</p>'
    body += table(("Device", "Prior intended recipient", "Destination recipient observed", "Outcome", "Evidence"), [
        tr(e(r["device"]), "Yes" if r["intended"] else "No", "Yes" if r["destination_recipient"] else "No",
           badge(pretty(r["status"]), "good" if r["status"] in good else "warn"),
           inspect(r["device"], observation_comparison("Effective profile", r["before_effective"], r["after_effective"])))
        for r in sorted(rows, key=lambda r: (r["status"] in good, r["device"], r["scope"]))], search=True)
    return body + '<p class="note">Observed matches do not verify inheritance, actual deployment, permissions or rollback. Review prior saved settings and assignments before any manual recovery.</p></section>'
