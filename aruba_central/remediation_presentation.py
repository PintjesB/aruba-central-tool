"""Display captured remediation evidence without inferring operational success."""
from .central_tool import field_differences
from .workspace_ui import e, badge, table, tr, inspect, raw, diff_table, property_table, pretty
from .workspace_views import url

OUTCOMES = {
    "observed_goal_met": "Captured override removal goal matches",
    "observed_profiles_match_goal": "Captured profile migration goal matches",
    "device_identity_unverified": "Device identity not verified",
    "local_override_still_present": "Local override still present",
    "verification_required": "Additional evidence required",
    "effective_configuration_changed": "Effective settings changed",
    "inheritance_unverified": "Inheritance not verified",
    "retained_definition_differs": "Retained definition differs",
    "old_identity_still_visible": "Old profile still visible",
}
STATES = {"present": "Present", "absent": "Absent (count confirmed)",
          "absence_unverified": "Absence not verified", "unavailable": "Read unavailable",
          "individual_evidence_conflict": "Individual read contradicts collection"}


def observation_comparison(label, before, after):
    def state(obs):
        return STATES.get(obs.get("state"), "Unknown")
    html = '<h3>' + e(label) + '</h3>' + table(("Before", "After"), [
        tr(e(state(before)), e(state(after)))])
    if before.get("state") == after.get("state") == "present":
        html += diff_table(field_differences(before["body"], after["body"]), "Before", "After")
    else:
        for title, obs in (("Before", before), ("After", after)):
            if obs.get("state") == "present":
                html += '<h4>' + title + ' settings</h4>' + property_table(obs["body"])
    for title, obs in (("Before", before), ("After", after)):
        if obs.get("state") == "individual_evidence_conflict":
            html += '<h4>' + title + ' conflicting individual evidence</h4>'
            html += '<p>Collection state: ' + e(STATES.get(obs["collection_state"], "Unknown")) + '</p>'
            if obs["collection_state"] == "present":
                html += diff_table(field_differences(obs["body"], obs["individual_body"]), "Collection", "Individual")
            else:
                html += property_table(obs["individual_body"])
    return html


def outcome_table(result, root, snapshot, previous):
    rows = []
    override = result["workflow"] == "override_removal"
    module = result["candidate"]["module"] if override else result["module"]
    for row in sorted(result["rows"], key=lambda r: (r["status"] in ("observed_goal_met", "observed_profiles_match_goal"), r["device"], r["scope"])):
        details = ""
        if override:
            persona = result["candidate"]["persona"]
            identity = result["candidate"]["identity"]
            details += observation_comparison("Saved local definition", row["before_local"], row["after_local"])
            details += observation_comparison("Effective settings", row["before_effective"], row["after_effective"])
            after = row["after_effective"]
            saved = row["after_local"]
            ann = after.get("annotations")
            inherited = isinstance(ann, dict) and ann.get("aruba-annotation:inherited") is True
            summary = e(STATES.get(saved.get("state"), "Unknown")) + "<small>Local definition after change</small>"
            summary += "<small>" + e("Inherited source observed" if inherited else "Inheritance not verified") + "</small>"
        else:
            persona = row["persona"]
            identity = result["retain"]
            for name in sorted(set(row["before_effective"]) | set(row["after_effective"])):
                details += observation_comparison(name, row["before_effective"].get(name, {}), row["after_effective"].get(name, {}))
            retained = row["after_effective"].get(identity, {})
            summary = e(STATES.get(retained.get("state"), "Unknown")) + "<small>Retained profile after change</small>"
        details += '<p class="note">Capture comparison only. Verify operational behavior separately.</p>' + raw(row, "Complete before/after evidence")
        links = []
        for title, capture in (("Before", previous), ("After", snapshot)):
            links.append(f'<a href="{url(root, "report", snapshot=capture, persona=persona, scope=row["scope"], module=module, view="all")}">{title} configuration</a>')
        met = row["status"] in ("observed_goal_met", "observed_profiles_match_goal")
        rows.append(tr(f'<strong>{e(row["device"])}</strong><small>{e(row["scope"])}</small>', summary,
                       badge(OUTCOMES.get(row["status"], pretty(row["status"])), "good" if met else "warn"),
                       " · ".join(links) + "<div>" + inspect("Before and after evidence", details, "Review") + "</div>"))
    return '<section><h2>Before and after evidence</h2><p>Unresolved or changed outcomes appear first. Matching captured settings do not prove deployment success.</p>' + table(("Device / scope", "Observed after change", "Verification result", "Evidence"), rows, search=True) + '</section>'
