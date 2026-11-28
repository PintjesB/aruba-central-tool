"""Browser workflow for comparing manual remediation with a newer capture."""
from .workspace_ui import e, page, intro, metrics, badge, table, tr, inspect, raw, module_label, pretty
from .workspace_views import load, select, url
from .remediation_review import comparable, override_candidates, duplicate_candidates, verify_override, verify_library_migration
from .history_view import private_export


def remediation_view(workspace, query):
    from .config_app import audit_files, read_audit
    from .central_tool import refresh_configuration_review
    loaded, empty = load(workspace, query, "Remediation verification", "remediation")
    if empty:
        return empty
    root, name, current, picker = loaded
    previous = query.get("previous", "")
    confirmed = query.get("confirmed") == "yes"
    body = intro("Remediation verification", "Compare an earlier consolidation opportunity with a newer capture after manual changes.", picker)
    others = [(p.name, p.name) for p in audit_files(workspace.directory) if p.name != name]
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "remediation")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}">'
             + select("previous", [("", "Choose before snapshot")] + others, previous, "Before snapshot")
             + f'<label><span><input type="checkbox" name="confirmed" value="yes" {"checked" if confirmed else ""} required> Both captures belong to the same tenant</span></label>'
             + '<button type="submit">Find prior candidates</button></form></section>')
    if not previous or not confirmed:
        return page("Remediation verification", body, workspace.nav(name))
    if previous not in dict(others):
        raise ValueError("Invalid before snapshot")
    before = refresh_configuration_review(read_audit(workspace.directory, previous))
    try:
        comparable(before, current, confirmed)
    except ValueError as exc:
        return page("Remediation verification", body + '<section>' + e(str(exc)) + '</section>', workspace.nav(name))
    overrides = override_candidates(before)
    duplicates = duplicate_candidates(before)
    from .promotion_verification import promotion_candidates, verify_promotion
    promotions = promotion_candidates(before)
    import json
    options = [("", "Choose a prior candidate")]
    options += [(json.dumps(["override", f["id"]]), "Remove override / " + f["module"] + " / " + f["identity"] + " / " + f["persona"] + " / " + ", ".join(s["name"] for s in f["sources"])) for f in overrides]
    options += [(json.dumps(["library", d["module"], identity]), "Library migration / " + d["module"] + " / retain " + identity) for d in duplicates for identity in d["identities"]]
    for f in promotions:
        reuse = f["action"] == "reuse_library"
        label = ("Reuse Library / " if reuse else "Promote local / ") + f["module"] + " / " + f["identity"] + " / " + f["persona"]
        if not any(d["destination"] == "library" for d in f.get("blocked_destinations", [])):
            options.append((json.dumps(["promotion", f["id"], "library"]), label + " / Library"))
        if not reuse:
            options.extend((json.dumps(["promotion", f["id"], p["scope"]]), label + " / " + p["kind"] + " / " + p["name"])
                           for p in f["placement_options"])
    chosen = query.get("candidate", "")
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "remediation")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="previous" value="{e(previous)}"><input type="hidden" name="confirmed" value="yes">'
             + select("candidate", options, chosen, "Prior opportunity") + '<button type="submit">Verify observed outcome</button></form>'
             + '<p class="note">Prior device override candidates, duplicate Library groups, existing Library reuse and local-profile promotions are supported. This is not a replay of an executed plan.</p></section>')
    if chosen:
        if chosen not in dict(options):
            raise ValueError("Unknown prior candidate")
        args = json.loads(chosen)
        if args[0] == "promotion":
            result = verify_promotion(before, current, args[1], args[2], confirmed=True)
            from .promotion_verification_view import promotion_outcome
            body += promotion_outcome(result)
            body += collateral_panel(result["collateral"], root, name, previous, chosen, query.get("collateral_offset", "0"))
            body += private_export("remediation-verification", {"previous_snapshot": previous, "current_snapshot": name, "report": result})
            return page("Remediation verification", body, workspace.nav(name))
        result = (verify_override(before, current, args[1], confirmed=True) if args[0] == "override"
                  else verify_library_migration(before, current, args[1], args[2], confirmed=True))
        rows = result["rows"]
        met = sum(row["status"] in ("observed_goal_met", "observed_profiles_match_goal") for row in rows)
        body += metrics([("Observed goal matches", met, "Captured profile evidence only"),
                         ("Other / unresolved recipients", len(rows)-met, "Review details"),
                         ("Prior candidate recipients", len(rows), "Not complete deployment coverage")])
        from .remediation_presentation import outcome_table
        body += outcome_table(result, root, name, previous)
        if result["workflow"] == "library_migration":
            body += '<section><h2>Remaining migration observations</h2>'
            body += '<p>Retained Library body matches prior capture: ' + e(str(result["retained_library_matches"])) + '</p>'
            from .remediation_presentation import observation_comparison
            body += '<h3>Old Library definitions</h3>' + table(("Profile", "Cleanup evidence", ""), [
                tr(e(row["identity"]), badge(pretty(row["status"]), "good" if row["status"] == "observed_library_removal" else "warn"),
                   inspect(row["identity"], observation_comparison("Library definition", row["before"], row["after"])))
                for row in result["library_cleanup"]])
            body += '<p>Assignment capture: ' + e(pretty(result["assignment_capture_status"])) + '</p>'
            body += table(("Evidence", "Observed count", ""), [
                tr(e(label), str(len(result[key])), inspect(label, raw(result[key]), "Review"))
                for key, label in (("remaining_references", "Old-name references"), ("remaining_assignments", "Old-name assignments"), ("unresolved_recipients", "Unresolved prior recipients"))])
            body += '<p class="note">Zero observed references or assignments does not establish removal or completeness.</p></section>'
        body += collateral_panel(result["collateral"], root, name, previous, chosen, query.get("collateral_offset", "0"))
        body += '<section><h2>Rollback preparation</h2><p>Retain the previous bodies, reference locations and assignments as review evidence. No rollback commands are generated; restoration must be qualified against fresh state.</p>'
        body += private_export("remediation-verification", {"previous_snapshot": previous, "current_snapshot": name, "report": result}) + '</section>'
    return page("Remediation verification", body, workspace.nav(name))

def collateral_panel(report, root, name, previous, candidate, offset):
    """Bound rendered detail; the complete private report retains every record."""
    from .workspace_ui import diff_table
    records = report["records"]
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        raise ValueError("Invalid collateral page") from None
    if offset < 0 or offset % 50 or (offset and offset >= len(records)):
        raise ValueError("Invalid collateral page")
    counts = report["counts"]
    body = '<section id="collateral"><h2>Additional effective-module comparison</h2>'
    body += '<p>Checks other profile identities and devices beyond those already reviewed for the selected remediation, across functions where this module was collected. Observed changes may be unrelated; no causal or complete-configuration claim is made.</p>'
    body += metrics([("Device/function pairs", counts.get("device_function_pairs", 0), "Module scope"),
                     ("Unchanged, count-confirmed pairs", counts.get("unchanged_count_confirmed_pairs", 0), "Compared remaining profiles"),
                     ("Unverified view pairs", counts.get("unverified_view_pairs", 0), "Missing read or count"),
                     ("Unverified device identities", counts.get("unverified_device_pairs", 0), "Not compared")])
    body += table(("Observation", "Count"), [tr(e(pretty(k)), str(n)) for k,n in sorted(report["outcomes"].items())])
    listing = []
    for row in records[offset:offset+50]:
        details = diff_table(row.get("fields", []), "Before", "After") if row.get("fields") else ""
        if row.get("source_fields"):
            details += '<h4>Source annotation differences</h4>' + diff_table(row["source_fields"], "Before", "After")
        listing.append(tr(e(row["device"]), e(row["persona"]), e(row["identity"] or "View / scope"),
                          badge(pretty(row["status"]), "warn"), inspect("Captured comparison", details + raw(row))))
    body += table(("Device", "Function", "Profile", "Evidence", ""), listing)
    if records:
        body += '<p>Showing ' + str(offset+1) + '–' + str(min(offset+50,len(records))) + ' of ' + str(len(records)) + ' observations. Full evidence is available in the private export.</p>'
    for label, next_offset in (("Previous", offset-50), ("Next", offset+50)):
        if 0 <= next_offset < len(records):
            body += f'<a class="button" href="{url(root, "remediation", snapshot=name, previous=previous, confirmed="yes", candidate=candidate, collateral_offset=next_offset)}#collateral">{label}</a> '
    return body + '</section>'
