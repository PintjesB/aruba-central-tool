"""Decision-oriented drift and standards views for private saved snapshots."""
from collections import Counter
from configuration_history import configuration_drift, reference_compliance, STANDARD_MODULES
from workspace_ui import e, page, intro, metrics, badge, raw, table, tr, inspect, diff_table, property_table, module_label, persona_label, pretty
from workspace_views import load, select, scope_filter_form


def change_detail(row):
    body = ""
    if row.get("fields"):
        body += diff_table(row["fields"], "Reference / previous", "Observed / current")
    if row.get("source_fields"):
        body += "<h3>Source changes</h3>" + diff_table(row["source_fields"], "Previous", "Current")
    if "before" in row or "after" in row:
        body += "<h3>Reference / previous settings</h3>" + property_table(row.get("before"))
        body += "<h3>Observed / current settings</h3>" + property_table(row.get("after"))
    return body + raw(row)


def drift_view(workspace, query):
    from config_app import audit_files, read_audit
    from central_tool import refresh_configuration_review
    loaded, empty = load(workspace, query, "Configuration drift", "drift")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    others = [(p.name, p.name) for p in audit_files(workspace.directory) if p.name != name]
    previous = query.get("previous", "")
    confirmed = query.get("confirmed") == "yes"
    body = intro("Configuration drift", "Compare saved and effective settings, Library profiles, scope membership and observed assignments across snapshots.", picker)
    if not others:
        return page("Configuration drift", body + "<section>Collect a second snapshot to compare historical changes.</section>", workspace.nav(name))
    body += (f'<section><form class="filter-bar" method="get" action="{e(root + "drift")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}">'
             + select("previous", [("", "Select an earlier snapshot")] + others, previous, "Previous snapshot")
             + f'<label><span><input type="checkbox" name="confirmed" value="yes" {"checked" if confirmed else ""} required> Both snapshots are from the same tenant</span></label>'
             + '<button type="submit">Compare snapshots</button></form></section>')
    if previous and confirmed:
        if previous not in dict(others):
            raise ValueError("Invalid previous snapshot")
        try:
            before = refresh_configuration_review(read_audit(workspace.directory, previous))
            result = configuration_drift(before, bundle, confirmed=True)
        except ValueError as exc:
            return page("Configuration drift", body + '<section><p>Cannot compare these snapshots: ' + e(str(exc)) + '</p></section>', workspace.nav(name))
        counts = result["counts"]
        rows = []
        for row in result["records"]:
            rows.append(tr(e(persona_label(row["persona"])), e(row["scope_name"]), e(module_label(row["module"])),
                           e(pretty(row["view"])), e(row["identity"] or "Collection"), badge(pretty(row["status"])),
                           inspect(row["identity"] or row["module"], change_detail(row), "Compare")))
        body += metrics([("Observed changes", counts.get("changed", 0) + counts.get("source_changed", 0), "Body or source differences"),
                         ("Added / removed profiles", counts.get("added", 0) + counts.get("removed", 0), "Count-confirmed opposite view"),
                         ("Uncertain observations", sum(v for k, v in counts.items() if k not in ("changed", "source_changed", "added", "removed")), "Review coverage and membership"),
                         ("Common device serials", result["identity_checks"]["common_serial_count"], "Identity check, not independent tenant proof")])
        body += '<section><h2>Change worklist</h2>' + (table(("Function", "Scope", "Module", "View", "Profile", "Change", ""), rows, search=True) if rows else "<p>No differences in the compared views.</p>")
        body += '<p class="note">Missing fields are not explicit defaults. A changed observation is not proof of who changed it or that the configuration was deployed. Captures are not atomic; coverage remains incomplete.</p></section>'
    return page("Configuration drift", body, workspace.nav(name))


def standards_view(workspace, query):
    loaded, empty = load(workspace, query, "Standards compliance", "standards")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    personas = sorted(bundle["results"])
    if not personas:
        return page("Standards compliance", intro("Standards compliance", "No device inventory captured.", picker), workspace.nav(name))
    persona = query.get("persona", personas[0])
    if persona not in personas:
        raise ValueError("Unknown device function")
    entry = bundle["results"][persona]
    reference, module, target = (query.get(k, "") for k in ("reference", "module", "target"))
    def references(entry):
        return [("", "Choose reference device")] + sorted((s["id"], s.get("name") or s["id"]) for s in entry["scopes"] if s["kind"] == "device")
    def modules(entry):
        return [("", "Choose module")] + [(m, module_label(m)) for m in sorted(STANDARD_MODULES & entry["modules"].keys())]
    def targets(entry):
        return [("", "Choose target scope")] + [(s["id"], pretty(s["kind"]) + " / " + (s.get("name") or s["id"])) for s in entry["scopes"]]
    controls = scope_filter_form(root, "standards", name, bundle, persona, (
        ("reference", "Approved reference device", reference, references),
        ("module", "Configuration module", module, modules),
        ("target", "Target device or scope", target, targets)), submit="Check standard")
    body = intro("Standards compliance", "Select an approved reference device, module and intended target scope. Review exact effective-profile differences.", picker)
    body += '<section class="filter-section">' + controls + '</section>'
    if reference and module and target:
        try:
            result = reference_compliance(bundle, persona, module, reference, target)
        except ValueError as exc:
            return page("Standards compliance", body + '<section>' + e(str(exc)) + '</section>', workspace.nav(name))
        counts = Counter(r["status"] for r in result["findings"])
        body += metrics([("Known target devices", result["target_count"], "Excludes reference device"),
                         ("Matches reference", counts["matches_reference"], "Count-confirmed exact observed bodies"),
                         ("Differences observed", counts["differences_observed"], "Review intentional exceptions"),
                         ("Verification required", counts["verification_required"] + counts["membership_unverified"], "Coverage or membership unverified")])
        rows = []
        for row in result["findings"]:
            details = "".join("<h3>" + e(d["identity"] or "Collection") + " · " + e(pretty(d["status"])) + "</h3>" + change_detail(d) for d in row["differences"])
            rows.append(tr(e(row["device"]), badge(pretty(row["status"])), str(len(row["differences"])),
                           inspect(row["device"], details or raw(row), "Inspect")))
        body += '<section><h2>Reference standard results</h2>' + table(("Device", "Result", "Differences / gaps", ""), rows, search=True)
        body += '<p class="note">The selected reference is an explicit comparison standard, not an automatically approved network policy. A match concerns captured configuration only. Record intentional exceptions before any remediation.</p></section>'
    return page("Standards compliance", body, workspace.nav(name))
