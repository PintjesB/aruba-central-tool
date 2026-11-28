"""Customer assessment with linked review queues and private JSON report."""
from .workspace_ui import e, page, intro, metrics, table, tr, module_label, persona_label, badge
from .workspace_views import load, url
from .history_view import private_export


def assessment_view(workspace, query):
    if query.get("mode") == "identities":
        from .identity_review_view import identity_view
        return identity_view(workspace,query)
    if query.get("mode") == "keyed":
        from .keyed_evidence_view import keyed_view
        return keyed_view(workspace, query)
    if query.get("mode") == "history":
        from .optimization_history import history_view
        return history_view(workspace, query)
    if query.get("mode") == "customer-report":
        from .customer_assessment import report_view
        return report_view(workspace, query)
    if query.get("mode") == "health":
        from .configuration_health import health_view
        return health_view(workspace, query)
    loaded, empty = load(workspace, query, "Configuration assessment", "assessment")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    from .optimization_worklist import reduction_scenario
    report = workspace.assessment_snapshot(bundle)
    coverage = report["coverage"]
    engineering, consolidation, assignments, variants = (report[k] for k in ("engineering", "consolidation", "assignments", "variants"))
    rules, sequences = report["policy_rules"], report["policy_sequences"]
    expected = coverage.get("expected", 0)
    parsed = coverage.get("parsed", 0)
    confirmed = coverage.get("count_confirmed", 0)
    body = intro("Configuration assessment", "Prioritize the observed optimization opportunities and evidence gaps in this capture.", picker)
    body += '<nav class="assessment-nav" aria-label="Assessment views">' + " ".join(
        f'<a class="button" href="{url(root, "assessment", snapshot=name, mode=mode)}">{e(label)}</a>'
        for mode, label in (("health", "Scope health"), ("keyed", "Individual API evidence"),
                            ("history", "Workload history"), ("customer-report", "Customer report"))) + '</nav>'
    body += metrics([("Device/function pairs", report["device_function_pairs"], "Captured inventory"),
                     ("Parsed scope views", f"{parsed}/{expected}", "Saved and effective reads"),
                     ("Count-confirmed views", f"{confirmed}/{expected}", "Not complete API coverage"),
                     ("Consolidation groups", consolidation["groups"], "Potential review work, not safe writes")])
    def linked(label, value, next_step, route, **params):
        return tr(f'<strong>{e(label)}</strong>', str(value), e(next_step),
                  f'<a href="{url(root, route, snapshot=name, **params)}">Open worklist</a>')
    evidence = [
        linked("Individual profile discrepancies", "Review", "Inspect unresolved schemas and exact field differences", "assessment", mode="keyed"),
        linked("Similar exact profile identities", report["identity_collisions"]["groups"], "Inspect case or whitespace collisions without merging names", "assessment", mode="identities"),
        linked("Unparsed scope views", expected-parsed, "Collect or interpret configuration evidence", "coverage"),
        linked("Parsed views without confirmed count", parsed-confirmed, "Verify missing collection counts", "coverage"),
        linked("Unresolved reference observations", engineering["unresolved_references"], "Establish target identity and visibility", "advanced", workflow="references"),
        linked("Conditional NAC enforcement observations", engineering["conditional_nac_observations"], "Review potential role and VLAN consumers separately from device references", "nac"),
        linked("Contradictory policy bodies", rules["individual_conflict_groups"], "Inspect contradictory individual and collection evidence", "advanced", workflow="rules"),
        linked("Assignments with unresolved scope", assignments["unknown_scopes"], "Verify membership and scope identity", "assignments", state="scope_unresolved"),
        linked("Policy groups with unsupported rule evidence", rules["groups_with_unsupported_rules"], "Qualify rule schemas and predicates", "advanced", workflow="rules"),
        linked("Unqualified policy sequences", sequences["unqualified_order"], "Verify policy group structure and order", "advanced", workflow="rules"),
        linked("Unqualified sequence targets", sequences["unqualified_targets"], "Verify policy visibility in the captured scope", "advanced", workflow="rules")]
    opportunities = [
        linked("Matching override candidates", report["actions"].get("remove_override", 0), "Verify nearest inherited definition", "advisor", finding="remove_override"),
        linked("Repeated local profile groups", report["actions"].get("promote_local", 0), "Review intended placement", "advisor", finding="promote_local"),
        linked("Matching Library groups", report["actions"].get("reuse_library", 0), "Verify assignment and local removal", "advisor", finding="reuse_library"),
        linked("Duplicate Library groups", engineering["duplicate_groups"], "Choose retained profile by observed usage", "advanced", workflow="duplicates"),
        linked("Repeated port groups", engineering["repeated_port_groups"], "Compare saved and effective port settings", "advanced", workflow="ports"),
        linked("Divergent policy variants", variants["groups"], "Compare settings and intentional exceptions", "advanced", workflow="variants"),
        linked("Overlapping assignment observations", assignments["overlaps"], "Review effective source and overlap", "assignments", state="overlap"),
        linked("Policy bodies with rule observations", rules["groups_with_findings"], "Review duplicate and broader earlier matches", "advanced", workflow="rules"),
        linked("Cross-policy match candidates", sequences["cross_policy_candidates"], "Review ordered policy groups and role applicability", "advanced", workflow="rules")]
    categories = {"remove_override": "Redundant override review", "promote_local": "Repeated local profiles",
                  "reuse_library": "Reuse Library profile", "duplicates": "Duplicate Library names",
                  "ports": "Repeated port settings"}
    worklist = workspace.optimization_worklist(bundle)
    category = query.get("category", "")
    if category and category not in categories:
        raise ValueError("Unknown optimization category")
    from .workspace_views import select
    from .workspace_ui import inspect
    from .review_dispositions import STATES, snapshot_binding, finding_key, read_disposition
    from .assessment_overview import review_overview, overview_panel
    binding = snapshot_binding(workspace, name, bundle)
    state_filter = query.get("state", "")
    if state_filter and state_filter not in STATES:
        raise ValueError("Unknown review state")
    return_fields = (f'<input type="hidden" name="return_category" value="{e(category)}">'
                     f'<input type="hidden" name="return_state" value="{e(state_filter)}">')
    records = [(row, finding_key(binding, row)) for row in worklist]
    records = [(row, key, read_disposition(workspace.directory, key)) for row, key in records]
    overview = review_overview(records)
    body += overview_panel(root, name, overview, categories, STATES, category, state_filter)
    def review_row(row, key, disposition):
        reduction = reduction_scenario(row)
        reduction_label = (str(reduction["count"]) + " " + reduction["unit"] if reduction["count"] is not None else "Not estimated")
        reduction_cell = f'<span title="{e(reduction["reason"])}">{e(reduction_label)}</span>'
        if state_filter and disposition["state"] != state_filter:
            return None
        form = (f'<form method="post" action="{e(root + "review-disposition")}">'
                f'<input type="hidden" name="csrf" value="{e(workspace.csrf)}">'
                f'<input type="hidden" name="snapshot" value="{e(name)}">'
                f'<input type="hidden" name="key" value="{e(key)}">'
                + return_fields
                + '<label>Review status<select name="state">' + "".join(
                    f'<option value="{e(value)}"{" selected" if value == disposition["state"] else ""}>{e(label)}</option>' for value, label in STATES.items()) + '</select></label>'
                + f'<label>Review note<input name="note" maxlength="500" value="{e(disposition["note"])}"></label>'
                + '<button type="submit">Save review status</button></form>'
                '<p class="note">Local review record only. It is not approval or change authorization. A changed snapshot requires review again.</p>')
        finding = f'<strong>{e(row["profile"])}</strong><small>{e(categories[row["category"]])} · {e(module_label(row["module"]))}</small><small>{e(persona_label(row["persona"]))}</small>'
        workload = f'<strong>{row["instances"]}</strong> {e(row["unit"])}<small>Conditional reduction: {reduction_cell}</small>'
        impact = f'<strong>{row["known"]}</strong> observed<small>' + (f'{row["unknown"]} unknown' if row["unknown"] is not None else "Unknown impact not assessed") + '</small>'
        next_step = (badge("Preview blocked", "warn") + '<small>Resolve evidence before preview</small>'
                     if row["next_step"] == "Evidence blocks preview" else e(row["next_step"]))
        review = badge(STATES[disposition["state"]], "warn" if disposition["state"] == "investigate" else "info" if disposition["state"] == "deferred" else "neutral")
        if disposition["note"]:
            review += f'<small class="review-note-preview">{e(disposition["note"])}</small>'
        actions = f'<a href="{url(root, row["route"], snapshot=name, **row["params"])}">Review finding</a><div>' + inspect("Review disposition", form, "Set status") + '</div>'
        return tr(f'<input type="checkbox" data-bulk-key="{e(key)}" aria-label="Select {e(row["profile"])}">',
                  finding, workload, impact, next_step, review, actions)
    body += '<section id="optimization-worklist"><h2>Prioritized optimization worklist</h2>'
    body += '<p>Review larger groups first. Counts are observed review workload, not safe removals. Unknown impact is not zero.</p>'
    body += '<details><summary>How to interpret the counts</summary><p>Conditional reduction counts exclude assignments and must not be summed across overlapping proposals. Hover over a reduction for its assumptions. Recipient counts represent source recipients for local copies, observed shared deployments for Library names, and captured devices for ports. No reduction is guaranteed.</p></details>'
    body += (f'<form class="filter-bar" method="get" action="{e(root + "assessment")}"><input type="hidden" name="snapshot" value="{e(name)}">'
             + select("category", [("", "All categories")] + list(categories.items()), category, "Category")
             + select("state", [("", "All review statuses")] + list(STATES.items()), state_filter, "Review status")
             + '<button type="submit">Filter worklist</button></form>')
    review_rows = [review_row(row, key, disposition) for row, key, disposition in records if not category or row["category"] == category]
    visible_count = sum(row is not None for row in review_rows)
    body += f'<p class="filter-hint"><strong>{visible_count}</strong> findings in this worklist · {overview["total"]} total review groups.</p>'
    body += '<div id="bulk-review-table">' + table(("", "Finding", "Configuration count", "Device/function impact", "Next step", "Review status", "Actions"),
                  [row for row in review_rows if row is not None], search=True, style="compact-review-table") + '</div>'
    body += ('<div class="table-toolbar"><button type="button" id="bulk-select-page">Select visible page</button>'
             '<button type="button" id="bulk-clear">Clear selection</button><span id="bulk-selection" aria-live="polite">0 selected</span></div>'
             f'<form id="bulk-review-form" method="post" action="{e(root + "bulk-review-disposition")}">'
             f'<input type="hidden" name="csrf" value="{e(workspace.csrf)}"><input type="hidden" name="snapshot" value="{e(name)}">'
             '<input type="hidden" name="keys" value="[]">'
             + return_fields
             + select("state", list(STATES.items()), "reviewed", "New review status").replace('id="state"', 'id="bulk-state"')
             + '<label>Notes<select name="replace_notes"><option value="no">Preserve existing notes</option><option value="yes">Replace with shared note</option></select></label>'
             '<label>Shared note<input name="note" maxlength="500"></label>'
             '<label><input type="checkbox" name="confirmed" value="yes" required>Confirm local status update only</label>'
             '<button type="submit" id="bulk-review-submit" disabled>Update selected findings</button></form>'
             '<p class="note">Maximum 200 findings per update. Selections persist across table pages and searches. Existing notes are preserved by default. Category and review-status filters remain active after saving; updated findings may leave the filtered list. No Central changes or approvals.</p>')
    body += '</section><script>' + BULK_REVIEW_JS + '</script>'
    body += '<section><h2>Evidence to resolve</h2>' + table(("Review queue", "Observed count", "Next step", ""), evidence) + '</section>'
    body += '<section><h2>Optimization opportunities</h2>' + table(("Review queue", "Observed count", "Next step", ""), opportunities) + '</section>'
    body += '<section><h2>Assessment scope</h2><p>Counts describe independent worklists and may overlap. They must not be summed as unique defects, affected devices or safe removals. No health score is inferred from missing or partial evidence.</p>'
    body += '<p>' + e(str(consolidation["reviewable"])) + ' consolidation groups are selectable for preview; ' + e(str(engineering["ports_in_groups"])) + ' ports occur in repeated-setting groups.</p>'
    checkpoint = report["checkpoint"]
    if checkpoint.get("enabled"):
        reused = checkpoint.get("reused_pairs", 0) + sum(checkpoint.get("additional_observations_reused", {}).values())
        body += "<p>" + e(str(reused)) + " checkpoint observations reused (scope pairs and additional reads). " + ("Mixed-time evidence; not valid for remediation verification." if checkpoint.get("mixed_capture_times") else "No earlier observations reused.") + "</p>"
    body += f'<p><a class="button" href="{url(root, "assessment", snapshot=name, mode="customer-report")}">Open customer assessment report</a></p>'
    body += private_export("configuration-assessment", {"snapshot": name, "assessment": report}) + '</section>'
    from .assessment_overview import OVERVIEW_CSS
    return page("Configuration assessment", body, workspace.nav(name), extra_css=OVERVIEW_CSS)


BULK_REVIEW_JS = r"""
(() => {
 const form = document.querySelector('#bulk-review-form');
 const boxes = Array.from(document.querySelectorAll('#bulk-review-table [data-bulk-key]'));
 const submit = document.querySelector('#bulk-review-submit');
 const count = document.querySelector('#bulk-selection');
 const confirmed = form.elements.confirmed;
 const visible = box => !box.closest('tr').hidden;
 function update() {
   const selected = boxes.filter(box => box.checked);
   const hidden = selected.filter(box => !visible(box)).length;
   count.textContent = selected.length + ' selected' + (hidden ? ' (' + hidden + ' outside visible page)' : '') + (selected.length > 200 ? ' — maximum 200' : '');
   form.elements.keys.value = JSON.stringify(selected.map(box => box.dataset.bulkKey));
   submit.disabled = !selected.length || selected.length > 200 || !confirmed.checked;
 }
 for (const box of boxes) box.addEventListener('change', () => { confirmed.checked = false; update(); });
 document.querySelector('#bulk-select-page').addEventListener('click', () => {
   for (const box of boxes.filter(visible)) box.checked = true;
   confirmed.checked = false; update();
 });
 document.querySelector('#bulk-clear').addEventListener('click', () => {
   for (const box of boxes) box.checked = false;
   confirmed.checked = false; update();
 });
 form.addEventListener('change', event => { if (event.target !== confirmed) confirmed.checked = false; update(); });
 new MutationObserver(update).observe(document.querySelector('#bulk-review-table'), {subtree:true, attributes:true, attributeFilter:['hidden']});
 update();
})();
"""
