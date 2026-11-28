"""Decision-oriented drift and standards views for private saved snapshots."""
from collections import Counter
import json
from .configuration_history import configuration_drift, reference_compliance, snapshot_identity_checks, STANDARD_MODULES, STANDARD_TEMPLATES
from .workspace_ui import e, page, intro, metrics, badge, raw, table, tr, inspect, diff_table, property_table, module_label, persona_label, pretty
from .workspace_views import load, select, scope_filter_form, url


def private_export(kind, data):
    payload = {"schema": 1, "kind": kind, "safe_to_apply": False, **data}
    return ('<button type="button" data-private-report="' + e(json.dumps(payload, ensure_ascii=False))
            + '" data-filename="' + e(kind) + '.json">Export private report JSON</button>'
            + """<script>
document.querySelectorAll('[data-private-report]').forEach(button=>{
 button.addEventListener('click',()=>{
  const url=URL.createObjectURL(new Blob([button.dataset.privateReport],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download=button.dataset.filename;a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
 });
});
</script>""")


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


def drift_control(root, common, kind, index, label):
    endpoint = url(root, "drift", **common, detail=kind, index=index)
    href = url(root, "drift", **common, evidence=kind, index=index)
    return (f'<button type="button" class="quiet inspect-trigger" data-inspect data-inspect-url="{endpoint}">{e(label)}</button>'
            f'<noscript><a href="{href}">{e(label)}</a></noscript>')


def drift_group_detail(group):
    evidence = group["observations"]
    locations = table(("Function", "Scope", "View", "Change"), [
        tr(e(persona_label(row["persona"])), e(row["scope_name"]), e(pretty(row["view"])),
           badge(pretty(row["status"]))) for row in evidence], search=True)
    return ("<h3>Observed locations</h3>" + locations + "<h3>Shared observed transition</h3>" + change_detail(evidence[0])
            + '<p class="note">Matching transitions across scopes do not prove a common cause. Each observation remains available in the detailed change worklist.</p>')


DRIFT_STATES = {"changes": "Observed changes", "gaps": "Coverage and identity gaps", "all": "All observations"}
OBSERVED_DRIFT = {"changed", "source_changed", "added", "removed", "assignment_observation_changed", "scope_presence_changed"}


def drift_batch(records, query, prefix, fields, *, predicate=None):
    keyword = query.get(prefix + "_q", "")
    if len(keyword) > 200:
        raise ValueError("Invalid drift search")
    terms = keyword.casefold().split()
    matches = [(i, row) for i, row in enumerate(records)
               if (predicate is None or predicate(row))
               and all(term in " ".join(str(row.get(k, "")) for k in fields).casefold() for term in terms)]
    try:
        offset = int(query.get(prefix + "_offset", "0"))
    except (ValueError, TypeError):
        raise ValueError("Invalid drift page") from None
    if offset < 0 or offset % 50 or (offset and offset >= len(matches)):
        raise ValueError("Invalid drift page")
    return matches[offset:offset+50], len(matches), offset, keyword


def drift_batch_controls(root, common, prefix, total, offset, keyword, *, state=None):
    body = (f'<form class="filter-bar" method="get" action="{e(root+"drift")}#{prefix}-drift">'
            + "".join(f'<input type="hidden" name="{e(key)}" value="{e(value)}">' for key,value in common.items() if key != "binding")
            + (select("record_state", list(DRIFT_STATES.items()), state, "Observation type") if state is not None else "")
            + f'<label>Search all observations<input name="{prefix}_q" maxlength="200" value="{e(keyword)}"></label>'
            + '<button type="submit">Filter</button></form>')
    body += '<p>' + ("Showing "+str(offset+1)+"–"+str(min(total,offset+50))+" of "+str(total) if total else "No matching observations") + '</p>'
    for label,next_offset in (("Previous",offset-50),("Next",offset+50)):
        if 0 <= next_offset < total:
            href=url(root,"drift",**{k:v for k,v in common.items() if k!="binding"},
                     **{prefix+"_q":keyword,prefix+"_offset":next_offset},
                     **({"record_state":state} if state is not None else {}))
            body += f'<a class="button" href="{href}#{prefix}-drift">{label}</a> '
    return body


def drift_view(workspace, query):
    from .config_app import audit_files
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
    special = query.get("detail") or query.get("evidence") or query.get("export")
    if special and (not previous or not confirmed):
        raise ValueError("Comparison context required")
    if previous and confirmed:
        if previous not in dict(others):
            raise ValueError("Invalid previous snapshot")
        try:
            result, binding = workspace.drift_snapshot(name, bundle, previous)
        except ValueError as exc:
            if special:
                raise
            return page("Configuration drift", body + '<section><p>Cannot compare these snapshots: ' + e(str(exc)) + '</p></section>', workspace.nav(name))
        common = {"snapshot":name,"previous":previous,"confirmed":"yes","binding":binding}
        groups = result["profile_change_groups"]
        if special:
            if query.get("binding") != binding:
                raise ValueError("Comparison snapshot changed; reopen worklist")
            if query.get("export") == "1":
                export = intro("Configuration drift", "Complete private comparison export. Keep this file private.", picker)
                export += private_export("configuration-drift", {"previous_snapshot":previous,"current_snapshot":name,"report":result})
                return page("Configuration drift",export,workspace.nav(name))
            kind=query.get("detail") or query.get("evidence")
            collections={"group":groups,"record":result["records"],"additional":result["additional_evidence"]["records"]}
            if kind not in collections:
                raise ValueError("Invalid drift evidence type")
            try:
                index=int(query.get("index",""))
            except (ValueError,TypeError):
                raise ValueError("Invalid drift evidence index") from None
            records=collections[kind]
            if not 0 <= index < len(records):
                raise ValueError("Unknown drift evidence")
            row=records[index]
            title=row.get("identity") or row["module"]
            content=drift_group_detail(row) if kind=="group" else change_detail(row)
            if query.get("evidence"):
                return page("Configuration drift",intro("Configuration drift",title,picker)+content,workspace.nav(name))
            return '<template data-advisor-evidence><div class="inspector-title"><h2>'+e(title)+'</h2></div>'+content+'</template>'
        counts=result["counts"]
        body += metrics([("Observed changes", counts.get("changed", 0) + counts.get("source_changed", 0), "Body or source differences"),
                         ("Added / removed profiles", counts.get("added", 0) + counts.get("removed", 0), "Count-confirmed opposite view"),
                         ("Uncertain observations", sum(v for k, v in counts.items() if k not in ("changed", "source_changed", "added", "removed")), "Review coverage and membership"),
                         ("Common device serials", result["identity_checks"]["common_serial_count"], "Identity check, not independent tenant proof")])
        batch,total,offset,keyword=drift_batch(groups,query,"group",("module","identity","status"))
        body += '<section id="group-drift"><h2>Profile change groups</h2><p>Identical before/after profile transitions are grouped to reduce repeated review. Effective device counts describe captured changes, not inferred deployment or causality.</p>'
        body += drift_batch_controls(root,common,"group",total,offset,keyword)
        body += table(("Module", "Profile", "Change", "Device/function pairs", "Saved scopes", "Higher effective scopes", "Library observations", ""),[
            tr(e(module_label(group["module"])),e(group["identity"]),
               badge(pretty(group["status"]))+('<small>Field evidence gaps</small>' if group["has_field_gaps"] else ""),
               str(group["effective_device_count"]),str(group["saved_scope_count"]),str(group["higher_effective_count"]),str(group["library_count"]),
               drift_control(root,common,"group",index,"Review impact")) for index,group in batch])
        body += '</section>'
        state = query.get("record_state", "changes")
        if state not in DRIFT_STATES:
            raise ValueError("Invalid drift observation type")
        def in_state(row):
            return state == "all" or (row["status"] in OBSERVED_DRIFT) == (state == "changes")
        batch,total,offset,keyword=drift_batch(result["records"],query,"record",("persona","scope","scope_name","module","view","identity","status","before_status","after_status"),predicate=in_state)
        body += '<section id="record-drift"><div class="section-head"><h2>Change worklist</h2>'
        body += f'<a class="button" href="{url(root,"drift",**common,export="1")}">Export private report JSON</a></div>'
        change_count = sum(r["status"] in OBSERVED_DRIFT for r in result["records"])
        body += '<p>Observed changes: '+str(change_count)+' · Coverage and identity gaps: '+str(len(result["records"])-change_count)+'. All observations remain in the private export.</p>'
        body += drift_batch_controls(root,common,"record",total,offset,keyword,state=state)
        body += table(("Function","Scope","Module","View","Profile","Change",""),[
            tr(e(persona_label(row["persona"])),e(row["scope_name"]),e(module_label(row["module"])),e(pretty(row["view"])),
               e(row["identity"] or "Collection"),badge(pretty(row["status"])) + (('<small>'+e(pretty(row["before_status"]))+' → '+e(pretty(row["after_status"]))+'</small>') if "before_status" in row and "after_status" in row else ""),drift_control(root,common,"record",index,"Compare"))
            for index,row in batch])
        body += '<p class="note">Missing fields are not explicit defaults. A changed observation is not proof of who changed it or that the configuration was deployed. Captures are not atomic; coverage remains incomplete.</p></section>'
        from .additional_drift_view import additional_drift_panel
        body += additional_drift_panel(result["additional_evidence"], root, name, previous, query, binding=binding)
    return page("Configuration drift", body, workspace.nav(name))


def standards_view(workspace, query):
    from .config_app import audit_files, read_audit
    from .central_tool import refresh_configuration_review
    loaded, empty = load(workspace, query, "Standards compliance", "standards")
    if empty:
        return empty
    from .local_standards import records, read_record, evaluate_standard, exception_candidates, active_exceptions, exception_history, apply_approvals
    from datetime import date, timedelta
    root, name, bundle, picker = loaded
    saved = records(workspace.directory, "standard")
    standard_id = query.get("standard", "")
    standard = read_record(workspace.directory, "standard", standard_id) if standard_id else None
    if standard:
        query = {**query, "persona": standard["persona"], "reference": standard["reference"],
                 "module": standard["module"], "target": standard["target"], "baseline": standard["baseline"]}
    personas = sorted(bundle["results"])
    if not personas:
        return page("Standards compliance", intro("Standards compliance", "No device inventory captured.", picker), workspace.nav(name))
    persona = query.get("persona", personas[0])
    if persona not in personas:
        raise ValueError("Unknown device function")
    entry = bundle["results"][persona]
    reference, module, target = (query.get(k, "") for k in ("reference", "module", "target"))
    baseline_name = query.get("baseline", name)
    confirmed = query.get("confirmed") == "yes"
    baseline_options = [(p.name, p.name) for p in audit_files(workspace.directory)]
    if baseline_name not in dict(baseline_options):
        raise ValueError("Unknown baseline snapshot")
    body = intro("Standards compliance", "Choose a fixed saved baseline, approved reference device, module and intended target scope.", picker)
    body += (f'<section><h2>Saved standards</h2><form class="filter-bar" method="get" action="{e(root + "standards")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}">'
             + select("standard", [("", "Create / assess a new standard")] +
                      [(v["id"], v["name"] + " · " + v["created_at"][:10] + " · " + v["id"][:8]) for v in saved],
                      standard_id, "Local standard version")
             + f'<label><span><input type="checkbox" name="confirmed" value="yes" {"checked" if confirmed else ""}> Same tenant as baseline</span></label>'
             + '<button type="submit">Load standard</button></form>'
             + '<p class="note">Saved versions retain their original baseline checksum, target scope and module set. No Central settings are changed.</p></section>')
    if standard:
        body += '<section><h2>' + e(standard["name"]) + '</h2><p>Frozen version ' + e(standard["id"][:8]) + ' · ' + e(standard["baseline"]) + ' · ' + e(", ".join(standard["modules"])) + '</p>' + ('<p>Selected field rules: ' + str(len(standard["field_rules"])) + '</p>' + table(("Module", "Profile", "Field", "Expected value"), [tr(e(v["module"]), e(v["identity"]), e(".".join(v["path"])), property_table(v["value"])) for v in standard["field_rules"]], search=True) if standard.get("field_rules") else "") + '</section>'
    else:
        body += (f'<section><form class="filter-bar" method="get" action="{e(root + "standards")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}">'
             + select("baseline", baseline_options, baseline_name, "Approved baseline snapshot")
             + f'<label><span><input type="checkbox" name="confirmed" value="yes" {"checked" if confirmed else ""}> Historical baseline belongs to the same tenant</span></label>'
             + '<button type="submit">Use baseline</button></form>'
             + '<p class="note">A saved baseline remains fixed while the selected current snapshot changes. Select a historical baseline to check even the original reference device for drift.</p></section>')
    historical = baseline_name != name
    baseline = bundle
    if historical:
        if not confirmed:
            return page("Standards compliance", body + '<section>Confirm that the historical baseline belongs to the same tenant.</section>', workspace.nav(name))
        baseline = refresh_configuration_review(read_audit(workspace.directory, baseline_name))
        try:
            snapshot_identity_checks(baseline, bundle)
        except ValueError as exc:
            return page("Standards compliance", body + '<section>' + e(str(exc)) + '</section>', workspace.nav(name))
    entry_persona = {id(value): key for key, value in bundle["results"].items()}
    def base_entry(current_entry):
        return baseline["results"].get(entry_persona[id(current_entry)], {})
    def references(entry):
        return [("", "Choose reference device")] + sorted((s["id"], s.get("name") or s["id"]) for s in base_entry(entry).get("scopes", []) if s["kind"] == "device")
    def modules(entry):
        available = STANDARD_MODULES & (entry["modules"].keys() | base_entry(entry).get("modules", {}).keys())
        return ([("", "Choose module or template"), ("all", "All standard modules")]
                + [(key, "Template: " + label + " (" + str(len(available & names)) + " observed modules)")
                   for key, (label, names) in STANDARD_TEMPLATES.items() if available & names]
                + [(m, module_label(m)) for m in sorted(available)])
    def targets(entry):
        return [("", "Choose target scope")] + [(s["id"], pretty(s["kind"]) + " / " + (s.get("name") or s["id"])) for s in entry["scopes"]]
    controls = scope_filter_form(root, "standards", name, bundle, persona, (
        ("reference", "Approved reference device", reference, references),
        ("module", "Module or standard template", module, modules),
        ("target", "Target device or scope", target, targets)), submit="Check standard")
    hidden = f'<input type="hidden" name="baseline" value="{e(baseline_name)}">'
    if confirmed:
        hidden += '<input type="hidden" name="confirmed" value="yes">'
    controls = controls.replace("</form>", hidden + "</form>")
    if not standard:
        body += '<section class="filter-section">' + controls + '</section>'
    if reference and module and target:
        try:
            if standard:
                bundle, result = evaluate_standard(workspace.directory, standard, name, confirmed=confirmed)
            else:
                result = reference_compliance(bundle, persona, module, reference, target, baseline=baseline, confirmed=confirmed)
        except ValueError as exc:
            return page("Standards compliance", body + '<section>' + e(str(exc)) + '</section>', workspace.nav(name))
        def post_form(route, values):
            return (f'<form method="post" action="{e(root + route)}">' +
                    "".join(f'<input type="hidden" name="{e(k)}" value="{e(v)}">' for k, v in
                            {**values, "csrf": workspace.csrf, "confirmed": "yes" if confirmed else ""}.items()))
        if not standard:
            from .field_standards import baseline_field_options, field_key
            field_options = baseline_field_options(baseline, persona, reference, result["modules"])
            field_controls = ('<details><summary>Optional: select individual baseline fields</summary><p>Select only the fields to enforce (Ctrl or Shift to select multiple). Leave empty to enforce complete profiles.</p>'
                              + '<label>Field rules<select name="field_selection" multiple size="12">'
                              + "".join(f'<option value="{e(field_key(v))}">{e(module_label(v["module"]) + " / " + v["identity"] + " / " + ".".join(v["path"]) + " = " + str(v["value"]))}</option>' for v in field_options)
                              + '</select></label></details>') if field_options else ""
            body += ('<section><h2>Save this standard version</h2>' + post_form("save-standard", {
                "snapshot": name, "baseline_name": baseline_name, "persona": persona, "reference": reference,
                "module": module, "target": target}) +
                '<label>Standard name<input name="name" required maxlength="120"></label>' + field_controls +
                '<button type="submit">Save local standard</button></form><p class="note">This freezes the selected baseline and module set; later changes require a new version.</p></section>')
        candidates = exception_candidates(bundle, standard, result, include_legacy=True) if standard else {}
        approved = active_exceptions(workspace.directory, standard_id, candidates) if standard else {}
        history = exception_history(workspace.directory, standard_id, candidates) if standard else []
        apply_approvals(result, candidates, approved)
        counts = Counter(r["status"] for r in result["findings"])
        body += metrics([("Known target devices", result["target_count"], "Includes original reference when historical" if historical else "Excludes reference device"),
                         ("Matches reference", counts["matches_reference"], "Count-confirmed exact observed bodies"),
                         ("Differences observed", counts["differences_observed"], "Review intentional exceptions"),
                         ("Devices with evidence gaps", sum(bool(r.get("has_gaps")) or r["status"] == "membership_unverified" for r in result["findings"]), "May also have observed differences"),
                         ("Modules checked", len(result["modules"]), "Selected supported module set"),
                         ("Approved deviations", len(approved), "Exact current deviations, not missing evidence")])
        rows = []
        for row in result["findings"]:
            module_rows = [tr(e(module_label(m)), badge(pretty(v["status"])), str(v["difference_count"]),
                              e("Yes" if v["has_gaps"] else "No")) for m, v in row.get("module_results", {}).items()]
            details = table(("Module", "Result", "Observations", "Evidence gaps"), module_rows) if module_rows else ""
            details += "".join("<h3>" + e(module_label(d["module"]) + " / " + (d["identity"] or "Collection")) + " · " + e(pretty(d["status"])) + "</h3>" + change_detail(d) for d in row["differences"])
            for key, candidate in candidates.items():
                if candidate["scope"] != row["scope"] or (candidate.get("legacy") and key not in approved):
                    continue
                details += '<h3>Exception · ' + e(module_label(candidate["module"]) + " / " + candidate["profile"] + (" / " + ".".join(candidate["field_path"]) if "field_path" in candidate else "")) + '</h3>' + change_detail(candidate["observation"])
                if key in approved:
                    details += ''.join('<p>Approved until ' + e(a["expiry"]) + ': ' + e(a["reason"]) + '</p>' for a in approved[key])
                else:
                    details += (post_form("approve-exception", {"standard_id": standard_id, "snapshot": name, "candidate": key}) +
                                '<label>Reason<input name="reason" required maxlength="500"></label>'
                                f'<label>Expiry<input type="date" name="expiry" required min="{date.today().isoformat()}" value="{(date.today()+timedelta(days=90)).isoformat()}"></label>'
                                '<button type="submit">Approve exact deviation</button></form>')
            module_counts = Counter(v["status"] for v in row.get("module_results", {}).values())
            summary = (f'{module_counts["matches_reference"]} match / {module_counts["differences_observed"]} differ / {module_counts["verification_required"]} verify'
                       if module_rows else "Membership unknown")
            rows.append(tr(e(row["device"]), badge(pretty(row["status"])) + ('<small>Approved exceptions: ' + str(len(row["approved_exceptions"])) + '</small>' if row["approved_exceptions"] else "") + ('<small>Evidence gaps also present</small>' if row.get("has_gaps") and row["status"] == "differences_observed" else ""), e(summary), str(len(row["differences"])),
                           inspect(row["device"], details or raw(row), "Inspect")))
        body += '<section><div class="section-head"><h2>Reference standard results</h2>' + private_export(
            "configuration-standards", {"baseline_snapshot": baseline_name, "current_snapshot": name,
                                        "persona": persona, "module": module, "target_scope": target, "standard_id": standard_id, "report": result}) + '</div>' + table(("Device", "Result", "Module results", "Differences / gaps", ""), rows, search=True)
        body += '<p class="note">The selected reference is an explicit comparison standard, not an automatically approved network policy. A match concerns captured configuration only. Record intentional exceptions before any remediation.</p></section>'
    if standard and reference and module and target:
        rows = []
        for item in history:
            detail = '<h3>Approval reason</h3><p>' + e(item["reason"]) + '</p>' + change_detail(item["observation"])
            for revocation in item["revocations"]:
                detail += '<p>Revoked: ' + e(revocation["created_at"]) + ' · ' + e(revocation["reason"]) + '</p>'
            if item["state"] != "revoked":
                detail += (post_form("revoke-exception", {"standard_id": standard_id, "snapshot": name, "exception_id": item["id"]}) +
                           '<label>Revocation reason<input name="reason" required maxlength="500"></label>'
                           '<button type="submit">Revoke approval</button></form>')
            rows.append(tr(e(item["device"]), e(module_label(item["module"])), e(item["profile"]),
                           badge(pretty(item["state"])), e(item["expiry"]), inspect("Exception history", detail, "Review")))
        body += '<section><h2>Exception history</h2>' + table(("Device", "Module", "Profile", "Approval state", "Expiry", ""), rows, search=True)
        body += '<p class="note">Expired, revoked and currently unobserved approvals remain visible for audit. Only exact active approvals affect the current assessment.</p></section>'
    return page("Standards compliance", body, workspace.nav(name))
