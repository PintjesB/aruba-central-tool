"""Private NAC registration and tag inspection."""
from collections import Counter
from .workspace_ui import e, page, intro, metrics, table, tr, badge, pretty, inspect, property_table
from .workspace_views import load, list_items, url
from .history_view import private_export
from .nac_review import nac_review


def nac_view(workspace, query):
    loaded, empty = load(workspace, query, "NAC identities", "nac")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    report = nac_review(bundle)
    from .review_dispositions import snapshot_binding
    binding = snapshot_binding(workspace, name, bundle)
    if "registration" in query or query.get("export") == "1":
        if query.get("binding") != binding:
            raise ValueError("NAC evidence or snapshot changed; reopen the worklist")
    if "registration" in query:
        try:
            index = int(query["registration"])
        except (TypeError, ValueError):
            raise ValueError("Invalid registration selector") from None
        if not 0 <= index < len(report["rows"]):
            raise ValueError("Unknown captured registration")
        row = report["rows"][index]
        body = intro("Registration evidence", "Exact captured registration; not a live authorization result.", picker)
        body += f'<p><a href="{url(root, "nac", snapshot=name)}#nac-registrations">Back to MAC registration worklist</a></p>'
        body += '<section><h2>' + e(row["display_name"] or row["id"] or "Captured registration") + '</h2>' + registration_detail(row) + '</section>'
        return page("NAC identities", body, workspace.nav(name))
    from .nac_authorization import policy_review
    from .nac_binding_review import nac_bindings, context_label
    policies = policy_review(bundle)
    bindings = nac_bindings(bundle, report, policies)
    if query.get("export") == "1":
        body = intro("Export private NAC report", "Full captured registration, authorization and binding review. Keep this data private.", picker)
        body += f'<p><a href="{url(root, "nac", snapshot=name)}">Back to NAC overview</a></p>'
        body += '<section>' + private_export("nac-registration-review", {"snapshot": name, "report": report, "authorization": policies, "bindings": bindings}) + '</section>'
        return page("NAC identities", body, workspace.nav(name))
    selected = query.get("tag")
    if selected is not None:
        from .nac_tag_review import tag_review_view
        return tag_review_view(root, name, picker, workspace.nav(name), report, bindings, selected)
    rows = report["rows"]
    body = intro("NAC identities", "Review registered MAC addresses, enable state, static tag relationships and identity evidence.", picker)
    body += metrics([("Observed registrations", len(rows), pretty(report["capture_status"])),
                     ("Enabled registrations", sum(r["enabled"] is True for r in rows), "Registration state, not authentication result"),
                     ("Duplicate MAC groups", len(report["duplicate_mac_groups"]), "Distinct registration IDs"),
                     ("Observed tag definitions", len(report["tag_definitions"]), pretty(report["tag_definition_status"]))])
    if not report["count_confirmed"]:
        body += '<p class="note">Registration count not confirmed. Missing identities or tags are not evidence of absence.</p>'
    services = bundle.get("nac_service_inventory")
    body += '<section id="nac-services"><h2>Additional NAC service inventory</h2>'
    if not services:
        body += '<p class="muted">Not collected in this snapshot. Available in new Deep captures.</p>'
    else:
        service_rows = []
        for row in services.get("operations", []):
            if row.get("operation") in ("cnac-dpp-reg", "cnac-job"):
                service_rows.append(tr(e(row["operation"]), e(pretty(row["status"])), e(row["rows"]),
                    e(row["total"] if row["total"] is not None else "Unavailable"),
                    "Confirmed" if row.get("count_confirmed") is True else "Unverified",
                    "Yes" if row.get("next_cursor_present") else "No"))
        body += table(("Collection", "Read state", "Observed rows", "Reported total", "Count", "Next cursor"), service_rows)
        detail_rows = [tr(e(row["operation"]), str(row["attempted"]),
                           e(", ".join(f"{pretty(k)}: {v}" for k, v in sorted(row["outcomes"].items())) or "No observed identity queried"))
                       for row in services.get("operations", []) if row.get("operation") in ("cnac-dpp-reg/:id", "cnac-job/:job-id/status")]
        body += table(("Individual operation", "Attempts", "Evidence"), detail_rows)
        body += '<p class="note">Bounded first-page reads and up to two observed identity checks per endpoint. No raw registration credentials, job payloads or downloads are retained. An unverified count does not establish absence. Populated schema and full pagination remain unqualified.</p>'
    body += '</section>'
    body += '<section id="nac-registrations"><h2>MAC registration worklist</h2>'
    listing = []
    duplicates = {v["mac"] for v in report["duplicate_mac_groups"]}
    for index, row in enumerate(rows):
        tag_status = "Not returned" if not row["tags_observed"] else ", ".join(str(ref["value"]) for ref in row["references"]) or "Explicitly empty"
        listing.append(tr(e(row["display_name"] or ""), e(row["record"].get("macAddress") or "Unavailable"),
                          badge("Enabled" if row["enabled"] is True else "Disabled" if row["enabled"] is False else "Unknown"),
                          e(tag_status), str(sum(ref["status"] in ("ambiguous", "unresolved") for ref in row["references"])),
                          badge("Duplicate MAC" if row["mac"] in duplicates else "Identity observed" if row["mac"] else "Invalid or missing MAC"),
                          f'<a href="{url(root, "nac", snapshot=name, registration=index, binding=binding)}">Review registration</a>'))
    body += table(("Name", "MAC address", "State", "Static tags", "Unresolved tags", "Identity", ""), listing, search=True) + '</section>'
    body += '<section><h2>Static tag definitions</h2><p>Usage counts are exact captured registration values, not a complete policy-use inventory. Name-only matches do not prove immutable tag identity.</p>'
    body += table(("Tag ID", "Name", "ID occurrences", "Name occurrences", ""), [
        tr(e(identity), f'<a href="{url(root, "nac", snapshot=name, tag=identity)}">{e(profile.get("name") or identity)}</a>', str(report["tag_usage"].get(identity, 0)),
           str(report["tag_usage"].get(profile.get("name") or "", 0)),
           inspect("Static tag evidence", property_table(profile), "Inspect")) for identity, profile in report["tag_definitions"].items()], search=True) + '</section>'
    body += '<section><h2>Duplicate registration identities</h2>' + table(("Normalized MAC", "Registration IDs"), [
        tr(e(row["mac"]), list_items(row["ids"])) for row in report["duplicate_mac_groups"]]) + '</section>'
    def refs(value):
        return table(("Identity store reference", "Evidence"), [
            tr(e(row["identity"]), badge(pretty(row["status"]))) for row in value["references"]]) if value["status"] == "observed" else '<p>Identity store list not qualified.</p>'
    def attrs(values):
        return table(("Attribute type", "Name", "Value", "Source"), [
            tr(e(v["kind"]), e(v["name"]), e(v["value"]), e(v["source"])) for v in values])
    body += '<section><h2>Authentication profiles</h2><p>Capture: ' + e(pretty(policies["auth_capture_status"])) + ' · Identity stores: ' + e(pretty(policies["store_capture_status"])) + '</p>'
    body += table(("Name", "Method", "Networks", ""), [
        tr(e(p["name"]), e(p["type"]), property_table(p["networks"]),
           inspect("Authentication evidence", refs(p["identity_stores"]), "Review stores"))
        for p in policies["authentication"]], search=True) + '</section>'
    body += '<section><h2>Authorization policies</h2><p>Capture: ' + e(pretty(policies["policy_capture_status"])) + ' · Observed policy order: ' + e(str(policies["policy_order_verified"])) + '. Policy and rule applicability are not evaluated against live clients.</p>'
    policy_rows = []
    for p in policies["policies"]:
        detail = '<h3>Policy preconditions</h3>' + property_table(p["conditions"]) + '<h3>Identity stores</h3>' + refs(p["identity_stores"])
        detail += '<h3>Default enforcement attributes</h3>' + attrs(p["default_attributes"]) + list_items(p["default_gaps"])
        detail += '<h3>Rule evaluation order</h3><p>Order observed: ' + e(str(p["rule_order_verified"])) + '</p>'
        for rule in p["rules"]:
            detail += '<h4>Rule position ' + e(rule["position"]) + '</h4><p>Enabled: ' + e(str(rule["enabled"])) + ' · ' + e(pretty(rule["status"])) + '</p>'
            detail += property_table(rule["conditions"]) + '<h4>Explicit rule attributes</h4>' + attrs(rule["attributes"])
            detail += '<h4>Conditional default + rule attributes</h4>' + attrs(rule["combined_candidate_attributes"]) + list_items(rule["gaps"])
        policy_rows.append(tr(e(p["position"]), e(p["name"]), e(p["type"]), e(str(p["enabled"])),
                              str(len(p["rules"])), inspect("Authorization policy evidence", detail, "Review rules")))
    body += table(("Position", "Policy", "Type", "Enabled", "Observed rules", ""), policy_rows, search=True) + '</section>'
    body += '<section><h2>Tag and policy cross-reference</h2><p>Exact condition values are review candidates only. Attribute semantics and authorization applicability are not established by a matching value.</p>'
    body += table(("Tag", "Registered identity count", "Condition observations", ""), [
        tr(f'<a href="{url(root, "nac", snapshot=name, tag=tag["id"])}">{e(tag["name"] or tag["id"])}</a>', str(tag["registered_id_count"]), str(len(tag["condition_observations"])),
           inspect("Tag condition evidence", table(("Policy", "Rule", "Attribute", "Operator", "Value"), [
               tr(e(v["policy"]), e(context_label(v)),
                  e(v["attribute"]), e(v["operator"]), e(v["value"])) for v in tag["condition_observations"]]), "Review"))
        for tag in bindings["tag_summary"]], search=True) + '</section>'
    body += '<section><h2>Configured VLAN enforcement</h2><p>Compare explicit NAC VLAN attributes with captured switch VLAN definitions. A switch without the VLAN is not necessarily an affected switch; actual client location and authorization remain unverified.</p>'
    vlan_rows = []
    for target in bindings["vlan_targets"]:
        visibility = bindings["vlan_visibility"].get(target["vlan_id"], [])
        counts = Counter(row["status"] for row in visibility)
        details = table(("Function", "Switch", "VLAN name", "Visibility"), [
            tr(e(v["persona"]), e(v["device"]), e(v["name"] or ""), badge(pretty(v["status"]))) for v in visibility], search=True)
        vlan_rows.append(tr(e(target["policy"]), e(context_label(target, "Default")),
                            e(target["value"]), badge(pretty(target["status"])), str(counts["observed"]),
                            str(counts["count_confirmed_absence"]), str(counts["unverified"]),
                            inspect("Switch VLAN evidence", details, "Review")))
    body += table(("Policy", "Rule position", "VLAN attribute", "Evidence", "Observed", "Confirmed absent", "Unknown", ""), vlan_rows, search=True) + '</section>'
    role_review=bindings["role_enforcement"]
    body+='<section><h2>Role enforcement evidence</h2><p>Explicit Aruba-User-Role custom attributes and exact role-name value candidates are shown separately. Similar names are not aliases. Captured visibility is not a client authorization result or proof of role applicability.</p>'
    role_rows=[]
    for target in role_review["targets"]:
        evidence=role_review["visibility"][target["role_identity"]]
        counts=Counter(r["status"] for r in evidence["devices"])
        detail=('<p>Library: '+e(pretty(evidence["library_status"]))+'</p><p>Other exact names differing in case: '+e(", ".join(evidence["similar_exact_names"]) or "None observed")+'</p>'
                +table(("Function","Device","Role visibility","Library body comparison"),[
                    tr(e(r["persona"]),e(r["device"]),badge(pretty(r["status"])),e(pretty(r["library_comparison"]))) for r in evidence["devices"]],search=True))
        role_rows.append(tr(e(target["policy"]),e(context_label(target,"Default")),e(target["name"]),e(target["role_identity"]),
                             badge(pretty(target["status"])),str(counts["observed"]),str(counts["count_confirmed_absence"]),
                             str(counts["unverified"]+counts["individual_evidence_conflict"]),inspect("Role evidence",detail,"Review")))
    body+=table(("Policy","Rule","Attribute","Exact value","Evidence","Observed","Confirmed absent","Unknown or conflicting",""),role_rows,search=True)+'</section>'
    body += '<section><h2>Authorization limits</h2><p>Registration and static tag association do not prove the effective role, VLAN, authentication result or authorization rule. Named MPSK secret collection is intentionally excluded.</p>'
    body += f'<a class="button" href="{url(root, "nac", snapshot=name, export="1", binding=binding)}">Prepare private report JSON</a></section>'
    return page("NAC identities", body, workspace.nav(name))


def registration_detail(row):
    return ('<h3>Static tag evidence</h3>' + table(("Registration value", "Resolution", "Candidate tag IDs"), [
        tr(e(ref["value"]), badge(pretty(ref["status"])), list_items(ref["candidates"])) for ref in row["references"]])
        + '<h3>Captured registration record</h3>' + property_table(row["record"]))
