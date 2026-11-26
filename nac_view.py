"""Private NAC registration and tag inspection."""
from collections import Counter
from workspace_ui import e, page, intro, metrics, table, tr, badge, pretty, inspect, property_table
from workspace_views import load, list_items
from history_view import private_export
from nac_review import nac_review


def nac_view(workspace, query):
    loaded, empty = load(workspace, query, "NAC identities", "nac")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    report = nac_review(bundle)
    rows = report["rows"]
    body = intro("NAC identities", "Review registered MAC addresses, enable state, static tag relationships and identity evidence.", picker)
    body += metrics([("Observed registrations", len(rows), pretty(report["capture_status"])),
                     ("Enabled registrations", sum(r["enabled"] is True for r in rows), "Registration state, not authentication result"),
                     ("Duplicate MAC groups", len(report["duplicate_mac_groups"]), "Distinct registration IDs"),
                     ("Observed tag definitions", len(report["tag_definitions"]), pretty(report["tag_definition_status"]))])
    if not report["count_confirmed"]:
        body += '<p class="note">Registration count not confirmed. Missing identities or tags are not evidence of absence.</p>'
    body += '<section><h2>MAC registration worklist</h2>'
    listing = []
    duplicates = {v["mac"] for v in report["duplicate_mac_groups"]}
    for row in rows:
        detail = '<h3>Static tag evidence</h3>' + table(("Registration value", "Resolution", "Candidate tag IDs"), [
            tr(e(ref["value"]), badge(pretty(ref["status"])), list_items(ref["candidates"])) for ref in row["references"]])
        detail += '<h3>Captured registration record</h3>' + property_table(row["record"])
        tag_status = "Not returned" if not row["tags_observed"] else ", ".join(str(ref["value"]) for ref in row["references"]) or "Explicitly empty"
        listing.append(tr(e(row["display_name"] or ""), e(row["record"].get("macAddress") or "Unavailable"),
                          badge("Enabled" if row["enabled"] is True else "Disabled" if row["enabled"] is False else "Unknown"),
                          e(tag_status), str(sum(ref["status"] in ("ambiguous", "unresolved") for ref in row["references"])),
                          badge("Duplicate MAC" if row["mac"] in duplicates else "Identity observed" if row["mac"] else "Invalid or missing MAC"),
                          inspect("Registration evidence", detail, "Review")))
    body += table(("Name", "MAC address", "State", "Static tags", "Unresolved tags", "Identity", ""), listing, search=True) + '</section>'
    body += '<section><h2>Static tag definitions</h2><p>Usage counts are exact captured registration values, not a complete policy-use inventory. Name-only matches do not prove immutable tag identity.</p>'
    body += table(("Tag ID", "Name", "ID occurrences", "Name occurrences", ""), [
        tr(e(identity), e(profile.get("name") or ""), str(report["tag_usage"].get(identity, 0)),
           str(report["tag_usage"].get(profile.get("name") or "", 0)),
           inspect("Static tag evidence", property_table(profile), "Inspect")) for identity, profile in report["tag_definitions"].items()], search=True) + '</section>'
    body += '<section><h2>Duplicate registration identities</h2>' + table(("Normalized MAC", "Registration IDs"), [
        tr(e(row["mac"]), list_items(row["ids"])) for row in report["duplicate_mac_groups"]]) + '</section>'
    from nac_authorization import policy_review
    policies = policy_review(bundle)
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
    from nac_binding_review import nac_bindings
    bindings = nac_bindings(bundle, report, policies)
    body += '<section><h2>Tag and policy cross-reference</h2><p>Exact condition values are review candidates only. Attribute semantics and authorization applicability are not established by a matching value.</p>'
    body += table(("Tag", "Registered identity count", "Condition observations", ""), [
        tr(e(tag["name"] or tag["id"]), str(tag["registered_id_count"]), str(len(tag["condition_observations"])),
           inspect("Tag condition evidence", table(("Policy", "Rule", "Attribute", "Operator", "Value"), [
               tr(e(v["policy"]), e(v["rule"] if v["rule"] is not None else "Policy precondition"),
                  e(v["attribute"]), e(v["operator"]), e(v["value"])) for v in tag["condition_observations"]]), "Review"))
        for tag in bindings["tag_summary"]], search=True) + '</section>'
    body += '<section><h2>Configured VLAN enforcement</h2><p>Compare explicit NAC VLAN attributes with captured switch VLAN definitions. A switch without the VLAN is not necessarily an affected switch; actual client location and authorization remain unverified.</p>'
    vlan_rows = []
    for target in bindings["vlan_targets"]:
        visibility = bindings["vlan_visibility"].get(target["vlan_id"], [])
        counts = Counter(row["status"] for row in visibility)
        details = table(("Function", "Switch", "VLAN name", "Visibility"), [
            tr(e(v["persona"]), e(v["device"]), e(v["name"] or ""), badge(pretty(v["status"]))) for v in visibility], search=True)
        vlan_rows.append(tr(e(target["policy"]), e(target["rule"] if target["rule"] is not None else "Default"),
                            e(target["value"]), badge(pretty(target["status"])), str(counts["observed"]),
                            str(counts["count_confirmed_absence"]), str(counts["unverified"]),
                            inspect("Switch VLAN evidence", details, "Review")))
    body += table(("Policy", "Rule position", "VLAN attribute", "Evidence", "Observed", "Confirmed absent", "Unknown", ""), vlan_rows, search=True) + '</section>'
    body += '<section><h2>Authorization limits</h2><p>Registration and static tag association do not prove the effective role, VLAN, authentication result or authorization rule. Named MPSK secret collection is intentionally excluded.</p>'
    body += private_export("nac-registration-review", {"snapshot": name, "report": report, "authorization": policies, "bindings": bindings}) + '</section>'
    return page("NAC identities", body, workspace.nav(name))
