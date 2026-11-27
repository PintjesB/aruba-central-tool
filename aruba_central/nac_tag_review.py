"""Focused NAC tag review; observed value matches are not live authorization."""
from collections import Counter
from .workspace_ui import e, page, intro, metrics, table, tr, badge, inspect, property_table, persona_label, pretty
from .workspace_views import url
from .nac_binding_review import context_label


def tag_evidence(registrations, bindings, identity):
    if identity not in registrations["tag_definitions"]:
        raise ValueError("Unknown observed static tag")
    rows = []
    for registration in registrations["rows"]:
        references = [ref for ref in registration["references"] if identity in ref["candidates"]]
        if not references:
            continue
        states = {ref["status"] for ref in references}
        # Multiple references for one registration do not inflate registration counts.
        state = "observed_id" if "observed_id" in states else "ambiguous" if "ambiguous" in states else "observed_name_only"
        rows.append({"registration": registration, "references": references, "state": state})
    conditions = [row for row in bindings["tag_condition_observations"] if identity in row["tag_candidates"]]
    # Exact policy ID and exact rule position only. A tag value in a
    # policy precondition does not prove any child rule is selected.
    contexts = {(row["policy_id"], row["rule_index"]) for row in conditions}
    vlans = [row for row in bindings["vlan_targets"] if (row["policy_id"], row["rule_index"]) in contexts]
    return {"tag": registrations["tag_definitions"][identity], "registrations": rows,
            "conditions": conditions, "vlan_targets": vlans, "safe_to_apply": False, "complete": False}


def tag_review_view(root, snapshot, picker, nav, registrations, bindings, identity):
    report = tag_evidence(registrations, bindings, identity)
    label = report["tag"].get("name") or identity
    body = intro("NAC tag review", "Trace one captured tag through registration values, exact policy conditions and configured VLAN attributes.", picker)
    body += f'<p><a href="{url(root, "nac", snapshot=snapshot)}">Back to NAC overview</a></p>'
    counts = Counter(r["state"] for r in report["registrations"])
    body += '<section><h2>' + e(label) + '</h2><p>Tag ID: ' + e(identity) + '</p>' + metrics([
        ("Exact ID registrations", counts["observed_id"], "Direct captured tag ID"),
        ("Name-only candidates", counts["observed_name_only"], "Identity not established"),
        ("Ambiguous candidates", counts["ambiguous"], "Multiple possible tag IDs"),
        ("Condition observations", len(report["conditions"]), "Exact values only")]) + '</section>'
    rows = []
    for item in report["registrations"]:
        r = item["registration"]
        details = property_table(r["record"]) + table(("Captured value", "Resolution"), [
            tr(e(ref["value"]), e(pretty(ref["status"]))) for ref in item["references"]])
        rows.append(tr(e(r["display_name"] or r["id"] or "Unknown"), e(r["record"].get("macAddress") or "Unavailable"),
                       e("Enabled" if r["enabled"] is True else "Disabled" if r["enabled"] is False else "Unknown"),
                       badge(pretty(item["state"]), "warn" if item["state"] != "observed_id" else "neutral"),
                       inspect("Registration evidence", details, "Review")))
    body += '<section><h2>Registered identities</h2><p>Exact ID, name-only and ambiguous registration observations remain separate.</p>' + table(("Registration", "MAC address", "Registration state", "Tag evidence", "Action"), rows, search=True) + '</section>'
    body += '<section><h2>Policy condition observations</h2><p>Matching captured values do not establish attribute semantics, policy selection, or actual client authorization.</p>' + table(
        ("Policy", "Rule", "Attribute", "Operator", "Value", "Tag identity candidates"),
        [tr(e(r["policy"]), e(context_label(r)), e(r["attribute"]),
            e(r["operator"]), e(r["value"]), str(len(r["tag_candidates"]))) for r in report["conditions"]], search=True) + '</section>'
    vlan_rows = []
    for target in report["vlan_targets"]:
        visibility = bindings["vlan_visibility"].get(target["vlan_id"], [])
        counts = Counter(r["status"] for r in visibility)
        details = table(("Switch", "Function", "VLAN visibility", "Action"), [
            tr(e(r["device"]), e(persona_label(r["persona"])), badge(pretty(r["status"])),
               f'<a href="{url(root, "report", snapshot=snapshot, persona=r["persona"], scope=r["scope"], module="layer2-vlan", view="all")}">VLAN configuration</a>')
            for r in visibility], search=True)
        vlan_rows.append(tr(e(target["policy"]), e(context_label(target, "Policy default")),
                            e(target["value"]), e(pretty(target["status"])),
                            str(counts["observed"]), str(counts["count_confirmed_absence"]), str(counts["unverified"]),
                            inspect("VLAN evidence", details, "Review switches")))
    body += '<section><h2>VLAN attributes in matching policy contexts</h2><p>Only attributes in the exact observed policy/default or rule context are shown. This is not a tag-to-VLAN assignment or a prediction of client authorization.</p>' + table(
        ("Policy", "Context", "Configured VLAN", "Attribute evidence", "Observed switches", "Count-confirmed absent", "Unknown", "Action"), vlan_rows, search=True) + '</section>'
    body += '<section><h2>Captured tag definition</h2>' + property_table(report["tag"]) + '</section>'
    return page("NAC identities", body, nav)
