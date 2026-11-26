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
    body += '<section><h2>Authorization limits</h2><p>Registration and static tag association do not prove the effective role, VLAN, authentication result or authorization rule. Named MPSK secret collection is intentionally excluded.</p>'
    body += private_export("nac-registration-review", {"snapshot": name, "report": report}) + '</section>'
    return page("NAC identities", body, workspace.nav(name))
