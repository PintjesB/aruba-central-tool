"""Load large coverage response bodies only when a captured record is selected."""
from .workspace_ui import e, page, intro, raw, property_table
from .workspace_views import url

KINDS = {"health": ("Configuration health summary", "coverage-health"),
         "health-pages": ("Original health summary responses", "coverage-health"),
         "hierarchy": ("Captured hierarchy response", "coverage-hierarchy"),
         "assignment": ("Captured assignment response", "coverage-hierarchy")}


def evidence_link(root, snapshot, binding, kind, index, label):
    return f'<a href="{url(root, "coverage", snapshot=snapshot, evidence_kind=kind, evidence_index=index, binding=binding)}">{e(label)}</a>'


def evidence_record(bundle, kind, index):
    if kind not in KINDS or type(index) is not int or index < 0:
        raise ValueError("Invalid coverage evidence selector")
    health = bundle.get("configuration_health") or {}
    if kind == "health-pages":
        records = [health.get("summary_pages", [])] if health else []
    elif kind == "health":
        from .central_tool import health_serial
        summary = {health_serial(row): row for row in health.get("devices", []) if health_serial(row)}
        issues = health.get("active_issues", {})
        inventory = {health_serial(record.get("inventory")): record["inventory"]
                     for record in bundle.get("inventory", []) if health_serial(record.get("inventory"))}
        serials = sorted(set(summary) | set(issues) | set(inventory))
        if index >= len(serials) or not health:
            raise ValueError("Unknown coverage evidence record")
        serial = serials[index]
        return {"serial": serial, "summary": summary.get(serial, {}), "active_issue_response": issues.get(serial, {})}
    elif kind == "hierarchy":
        records = (bundle.get("scope_hierarchy_evidence") or {}).get("records", [])
    else:
        records = (bundle.get("keyed_assignment_details") or {}).get("records", [])
    if index >= len(records):
        raise ValueError("Unknown coverage evidence record")
    return records[index]


def evidence_view(workspace, query, root, name, bundle, picker, binding):
    kind = query.get("evidence_kind")
    if query.get("binding") != binding or kind not in KINDS:
        raise ValueError("Coverage evidence or snapshot changed; reopen the coverage page")
    try:
        index = int(query.get("evidence_index", ""))
    except (TypeError, ValueError):
        raise ValueError("Invalid coverage evidence selector") from None
    record = evidence_record(bundle, kind, index)
    title, anchor = KINDS[kind]
    body = intro(title, "Exact captured evidence. This does not establish complete API coverage.", picker)
    body += f'<p><a href="{url(root, "coverage", snapshot=name)}#{anchor}">Back to coverage section</a></p>'
    body += '<section><h2>Complete captured response</h2>' + raw(record, title) + '</section>'
    return page("Module coverage", body, workspace.nav(name))
