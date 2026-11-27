"""Side-by-side captured configuration comparison across scopes."""
from .central_tool import canonical, profile_body
from .workspace_ui import e, page, intro, table, tr, setting_value, badge
from .workspace_views import load, scope_filter_form, module_options, url


def comparison_matrix(bundle, persona, module, identity, scopes, *, view="effective"):
    if view not in ("local", "effective") or not 2 <= len(scopes) <= 5 or len(set(scopes)) != len(scopes):
        raise ValueError("Select two to five distinct scopes and a valid view")
    entry = bundle["results"][persona]
    names = {s["id"]: s for s in entry["scopes"]}
    if module not in entry["modules"] or any(sid not in names for sid in scopes):
        raise ValueError("Unknown comparison scope or module")
    observations = {r["scope"]: r.get(view + "_view", {}) for r in entry["modules"][module]["scope_results"]}
    columns = []
    for sid in scopes:
        capture = observations.get(sid, {})
        raw = capture.get("profiles", {}).get(identity) if capture.get("status") == "list_parsed" else None
        body = profile_body(raw) if isinstance(raw, dict) else None
        state = ("observed" if body is not None else "confirmed_absent" if capture.get("status") == "list_parsed"
                 and capture.get("count_confirmed") is True else "unqualified")
        columns.append({"scope": sid, "name": names[sid].get("name") or sid, "kind": names[sid]["kind"],
                        "state": state, "body": body, "count_confirmed": capture.get("count_confirmed") is True})
    keys = sorted({key for col in columns for key in (col["body"] or {})})
    rows = []
    for key in keys:
        cells = [{"state": "observed", "value": col["body"][key]} if col["body"] is not None and key in col["body"]
                 else {"state": "not_returned" if col["body"] is not None else col["state"]} for col in columns]
        values = {canonical(cell["value"]) for cell in cells if cell["state"] == "observed"}
        state = ("different" if len(values) > 1 else "matching" if all(cell["state"] == "observed" for cell in cells)
                 else "unqualified")
        rows.append({"field": key, "state": state, "cells": cells})
    return {"columns": columns, "rows": rows, "safe_to_apply": False}


def matrix_view(workspace, query):
    loaded, empty = load(workspace, query, "Compare devices", "compare")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    personas = sorted(bundle["results"])
    body = intro("Multi-scope comparison", "Compare the same captured profile across two to five devices or configuration scopes.", picker)
    body += f'<p><a href="{url(root, "compare", snapshot=name)}">Return to two-device comparison</a></p>'
    if not personas:
        return page("Compare devices", body, workspace.nav(name))
    persona = query.get("persona", personas[0])
    if persona not in personas:
        raise ValueError("Unknown device function")
    module, identity, view = (query.get(k, default) for k, default in (("module", ""), ("identity", ""), ("view", "effective")))
    slots = [query.get("scope" + str(i), "") for i in range(1, 6)]
    def scope_options(entry):
        return [("", "Select scope")] + [(s["id"], s["kind"].title() + " / " + (s.get("name") or s["id"])) for s in entry["scopes"]]
    from .workspace_views import select
    controls = scope_filter_form(root, "compare", name, bundle, persona,
        tuple(("scope" + str(i), "Scope " + str(i), value, scope_options) for i, value in enumerate(slots, 1)) +
        (("module", "Configuration module", module, lambda entry: module_options(entry, "Select module")),),
        submit="Compare scopes", extra_fields=(("mode", "Comparison", "matrix", [("matrix", "Multi-scope")]),
        ("view", "Configuration view", view, [("effective", "Effective"), ("local", "Saved local")])))
    # Suggest only observed identities, while retaining manual entry for absence checks.
    entry = bundle["results"][persona]
    scopes = [sid for sid in slots if sid]
    if module and module not in entry["modules"]:
        raise ValueError("Unknown module")
    if view not in ("local", "effective"):
        raise ValueError("Unknown configuration view")
    observed = set()
    if module:
        for record in entry["modules"][module]["scope_results"]:
            if scopes and record["scope"] not in scopes:
                continue
            capture = record.get(view + "_view", {})
            if capture.get("status") == "list_parsed":
                observed.update(capture.get("profiles", {}))
    options = "".join(f'<option value="{e(value)}"></option>' for value in sorted(observed))
    controls = controls.replace('<button type="submit">Compare scopes</button>',
        f'<label>Exact profile identity<input name="identity" list="matrix-identities" value="{e(identity)}" maxlength="512"></label>'
        f'<datalist id="matrix-identities">{options}</datalist><button type="submit">Compare scopes</button>')
    controls = controls.replace('class="button reset-link" href="' + url(root, "compare", snapshot=name) + '"',
        'class="button reset-link" href="' + url(root, "compare", snapshot=name, mode="matrix") + '"')
    controls += '<p class="filter-hint">Choose scopes and a module, then submit to populate the observed profile suggestions. Manual identities remain valid for absence checks.</p>'
    body += '<section>' + controls + '<p class="note">Use the same device function and profile identity. Missing fields, confirmed profile absence and unavailable reads are distinct. This compares collection evidence, not deployed behavior or a removal simulation.</p></section>'
    scopes = [sid for sid in slots if sid]
    if module and identity and scopes:
        if len(scopes) < 2 or len(set(scopes)) != len(scopes):
            body += '<section class="empty">Select at least two distinct scopes.</section>'
        else:
            result = comparison_matrix(bundle, persona, module, identity, scopes, view=view)
            labels = {"observed": "Profile observed", "confirmed_absent": "Profile absent (count confirmed)",
                      "unqualified": "Read or presence unqualified", "not_returned": "Field not returned"}
            headers = ("Setting", "Comparison") + tuple(c["kind"].title() + " / " + c["name"] for c in result["columns"])
            rows = [tr("Profile evidence", "", *(badge(labels[c["state"]]) for c in result["columns"])),
                    tr("Collection count", "", *(e("Confirmed" if c["count_confirmed"] else "Unverified") for c in result["columns"]))]
            counts = {state: sum(row["state"] == state for row in result["rows"]) for state in ("matching", "different", "unqualified")}
            differences_only = query.get("fields", "") == "differences"
            params = {"mode": "matrix", "persona": persona, "module": module, "identity": identity, "view": view,
                      **{"scope" + str(i): sid for i, sid in enumerate(slots, 1) if sid}}
            body += '<section><h2>Comparison summary</h2><p>' + e(
                f'{counts["different"]} differing · {counts["matching"]} matching · {counts["unqualified"]} insufficient comparison') + '</p>'
            body += f'<a class="button" href="{url(root, "compare", snapshot=name, **params, fields="" if differences_only else "differences")}">{"Show all fields" if differences_only else "Hide matching fields"}</a></section>'
            for row in result["rows"]:
                if differences_only and row["state"] == "matching":
                    continue
                cells = [setting_value(c["value"]) if c["state"] == "observed" else badge(labels[c["state"]]) for c in row["cells"]]
                rows.append(tr(e(row["field"]), badge({"matching": "Observed values match", "different": "Observed values differ",
                    "unqualified": "Insufficient comparison"}[row["state"]]), *cells))
            body += '<section><h2>Profile comparison: ' + e(identity) + '</h2>' + table(headers, rows, search=False, style="setting-table") + '</section>'
    return page("Compare devices", body, workspace.nav(name))
