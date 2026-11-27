"""Private local presets for server-side workspace filters."""
import json
import os
import re
import uuid
from pathlib import Path
from .workspace_ui import e, page, intro, table, tr, badge

ROUTES = {
    "assessment": {"mode", "scope", "module", "category", "state", "persona", "group_by", "parent_kind", "drill", "previous", "confirmed"},
    "overrides": {"persona", "device", "module", "result", "readiness", "q"},
    "report": {"mode", "persona", "module", "scope", "view", "q", "evidence", "presentation", "group"},
    "compare": {"mode", "persona", "module", "left", "right", "view", "identity", "fields", "depth", *("scope" + str(i) for i in range(1, 6))},
    "scopes": {"mode", "persona", "device"},
    "library": {"module", "visibility", "profile"},
    "advanced": {"workflow", "group"},
    "assignments": {"module", "persona", "identity"},
    "advisor": {"finding", "group", "persona", "module", "scope", "identity"},
}
LABELS = {"assessment": "Configuration assessment", "overrides": "Device overrides",
          "report": "Configuration explorer", "compare": "Compare", "library": "Library",
          "scopes": "Inventory", "advanced": "Engineering", "assignments": "Library assignments", "advisor": "Consolidation"}
TARGET_FIELDS = {"profile", "device", "scope", "left", "right", "identity", "group", "drill", "evidence", "previous", *("scope" + str(i) for i in range(1, 6))}
ID = re.compile(r"[0-9a-f]{32}")


def selection(route, params):
    if route not in ROUTES or not isinstance(params, dict) or not params.keys() <= ROUTES[route]:
        raise ValueError("Invalid filter route or fields")
    if any(not isinstance(v, str) or len(v) > 512 or any(ord(c) < 32 for c in v) for v in params.values()):
        raise ValueError("Invalid filter value")
    return {k: v for k, v in params.items() if v}


def preset_path(directory, identity):
    if not ID.fullmatch(identity):
        raise ValueError("Invalid filter identity")
    return Path(directory) / f"workspace-filter-{identity}.json"


def read_presets(directory):
    records = []
    for path in sorted(Path(directory).glob("workspace-filter-*.json")):
        try:
            identity = path.stem.removeprefix("workspace-filter-")
            if not ID.fullmatch(identity) or path.is_symlink():
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("schema") != 1 or data.get("id") != identity or not isinstance(data.get("name"), str):
                continue
            data["params"] = selection(data["route"], data["params"])
            records.append(data)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            continue
    return sorted(records, key=lambda r: (r["name"].casefold(), r["id"]))


def save_preset(workspace, snapshot, route, params, name, expected_binding):
    from .review_dispositions import snapshot_binding
    params = selection(route, params)
    name = name.strip()
    if not name or len(name) > 100 or any(ord(c) < 32 for c in name):
        raise ValueError("Invalid preset name")
    bundle = workspace.reviewed_snapshot(snapshot)
    binding = snapshot_binding(workspace, snapshot, bundle)
    if expected_binding != binding:
        raise ValueError("Snapshot changed; reopen the filter form")
    scoped = bool(TARGET_FIELDS & params.keys())
    identity = uuid.uuid4().hex
    record = {"schema": 1, "id": identity, "name": name, "route": route, "params": params,
              "snapshot": snapshot if scoped else None, "binding": binding if scoped else None}
    path = preset_path(workspace.directory, identity)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return record


def delete_preset(directory, identity):
    path = preset_path(directory, identity)
    if not path.is_file() or path.is_symlink():
        raise ValueError("Unknown filter")
    path.unlink()


def preset_link(root, snapshot, route, query):
    from .workspace_views import url
    if route not in ROUTES:
        return ""
    params = selection(route, {k: v for k, v in query.items() if k in ROUTES[route]})
    return f'<a class="button quiet" href="{url(root, "filters", snapshot=snapshot, source=route, selection=json.dumps(params, ensure_ascii=False))}">Saved filters</a>'


def filters_view(workspace, query):
    from .workspace_views import load, url
    from .review_dispositions import snapshot_binding
    loaded, empty = load(workspace, query, "Saved filters", "filters")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    binding = snapshot_binding(workspace, name, bundle)
    body = intro("Saved filters", "Save frequently used workspace selections locally.", picker)
    source = query.get("source", "")
    if source:
        params = selection(source, json.loads(query.get("selection", "{}")))
        body += '<section><h2>Save current selection</h2><p>' + e(LABELS[source]) + '</p>'
        body += table(("Filter", "Value"), [tr(e(k), e(v)) for k, v in params.items()])
        body += (f'<form method="post" action="{e(root + "save-filter")}">'
                 f'<input type="hidden" name="csrf" value="{e(workspace.csrf)}"><input type="hidden" name="snapshot" value="{e(name)}">'
                 f'<input type="hidden" name="route" value="{e(source)}"><input type="hidden" name="params" value="{e(json.dumps(params, ensure_ascii=False))}">'
                 f'<input type="hidden" name="binding" value="{e(binding)}">'
                 '<label>Preset name<input name="name" required maxlength="100"></label><button type="submit">Save filter</button></form></section>')
    body += '<p class="note">Presets retain submitted page filters, not temporary table searches or unsaved client-side selections. Scope and profile-specific presets are bound to their exact snapshot; generic filters can be reused on another capture. Select the original snapshot to reopen a bound preset. No Central changes are performed.</p>'
    rows = []
    for record in read_presets(workspace.directory):
        applicable = record.get("binding") is None or (record.get("snapshot") == name and record["binding"] == binding)
        if applicable:
            open_link = f'<a href="{url(root, record["route"], snapshot=name, **record["params"])}">Open filter</a>'
        else:
            open_link = badge("Different or changed snapshot")
            if record.get("snapshot") and record["snapshot"] != name:
                from .config_app import audit_files
                if any(p.name == record["snapshot"] for p in audit_files(workspace.directory)):
                    open_link += f'<p><a href="{url(root, "filters", snapshot=record["snapshot"])}">Select original snapshot</a></p>'
        remove = (f'<form method="post" action="{e(root + "delete-filter")}"><input type="hidden" name="csrf" value="{e(workspace.csrf)}">'
                  f'<input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="id" value="{e(record["id"])}">'
                  '<button type="submit" class="quiet">Delete</button></form>')
        rows.append(tr(e(record["name"]), e(LABELS[record["route"]]), e(", ".join(f"{k}: {v}" for k, v in record["params"].items()) or "Default view"),
                       e("Exact snapshot" if record.get("binding") else "Reusable"), open_link, remove))
    body += '<section><h2>Saved selections</h2>' + table(("Name", "Page", "Filters", "Scope", "", ""), rows, search=True) + '</section>'
    return page("Saved filters", body, workspace.nav(name))
