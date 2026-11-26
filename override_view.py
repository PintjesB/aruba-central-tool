"""Device-first review of committed local settings against Global."""
from collections import Counter
from central_tool import canonical, profile_body
from consolidation import scope_memberships, REUSABLE
from workspace_ui import e, page, intro, badge, raw, table, tr, inspect, diff_table, property_table, module_label, persona_label
from workspace_views import load, url, select, title_profile, vlan_explanation

RESULTS = {
    "identical": "Identical to Global",
    "different": "Different from Global",
    "no_global": "No matching Global profile",
    "global_unknown": "Global comparison unavailable",
    "source_uncertain": "Local source or effective settings disagree",
}
NEXT_STEP = {
    "identical": "Review possible override removal",
    "different": "Keep local unless the difference is unnecessary",
    "no_global": "Local definition, not a proven Global override",
    "global_unknown": "Validate Global configuration first",
    "source_uncertain": "Validate the saved and effective configuration",
}


def device_override_rows(bundle, persona):
    entry = bundle["results"][persona]
    names = {s["id"]: s.get("name") or s["id"] for s in entry["scopes"]}
    membership = scope_memberships(entry["scopes"])
    kinds = {s["kind"] for s in entry["scopes"]}
    findings, incomplete = [], []
    for module, data in sorted(entry["modules"].items()):
        if data.get("device_scope_only"):
            continue
        views = {s["scope"]: s for s in data["scope_results"]}
        for sid, member in membership.items():
            review = views.get(sid, {}).get("review", {})
            if not review.get("qualified"):
                incomplete.append({"device": sid, "module": module})
                continue
            global_view = views.get(member["global"], {}).get("effective_view", {})
            for row in review["profiles"]:
                if row["local"] is None or row["status"] == "default_profile":
                    continue
                local, ref = row["local"], row["global_reference"]
                identity = row["identity"]
                if row["status"] in ("source_conflict", "local_effective_mismatch"):
                    state = "source_uncertain"
                elif global_view.get("status") != "list_parsed":
                    state = "global_unknown"
                elif ref is None:
                    state = "no_global"
                elif canonical(local) == canonical(ref):
                    state = "identical"
                else:
                    state = "different"
                chain = []
                for kind in ("group", "site", "collection", "global"):
                    ancestor = member[kind]
                    if ancestor is None:
                        if kind in kinds:
                            chain.append({"name": kind.capitalize(), "state": "Membership unknown"})
                        continue
                    view = views.get(ancestor, {}).get("effective_view", {})
                    if view.get("status") != "list_parsed":
                        text = "Cannot compare"
                    elif identity not in view["profiles"]:
                        text = "Profile not returned"
                    else:
                        text = "Identical settings" if canonical(profile_body(view["profiles"][identity])) == canonical(local) else "Different settings"
                    chain.append({"name": names[ancestor], "state": text, "kind": kind})
                ann = row.get("annotations", {})
                direct = ann.get("aruba-annotation:object_type") == "LOCAL" and ann.get("aruba-annotation:inherited") is False
                findings.append({"device": sid, "device_name": names[sid], "module": module,
                                 "identity": identity, "result": state, "profile": row, "chain": chain,
                                 "direct_confirmed": direct,
                                 "candidate": state == "identical" and module in REUSABLE and direct})
    return findings, incomplete


def overrides_view(workspace, query):
    loaded, empty = load(workspace, query, "Device overrides", "overrides")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    personas = sorted(bundle["results"])
    if not personas:
        return page("Device overrides", intro("Device overrides", "No device functions captured.", picker), workspace.nav(name))
    persona = query.get("persona", "ACCESS_SWITCH" if "ACCESS_SWITCH" in personas else personas[0])
    if persona not in personas:
        raise ValueError("Unknown device function")
    entry = bundle["results"][persona]
    devices = [(s["id"], s.get("name") or s["id"]) for s in entry["scopes"] if s["kind"] == "device"]
    modules = sorted(m for m, data in entry["modules"].items() if not data.get("device_scope_only"))
    device, module, result = query.get("device", ""), query.get("module", ""), query.get("result", "")
    if (device and device not in dict(devices)) or (module and module not in modules) or (result and result not in RESULTS):
        raise ValueError("Unknown comparison filter")
    findings, incomplete = device_override_rows(bundle, persona)
    scoped = [f for f in findings if (not device or f["device"] == device) and (not module or f["module"] == module)]
    missing = [f for f in incomplete if (not device or f["device"] == device) and (not module or f["module"] == module)]
    counts = Counter(f["result"] for f in scoped)
    filters = (f'<form method="get" action="{root}overrides"><input type="hidden" name="snapshot" value="{e(name)}">'
               + select("persona", [(p, persona_label(p)) for p in personas], persona, "Device function")
               + '<button type="submit" class="quiet">Load devices</button></form><hr>'
               + f'<form method="get" action="{root}overrides"><input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="persona" value="{e(persona)}">'
               + select("device", [("", "All devices")] + devices, device, "Device")
               + select("module", [("", "All comparable modules")] + [(m, module_label(m)) for m in modules], module, "Configuration")
               + select("result", [("", "All results")] + [(k, f"{v} ({counts[k]})") for k, v in RESULTS.items()], result, "Comparison result")
               + '<button type="submit">Compare with Global</button></form>')
    rows = []
    for f in sorted(scoped, key=lambda f: (list(RESULTS).index(f["result"]), f["device_name"], f["module"], f["identity"])):
        if result and f["result"] != result:
            continue
        p = f["profile"]
        label = title_profile(f["identity"], p["local"])
        state = f["result"]
        next_step = NEXT_STEP[state]
        if state == "identical" and not f["candidate"]:
            next_step = "Verify direct source and module support; do not remove yet"
        comparison = diff_table(p["global_differences"], "Device local", "Global")
        if f["module"] == "layer2-vlan" and state == "different":
            comparison = vlan_explanation(p["local"], p["global_reference"]) or comparison
        detail = ('<h3>Comparison result</h3><p>' + e(RESULTS[state]) + '. ' + e(next_step) + '.</p>'
                  + '<h3>Device local vs Global</h3>' + comparison
                  + '<h3>Saved device settings</h3>' + property_table(p["local"])
                  + '<h3>Global settings</h3>' + property_table(p["global_reference"])
                  + '<h3>Applicable higher scopes (captured effective settings)</h3>'
                  + table(("Scope", "Comparison with local"), [tr(e(v["name"]), e(v["state"])) for v in f["chain"]])
                  + '<p class="note">A Global match alone does not prove that removing the override preserves configuration. Verify the inherited source, dependencies and rollback first.</p>'
                  + raw(p))
        if f["candidate"]:
            detail += f'<p><a href="{url(root, "advisor", snapshot=name, finding="remove_override", module=f["module"], persona=persona, scope=f["device"], identity=f["identity"])}">Open matching consolidation preview</a></p>'
        rows.append(tr(f'<strong>{e(f["device_name"])}</strong>', e(module_label(f["module"])), e(label),
                       badge(RESULTS[state], "good" if state == "identical" else "warn" if state == "different" else "neutral"),
                       e(next_step), inspect(label, detail, "Compare settings")))
    cards = []
    for key in ("identical", "different", "no_global"):
        href = url(root, "overrides", snapshot=name, persona=persona, device=device, module=module, result=key)
        cards.append(f'<a class="workflow-card" href="{href}"><strong>{counts[key]} · {e(RESULTS[key])}</strong><span>Show these profiles →</span></a>')
    body = (intro("Device overrides", "Find saved device-level configuration and compare it directly with Global.", picker)
            + '<section>' + filters + '</section><div class="workflow-grid">' + "".join(cards) + '</div>'
            + '<section><h2>Device-local configuration</h2><p class="muted">One row per saved non-default local profile. Device-only interfaces are excluded because there is no comparable Global profile.</p>'
            + table(("Device", "Configuration", "Profile", "Compared with Global", "Suggested next step", ""), rows, search=True)
            + f'<p class="note">{len(missing)} device/module reads could not be interpreted. '
              'An empty result is not proof that a device has no overrides. '
              'Removal is not enabled in the production browser.</p></section>')
    return page("Device overrides", body, workspace.nav(name))
