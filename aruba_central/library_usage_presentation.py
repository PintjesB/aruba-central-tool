"""Separate captured Library usage states; never infer unused profiles."""
from .workspace_ui import e, table, tr, badge, persona_label
from .workspace_views import url

STATES = (
    ("shared_devices", "Matching shared definition"),
    ("matching_other_devices", "Matching settings, source not verified"),
    ("different_devices", "Same name, different settings"),
    ("unknown_devices", "Visibility unverified"),
    ("absent_devices", "Profile absent (count confirmed)"),
)


def visibility_filter(usage, selected):
    if selected == "all":
        return set(usage)
    if selected not in {key for key, _ in STATES}:
        raise ValueError("Unknown Library visibility filter")
    return {identity for identity, u in usage.items() if u.get(selected)}


def usage_summary(root, snapshot, module, usage, selected):
    # Categories may overlap across profiles; do not sum as distinct devices.
    labels = [("all", "All profiles")] + list(STATES)
    links = []
    for key, label in labels:
        count = len(visibility_filter(usage, key))
        href = url(root, "library", snapshot=snapshot, module=module, visibility=key)
        links.append(f'<a class="button" href="{href}"' + (' aria-current="true"' if selected == key else "")
                     + f'>{e(label)} ({count})</a>')
    return '<section><h2>Profile visibility filters</h2><p>Counts are profiles with at least one observation of the selected type. Categories can overlap; none establishes whether a profile is unused.</p><div class="filter-bar">' + " ".join(links) + '</div></section>'


def device_visibility(usage, *, root=None, snapshot=None, module=None):
    rows = []
    for key, label in STATES:
        for device in usage.get(key, []):
            action = ""
            if root and snapshot and module and device.get("persona") and device.get("scope"):
                action = f'<a href="{url(root, "report", snapshot=snapshot, persona=device["persona"], scope=device["scope"], module=module, view="all")}">Configuration</a> · '
                action += f'<a href="{url(root, "scopes", snapshot=snapshot, mode="device", persona=device["persona"], device=device["scope"])}">Device review</a>'
            rows.append(tr(e(device["name"]), e(persona_label(device.get("persona", ""))),
                           badge(label, "warn" if key in ("different_devices", "unknown_devices") else "neutral"), action))
    return '<h3>Observed device visibility</h3><p>Each device/function pair is listed with its captured relationship to this Library definition.</p>' + (
        table(("Device", "Function", "Visibility", "Action"), rows, search=True) if rows else
        '<p class="note">No device observations available; usage is not established.</p>')
