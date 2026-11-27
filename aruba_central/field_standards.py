"""Explicit field rules from a captured baseline; missing values remain unknown."""
from .central_tool import canonical, profile_body, field_differences

GAP_KINDS = {"missing_local", "missing_reference", "null_vs_value"}


def leaf_fields(value, path=()):
    # Treat arrays atomically: list positions are not stable object identities.
    if isinstance(value, dict) and value:
        for key, item in sorted(value.items()):
            yield from leaf_fields(item, path + (key,))
    elif path and value is not None:
        yield list(path), value


def baseline_field_options(baseline, persona, reference, modules):
    entry = baseline["results"][persona]
    options = []
    for module in modules:
        view = next((v.get("effective_view", {}) for v in entry.get("modules", {}).get(module, {}).get("scope_results", [])
                     if v["scope"] == reference), {})
        if view.get("status") != "list_parsed":
            continue
        for identity, raw in sorted(view["profiles"].items()):
            for path, value in leaf_fields(profile_body(raw)):
                options.append({"module": module, "identity": identity, "path": path, "value": value})
    return options


def field_key(rule):
    return canonical([rule["module"], rule["identity"], rule["path"]])


def selected_field_rules(baseline, persona, reference, modules, selection):
    import json
    keys = json.loads(selection)
    if not isinstance(keys, list) or not keys or len(keys) > 500 or not all(isinstance(k, str) for k in keys):
        raise ValueError("Select between one and 500 baseline fields")
    options = {field_key(rule): rule for rule in baseline_field_options(baseline, persona, reference, modules)}
    if not set(keys) <= options.keys():
        raise ValueError("Unknown baseline field selection")
    return [options[k] for k in sorted(set(keys))]


def read_path(body, path):
    for part in path:
        if not isinstance(body, dict) or part not in body:
            return False, None
        body = body[part]
    return True, body


def compare_fields(expected, actual, rules):
    """Check only explicitly selected paths, not the entire profile."""
    if actual.get("status") != "list_parsed":
        return [{"identity": "", "status": "unavailable"}]
    observations = []
    for rule in rules:
        identity, path, value = rule["identity"], rule["path"], rule["value"]
        if identity not in actual["profiles"]:
            observations.append({"identity": identity, "status": "field_profile_absent" if actual.get("count_confirmed") is True else "presence_unverified",
                                 "rule_path": path, "expected_value": value})
            continue
        found, observed = read_path(profile_body(actual["profiles"][identity]), path)
        if not found or observed is None:
            observations.append({"identity": identity, "status": "field_values_unavailable", "rule_path": path,
                                 "expected_value": value, "observed_value": observed})
            continue
        if canonical(value) != canonical(observed):
            differences = field_differences(value, observed, tuple(path))
            observations.append({"identity": identity, "status": "changed", "rule_path": path,
                                 "before": value, "after": observed, "fields": differences})
    return observations
