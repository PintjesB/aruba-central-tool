"""Anonymous offline diagnostics for unresolved keyed reads and exact differences."""
from collections import Counter
from .central_tool import canonical
from .coverage_diagnostics import raw_shape
from .applicability_evidence import applicability_evidence

MODULE_KEYS = {"role-gpids": "name", "roles": "name", "server-groups": "name"}
PUBLIC_FIELDS = frozenset(("name", "servers", "type", "count-servers", "description",
                           "assignment-rules", "attribute-profile", "fail-through",
                           "load-balance", "load-balance-algo"))
SIDES = frozenset(("local", "effective", "library", "tenant"))
TYPES = frozenset(("dict", "list", "str", "int", "float", "bool", "NoneType", "missing"))


def difference_category(diff):
    left, right = diff.get("local_value"), diff.get("reference_value")
    if isinstance(left, list) and isinstance(right, list) and canonical(left) != canonical(right):
        if Counter(map(canonical, left)) == Counter(map(canonical, right)):
            return "order_only"
    kind = diff.get("kind")
    return kind if kind in ("missing_local", "missing_reference", "null_vs_value",
                            "type_difference", "value_difference") else "other"


def response_structure(raw, key, identity):
    shape, records, recognized = raw_shape(raw, (key,))
    # Inspect only immediate objects and list rows; do not infer identities
    # from arbitrary nested fields or disclose returned names or values.
    candidates = []
    if isinstance(raw, dict):
        candidates.append(raw)
        for field, value in raw.items():
            if field in ("metadata", "@"):
                continue
            if isinstance(value, dict):
                candidates.append(value)
            elif isinstance(value, list):
                candidates.extend(row for row in value if isinstance(row, dict))
    matches = sum(type(row.get(key)) in (str, int) and str(row[key]) == identity for row in candidates)
    return shape, records, recognized, matches


def identity_relationship(raw, key, identity):
    """Return fixed categories only, without exposing requested/returned names."""
    if not isinstance(raw, dict) or type(raw.get(key)) not in (str, int):
        return "no_direct_identity"
    observed = str(raw[key])
    if observed == identity:
        return "exact"
    if observed.casefold() == identity.casefold():
        return "case_only"
    if observed.strip() == identity.strip():
        return "surrounding_whitespace_only"
    if observed.strip().casefold() == identity.strip().casefold():
        return "case_and_whitespace"
    from urllib.parse import unquote
    if unquote(observed) == identity or observed == unquote(identity):
        return "percent_decoding_only"
    return "different_identity"


def schema_fields(raw):
    """Allowlisted immediate envelope and record fields, never tenant keys."""
    allowed = PUBLIC_FIELDS | {"metadata", "@", "role", "roles", "role-gpid", "role-gpids",
                              "role-name", "role-id", "gpid", "id", "items", "data",
                              "count", "total", "offset", "limit", "count_objects_in_module",
                              "ANY", "LOCAL", "SHARED"}
    def fields(level, obj):
        for key, value in obj.items():
            name = key if key in allowed else "other"
            kind = type(value).__name__
            yield (level, name, kind if kind in TYPES else "other")
    if not isinstance(raw, dict):
        return
    yield from fields("envelope", raw)
    if isinstance(raw.get("metadata"), dict):
        yield from fields("metadata", raw["metadata"])
        counts = raw["metadata"].get("count_objects_in_module")
        if isinstance(counts, dict):
            yield from fields("object_counts", counts)
    for key, value in raw.items():
        if key in ("metadata", "@"):
            continue
        if isinstance(value, dict):
            yield from fields("object", value)
        elif isinstance(value, list):
            for row in value:
                if isinstance(row, dict):
                    yield from fields("list_record", row)


def case_candidate_evidence(bundle, persona, scope, module, identity, side, raw):
    """Compare only captured collections in the exact request context."""
    from .central_tool import observed_profile_candidates, profile_body
    views = []
    if persona == "Library" and side == "library":
        views.append((bundle.get("library") or {}).get("modules", {}).get(module, {}))
        views.append((bundle.get("unadapted_profiles") or {}).get(module, {}).get("library", {}))
    else:
        entry = bundle.get("results", {}).get(persona, {}).get("modules", {}).get(module, {})
        for row in entry.get("scope_results", []):
            if str(row.get("scope")) == str(scope):
                views.append(row.get(side + "_view", {}))
        for row in (bundle.get("unadapted_profiles") or {}).get(module, {}).get("source_views", []):
            if row.get("persona") == persona and str(row.get("scope")) == str(scope):
                views.append(row.get("committed" if side == "local" else side, {}))
    candidates = {}
    for view in views:
        for name, profile in observed_profile_candidates(view, "name").items():
            if name.casefold() == identity.casefold():
                candidates.setdefault(name, set()).add(canonical(profile_body(profile)))
    if len(candidates) > 1:
        return "observed_case_collision"
    if identity not in candidates:
        return "requested_collection_identity_unobserved"
    if len(candidates[identity]) != 1:
        return "conflicting_collection_bodies"
    import json
    saved = json.loads(next(iter(candidates[identity])))
    observed = profile_body(raw)
    # This is a diagnostic, not an equivalence or source qualification rule.
    saved = {k: v for k, v in saved.items() if k != "name"}
    observed = {k: v for k, v in observed.items() if k != "name"}
    return "body_matches_except_name" if canonical(saved) == canonical(observed) else "body_differs_beyond_name"


def server_count_relationship(read, diff):
    path = diff.get("path")
    value = diff.get("local_value")
    if (not isinstance(path, list) or len(path) != 1 or diff.get("kind") != "missing_reference"
            or type(value) is not int):
        return None
    profile = read.get("profile")
    servers = profile.get("servers") if isinstance(profile, dict) else None
    if not isinstance(servers, list):
        return "server_list_unavailable"
    return "equals_observed_server_count" if value == len(servers) else "differs_from_observed_server_count"


def keyed_qualification(bundle):
    schemas, differences, profiles, structures = Counter(), Counter(), Counter(), Counter()
    relationships, locations = Counter(), Counter()
    case_candidates, integer_relationships = Counter(), Counter()
    private_paths = {}
    for persona, scopes in (bundle.get("keyed_profile_details") or {}).get("profiles", {}).items():
        for scope, modules in scopes.items():
            for module, identities in modules.items():
                if module not in MODULE_KEYS:
                    continue
                for identity, views in identities.items():
                    for side, read in views.items():
                        side = side if side in SIDES else "other"
                        if read.get("status") == "schema_unresolved":
                            shape = response_structure(read.get("raw"), MODULE_KEYS[module], str(identity))
                            schemas[(module, side, *shape)] += 1
                            relation = identity_relationship(read.get("raw"), MODULE_KEYS[module], str(identity))
                            relationships[(module, side, relation)] += 1
                            if module in ("roles", "role-gpids") and relation == "case_only":
                                outcome = case_candidate_evidence(bundle, persona, scope, module, str(identity), side, read["raw"])
                                case_candidates[(module, side, outcome)] += 1
                            for level, field, kind in schema_fields(read.get("raw")):
                                structures[(module, side, level, field, kind)] += 1
                        diffs = read.get("differences")
                        if read.get("status") != "identity_observed" or not isinstance(diffs, list) or not diffs:
                            continue
                        categories = []
                        for diff in diffs:
                            if not isinstance(diff, dict):
                                categories.append("other")
                                continue
                            kind = difference_category(diff)
                            categories.append(kind)
                            if module == "server-groups":
                                relationship = server_count_relationship(read, diff)
                                if relationship is not None:
                                    integer_relationships[(module, side, relationship)] += 1
                            path = diff.get("path")
                            field = path[0] if isinstance(path, list) and path and path[0] in PUBLIC_FIELDS else "other"
                            if isinstance(path, list):
                                # Assign anonymous ordinal labels per module.
                                # No private field names or hashes leave the capture.
                                signature = tuple((type(part).__name__, str(part)) for part in path)
                                ids = private_paths.setdefault(module, {})
                                number = ids.setdefault(signature, len(ids) + 1)
                                shape = "/".join("index" if type(part) is int else "field" for part in path) or "root"
                                locations[(module, side, number, shape, field, kind)] += 1
                            local = diff.get("local_type")
                            reference = diff.get("reference_type")
                            differences[(module, side, field, kind,
                                         local if local in TYPES else "other",
                                         reference if reference in TYPES else "other")] += 1
                        profiles[(module, side, "order_only" if categories and all(c == "order_only" for c in categories)
                                  else "includes_non_order_difference")] += 1
    return {"schema": 1, "kind": "anonymous_keyed_qualification",
            "schema_shapes": [{"module": m, "view": v, "shape": s, "records": n,
                               "recognized_records": k, "exact_identity_candidates": x, "reads": c}
                              for (m, v, s, n, k, x), c in sorted(schemas.items())],
            "schema_fields": [{"module": m, "view": v, "level": l, "field": f, "type": t, "occurrences": n}
                              for (m, v, l, f, t), n in sorted(structures.items())],
            "field_differences": [{"module": m, "view": v, "field": f, "category": k,
                                   "local_type": l, "reference_type": r, "occurrences": c}
                                  for (m, v, f, k, l, r), c in sorted(differences.items())],
            "profile_differences": [{"module": m, "view": v, "category": k, "reads": c}
                                    for (m, v, k), c in sorted(profiles.items())],
            "identity_relationships": [{"module": m, "view": v, "relationship": k, "reads": n}
                                       for (m, v, k), n in sorted(relationships.items())],
            "difference_locations": [{"module": m, "view": v, "anonymous_path_number": p, "path_shape": s,
                                       "field": f, "category": k, "occurrences": n}
                                      for (m, v, p, s, f, k), n in sorted(locations.items())],
            "role_case_collection_evidence": [{"module": m, "view": v, "relationship": k, "reads": n}
                                              for (m, v, k), n in sorted(case_candidates.items())],
            "server_group_integer_relationships": [{"module": m, "view": v, "relationship": k, "occurrences": n}
                                                   for (m, v, k), n in sorted(integer_relationships.items())],
            "applicability": applicability_evidence(bundle),
            "safe_to_apply": False, "order_equivalence_qualified": False}
