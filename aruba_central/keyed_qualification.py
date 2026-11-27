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


def keyed_qualification(bundle):
    schemas, differences, profiles = Counter(), Counter(), Counter()
    for scopes in (bundle.get("keyed_profile_details") or {}).get("profiles", {}).values():
        for modules in scopes.values():
            for module, identities in modules.items():
                if module not in MODULE_KEYS:
                    continue
                for identity, views in identities.items():
                    for side, read in views.items():
                        side = side if side in SIDES else "other"
                        if read.get("status") == "schema_unresolved":
                            shape = response_structure(read.get("raw"), MODULE_KEYS[module], str(identity))
                            schemas[(module, side, *shape)] += 1
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
                            path = diff.get("path")
                            field = path[0] if isinstance(path, list) and path and path[0] in PUBLIC_FIELDS else "other"
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
            "field_differences": [{"module": m, "view": v, "field": f, "category": k,
                                   "local_type": l, "reference_type": r, "occurrences": c}
                                  for (m, v, f, k, l, r), c in sorted(differences.items())],
            "profile_differences": [{"module": m, "view": v, "category": k, "reads": c}
                                    for (m, v, k), c in sorted(profiles.items())],
            "applicability": applicability_evidence(bundle),
            "safe_to_apply": False, "order_equivalence_qualified": False}
