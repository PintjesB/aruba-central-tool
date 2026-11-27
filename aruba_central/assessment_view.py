"""Customer assessment with linked review queues and private JSON report."""
from .workspace_ui import e, page, intro, metrics, table, tr, module_label, persona_label
from .workspace_views import load, url
from .assessment_review import assessment
from .history_view import private_export


def assessment_view(workspace, query):
    if query.get("mode") == "health":
        from .configuration_health import health_view
        return health_view(workspace, query)
    loaded, empty = load(workspace, query, "Configuration assessment", "assessment")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    from .consolidation import profile_recommendations
    from .optimization_worklist import optimization_worklist
    findings = profile_recommendations(bundle)
    analysis = workspace.advanced_snapshot(bundle)
    report = assessment(bundle, findings=findings, engineering=analysis)
    coverage = report["coverage"]
    engineering, consolidation, assignments, variants = (report[k] for k in ("engineering", "consolidation", "assignments", "variants"))
    rules, sequences = report["policy_rules"], report["policy_sequences"]
    expected = coverage.get("expected", 0)
    parsed = coverage.get("parsed", 0)
    confirmed = coverage.get("count_confirmed", 0)
    body = intro("Configuration assessment", "Prioritize the observed optimization opportunities and evidence gaps in this capture.", picker)
    body += f'<p><a class="button" href="{url(root, "assessment", snapshot=name, mode="health")}">Review health by site, group or device</a></p>'
    body += metrics([("Device/function pairs", report["device_function_pairs"], "Captured inventory"),
                     ("Parsed scope views", f"{parsed}/{expected}", "Saved and effective reads"),
                     ("Count-confirmed views", f"{confirmed}/{expected}", "Not complete API coverage"),
                     ("Consolidation groups", consolidation["groups"], "Potential review work, not safe writes")])
    def linked(label, value, next_step, route, **params):
        return tr(f'<strong>{e(label)}</strong>', str(value), e(next_step),
                  f'<a href="{url(root, route, snapshot=name, **params)}">Open worklist</a>')
    evidence = [
        linked("Unparsed scope views", expected-parsed, "Collect or interpret configuration evidence", "coverage"),
        linked("Parsed views without confirmed count", parsed-confirmed, "Verify missing collection counts", "coverage"),
        linked("Unresolved reference observations", engineering["unresolved_references"], "Establish target identity and visibility", "advanced", workflow="references"),
        linked("Assignments with unresolved scope", assignments["unknown_scopes"], "Verify membership and scope identity", "assignments"),
        linked("Policy groups with unsupported rule evidence", rules["groups_with_unsupported_rules"], "Qualify rule schemas and predicates", "advanced", workflow="rules"),
        linked("Unqualified policy sequences", sequences["unqualified_order"], "Verify policy group structure and order", "advanced", workflow="rules"),
        linked("Unqualified sequence targets", sequences["unqualified_targets"], "Verify policy visibility in the captured scope", "advanced", workflow="rules")]
    opportunities = [
        linked("Matching override candidates", report["actions"].get("remove_override", 0), "Verify nearest inherited definition", "advisor", finding="remove_override"),
        linked("Repeated local profile groups", report["actions"].get("promote_local", 0), "Review intended placement", "advisor", finding="promote_local"),
        linked("Matching Library groups", report["actions"].get("reuse_library", 0), "Verify assignment and local removal", "advisor", finding="reuse_library"),
        linked("Duplicate Library groups", engineering["duplicate_groups"], "Choose retained profile by observed usage", "advanced", workflow="duplicates"),
        linked("Repeated port groups", engineering["repeated_port_groups"], "Compare saved and effective port settings", "advanced", workflow="ports"),
        linked("Divergent policy variants", variants["groups"], "Compare settings and intentional exceptions", "advanced", workflow="variants"),
        linked("Overlapping assignment observations", assignments["overlaps"], "Review effective source and overlap", "assignments"),
        linked("Policy bodies with rule observations", rules["groups_with_findings"], "Review duplicate and broader earlier matches", "advanced", workflow="rules"),
        linked("Cross-policy match candidates", sequences["cross_policy_candidates"], "Review ordered policy groups and role applicability", "advanced", workflow="rules")]
    categories = {"remove_override": "Redundant override review", "promote_local": "Repeated local profiles",
                  "reuse_library": "Reuse Library profile", "duplicates": "Duplicate Library names",
                  "ports": "Repeated port settings"}
    worklist = optimization_worklist(bundle, findings, analysis)
    category = query.get("category", "")
    if category and category not in categories:
        raise ValueError("Unknown optimization category")
    from .workspace_views import select
    body += '<section><h2>Prioritized optimization worklist</h2>'
    body += '<p>Review larger groups first within each category. Counts describe observed review workload, not proven safe removals or a risk score. Recipient counts mean source recipients for local copies, observed shared deployments for Library names, and captured devices for ports. Unknown impact is not zero.</p>'
    body += (f'<form class="filter-bar" method="get" action="{e(root + "assessment")}"><input type="hidden" name="snapshot" value="{e(name)}">'
             + select("category", [("", "All categories")] + list(categories.items()), category, "Category")
             + '<button type="submit">Filter worklist</button></form>')
    body += table(("Opportunity", "Profile / configuration", "Function", "Count", "Unit", "Observed device/function pairs", "Unknown device/function pairs", "Next step", ""), [
        tr(e(categories[row["category"]]), f'<strong>{e(row["profile"])}</strong><small>{e(module_label(row["module"]))}</small>',
           e(persona_label(row["persona"])), str(row["instances"]), e(row["unit"]), str(row["known"]),
           str(row["unknown"]) if row["unknown"] is not None else "Not assessed", e(row["next_step"]),
           f'<a href="{url(root, row["route"], snapshot=name, **row["params"])}">Review finding</a>')
        for row in worklist if not category or row["category"] == category], search=True)
    body += '</section>'
    body += '<section><h2>Evidence to resolve</h2>' + table(("Review queue", "Observed count", "Next step", ""), evidence) + '</section>'
    body += '<section><h2>Optimization opportunities</h2>' + table(("Review queue", "Observed count", "Next step", ""), opportunities) + '</section>'
    body += '<section><h2>Assessment scope</h2><p>Counts describe independent worklists and may overlap. They must not be summed as unique defects, affected devices or safe removals. No health score is inferred from missing or partial evidence.</p>'
    body += '<p>' + e(str(consolidation["reviewable"])) + ' consolidation groups are selectable for preview; ' + e(str(engineering["ports_in_groups"])) + ' ports occur in repeated-setting groups.</p>'
    checkpoint = report["checkpoint"]
    if checkpoint.get("enabled"):
        reused = checkpoint.get("reused_pairs", 0) + sum(checkpoint.get("additional_observations_reused", {}).values())
        body += "<p>" + e(str(reused)) + " checkpoint observations reused (scope pairs and additional reads). " + ("Mixed-time evidence; not valid for remediation verification." if checkpoint.get("mixed_capture_times") else "No earlier observations reused.") + "</p>"
    body += private_export("configuration-assessment", {"snapshot": name, "assessment": report}) + '</section>'
    return page("Configuration assessment", body, workspace.nav(name))
