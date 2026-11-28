"""Compare observed optimization workload across two saved captures."""
from collections import Counter, defaultdict
from .configuration_history import snapshot_identity_checks
from .consolidation import profile_recommendations
from .advanced_review import advanced_analysis
from .workspace_ui import e, page, intro, table, tr, metrics
from .workspace_views import load, select, url


def workload(bundle, *, findings=None, engineering=None):
    findings = profile_recommendations(bundle) if findings is None else findings
    engineering = advanced_analysis(bundle) if engineering is None else engineering
    categories = Counter(f["action"] for f in findings)
    views = {}
    for persona, entry in bundle["results"].items():
        for module, data in entry["modules"].items():
            for row in data["scope_results"]:
                for side in ("local_view", "effective_view"):
                    read = row.get(side, {})
                    views[(persona, module, row["scope"], side)] = (read.get("status"), read.get("count_confirmed") is True)
    devices = {(persona, s["id"]) for persona, entry in bundle["results"].items() for s in entry["scopes"] if s["kind"] == "device"}
    return {"counts": {"remove_override": categories["remove_override"], "promote_local": categories["promote_local"],
                       "reuse_library": categories["reuse_library"], "duplicates": len(engineering["library_duplicates"]),
                       "ports": len(engineering["port_groups"]),
                       "preview_candidates": sum(f["action"] in ("remove_override", "promote_local", "reuse_library") and f["preview_selectable"] for f in findings)},
            "views": views, "devices": devices,
            "mixed_time": bool((bundle.get("collection_checkpoint") or {}).get("mixed_capture_times"))}


def workload_transitions(before_rows,after_rows):
    """Compare worklist descriptors, not approval, evidence or removals."""
    from .central_tool import canonical
    def index(rows):
        result=defaultdict(list)
        for row in rows:
            key=tuple(row[k] for k in ("category","persona","module","profile"))
            result[key].append(row)
        return result
    old,new=index(before_rows),index(after_rows)
    records=[]
    counts=Counter()
    for key in sorted(old.keys()|new.keys()):
        a,b=old.get(key,[]),new.get(key,[])
        if len(a)>1 or len(b)>1:
            status="ambiguous_group"
        elif not a:
            status="new_worklist_group"
        elif not b:
            status="prior_group_not_listed"
        elif canonical(a[0])==canonical(b[0]):
            status="same_workload_descriptor"
        else:
            status="changed_workload_descriptor"
        counts[status]+=1
        records.append({"category":key[0],"persona":key[1],"module":key[2],"profile":key[3],
                        "status":status,"before":a,"after":b})
    return {"counts":dict(counts),"records":records,"verified_removals":False,"safe_to_apply":False}


def compare_workload(previous, current, *, current_findings=None, current_engineering=None):
    from .optimization_worklist import optimization_worklist
    identity = snapshot_identity_checks(previous, current)
    prior_findings=profile_recommendations(previous)
    prior_engineering=advanced_analysis(previous)
    current_findings=profile_recommendations(current) if current_findings is None else current_findings
    current_engineering=advanced_analysis(current) if current_engineering is None else current_engineering
    before = workload(previous,findings=prior_findings,engineering=prior_engineering)
    after = workload(current, findings=current_findings, engineering=current_engineering)
    transitions=workload_transitions(optimization_worklist(previous,prior_findings,prior_engineering),
                                     optimization_worklist(current,current_findings,current_engineering))
    common = before["views"].keys() & after["views"].keys()
    same_reads = before["views"] == after["views"]
    same_devices = before["devices"] == after["devices"]
    return {"identity": identity, "before": before["counts"], "after": after["counts"],
            "before_devices": len(before["devices"]), "after_devices": len(after["devices"]),
            "before_views": len(before["views"]), "after_views": len(after["views"]),
            "common_views": len(common), "same_structured_read_states": same_reads,
            "same_device_selectors": same_devices, "mixed_time": before["mixed_time"] or after["mixed_time"],
            "transitions":transitions,"verified_removals": False}


def history_view(workspace, query):
    from .config_app import audit_files, read_audit
    from .central_tool import refresh_configuration_review
    loaded, empty = load(workspace, query, "Configuration assessment", "assessment")
    if empty:
        return empty
    root, name, bundle, picker = loaded
    others = [(p.name, p.name) for p in audit_files(workspace.directory) if p.name != name]
    previous = query.get("previous", "")
    confirmed = query.get("confirmed") == "yes"
    body = intro("Optimization workload history", "Compare observed review workloads between two captures, not verified configuration removals.", picker)
    body += f'<p><a href="{url(root, "assessment", snapshot=name)}">Return to optimization worklist</a></p>'
    body += (f'<section><form method="get" class="filter-bar" action="{e(root + "assessment")}">'
             f'<input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="mode" value="history">'
             + select("previous", [("", "Select baseline snapshot")] + others, previous, "Baseline")
             + '<label><input type="checkbox" name="confirmed" value="yes" required> Confirm same tenant</label>'
             + '<button type="submit">Compare workloads</button></form></section>')
    if previous and confirmed:
        if previous not in dict(others):
            raise ValueError("Invalid baseline")
        prior = refresh_configuration_review(read_audit(workspace.directory, previous))
        result = compare_workload(prior, bundle, current_findings=workspace.consolidation_snapshot(bundle),
                                  current_engineering=workspace.advanced_snapshot(bundle))
        body += metrics([("Baseline devices", result["before_devices"], "Device/function pairs"),
                         ("Current devices", result["after_devices"], "Device/function pairs"),
                         ("Common structured views", result["common_views"], "Same capture selectors")])
        body += '<section><h2>Comparability checks</h2>' + table(("Check", "Result"), [
            tr("Device selectors", "Same" if result["same_device_selectors"] else "Changed"),
            tr("Structured view selectors and read states", "Same" if result["same_structured_read_states"] else "Changed"),
            tr("Mixed-time checkpoint evidence", "Present" if result["mixed_time"] else "Not indicated")]) + '</section>'
        labels = {"remove_override": "Override review groups", "promote_local": "Repeated local profile groups",
                  "reuse_library": "Library reuse groups", "duplicates": "Duplicate Library groups",
                  "ports": "Repeated port groups", "preview_candidates": "Selectable consolidation previews"}
        rows = []
        for key, label in labels.items():
            old, new = result["before"][key], result["after"][key]
            rows.append(tr(e(label), str(old), str(new), f'{new-old:+d}'))
        body += '<section><h2>Observed workload change</h2>' + table(("Review category", "Baseline", "Current", "Count change"), rows) + '</section>'
        from .workspace_ui import badge,pretty,inspect,raw,module_label,persona_label
        from .history_view import private_export
        transitions=result["transitions"]
        body += '<section><h2>Individual worklist transitions</h2><p>Compare review descriptors by category, function, module and exact displayed profile. Multiple matching groups remain ambiguous. Identical descriptors do not establish identical configuration evidence or transfer review status.</p>'
        body += table(("Transition","Groups"),[tr(e(pretty(status)),str(count)) for status,count in sorted(transitions["counts"].items())])
        changes=[]
        for row in transitions["records"]:
            if row["status"]=="same_workload_descriptor":
                continue
            current_links=" ".join(f'<a href="{url(root,r["route"],snapshot=name,**r["params"])}">Current finding</a>' for r in row["after"])
            before_links=" ".join(f'<a href="{url(root,r["route"],snapshot=previous,**r["params"])}">Prior finding</a>' for r in row["before"])
            changes.append(tr(e(pretty(row["category"])),e(persona_label(row["persona"])),e(module_label(row["module"])),
                e(row["profile"]),badge(pretty(row["status"])),str(len(row["before"])),str(len(row["after"])),
                before_links+" "+current_links+" "+inspect("Workload transition",raw(row),"Evidence")))
        body += table(("Category","Function","Module","Profile","Transition","Prior groups","Current groups",""),changes,search=True)
        body += private_export("optimization-workload-history",result)+'</section>'
        body += '<p class="note">A lower workload count does not establish successful remediation. Group boundaries, inventory, evidence availability and analysis logic can affect counts. Use Configuration drift and Remediation verification for exact changes. Same structured read states do not establish complete evidence equivalence.</p>'
        body += f'<p><a href="{url(root, "drift", snapshot=name, previous=previous, confirmed="yes")}">Review exact configuration drift</a></p>'
    return page("Configuration assessment", body, workspace.nav(name))
