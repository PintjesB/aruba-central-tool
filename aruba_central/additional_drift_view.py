"""Bounded historical worklist for evidence outside structured profile drift."""
from .workspace_ui import e, metrics, table, tr, badge, pretty, inspect, module_label, persona_label
from .workspace_views import url, select


def additional_drift_panel(report, root, name, previous, query, *, binding):
    from .history_view import drift_control
    families = {"": "All evidence", "supplemental": "Supplemental responses",
                "individual": "Individual profile reads", "nac_configuration": "NAC configuration"}
    family = query.get("additional_family","")
    if family not in families:
        raise ValueError("Unknown additional evidence filter")
    try:
        offset = int(query.get("additional_offset","0"))
    except (TypeError,ValueError):
        raise ValueError("Invalid additional evidence page") from None
    records = [(i,r) for i,r in enumerate(report["records"]) if not family or r["family"] == family]
    common = {"snapshot":name,"previous":previous,"confirmed":"yes","binding":binding}
    if offset < 0 or offset % 50 or (offset and offset >= len(records)):
        raise ValueError("Invalid additional evidence page")
    body = '<section id="additional-drift"><h2>Additional configuration evidence</h2>'
    body += '<p>Supplemental responses, individual reads and NAC configuration are compared separately from structured profile drift. Raw response differences can include metadata or order. Missing, sampled or ambiguous selectors do not establish profile removal.</p>'
    body += table(("Evidence","Exact selectors","Exact matches","Not comparable","Changed responses","Other counts"),[
        tr(e(families.get(f,f)),str(c.get("selectors",0)),str(c.get("exact_match",0)),str(c.get("not_comparable",0)),
           str(c.get("response_changed",0)),e(", ".join(pretty(k)+": "+str(n) for k,n in sorted(c.items()) if k not in ("selectors","exact_match","not_comparable","response_changed"))))
        for f,c in report["counts"].items()])
    body += (f'<form class="filter-bar" method="get" action="{e(root+"drift")}#additional-drift">'
             f'<input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="previous" value="{e(previous)}"><input type="hidden" name="confirmed" value="yes">'
             +select("additional_family",list(families.items()),family,"Evidence source")+'<button type="submit">Filter observations</button></form>')
    listing = [tr(e(families[r["family"]]),e(persona_label(r["persona"])),e(r["scope_name"]),e(module_label(r["module"])),
                  e(pretty(r["view"])),e(r["identity"] or "Response"),badge(pretty(r["status"])),
                  drift_control(root,common,"additional",i,"Compare")) for i,r in records[offset:offset+50]]
    body += table(("Evidence","Function","Scope","Module","View","Profile","Observation",""),listing)
    if records:
        body += '<p>Showing '+str(offset+1)+'–'+str(min(offset+50,len(records)))+' of '+str(len(records))+' observations. Complete evidence is in the private drift export.</p>'
    else:
        body += '<p>No changed or newly unqualified observations for this source. Check the coverage counts above.</p>'
    for label,next_offset in (("Previous",offset-50),("Next",offset+50)):
        if 0 <= next_offset < len(records):
            body += f'<a class="button" href="{url(root,"drift",snapshot=name,previous=previous,confirmed="yes",additional_family=family,additional_offset=next_offset)}#additional-drift">{label}</a> '
    return body+'</section>'
