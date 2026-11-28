"""Local browser entry point and summary for an entire saved review plan."""
import json
from collections import Counter
from .workspace_ui import e, page, intro, metrics, table, tr, badge, pretty
from .workspace_views import url
from .history_view import private_export


def plan_form(workspace, root, snapshot):
    return (f'<section><h2>Verify an exported consolidation plan</h2>'
            '<p>Choose the original preview or reconstructed plan. Only its selection manifest is sent to the local workspace. The original capture must still match exactly; no deployment or rollback is executed.</p>'
            f'<form method="post" id="verify-exported-plan" action="{e(root + "verify-plan")}">'
            f'<input type="hidden" name="snapshot" value="{e(snapshot)}"><input type="hidden" name="csrf" value="{e(workspace.csrf)}">'
            '<input type="hidden" name="manifest"><div class="filter-bar">'
            '<label>Original private plan JSON<input id="verification-file" type="file" accept=".json,application/json" required></label>'
            '<label>Review purpose<select name="operation"><option value="verify">Verify observed outcome after manual changes</option><option value="revalidate">Revalidate captured plan before manual changes</option></select></label>'
            '<label><span><input type="checkbox" name="confirmed" value="yes" required> Both captures belong to the same tenant</span></label>'
            '<button type="submit">Verify entire plan</button></div><p id="verification-error" role="alert" hidden></p></form>'
            '<noscript><p>Use the offline plan_verification CLI if JavaScript is disabled.</p></noscript>'
            """<script>
(()=>{
const form=document.getElementById('verify-exported-plan');
const input=document.getElementById('verification-file');
const error=document.getElementById('verification-error');
const button=form.querySelector('button[type=submit]');
form.addEventListener('submit',async event=>{
 event.preventDefault();
 error.hidden=true;button.disabled=true;
 try{
  const file=input.files[0];
  if(!file||file.size>32*1024*1024)throw Error('Choose a private plan JSON no larger than 32 MB.');
  const data=JSON.parse(await file.text());
  const manifest=data&&data.selection_manifest;
  if(!manifest||manifest.kind!=='consolidation_selection')throw Error('The file has no original selection manifest.');
  form.elements.manifest.value=JSON.stringify(manifest);
  if(new URLSearchParams(new FormData(form)).toString().length>24576)throw Error('Selection exceeds the local form limit; use the offline CLI.');
  form.submit();
 }catch(exc){
  error.textContent='Unable to read the original selection manifest. Check the JSON file and size, or use the offline CLI.';
  error.hidden=false;button.disabled=false;
 }
});
})();
</script></section>""")


def plan_result(workspace, report):
    root = "/" + workspace.token + "/"
    name = report["after_snapshot"]
    before = report["selection_manifest"]["snapshot"]
    body = intro("Remediation verification", "Entire exported plan: observed before/after evidence.", "")
    body += metrics([("Reviewed proposals", len(report["reports"]), "Original validated selection"),
                     ("Workflows", len(report["proposal_counts"]), "Distinct proposal actions"),
                     ("Deployment qualification", "Not established", "Capture comparison only")])
    body += '<section><h2>Plan verification results</h2><p>Each proposal is checked independently. Collateral changes can include other selected proposals; counts must not be summed as unique impact.</p>'
    listing = []
    for item in report["reports"]:
        detail = item["report"]
        action = item["action"]
        candidate = detail["candidate"]
        states = Counter(row["status"] for row in detail["rows"])
        source_states = Counter(row["status"] for row in detail.get("source_rows", []))
        summary = "<br>".join(e(pretty(key)) + ": " + str(n) for key,n in sorted(states.items())) or "No recipient observations"
        cleanup = "<br>".join(e(pretty(key)) + ": " + str(n) for key,n in sorted(source_states.items())) or "See recipient evidence"
        args = ["override", item["id"]] if action == "remove_override" else ["promotion", item["id"], detail["destination"]]
        href = url(root, "remediation", snapshot=name, previous=before, confirmed="yes", candidate=json.dumps(args))
        destination = ("Observed" if detail.get("destination_and_assignments_observed") else "Unverified") if action != "remove_override" else "Not applicable"
        listing.append(tr(e(pretty(action)), e(candidate["module"]), e(candidate["identity"]), e(candidate["persona"]),
                          summary, cleanup, e(destination), str(len(detail["collateral"]["records"])),
                          f'<a href="{href}">Reopen individual verification</a>'))
    body += table(("Action","Module","Profile","Function","Recipient outcomes","Source cleanup","Destination evidence","Collateral observations","Evidence"),listing,search=True)
    body += '</section><section><h2>Combined collateral review</h2><p>Each affected module is compared outside all exact profile/device pairs already covered by the selected proposals. These counts are not the sum of the individual collateral reports.</p>'
    body += table(("Module","Proposals","Device/function pairs","Count-confirmed unchanged","Unverified views","Unverified device identities","Other observations"),[
        tr(e(item["module"]),str(item["proposal_count"]),str(item["counts"].get("device_function_pairs",0)),
           str(item["counts"].get("unchanged_count_confirmed_pairs",0)),str(item["counts"].get("unverified_view_pairs",0)),
           str(item["counts"].get("unverified_device_pairs",0)),str(len(item["records"])))
        for item in report.get("combined_collateral",[])])
    body += '<p>Full combined collateral observations are in the private export.</p>'
    body += '<p class="note">Original and newer captures were bound during verification. Reopening a proposal recalculates evidence from the currently saved snapshots.</p>'
    body += private_export("private_plan_verification", report) + '</section>'
    body += f'<p><a href="{url(root,"remediation",snapshot=name)}">Return to remediation verification</a></p>'
    return page("Remediation verification",body,workspace.nav(name))


def preflight_result(workspace, report):
    root = "/" + workspace.token + "/"
    name = report["current_snapshot"]
    body = intro("Remediation verification", "Captured-plan revalidation before manual changes.", "")
    body += metrics([("Selected proposals", len(report["rows"]), "Original review manifest"),
                     ("Exact observed evidence retained", sum(r["status"] == "observed_evidence_unchanged" for r in report["rows"]), "Not deployment qualification"),
                     ("Combined review evidence", "Unchanged" if report["observed_review_matches"] else "Review required", "No authorization to apply")])
    body += '<section><h2>Captured plan revalidation results</h2><p>Any changed, missing or contradictory captured evidence requires a new review. Matching evidence does not establish freshness at the live API, complete dependencies, permissions, rollback, or actual deployment behavior.</p>'
    body += table(("Action","Module","Profile","Function","Outcome","Reasons"),[
        tr(e(pretty(r["action"])),e(r["module"]),e(r["identity"]),e(r["persona"]),badge(pretty(r["status"])),
           "<br>".join(e(pretty(reason)) for reason in r["reasons"]) or "No observed differences")
        for r in report["rows"]],search=True)
    if report["combined_reasons"]:
        body += '<h3>Combined review blockers</h3><p>' + e(", ".join(pretty(r) for r in report["combined_reasons"])) + '</p>'
    body += private_export("private_plan_preflight",report) + '</section>'
    body += f'<p><a href="{url(root,"remediation",snapshot=name)}">Return to remediation verification</a></p>'
    return page("Remediation verification",body,workspace.nav(name))
