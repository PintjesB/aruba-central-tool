"""Private worklist for exact profile identity collisions."""
from .identity_review import identity_collisions
from .workspace_views import load,url,select
from .workspace_ui import e,page,intro,metrics,table,tr,badge,raw,pretty,persona_label,module_label
from .review_dispositions import snapshot_binding
from .history_view import private_export


def identity_view(workspace,query):
    loaded,empty=load(workspace,query,"Profile identities","assessment")
    if empty:
        return empty
    root,name,bundle,picker=loaded
    rows=identity_collisions(bundle)
    binding=snapshot_binding(workspace,name,bundle)
    common={"snapshot":name,"mode":"identities"}
    if query.get("detail") or query.get("export"):
        if query.get("binding")!=binding:
            raise ValueError("Snapshot changed; reopen identity review")
        if query.get("export")=="1":
            return page("Profile identities",intro("Private identity report","Exact observed names and bodies. Keep private.",picker)+private_export("identity-collisions",rows),workspace.nav(name))
        try:
            i=int(query["detail"])
        except (ValueError,KeyError):
            raise ValueError("Invalid identity selector") from None
        if not 0<=i<len(rows):
            raise ValueError("Unknown identity group")
        row=rows[i]
        details='<p>Distinct exact names are not aliases. No case or whitespace normalization is applied.</p>'+table(("Function","Scope","View","Exact name","Captured evidence"),[
            tr(e(persona_label(r["persona"])),e(r["scope_name"]),e(pretty(r["view"])),e(r["identity"]),raw(r["observations"])) for r in row["observations"]],search=True)
        return '<template data-advisor-evidence><div class="inspector-title"><h2>'+e(module_label(row["module"]))+'</h2></div>'+details+'</template>'
    module=query.get("module","")
    state=query.get("state","all")
    if state not in ("all","same_context","separate_context"):
        raise ValueError("Invalid identity context")
    selected=[(i,r) for i,r in enumerate(rows) if (not module or r["module"]==module) and
              (state=="all" or bool(r["same_context_collisions"])==(state=="same_context"))]
    body=intro("Profile identity review","Find distinct captured names that differ only in case or surrounding whitespace. Same-context collisions are distinguished from similar names across unrelated scopes.",picker)
    body+=metrics([("Identity groups",len(rows),"Exact names retained"),("Same-context groups",sum(r["same_context_collisions"]>0 for r in rows),"At least two names in one selector")])
    body+=(f'<form class="filter-bar" action="{e(root+"assessment")}" method="get">'
           f'<input type="hidden" name="snapshot" value="{e(name)}"><input type="hidden" name="mode" value="identities">'
           +select("module",[("","All modules")]+[(m,module_label(m)) for m in sorted({r["module"] for r in rows})],module,"Module")
           +select("state",[("all","All groups"),("same_context","Same context"),("separate_context","Separate contexts only")],state,"Context")
           +'<button type="submit">Filter</button></form>')
    body+=table(("Module","Exact names","Relationship","Contexts","Same-context collisions",""),[
        tr(e(module_label(r["module"])),e(" / ".join(r["identities"])),badge(pretty(r["relationship"])),str(r["context_count"]),str(r["same_context_collisions"]),
           f'<button class="quiet inspect-trigger" data-inspect data-inspect-url="{url(root,"assessment",**common,detail=i,binding=binding)}">Inspect</button>') for i,r in selected],search=True)
    body+=f'<p><a href="{url(root,"assessment",**common,export="1",binding=binding)}">Export private identity evidence</a></p>'
    return page("Profile identities",body,workspace.nav(name))
