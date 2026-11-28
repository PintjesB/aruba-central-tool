"""Inspect similar exact names without ever normalizing configuration identity."""
from collections import defaultdict
from .central_tool import CONFIG_MODULES, observed_profile_candidates, profile_body, canonical


def identity_collisions(bundle):
    keys = {m: spec[0] for m,spec in CONFIG_MODULES.items()}
    keys["role-gpids"] = "name"
    names = {(p,str(s["id"])):s.get("name") or str(s["id"])
             for p,entry in bundle.get("results",{}).items() for s in entry.get("scopes",[])}
    groups = defaultdict(dict)
    def add(persona,sid,module,side,view,origin):
        key = keys.get(module)
        if key is None:
            return
        for identity,body in observed_profile_candidates(view,key).items():
            if not isinstance(body,dict) or not isinstance(body.get(key),str) or body[key] != identity:
                continue
            folded = identity.strip().casefold()
            if not folded:
                continue
            signature = (persona,str(sid),side,identity)
            bucket = groups[module,folded]
            row = bucket.setdefault(signature,{"persona":persona,"scope":str(sid),"scope_name":names.get((persona,str(sid)),str(sid) or persona),
                "view":side,"identity":identity,"observations":[]})
            row["observations"].append({"origin":origin,"status":view.get("status"),"body":profile_body(body)})
    for persona,entry in sorted(bundle.get("results",{}).items()):
        for module,data in sorted(entry.get("modules",{}).items()):
            for row in data.get("scope_results",[]):
                for side in ("local","effective"):
                    add(persona,row["scope"],module,side,row.get(side+"_view",{}),"structured")
    for module,view in sorted((bundle.get("library") or {}).get("modules",{}).items()):
        add("Library","",module,"library",view,"structured")
    for module,entry in sorted((bundle.get("unadapted_profiles") or {}).items()):
        for row in entry.get("source_views",[]):
            for field,side in (("committed","local"),("effective","effective")):
                add(row["persona"],row["scope"],module,side,row.get(field,{}),"supplemental")
        if isinstance(entry.get("library"),dict):
            add("Library","",module,"library",entry["library"],"supplemental")
    results = []
    for (module,_),rows in sorted(groups.items()):
        identities=sorted({row["identity"] for row in rows.values()})
        if len(identities)<2:
            continue
        contexts=defaultdict(set)
        for row in rows.values():
            contexts[row["persona"],row["scope"],row["view"]].add(row["identity"])
        same_context=sum(len(values)>1 for values in contexts.values())
        results.append({"module":module,"identities":identities,"observations":list(rows.values()),
                        "same_context_collisions":same_context,"context_count":len(contexts),
                        "relationship":"case_only" if len({i.casefold() for i in identities})==1 else "case_or_whitespace",
                        "safe_to_apply":False})
    return sorted(results,key=lambda r:(-r["same_context_collisions"],r["module"],r["identities"]))
