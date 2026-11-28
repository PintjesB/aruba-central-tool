"""Exact profile evidence for captured-plan revalidation."""
from .central_tool import canonical, profile_body, health_serial
from .inheritance_review import ATOMIC


def profile_evidence(bundle, persona, module, identity, library_destination):
    """Preserve exact body, read qualification and source evidence.

    Include all same-function scopes, and observed other functions for a
    Library destination. Atomic modules require comparison of all identities.
    This does not infer applicability for an uncollected function.
    """
    result = {}
    direct = (bundle.get("keyed_profile_details") or {}).get("profiles", {})
    def observe(function, sid, side, view):
        profiles = view.get("profiles", {}) if view.get("status") == "list_parsed" else {}
        reads = direct.get(function, {}).get(str(sid), {}).get(module, {})
        ids = set(profiles) | set(reads) if module in ATOMIC and function != "Library" else {identity}
        selected = {}
        for key in sorted(ids):
            body = profiles.get(key)
            read = reads.get(key, {}).get(side, {})
            evidence = {"collection": {"body":profile_body(body), "annotations":body.get("@")} if isinstance(body,dict) else None,
                        "individual_status":read.get("status","not_collected")}
            if read.get("status") == "identity_observed" and isinstance(read.get("profile"),dict):
                evidence["individual_body"] = profile_body(read["profile"])
                evidence["individual_annotations"] = read.get("annotations")
            selected[key] = evidence
        return {"read_status":view.get("status","not_collected"),
                "count_confirmed":view.get("count_confirmed") is True,
                "profiles":selected}
    for function, entry in sorted(bundle["results"].items()):
        if function != persona and (not library_destination or module not in entry.get("modules",{})):
            continue
        views = {}
        for row in entry.get("modules",{}).get(module,{}).get("scope_results",[]):
            views.setdefault(str(row["scope"]),row)
        for scope in entry.get("scopes",[]):
            sid = str(scope["id"])
            row = views.get(sid,{})
            result[function,sid,"scope"] = {"kind":scope["kind"], "serial":health_serial(scope.get("metadata")) if scope["kind"]=="device" else None}
            for side in ("local","effective"):
                result[function,sid,side] = observe(function,sid,side,row.get(side+"_view",{}))
    if library_destination:
        result["Library","","library"] = observe("Library","","library",(bundle.get("library") or {}).get("modules",{}).get(module,{}))
    return result


def compare_profile_evidence(before,after,persona,module,identity,library_destination):
    a = profile_evidence(before,persona,module,identity,library_destination)
    b = profile_evidence(after,persona,module,identity,library_destination)
    changes = []
    for function,sid,side in sorted(a.keys()|b.keys()):
        old,new = a.get((function,sid,side)),b.get((function,sid,side))
        if canonical(old) != canonical(new):
            changes.append({"persona":function,"scope":sid,"view":side,"before":old,"after":new})
    return changes
