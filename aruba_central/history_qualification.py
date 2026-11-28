"""Anonymous performance and evidence counts for two private saved captures."""
from collections import Counter
from statistics import median
from time import perf_counter
from .config_app import Workspace


def history_qualification(directory, snapshot, previous, *, repeat=3):
    if type(repeat) is not int or not 1 <= repeat <= 5 or previous == snapshot:
        raise ValueError("Invalid history qualification")
    stages = {}
    counts = None
    for _ in range(repeat):
        workspace = Workspace(directory)
        bundle = workspace.reviewed_snapshot(snapshot)
        def measure(label, fn):
            start = perf_counter()
            result = fn()
            stages.setdefault(label,[]).append(perf_counter()-start)
            return result
        report,binding = measure("cold_comparison",lambda:workspace.drift_snapshot(snapshot,bundle,previous))
        cached,cached_binding = measure("warm_comparison",lambda:workspace.drift_snapshot(snapshot,bundle,previous))
        if cached is not report or binding != cached_binding:
            raise ValueError("History comparison cache mismatch")
        query={"snapshot":snapshot,"previous":previous,"confirmed":"yes"}
        overview=measure("overview_render",lambda:workspace.drift(query))
        current={"structured_records":len(report["records"]),"profile_groups":len(report["profile_change_groups"]),
                 "structured_counts":report["counts"],"structured_unavailable_reasons":report["unavailable_reasons"],
                 "additional_counts":report["additional_evidence"]["counts"],
                 "additional_noncomparable_reasons":report["additional_evidence"]["noncomparable_reasons"],
                 "additional_record_count":len(report["additional_evidence"]["records"]),
                 "overview_bytes":len(overview.encode("utf-8"))}
        for kind,records in (("group",report["profile_change_groups"]),("record",report["records"]),
                             ("additional",report["additional_evidence"]["records"])):
            if records:
                detail=measure(kind+"_inspector_render",lambda:workspace.drift({**query,"binding":binding,"detail":kind,"index":"0"}))
                current[kind+"_inspector_bytes"]=len(detail.encode("utf-8"))
        # No raw names, IDs, values, snapshot filenames or file fingerprints.
        if counts is not None and counts != current:
            raise ValueError("History comparison counts changed during qualification")
        counts=current
        final,final_binding=workspace.drift_snapshot(snapshot,bundle,previous)
        if final is not report or final_binding != binding:
            raise ValueError("History captures changed during qualification")
        del workspace,bundle,report,cached,final,overview
    return {"schema":1,"kind":"anonymous_history_qualification","repeat":repeat,"counts":counts,
            "stages":{key:{"samples_seconds":values,"median_seconds":median(values)} for key,values in stages.items()},
            "central_api_requests":0,"complete":False,"safe_to_apply":False}
