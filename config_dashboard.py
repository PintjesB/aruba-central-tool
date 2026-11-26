"""Standalone, offline configuration review dashboard."""
import json
from collections import Counter
from html import escape


LABELS = {
    "local_differs_from_global": "Differs from Global",
    "local_matches_global": "Matches Global",
    "local_without_global_match": "Local only",
    "device_local_profile": "Device local",
    "global_local_profile": "Global local",
    "global_reference_unverified": "Global reference unknown",
    "local_effective_mismatch": "Local/effective mismatch",
    "source_conflict": "Source conflict",
    "effective_source_unverified": "Source unknown",
    "effective_only_unverified": "Effective only",
    "scope_unqualified": "Scope unqualified",
    "no_profiles_observed": "No profiles observed",
    "inherited": "Inherited",
    "shared": "Library assigned",
    "default_profile": "Default",
}

LOCAL = {"local_differs_from_global", "local_matches_global", "local_without_global_match",
         "device_local_profile", "global_local_profile", "global_reference_unverified",
         "local_effective_mismatch"}
REVIEW = {"scope_unqualified", "effective_only_unverified", "source_conflict",
          "effective_source_unverified", "global_reference_unverified",
          "local_effective_mismatch", "local_differs_from_global", "local_without_global_match"}


def e(value):
    return escape(str(value), quote=True)


def dump(value):
    return e(json.dumps(value, indent=2, ensure_ascii=False))


def option_list(values, labels=None):
    return '<option value="">All</option>' + "".join(
        f'<option value="{e(v)}">{e((labels or {}).get(v, v))}</option>'
        for v in sorted(set(values)))


def difference_table(fields):
    if fields is None:
        return '<p class="muted">No verified comparison reference.</p>'
    if not fields:
        return '<p class="muted">Exact captured bodies match.</p>'
    def value(d, key):
        return f'<code>{dump(d[key])}</code>' if key in d else '<em class="muted">Absent</em>'
    rows = []
    for d in fields:
        path = ".".join(map(str, d["path"])) or "(root)"
        rows.append(f'<tr><td>{e(path)}</td><td>{value(d, "reference_value")}</td>'
                    f'<td>{value(d, "local_value")}</td><td>{e(d["kind"].replace("_", " "))}</td></tr>')
    return ('<div class="diff-wrap"><table class="diff"><thead><tr><th>Setting</th><th>Global reference</th>'
            '<th>Local value</th><th>Difference</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>')


def render_dashboard(bundle, records, shape):
    rows = []
    counts = Counter()
    qualified = sum(scope["review"]["qualified"] for _, _, _, scope in records)
    for persona, module, name, scope in records:
        review = scope["review"]
        profiles = review["profiles"]
        if not review["qualified"] or not profiles:
            profiles = [{"identity": "", "status": "scope_unqualified" if not review["qualified"]
                         else "no_profiles_observed", "local": None, "effective": None,
                         "global_reference": None, "global_differences": None, "annotations": {}}]
            if not review["qualified"] and scope["effective_view"].get("status") == "list_parsed":
                for key, raw in scope["effective_view"].get("profiles", {}).items():
                    profiles.append({"identity": key, "status": "effective_only_unverified",
                                     "local": None, "effective": {k: v for k, v in raw.items() if k != "@"},
                                     "global_reference": None, "global_differences": None,
                                     "annotations": raw.get("@", {})})
        for row in profiles:
            status = row["status"]
            counts[status] += 1
            fields = row.get("global_differences")
            diff_count = "Not comparable" if fields is None else str(len(fields))
            body = {k: row[k] for k in ("local", "effective", "global_reference",
                                        "global_differences", "annotations")}
            if status == "scope_unqualified":
                body = {"local_shape": shape(scope["local_view"]),
                        "effective_shape": shape(scope["effective_view"]),
                        "local_status": review["local_status"], "effective_status": review["effective_status"]}
            tone = ("warning" if status in REVIEW else "positive" if status in
                    {"inherited", "shared", "local_matches_global"} else "neutral")
            attrs = {"persona": persona, "module": module, "scope": scope["scope_kind"],
                     "name": name, "status": status, "local": "yes" if status in LOCAL else "no",
                     "review": "yes" if status in REVIEW else "no"}
            attributes = " ".join(f'data-{k}="{e(v)}"' for k, v in attrs.items())
            cells = (persona, module, scope["scope_kind"], name, row["identity"] or "—")
            cells_html = "".join(f"<td>{e(v)}</td>" for v in cells)
            details = (difference_table(fields) +
                       '<div class="evidence-grid">' +
                       "".join(f'<section><h4>{label}</h4><pre>{dump(body.get(key))}</pre></section>'
                               for key, label in (("local", "Local"), ("effective", "Effective"),
                                                  ("global_reference", "Global reference")))
                       + '</div>' if status != "scope_unqualified" else
                       '<p class="muted">These views are not sufficiently validated to classify the scope.</p>')
            rows.append(f'<tr class="finding" {attributes}>' + cells_html +
                        f'<td><span class="status {tone}">{e(LABELS.get(status, status))}</span></td>'
                        f'<td class="numeric">{e(diff_count)}</td>'
                        f'<td><button class="inspect" type="button">Inspect</button>'
                        f'<template><div class="detail-title"><h2>{e(module)} · {e(row["identity"] or name)}</h2>'
                        f'<p>{e(persona)} / {e(scope["scope_kind"])} / {e(name)} · {e(LABELS.get(status, status))}</p></div>'
                        + details + f'<details><summary>Raw evidence and source annotations</summary><pre>{dump(body)}</pre></details>'
                        '</template></td></tr>')
    selectors = [
        ("persona", "Device function", [p for p, _, _, _ in records], None),
        ("module", "Module", [m for _, m, _, _ in records], None),
        ("scope", "Scope type", [s["scope_kind"] for _, _, _, s in records], None),
        ("name", "Scope / device", [n for _, _, n, _ in records], None),
        ("status", "Finding", list(counts), LABELS),
    ]
    filters = "".join(f'<label>{label}<select id="{key}">{option_list(values, labels)}</select></label>'
                      for key, label, values, labels in selectors)
    metrics = [
        ("all", "Qualified module scopes", f"{qualified}/{len(records)}", "Coverage of captured scope views"),
        ("local", "Local profiles", sum(counts[s] for s in LOCAL), "Includes device-specific configuration"),
        ("different", "Global differences", counts["local_differs_from_global"], "Exact configuration comparisons"),
        ("review", "Needs review", sum(counts[s] for s in REVIEW), "Includes unqualified evidence"),
    ]
    cards = "".join(f'<button class="metric" data-quick="{k}"><span>{e(title)}</span>'
                    f'<strong>{e(number)}</strong><small>{e(note)}</small></button>'
                    for k, title, number, note in metrics)
    return HEAD + f'<p class="captured">Captured {e(bundle.get("captured_at", "unknown"))} · Qualified module scopes: {qualified}/{len(records)}</p>' + (
        '<section class="metrics" aria-label="Overview">' + cards + '</section>'
        '<section class="workspace"><div class="section-head"><div><h2>Configuration explorer</h2>'
        '<p class="muted">Filter by scope, profile type and observed configuration source.</p></div>'
        '<button id="export">Export filtered summary CSV</button></div>'
        '<div class="quick"><button data-quick="all" class="selected">All findings</button>'
        '<button data-quick="local">Local profiles</button><button data-quick="different">Global differences</button>'
        '<button data-quick="review">Needs review</button><button data-quick="unqualified">Unqualified scopes</button></div>'
        '<div class="filters">' + filters +
        '<label class="search">Search<input id="query" type="search" placeholder="Scope, profile, status or setting"></label>'
        '<button id="reset">Reset filters</button></div>'
        '<div class="table-bar"><span id="count" aria-live="polite"></span><label>Rows per page '
        '<select id="page-size"><option>25</option><option selected>50</option><option>100</option></select></label></div>'
        '<div class="table-wrap"><table id="findings"><thead><tr>' +
        "".join(f'<th><button data-sort="{i}">{label}</button></th>'
                for i, label in enumerate(("Function", "Module", "Scope type", "Scope / device", "Profile",
                                           "Finding", "Fields"))) +
        '<th>Evidence</th></tr></thead><tbody>' + "".join(rows) +
        '</tbody></table><p id="empty" hidden>No findings match your filters.</p></div>'
        '<div class="pager"><button id="prev">Previous</button><span id="page"></span><button id="next">Next</button></div></section>'
        + TAIL)


HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Central Configuration Explorer</title><style>
:root{color-scheme:light;--bg:#f3f6fa;--surface:#fff;--text:#17253b;--muted:#64748b;--line:#dbe3ed;--accent:#1365bf;--soft:#eaf2fc;--green:#176847;--green-bg:#e5f5eb;--warn:#8a4b08;--warn-bg:#fff0d7;--shadow:0 3px 14px #142a4610}
:root[data-theme=dark]{color-scheme:dark;--bg:#101a2a;--surface:#182538;--text:#e7edf8;--muted:#a1b0c5;--line:#33445d;--accent:#8dc2ff;--soft:#223b5c;--green:#8cdbb2;--green-bg:#173f36;--warn:#ffd08a;--warn-bg:#503821;--shadow:none}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:#18304c;color:#fff;padding:20px max(24px,calc((100vw - 1500px)/2));display:flex;justify-content:space-between;align-items:center;gap:20px}
header h1{font-size:22px;margin:0;letter-spacing:-.5px}header p{margin:3px 0 0;color:#c7d6ea}
header button{background:#274666;color:#fff;border-color:#456580}main{max-width:1500px;margin:auto;padding:24px}
.captured,.muted{color:var(--muted);margin:0 0 12px}.notice{border-left:4px solid var(--accent);background:var(--surface);padding:12px 16px;border-radius:6px;margin-bottom:18px}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:18px 0}
button,select,input{font:inherit;color:var(--text)}button{background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:8px 12px;cursor:pointer}
button:hover{border-color:var(--accent)}button:focus-visible,select:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
button:disabled{opacity:.45;cursor:default}.metric{text-align:left;padding:18px;box-shadow:var(--shadow);display:grid;gap:7px;border-top:3px solid var(--accent)}
.metric span{color:var(--muted);font-weight:600}.metric strong{font-size:28px;line-height:1.2;font-variant-numeric:tabular-nums}.metric small{color:var(--muted);font-size:12px}
.workspace{background:var(--surface);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow);overflow:hidden}
.section-head{display:flex;justify-content:space-between;align-items:center;padding:20px;gap:12px}h2{margin:0 0 4px;font-size:19px}h4{margin:0 0 6px;font-size:13px}
.quick{display:flex;flex-wrap:wrap;gap:7px;padding:0 20px 16px}.selected{background:var(--soft);border-color:var(--accent);color:var(--accent);font-weight:600}
.filters{display:flex;flex-wrap:wrap;gap:12px;padding:16px 20px;background:var(--bg);border-block:1px solid var(--line);align-items:end}
label{display:grid;gap:5px;font-size:12px;font-weight:600;color:var(--muted)}select,input{padding:8px;border:1px solid var(--line);border-radius:6px;background:var(--surface);min-width:110px;max-width:260px}
.search{flex:1;min-width:180px}.search input{max-width:none;width:100%}.table-bar,.pager{display:flex;align-items:center;justify-content:space-between;padding:12px 20px;gap:12px}.table-bar label{display:flex;align-items:center}
.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left}th{background:var(--bg);color:var(--muted);white-space:nowrap;font-size:12px}
th,td{padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}th button{padding:0;border:0;background:none;color:inherit;font-size:inherit;font-weight:650}th button:hover{color:var(--accent)}
tr.finding:hover{background:var(--soft)}td{overflow-wrap:anywhere}.numeric{font-variant-numeric:tabular-nums}.status{display:inline-block;font-size:12px;font-weight:600;padding:4px 8px;border-radius:5px}
.positive{background:var(--green-bg);color:var(--green)}.warning{background:var(--warn-bg);color:var(--warn)}.neutral{background:var(--soft);color:var(--accent)}
.inspect{padding:4px 10px;color:var(--accent)}[hidden]{display:none!important}#empty{padding:24px;color:var(--muted)}
dialog{background:var(--surface);color:var(--text);border:1px solid var(--line);border-radius:12px;width:min(1200px,94vw);max-height:90vh;padding:24px;box-shadow:0 15px 70px #0005}dialog::backdrop{background:#08162799}
.dialog-head{display:flex;justify-content:flex-end;position:sticky;top:0;z-index:1;background:var(--surface)}.detail-title p{color:var(--muted);margin:0 0 20px}
.evidence-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:16px 0}
pre,code{font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}pre{background:var(--bg);border:1px solid var(--line);padding:12px;border-radius:6px;max-height:400px;overflow:auto;margin:0}
.diff-wrap{overflow:auto}.diff th,.diff td{padding:9px;border:1px solid var(--line)}summary{cursor:pointer;margin:12px 0;color:var(--accent)}
@media(max-width:900px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.evidence-grid{grid-template-columns:1fr}main{padding:14px}.section-head{align-items:start;flex-wrap:wrap}}
@media(max-width:500px){.metrics{grid-template-columns:1fr}header{padding:14px}.filters select{max-width:100%}}
</style></head><body><header><div><h1>Central Configuration Explorer</h1><p>Hierarchy · overrides · configuration evidence</p></div><button id="theme">Dark mode</button></header><main>
<div class="notice"><strong>Confidential · offline · read-only</strong><br>Global comparisons do not prove inheritance or migration safety. Unqualified scopes are not empty scopes. Keep this report and exported files private.</div>
"""


TAIL = r"""</main><dialog id="detail"><div class="dialog-head"><button id="close">Close</button></div><div id="detail-body"></div></dialog>
<script>
'use strict';
const $=id=>document.getElementById(id);
const table=$('findings'), tbody=table.tBodies[0];
const rows=Array.from(tbody.querySelectorAll('.finding'));
const keys=['persona','module','scope','name','status'];
const searchable=new Map(rows.map(row=>[row,(Array.from(row.cells).slice(0,7).map(c=>c.textContent).join(' ')+' '+row.querySelector('template').content.textContent).toLowerCase()]));
let quick='all', page=0, sort=0, ascending=true, filtered=[];
const collator=new Intl.Collator(undefined,{numeric:true,sensitivity:'base'});
function matchQuick(r){
  if(quick==='local')return r.dataset.local==='yes';
  if(quick==='review')return r.dataset.review==='yes';
  if(quick==='different')return r.dataset.status==='local_differs_from_global';
  if(quick==='unqualified')return r.dataset.status==='scope_unqualified';
  return true;
}
function update(reset=false){
  if(reset)page=0;
  const q=$('query').value.trim().toLowerCase();
  filtered=rows.filter(r=>matchQuick(r)&&keys.every(k=>!$(k).value||r.dataset[k]===$(k).value)&&searchable.get(r).includes(q));
  filtered.sort((a,b)=>(ascending?1:-1)*collator.compare(a.cells[sort].textContent,b.cells[sort].textContent));
  const size=Number($('page-size').value), pages=Math.max(1,Math.ceil(filtered.length/size));
  page=Math.max(0,Math.min(page,pages-1));
  const visible=filtered.slice(page*size,(page+1)*size);
  for(const r of rows)r.hidden=true;
  for(const r of visible){r.hidden=false;tbody.appendChild(r);}
  $('count').textContent=filtered.length.toLocaleString()+' of '+rows.length.toLocaleString()+' findings';
  $('page').textContent='Page '+(page+1)+' of '+pages;
  $('prev').disabled=page===0;$('next').disabled=page>=pages-1;
  $('empty').hidden=filtered.length!==0;
  for(const b of document.querySelectorAll('[data-quick]'))b.classList.toggle('selected',b.dataset.quick===quick);
  for(const b of table.querySelectorAll('[data-sort]')){
    b.parentElement.removeAttribute('aria-sort');
    if(Number(b.dataset.sort)===sort)b.parentElement.setAttribute('aria-sort',ascending?'ascending':'descending');
  }
}
for(const b of document.querySelectorAll('[data-quick]'))b.addEventListener('click',()=>{quick=b.dataset.quick;update(true);});
for(const k of keys)$(k).addEventListener('change',()=>update(true));
$('query').addEventListener('input',()=>update(true));
$('page-size').addEventListener('change',()=>update(true));
$('reset').addEventListener('click',()=>{for(const k of keys)$(k).value='';$('query').value='';quick='all';update(true);});
$('prev').addEventListener('click',()=>{page--;update();});
$('next').addEventListener('click',()=>{page++;update();});
for(const b of table.querySelectorAll('[data-sort]'))b.addEventListener('click',()=>{
  const n=Number(b.dataset.sort);ascending=n===sort?!ascending:true;sort=n;update(true);
});
tbody.addEventListener('click',event=>{
  const b=event.target.closest('.inspect');if(!b)return;
  $('detail-body').replaceChildren(b.parentElement.querySelector('template').content.cloneNode(true));
  $('detail').showModal();
});
$('close').addEventListener('click',()=>$('detail').close());
$('theme').addEventListener('click',()=>{
  const dark=document.documentElement.dataset.theme!=='dark';
  document.documentElement.dataset.theme=dark?'dark':'light';$('theme').textContent=dark?'Light mode':'Dark mode';
});
function csvCell(value){
  let s=String(value);
  if(/^[\s]*[=+\-@]/.test(s)||/^[\t\r\n]/.test(s))s="'"+s;
  return '"'+s.replace(/"/g,'""')+'"';
}
$('export').addEventListener('click',()=>{
  const header=['Function','Module','Scope type','Scope','Profile','Finding','Global differences'];
  const csv=[header,...filtered.map(row=>Array.from(row.cells).slice(0,7).map(c=>c.textContent))].map(r=>r.map(csvCell).join(',')).join('\r\n');
  const url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));
  const a=document.createElement('a');a.href=url;a.download='central-config-summary.csv';a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
});
update();
</script></body></html>"""
