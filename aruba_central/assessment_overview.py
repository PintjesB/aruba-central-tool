"""Summarize local review workload without treating review status as safety."""
from collections import Counter
from .workspace_ui import e, icon
from .workspace_views import url


def review_overview(records):
    states = Counter()
    categories = {}
    for row, _, disposition in records:
        state = disposition["state"]
        states[state] += 1
        category = categories.setdefault(row["category"], Counter())
        category["total"] += 1
        category[state] += 1
        if row["next_step"] == "Evidence blocks preview":
            category["blocked"] += 1
    return {"total": sum(states.values()), "states": dict(states),
            "categories": {name: dict(counts) for name, counts in categories.items()}}


def overview_panel(root, snapshot, overview, categories, states, category, state):
    def link(**params):
        return url(root, "assessment", snapshot=snapshot, **params) + "#optimization-worklist"
    state_links = []
    for key, label in states.items():
        count = overview["states"].get(key, 0)
        current = ' aria-current="true"' if state == key and not category else ""
        state_links.append(f'<a class="review-status-tile"{current} href="{link(state=key)}">'
                           f'<strong>{count}</strong><span>{e(label)}</span></a>')
    cards = []
    for key, label in categories.items():
        counts = overview["categories"].get(key, {})
        total = counts.get("total", 0)
        open_ = counts.get("open", 0)
        investigate = counts.get("investigate", 0)
        blocked = counts.get("blocked", 0)
        current = ' aria-current="true"' if category == key and not state else ""
        cards.append(f'<a class="review-category-tile"{current} href="{link(category=key)}">'
                     f'<span>{e(label)}</span><strong>{total}</strong>'
                     f'<small>{open_} open · {investigate} investigate</small>'
                     + (f'<small class="review-blocked">{blocked} preview blocked</small>' if blocked else "")
                     + '</a>')
    return ('<section class="review-overview" aria-labelledby="review-overview-title">'
            '<div class="review-overview-head"><div><h2 id="review-overview-title">Review workload</h2>'
            '<p>Choose a category or status to open the matching findings. Counts describe review groups, not verified changes.</p></div>'
            f'<a href="{link()}">All findings ({overview["total"]}) {icon("arrow")}</a></div>'
            '<h3>Review status</h3><div class="review-status-grid">' + "".join(state_links)
            + '</div><h3>Optimization categories</h3><div class="review-category-grid">' + "".join(cards)
            + '</div><p class="note">A reviewed or intentional finding is a local review record, not change approval. Preview blockers can overlap any review status.</p></section>')


OVERVIEW_CSS = """
.assessment-nav { display:flex; flex-wrap:wrap; gap:8px; margin:0 0 18px; }
.review-overview-head { display:flex; align-items:start; justify-content:space-between; gap:16px; flex-wrap:wrap; }
.review-overview-head p { color:var(--muted); margin:6px 0 12px; }
.review-status-grid,.review-category-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin:8px 0 18px; }
.review-status-tile,.review-category-tile { display:flex; flex-direction:column; gap:4px; color:var(--text); border:1px solid var(--line); border-radius:9px; padding:12px; text-decoration:none; background:var(--surface); min-width:0; }
.review-status-tile:hover,.review-category-tile:hover,.review-status-tile[aria-current=true],.review-category-tile[aria-current=true] { border-color:var(--accent); background:var(--soft); text-decoration:none; }
.review-status-tile strong,.review-category-tile strong { font-size:26px; line-height:1.15; font-variant-numeric:tabular-nums; }
.review-category-tile span { font-weight:650; }
.review-category-tile small,.review-status-tile span { color:var(--muted); }
.review-category-tile .review-blocked { color:var(--warn); font-weight:600; }
.review-note-preview { display:block; max-width:18rem; overflow-wrap:anywhere; margin-top:5px; }
#optimization-worklist { scroll-margin-top:80px; }
@media(max-width:680px) { .review-status-grid,.review-category-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } }
"""
