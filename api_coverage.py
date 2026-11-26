"""Observe read coverage without retaining request identifiers or values."""
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import threading


class ReadCoverage:
    """Audit-local client wrapper. Counts logical GET calls, not HTTP retries.

    Only known vendor path templates enter the report; concrete resource IDs,
    query values, exception text, credentials and response bodies never do.
    A successful response is not proof of coverage of every resource or field.
    """

    def __init__(self, client, catalog=None):
        self.client = client
        if catalog is None:
            catalog = json.loads(Path(__file__).with_name("central_api_catalog.json").read_text(encoding="utf-8"))
        self.revision = catalog["source_updated_at"]
        self.operations = {}
        for row in catalog["get_requests"]:
            if row["method"] != "GET":
                continue
            entry = self.operations.setdefault(row["path"], {"groups": set(), "definitions": 0})
            entry["groups"].add(row["group"])
            entry["definitions"] += 1
        for row in catalog.get("release_note_collections", []):
            self.operations.setdefault(row["path"], {"groups": {"Release notes"}, "definitions": 0})
        self.exact = {path for path in self.operations if ":" not in path}
        self.templates = defaultdict(list)
        for path in self.operations.keys() - self.exact:
            parts = path.split("/")
            pattern = "/".join("[^/]+" if part.startswith(":") else re.escape(part) for part in parts)
            score = sum(not part.startswith(":") for part in parts)
            self.templates[len(parts)].append((re.compile(pattern), score, path))
        self.counts = defaultdict(Counter)
        self.unmatched = Counter()
        self.lock = threading.Lock()

    def __getattr__(self, name):
        return getattr(self.client, name)

    def resolve(self, path):
        if path in self.exact:
            return path
        matches = [(score, template) for pattern, score, template in self.templates.get(len(path.split("/")), ())
                   if pattern.fullmatch(path)]
        if not matches:
            return None
        highest = max(score for score, _ in matches)
        best = [template for score, template in matches if score == highest]
        return best[0] if len(best) == 1 else None

    def get(self, path, **params):
        from central_tool import APIError
        template = self.resolve(path)
        try:
            result = self.client.get(path, **params)
        except APIError as exc:
            outcome = "http_" + str(exc.status)
            raise
        except BaseException:
            outcome = "read_failed"
            raise
        else:
            outcome = "response_received"
            return result
        finally:
            with self.lock:
                if template is None:
                    self.unmatched[outcome] += 1
                else:
                    self.counts[template][outcome] += 1

    def report(self):
        with self.lock:
            rows = []
            for path, meta in sorted(self.operations.items()):
                counts = dict(self.counts.get(path, {}))
                received = counts.get("response_received", 0)
                attempted = sum(counts.values())
                state = ("not_attempted" if not attempted else "no_response" if not received
                         else "mixed_outcomes" if received != attempted else "response_received")
                rows.append({"path": path, "groups": sorted(meta["groups"]),
                             "definitions": meta["definitions"], "attempted": attempted,
                             "received": received, "outcomes": counts, "status": state})
            return {"revision": self.revision, "operations": rows,
                    "unmatched_get_outcomes": dict(self.unmatched), "complete": False}
