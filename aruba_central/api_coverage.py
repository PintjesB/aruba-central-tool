"""Observe read coverage without retaining request identifiers or values."""
from collections import Counter, defaultdict, OrderedDict
from concurrent.futures import Future
import json
import hashlib
from pathlib import Path
import re
import threading
import time


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
        self.prefix_lengths = defaultdict(set)
        for path in self.operations.keys() - self.exact:
            parts = path.split("/")
            prefix_length = next((i for i, part in enumerate(parts) if part.startswith(":")), len(parts))
            prefix = tuple(parts[:prefix_length])
            pattern = "/".join("[^/]+" if part.startswith(":") else re.escape(part) for part in parts)
            score = sum(not part.startswith(":") for part in parts)
            self.templates[(len(parts), prefix)].append((re.compile(pattern), score, path))
            self.prefix_lengths[len(parts)].add(prefix_length)
        self.counts = defaultdict(Counter)
        self.timing = defaultdict(lambda: [0, 0])
        self.unmatched = Counter()
        self.lock = threading.Lock()
        self.cache = OrderedDict()
        self.cache_bytes = 0
        self.inflight = {}
        self.reused = 0
        self.empty_reused = 0
        self.seen_selectors = set()
        self.duplicate_attempts = Counter()
        self.selector_accounting_truncated = False

    def __getattr__(self, name):
        return getattr(self.client, name)

    def resolve(self, path):
        if path in self.exact:
            return path
        parts = path.split("/")
        size = len(parts)
        # Check every matching literal prefix, including shorter/leading
        # wildcard templates. Keep the original specificity and tie rules.
        matches = [(score, template)
                   for length in self.prefix_lengths.get(size, ())
                   for pattern, score, template in self.templates.get((size, tuple(parts[:length])), ())
                   if pattern.fullmatch(path)]
        if not matches:
            return None
        highest = max(score for score, _ in matches)
        best = [template for score, template in matches if score == highest]
        return best[0] if len(best) == 1 else None

    def get(self, path, **params):
        """Coalesce identical configuration collection GETs within this audit.

        Do not reuse polling, inventory, health, keyed reads, errors or
        unqualified empty responses. An explicit, consistent zero count for
        an identical collection selector is eligible within this audit only.
        """
        if (path not in self.exact
                or not re.fullmatch(r"/network-config/v1alpha1/[a-z][a-z0-9-]*", path)
                or params.get("view-type") not in ("LOCAL", "LIBRARY")
                or {"limit", "offset"} & params.keys()):
            return self._get(path, **params)
        key = (path, json.dumps(params, sort_keys=True, separators=(",", ":")))
        while True:
            with self.lock:
                if key in self.cache:
                    self.cache.move_to_end(key)
                    self.reused += 1
                    payload, empty = self.cache[key]
                    self.empty_reused += empty
                    break
                future = self.inflight.get(key)
                if future is None:
                    future = self.inflight[key] = Future()
                    payload = None
                    break
            # A failed or empty response is not cached; the waiting caller
            # performs its own read, preserving existing recovery behavior.
            future.result()
        # Decode outside the lock. Cached bytes are immutable, even if a
        # concurrent insert evicts this entry before decoding completes.
        if payload is not None:
            return json.loads(payload)
        try:
            result = self._get(path, **params)
            if self._complete_collection(result, params):
                payload = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                if len(payload) <= 64 * 1024 * 1024:
                    with self.lock:
                        self.cache[key] = (payload, self._counted_empty_collection(result))
                        self.cache_bytes += len(payload)
                        while self.cache_bytes > 64 * 1024 * 1024 or len(self.cache) > 8192:
                            _, (old, _) = self.cache.popitem(last=False)
                            self.cache_bytes -= len(old)
            return result
        finally:
            with self.lock:
                self.inflight.pop(key, None)
                future.set_result(None)

    @staticmethod
    def _complete_collection(result, params):
        if not isinstance(result, dict):
            return False
        meta = result.get("metadata")
        lists = [(k, v) for k, v in result.items() if k != "metadata" and isinstance(v, list)]
        if not isinstance(meta, dict) or len(lists) != 1 or set(result) != {"metadata", lists[0][0]}:
            return False
        rows = lists[0][1]
        counts = meta.get("count_objects_in_module", {})
        if not isinstance(counts, dict) or not all(isinstance(v, dict) for v in rows):
            return False
        expected = counts.get(params.get("object-type", "ANY"))
        total = meta.get("total", expected)
        return (type(total) is int and total == len(rows)
                and (expected is None or type(expected) is int and expected == total)
                and type(meta.get("count", total)) is int and meta.get("count", total) == total
                and type(meta.get("offset", 0)) is int and meta.get("offset", 0) in (0, total)
                and len({json.dumps(row, sort_keys=True) for row in rows}) == total)

    @staticmethod
    def _counted_empty_collection(result):
        # Only called for a response already qualified by _complete_collection.
        return any(isinstance(v, list) and not v for k, v in result.items() if k != "metadata")

    def _get(self, path, **params):
        from .central_tool import APIError
        template = self.resolve(path)
        # Count actual duplicate configuration GET attempts (including keyed
        # and paginated selectors) without retaining identifiers in the report.
        if template is not None and path.startswith("/network-config/"):
            fingerprint = hashlib.sha256(json.dumps(
                [path, params], sort_keys=True, separators=(",", ":")).encode()).digest()
            with self.lock:
                if fingerprint in self.seen_selectors:
                    self.duplicate_attempts[template] += 1
                elif len(self.seen_selectors) < 100000:
                    self.seen_selectors.add(fingerprint)
                else:
                    self.selector_accounting_truncated = True
        started = time.monotonic()
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
            elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
            with self.lock:
                if template is None:
                    self.unmatched[outcome] += 1
                else:
                    self.counts[template][outcome] += 1
                    timing = self.timing[template]
                    timing[0] += elapsed_ms
                    timing[1] = max(timing[1], elapsed_ms)

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
                             "received": received, "outcomes": counts, "status": state,
                             "elapsed_ms_sum": self.timing[path][0],
                             "elapsed_ms_max": self.timing[path][1]})
            return {"revision": self.revision, "operations": rows,
                    "unmatched_get_outcomes": dict(self.unmatched),
                    "exact_collection_gets_reused": self.reused,
                    "exact_counted_empty_gets_reused": self.empty_reused,
                    "duplicate_config_get_attempts": [
                        {"path": path, "duplicates": n} for path, n in sorted(self.duplicate_attempts.items())],
                    "duplicate_accounting_truncated": self.selector_accounting_truncated,
                    "complete": False}
