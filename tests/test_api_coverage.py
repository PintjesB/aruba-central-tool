import json
import unittest
from concurrent.futures import ThreadPoolExecutor

from api_coverage import ReadCoverage
from central_tool import APIError


class Client:
    base = "test"

    def get(self, path, **params):
        if params.get("fail"):
            raise APIError(path, 403)
        if params.get("broken"):
            raise ValueError("private error")
        return {}


def catalog():
    return {"source_updated_at": "example", "get_requests": [
        {"method": "GET", "path": "/api/profiles", "group": "Profiles"},
        {"method": "GET", "path": "/api/profiles", "group": "Another category"},
        {"method": "GET", "path": "/api/profiles/:id", "group": "Profiles"},
        {"method": "GET", "path": "/api/profiles/status", "group": "Health"},
        {"method": "GET", "path": "/api/unused", "group": "Profiles"},
        {"method": "GET", "path": "/api/:id/detail", "group": "Profiles"},
        {"method": "GET", "path": "/api/profile/:key", "group": "Profiles"},
    ], "release_note_collections": [{"path": "/api/new"}]}


class CoverageTests(unittest.TestCase):
    def test_coverage_and_privacy(self):
        tracked = ReadCoverage(Client(), catalog())
        self.assertEqual(tracked.base, "test")
        tracked.get("/api/profiles")
        tracked.get("/api/profiles/PRIVATE-DEVICE", filter="PRIVATE-QUERY")
        with self.assertRaises(APIError):
            tracked.get("/api/profiles/PRIVATE-DEVICE", fail=True)
        with self.assertRaises(ValueError):
            tracked.get("/api/profiles/status", broken=True)
        tracked.get("/unknown/PRIVATE-DEVICE")
        tracked.get("/api/profile/detail")  # two equally specific templates
        tracked.get("/api/new")
        report = tracked.report()
        rows = {row["path"]: row for row in report["operations"]}
        self.assertEqual(rows["/api/profiles"]["definitions"], 2)
        self.assertEqual(rows["/api/profiles/:id"]["status"], "mixed_outcomes")
        self.assertEqual(rows["/api/profiles/:id"]["outcomes"], {"response_received": 1, "http_403": 1})
        self.assertEqual(rows["/api/profiles/status"]["status"], "no_response")
        self.assertEqual(rows["/api/unused"]["status"], "not_attempted")
        self.assertEqual(rows["/api/new"]["status"], "response_received")
        self.assertEqual(report["unmatched_get_outcomes"], {"response_received": 2})
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertNotIn("private error", json.dumps(report))
        self.assertFalse(report["complete"])

    def test_exact_complete_collection_reused_but_not_empty_or_partial(self):
        class CountingClient:
            def __init__(self):
                self.calls = 0

            def get(self, path, **params):
                self.calls += 1
                if params.get("scope-id") == "empty":
                    return {"profiles": [], "metadata": {"total": 0}}
                if params.get("scope-id") == "partial":
                    return {"profiles": [{"name": "x"}], "metadata": {"total": 2}}
                return {"profiles": [{"name": "x"}], "metadata": {"total": 1}}

        path = "/network-config/v1alpha1/example"
        spec = {"source_updated_at": "example", "get_requests": [
            {"method": "GET", "path": path, "group": "Profiles"}]}
        client = CountingClient()
        tracked = ReadCoverage(client, spec)
        first = tracked.get(path, **{"view-type": "LOCAL", "scope-id": "1"})
        first["profiles"][0]["name"] = "modified"
        self.assertEqual(tracked.get(path, **{"scope-id": "1", "view-type": "LOCAL"})["profiles"][0]["name"], "x")
        for scope in ("empty", "partial"):
            for _ in range(2):
                tracked.get(path, **{"view-type": "LOCAL", "scope-id": scope})
        tracked.get(path, **{"view-type": "LOCAL", "scope-id": "2"})
        tracked.get(path, **{"view-type": "LOCAL", "scope-id": "1", "offset": 0})
        self.assertEqual(client.calls, 7)
        self.assertEqual(tracked.report()["exact_collection_gets_reused"], 1)
        self.assertEqual(tracked.report()["operations"][0]["attempted"], 7)

    def test_endpoint_duration_aggregates_success_and_failure(self):
        from unittest.mock import patch
        tracked = ReadCoverage(Client(), catalog())
        with patch("api_coverage.time.monotonic", side_effect=[1, 1.25, 2, 2.5]):
            tracked.get("/api/profiles")
            with self.assertRaises(APIError):
                tracked.get("/api/profiles", fail=True)
        row = next(r for r in tracked.report()["operations"] if r["path"] == "/api/profiles")
        self.assertEqual(row["elapsed_ms_sum"], 750)
        self.assertEqual(row["elapsed_ms_max"], 500)
        self.assertEqual(row["attempted"], 2)

    def test_parallel_counts(self):
        tracked = ReadCoverage(Client(), catalog())
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda n: tracked.get("/api/profiles/" + str(n)), range(100)))
        row = next(r for r in tracked.report()["operations"] if r["path"] == "/api/profiles/:id")
        self.assertEqual(row["attempted"], 100)
        self.assertEqual(row["received"], 100)
