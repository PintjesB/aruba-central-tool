import unittest
from central_tool import APIError, Central, EU_REGIONS, detect_region, inventory, offset_rows, report, vlan_map, vlan_rows


class Fake:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = []

    def get(self, path, **params):
        self.calls.append((path, params))
        return next(self.pages)


def scope(id_, kind, effective, local=()):
    return {"id": id_, "kind": kind, "name": id_, "effective": effective, "local": list(local)}


class RegionFake:
    def __init__(self, results):
        self.results = results
        self.calls = []
        self.base = None

    def get(self, path, **params):
        self.calls.append(self.base)
        status = self.results[self.base]
        if status != 200:
            raise APIError(path, status)
        return {"items": []}


class Tests(unittest.TestCase):
    def test_region_preferred_success(self):
        client = RegionFake({EU_REGIONS[1]: 200})
        self.assertEqual(detect_region(client, EU_REGIONS[1]), EU_REGIONS[1])
        self.assertEqual(client.calls, [EU_REGIONS[1]])

    def test_region_fallback(self):
        client = RegionFake(dict(zip(EU_REGIONS, (401, 200, 401))))
        self.assertEqual(detect_region(client, EU_REGIONS[0]), EU_REGIONS[1])
        self.assertEqual(client.base, EU_REGIONS[1])
        self.assertEqual(client.calls, list(EU_REGIONS))

    def test_region_without_preference(self):
        client = RegionFake(dict(zip(EU_REGIONS, (401, 200, 401))))
        self.assertEqual(detect_region(client), EU_REGIONS[1])

    def test_region_ambiguous(self):
        client = RegionFake(dict(zip(EU_REGIONS, (401, 200, 200))))
        with self.assertRaisesRegex(RuntimeError, "Multiple"):
            detect_region(client)

    def test_region_no_match(self):
        client = RegionFake(dict(zip(EU_REGIONS, (401, 401, 401))))
        with self.assertRaisesRegex(RuntimeError, "no authorized"):
            detect_region(client)

    def test_region_permission_failure_no_fallback(self):
        client = RegionFake({EU_REGIONS[0]: 403})
        with self.assertRaises(APIError):
            detect_region(client, EU_REGIONS[0])
        self.assertEqual(client.calls, [EU_REGIONS[0]])

    def test_cursor_pagination(self):
        client = Fake([{"items": [{"id": "1"}], "next": "2", "total": 2},
                       {"items": [{"id": "2"}], "total": 2}])
        self.assertEqual(len(inventory(client)), 2)
        self.assertEqual(client.calls[1][1]["next"], "2")

    def test_vlan_pagination_uses_ten_and_explicit_offset(self):
        first = [{"vlan": n} for n in range(1, 11)]
        second = [{"vlan": 11}]
        client = Fake([{"l2-vlan": first, "metadata": {}},
                       {"l2-vlan": second, "metadata": {}},
                       {"l2-vlan": [], "metadata": {}}])
        self.assertEqual(vlan_rows(client, **{"view-type": "LIBRARY"}), first + second)
        self.assertEqual([p["limit"] for _, p in client.calls], [10, 10, 10])
        self.assertEqual([p["offset"] for _, p in client.calls], [0, 10, 11])

    def test_vlan_error_has_safe_parameters(self):
        class Reject:
            def get(self, path, **params):
                raise APIError(path, 400)
        with self.assertRaises(RuntimeError) as error:
            vlan_rows(Reject(), **{"view-type": "LOCAL", "scope-id": "123456789"})
        message = str(error.exception)
        self.assertIn("limit=10, offset=0", message)
        self.assertIn("LOCAL", message)
        self.assertNotIn("123456789", message)

    def test_offset_pagination(self):
        client = Fake([{"items": [{"id": "1"}]}, {"items": [{"id": "2"}]}, {"items": []}])
        self.assertEqual(len(offset_rows(client, "/x", ("items",))), 2)
        self.assertEqual(client.calls[1][1]["offset"], 1)

    def test_repeated_page_fails(self):
        client = Fake([{"items": [{"id": "1"}]}] * 2)
        with self.assertRaises(ValueError):
            offset_rows(client, "/x", ("items",))

    def test_unknown_envelope_fails(self):
        with self.assertRaises(ValueError):
            inventory(Fake([{"unknown": []}]))

    def test_duplicate_vlan_fails(self):
        with self.assertRaises(ValueError):
            vlan_map([{"vlan": 30}, {"vlan": 30}])

    def test_untrusted_host_fails(self):
        with self.assertRaises(ValueError):
            Central("https://de1.api.central.arubanetworks.com.evil.example", token="fake")

    def test_report_distinguishes_coverage_and_conflicts(self):
        base = {"vlan": 10, "name": "Corp"}
        local = {"vlan": 30, "name": "CCTV"}
        conflicting = {"vlan": 30, "name": "Other"}
        snapshot = {"schema": 1, "captured_at": "example", "persona": "ACCESS_SWITCH",
                    "library": [conflicting], "excluded_devices": [{}],
                    "scopes": [scope("1", "global", [base]),
                               scope("2", "device", [base, local], [local]),
                               scope("3", "device", [base, local], [local]),
                               scope("4", "device", [base], [base])]}
        result = report(snapshot)
        candidate = result["duplicate_local_candidates"][0]
        self.assertEqual(candidate["matching_scanned_devices"], ["2", "3"])
        self.assertEqual(candidate["other_scanned_devices"], ["4"])
        self.assertEqual(candidate["library_state"], "conflict")
        self.assertEqual(result["scope_comparisons"][3]["local_matching_global"], ["10"])
        self.assertFalse(result["safe_to_apply"])


if __name__ == "__main__":
    unittest.main()
