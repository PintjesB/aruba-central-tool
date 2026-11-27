import unittest
from central_tool import inspect_unadapted_profiles
from singleton_review import singleton_view, singleton_review


class SingletonTests(unittest.TestCase):
    def test_explicit_envelope_and_direct_settings_keep_unknown_fields(self):
        raw = {"metadata": {"count": 1}, "lacp": {"system-priority": 32768,
                "hash": "L3", "future-setting": True, "@": {"source": "observed"}}}
        view = singleton_view("lacp", {"status": "response_received", "raw": raw})
        self.assertEqual(view["status"], "settings_observed")
        self.assertTrue(view["settings"]["future-setting"])
        self.assertNotIn("@", view["settings"])
        self.assertFalse(view["source_verified"])
        other = {"status": "response_received", "raw": {"hash": "L2", "system-priority": 32768}}
        result = singleton_review("lacp", {"status": "response_received", "raw": raw}, other)
        self.assertTrue(result["differences"])
        self.assertFalse(result["safe_to_apply"])

    def test_missing_and_mixed_objects_are_not_interpreted_as_absent(self):
        for raw in ({}, {"metadata": {}}, {"lacp": [{"hash": "L2"}, {"hash": "L3"}]},
                    {"lacp": {"hash": "L2"}, "other": {"hash": "L3"}}):
            read = {"status": "response_received", "raw": raw}
            self.assertIsNone(singleton_view("lacp", read)["settings"])
            self.assertIsNone(singleton_review("lacp", read, read)["differences"])
        self.assertEqual(singleton_view("lacp", {"status": "read_failed"})["status"], "read_failed")

    def test_deep_system_collection_includes_persona_filtered_and_unfiltered_views(self):
        class Client:
            def __init__(self):
                self.calls = []
            def get(self, path, **params):
                self.calls.append((path, params))
                return {"lacp": {"hash": "L3", "system-priority": 32768}}
        client = Client()
        discovery = {"unknown_adapter_modules": [], "survey_modules": ["lacp"], "modules": {},
                     "documented_catalog": {"modules": {"lacp": {"all_function_scope": True,
                                                                  "source": "vendor_collection"}}}}
        result = inspect_unadapted_profiles(client, discovery, {}, {}, deep_catalog=True,
                 scopes_by_persona={"ACCESS_SWITCH": [{"id": "1", "kind": "global"},
                                                      {"id": "2", "kind": "device"}]})["lacp"]
        self.assertEqual(len(client.calls), 9)
        self.assertEqual(len(result["source_views"]), 4)
        self.assertEqual(result["singleton_library"]["settings"]["hash"], "L3")
        self.assertTrue(all(v["singleton_review"]["differences"] == [] for v in result["source_views"]))
        self.assertEqual({p.get("device-function") for _, p in client.calls}, {"ACCESS_SWITCH", None})
        self.assertFalse(result["safe_to_apply"])
