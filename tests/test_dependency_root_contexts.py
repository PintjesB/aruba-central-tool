import unittest

from aruba_central.dependency_impact import dependency_impact


class DependencyRootContextsTests(unittest.TestCase):
    def test_unrelated_contexts_and_unresolved_root_remain_non_transitive(self):
        def edge(scope, source, target, status="observed", view="effective"):
            return {"persona": "ACCESS_SWITCH", "scope": scope, "source_module": "dns",
                    "source": source, "target_module": "dns", "target": target,
                    "source_view": view, "status": status}
        unrelated = [edge(str(i), "other", "unrelated") for i in range(100)]
        relevant = [edge("root", "client", "selected"), edge("root", "selected", "server"),
                    edge("root", "server", "upstream"), edge("unresolved", "selected", None, "unresolved"),
                    edge("saved", "selected", "saved-reference", "definition_observed", "saved")]
        expected = dependency_impact(relevant, "dns", "selected")
        self.assertEqual(dependency_impact(unrelated + relevant, "dns", "selected"), expected)
        self.assertEqual([p["identity"] for p in expected["paths"]], ["client", "server", "upstream"])
        self.assertEqual(len(expected["direct"]), 4)
        self.assertEqual(len(expected["unresolved_target_observations"]), 1)
        limited = dependency_impact(unrelated + relevant, "dns", "selected", limit=1)
        self.assertTrue(limited["truncated"])
        self.assertEqual(limited["paths"], expected["paths"][:1])
        self.assertFalse(expected["safe_to_apply"])
