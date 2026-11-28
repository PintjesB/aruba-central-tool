import unittest
from aruba_central.advanced_review import advanced_analysis,library_usage,preferred_duplicate,duplicate_migration_preview
from aruba_central.dependency_impact import dependency_impact
from aruba_central.optimization_dependencies import attach_dependency_review
from aruba_central.retention_review import retention_comparison
from test_nac_authorization import captured,radius


class NACDependencyTests(unittest.TestCase):
    def test_nac_candidates_are_visible_without_proven_device_consumers(self):
        bundle={"results":{},"library":{"modules":{"roles":captured({"Office":{"name":"Office","enable":True},
            "Other":{"name":"Other","enable":True}})},"assignments":{"status":"response_received","rows":[]}},
            "nac_configuration":{"authz-policies":captured({"p":{"name":"Policy","position":1,"enable":True,
                "default-enf-profile":radius(("ATTR_VLAN_ID","20"),("UNKNOWN_ENUM","Office")),"rule":[]}})}}
        refs=advanced_analysis(bundle)["references"]
        self.assertEqual({(r["target_module"],r["target"]) for r in refs},{("roles","Office"),("layer2-vlan","20")})
        self.assertTrue(all(r["source_view"]=="tenant" and r["status"]=="conditional_enforcement_candidate" for r in refs))
        impact=dependency_impact(refs,"roles","Office")
        self.assertEqual(len(impact["direct"]),1)
        self.assertEqual(impact["paths"],[])
        u=library_usage(bundle,"roles",["Office","Other"],refs)
        self.assertEqual(u["Office"]["reference_count"],0)
        self.assertEqual(u["Office"]["conditional_nac_observations"],1)
        self.assertIsNone(preferred_duplicate(u))
        self.assertEqual(retention_comparison(u,None)["short_reason"],"Conditional NAC dependencies")
        plan=duplicate_migration_preview("roles",u,"Other",bundle)
        self.assertEqual(plan["recipient_review"],[])
        self.assertIn("NAC enforcement candidate",plan["unresolved_recipient_observations"][0]["reason"])
        finding={"persona":"ACCESS_SWITCH","module":"roles","identity":"Office"}
        report=attach_dependency_review([finding],refs)[0]["dependency_review"]
        self.assertEqual(len(report["other_function_consumers"]),1)
        self.assertEqual(report["observed_consumer_devices"],0)
