import unittest
from aruba_central.optimization_history import workload_transitions


class WorkloadTransitionTests(unittest.TestCase):
    def row(self,profile,instances=1,group="a"):
        return {"category":"promote_local","persona":"ACCESS_SWITCH","module":"roles","profile":profile,
                "instances":instances,"unit":"local copies","known":1,"unknown":0,
                "route":"advisor","params":{"group":group},"next_step":"Review"}

    def test_workload_descriptor_transitions_never_claim_removals_or_transfer_status(self):
        prior=[self.row("same"),self.row("changed"),self.row("gone"),self.row("ambiguous"),self.row("ambiguous",2)]
        current=[self.row("same"),self.row("changed",2),self.row("new"),self.row("ambiguous")]
        report=workload_transitions(prior,current)
        self.assertEqual(report["counts"],{"same_workload_descriptor":1,"changed_workload_descriptor":1,
            "prior_group_not_listed":1,"new_worklist_group":1,"ambiguous_group":1})
        self.assertFalse(report["verified_removals"])
        self.assertFalse(report["safe_to_apply"])
        self.assertEqual(next(r for r in report["records"] if r["profile"]=="ambiguous")["status"],"ambiguous_group")
