import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from aruba_central.config_app import Workspace
from aruba_central.configuration_history import configuration_drift
from test_configuration_history import snapshot


class DriftWorklistTests(unittest.TestCase):
    def test_full_search_lazy_evidence_export_and_both_file_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            names=["config-audit-before.json","config-audit-after.json"]
            for name,value in zip(names,["old","new"]):
                data=snapshot()
                view=data["results"]["ACCESS_SWITCH"]["modules"]["layer2-vlan"]["scope_results"][-1]["effective_view"]
                view["profiles"].update({str(i):{"vlan":i,"private-setting":value+"-marker-"+str(i)} for i in range(100,220)})
                (Path(directory)/name).write_text(json.dumps(data))
            workspace=Workspace(directory)
            query={"snapshot":names[1],"previous":names[0],"confirmed":"yes"}
            with patch("aruba_central.configuration_history.configuration_drift",wraps=configuration_drift) as compare:
                html=workspace.drift(query)
                self.assertIn("Showing 1–50 of 120",html)
                self.assertNotIn("new-marker-219",html)
                self.assertIn("data-inspect-url",html)
                filtered=workspace.drift({**query,"record_q":"219"})
                self.assertIn("Showing 1–1 of 1",filtered)
                bundle=workspace.reviewed_snapshot(names[1])
                report,binding=workspace.drift_snapshot(names[1],bundle,names[0])
                idx=next(i for i,r in enumerate(report["records"]) if r["identity"]=="219")
                detail=workspace.drift({**query,"detail":"record","index":str(idx),"binding":binding})
                self.assertIn("new-marker-219",detail)
                self.assertNotIn("new-marker-218",detail)
                export=workspace.drift({**query,"export":"1","binding":binding})
                self.assertIn("new-marker-219",export)
                self.assertIn("new-marker-100",export)
                self.assertEqual(compare.call_count,1)
                path=Path(directory)/names[0]
                path.write_text(path.read_text()+" ")
                with self.assertRaises(ValueError):
                    workspace.drift({**query,"detail":"record","index":str(idx),"binding":binding})
                self.assertEqual(compare.call_count,2)
