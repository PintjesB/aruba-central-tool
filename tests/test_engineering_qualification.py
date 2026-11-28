import json
import unittest
from unittest.mock import patch
from aruba_central.engineering_qualification import engineering_qualification,FIELDS


class EngineeringQualificationTests(unittest.TestCase):
    def test_only_fixed_numeric_fields_exported(self):
        report={category:{key:1 for key in fields} for category,fields in FIELDS.items()}
        report["captured_at"]="private-marker"
        report["engineering"]["private-name"]="private-marker"
        with patch("aruba_central.engineering_qualification.refresh_configuration_review",return_value={}),patch("aruba_central.engineering_qualification.assessment",return_value=report):
            result=engineering_qualification({})
            self.assertNotIn("private",json.dumps(result))
            self.assertEqual(result["counts"]["identity_collisions"]["linked_same_context_responses"],1)
            report["engineering"]["conditional_nac_observations"]="private-marker"
            with self.assertRaises(ValueError):
                engineering_qualification({})
