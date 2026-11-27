import copy
import unittest
from unittest.mock import patch

from aruba_central.advanced_review import advanced_analysis, effective_views


class EngineeringViewIndexTests(unittest.TestCase):
    def test_one_view_index_per_persona(self):
        bundle = {"results": {
            "ACCESS_SWITCH": {"scopes": [], "modules": {}},
            "CORE_SWITCH": {"scopes": [], "modules": {}},
        }, "keyed_profile_details": {"profiles": {"ACCESS_SWITCH": {}, "CORE_SWITCH": {}}}}
        before = copy.deepcopy(bundle)
        with patch("aruba_central.advanced_review.effective_views", wraps=effective_views) as index:
            result = advanced_analysis(bundle)
            self.assertEqual(index.call_count, 2)
        self.assertEqual(result["references"], [])
        self.assertEqual(bundle, before)
        self.assertFalse(result["safe_to_apply"])
