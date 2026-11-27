import unittest
from aruba_central.central_tool import field_differences
from aruba_central.workspace_ui import diff_table


class TypedDiffTests(unittest.TestCase):
    def test_type_and_missing_state_are_visible_without_changing_values(self):
        fields = field_differences({"flag": False, "missing": 1, "nullable": None, "ordered": ["a", "b"]},
                                   {"flag": "False", "nullable": 0, "ordered": ["b", "a"]})
        html = diff_table(fields, "Saved device", "Nearest scope")
        for label in ("Boolean", "String", "Value types differ", "Missing from second observation",
                      "Not returned", "Null vs explicit value", "Ordered list", "Values differ"):
            self.assertIn(label, html)
        self.assertIn("Saved device", html)
        self.assertIn("Nearest scope", html)
        self.assertIn('class="value-bool">False', html)
        self.assertIn('class="value-scalar">False', html)
        self.assertIn("Captured configuration bodies are identical", diff_table([]))
        self.assertIn("No comparable reference captured", diff_table(None))

    def test_private_values_and_labels_are_escaped(self):
        html = diff_table(field_differences({"<script>": "<img>"}, {"<script>": "other"}))
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img&gt;", html)
