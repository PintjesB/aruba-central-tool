"""Responsive acceptance of the newer offline review screens."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from aruba_central.config_app import Workspace
from test_consolidation import fixture

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


@unittest.skipUnless(sync_playwright, "Browser test dependency unavailable")
class ReviewScreenLayoutTests(unittest.TestCase):
    def test_new_review_screens_fit_desktop_and_mobile_in_both_themes(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(fixture()))
            w = Workspace(directory)
            q = {"snapshot": name}
            pages = {
                "assessment": w.assessment(q),
                "scope health": w.assessment({**q, "mode": "health"}),
                "keyed evidence": w.assessment({**q, "mode": "keyed"}),
                "device review": w.scopes({**q, "mode": "device", "persona": "ACCESS_SWITCH", "device": "3"}),
                "source trace": w.sources({**q, "persona": "ACCESS_SWITCH", "device": "3", "module": "layer2-vlan", "identity": "10"}),
                "dependency impact": w.impact({**q, "module": "layer2-vlan", "identity": "10"}),
                "entity search": w.report({**q, "mode": "entities", "q": "Switch"}),
                "library profile": w.library({**q, "module": "layer2-vlan", "identity": "30"}),
                "NAC": w.nac(q),
            }
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"), args=["--no-sandbox"])
                try:
                    for label, html in pages.items():
                        with self.subTest(screen=label):
                            view = browser.new_page(viewport={"width": 1440, "height": 900})
                            view.set_default_timeout(5000)
                            errors = []
                            view.on("pageerror", lambda exc: errors.append(str(exc)))
                            try:
                                view.set_content(html)
                                self.assertEqual(view.locator("main h1").count(), 1)
                                for width in (1440, 390):
                                    view.set_viewport_size({"width": width, "height": 900})
                                    for theme in ("light", "dark"):
                                        view.evaluate("(theme) => document.documentElement.setAttribute('data-theme', theme)", theme)
                                        self.assertLessEqual(view.evaluate("document.documentElement.scrollWidth"), width + 2,
                                                             f"{label} / {width} / {theme}")
                                self.assertEqual(errors, [])
                            finally:
                                view.close()
                finally:
                    browser.close()
