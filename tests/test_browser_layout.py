"""Browser regression for the shared inspector. Run with Playwright and Chromium."""
import unittest
import shutil
import importlib.util

from workspace_ui import page, table, tr, inspect, raw
from workspace_views import vlan_explanation


@unittest.skipUnless(importlib.util.find_spec("playwright"), "Optional browser test requires Playwright")
class BrowserLayoutTests(unittest.TestCase):
    def test_inspector_has_one_vertical_scroll_owner(self):
        from playwright.sync_api import sync_playwright

        saved = {"vlan": 1000}
        effective = {"vlan": 1000, "name": "VOICE", "enable": True, "dhcpv4-snooping": {"enable": False}}
        reference = {**effective, "igmp": {"snooping": False}, "mld": {"snooping": False}}
        content = (vlan_explanation(saved, reference, effective)
                   + table(("Scope", "Result"), [tr(f"Scope {i}", "Captured") for i in range(45)], search=True)
                   + raw({"evidence": ["Captured field " + str(i) for i in range(120)]}))
        html = page("Layout test", "<section>" + inspect("VLAN 1000", content)
                    + "<p>" + "</p><p>".join("Background row " + str(i) for i in range(100)) + "</p></section>")
        with sync_playwright() as pw:
            executable = shutil.which("google-chrome") or shutil.which("chromium")
            browser = pw.chromium.launch(executable_path=executable, args=["--no-sandbox"])
            try:
                for width, height in ((1440, 900), (850, 780), (390, 844)):
                    with self.subTest(width=width):
                        view = browser.new_page(viewport={"width": width, "height": height})
                        view.set_content(html)
                        view.locator("[data-inspect]").click()
                        self.assertEqual(view.locator("#workspace-inspector-title").inner_text(), "VLAN 1000")
                        self.assertTrue(view.locator("#workspace-close").is_visible())
                        self.assertEqual(view.locator("#workspace-inspector-body [data-page]").inner_text(), "Page 1 / 2")
                        view.locator("#workspace-inspector-body [data-next]").click()
                        self.assertEqual(view.locator("#workspace-inspector-body [data-page]").inner_text(), "Page 2 / 2")
                        view.locator("#workspace-inspector-body details.raw summary").click()
                        result = view.evaluate("""() => {
                            const dialog = document.querySelector('.inspector');
                            const body = document.querySelector('#workspace-inspector-body');
                            const overflow = [...body.querySelectorAll('*')].filter(el =>
                                el.clientHeight > 0 && el.scrollHeight > el.clientHeight + 2 &&
                                ['scroll','auto'].includes(getComputedStyle(el).overflowY));
                            return {locked: getComputedStyle(document.documentElement).overflowY,
                                dialogOverflow: getComputedStyle(dialog).overflowY,
                                bodyOverflow: getComputedStyle(body).overflowY,
                                bodyScrolls: body.scrollHeight > body.clientHeight,
                                nested: overflow.map(el => el.className || el.tagName)};
                        }""")
                        self.assertEqual(result["locked"], "hidden")
                        self.assertEqual(result["dialogOverflow"], "hidden")
                        self.assertEqual(result["bodyOverflow"], "auto")
                        self.assertTrue(result["bodyScrolls"])
                        self.assertEqual(result["nested"], [])
                        self.assertTrue(view.locator("#workspace-close").is_in_viewport() if hasattr(view.locator("#workspace-close"), "is_in_viewport") else view.locator("#workspace-close").bounding_box()["y"] >= 0)
                        view.keyboard.press("Escape")
                        view.wait_for_function("!document.documentElement.classList.contains('inspector-open')")
                        self.assertEqual(view.locator("[data-inspect]").evaluate("(el) => el === document.activeElement"), True)
                        view.locator("[data-inspect]").click()
                        self.assertEqual(view.locator("#workspace-inspector-body").evaluate("(el) => el.scrollTop"), 0)
                        view.close()
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
