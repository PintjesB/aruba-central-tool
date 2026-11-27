import unittest
import shutil

from aruba_central.workspace_ui import page, table, tr

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


class WorklistControlsTests(unittest.TestCase):
    def test_only_searchable_tables_have_controls(self):
        rows = [tr("Switch 2", "10")]
        html = table(("Device", "Count"), rows, search=True)
        self.assertIn('data-sort-column="0"', html)
        self.assertIn('data-sort-column="1"', html)
        self.assertIn("data-page-size", html)
        self.assertNotIn("data-sort-column", table(("Device", "Count"), rows))

    @unittest.skipUnless(sync_playwright, "Browser test dependency unavailable")
    def test_sort_filter_and_page_size(self):
        rows = [tr("Switch " + str(i), str(i), "Office" if i % 2 else "Lab")
                for i in range(1, 61)]
        html = page("Test", table(("Device", "Count", "Site"), rows, search=True))
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"), args=["--no-sandbox"])
            try:
                tab = browser.new_page()
                tab.set_content(html)
                visible = tab.locator("tbody > tr:visible")
                self.assertEqual(visible.count(), 30)
                tab.locator("[data-sort-column='1']").click()
                self.assertEqual(visible.first.locator("td").nth(1).inner_text(), "1")
                tab.locator("[data-sort-column='1']").click()
                self.assertEqual(visible.first.locator("td").nth(1).inner_text(), "60")
                self.assertEqual(tab.locator("th").nth(1).get_attribute("aria-sort"), "descending")
                tab.locator("[data-page-size]").select_option("50")
                self.assertEqual(visible.count(), 50)
                tab.locator("[data-next]").click()
                self.assertEqual(visible.count(), 10)
                tab.locator("[data-table-search]").fill("office switch")
                self.assertEqual(visible.count(), 30)
                self.assertEqual(visible.first.locator("td").nth(1).inner_text(), "59")
                tab.locator("[data-table-search]").fill("no-such-device")
                self.assertEqual(visible.count(), 0)
                self.assertTrue(tab.locator("[data-table-empty]").is_visible())
            finally:
                browser.close()

    @unittest.skipUnless(sync_playwright, "Browser test dependency unavailable")
    def test_large_grid_paging_updates_only_visible_rows_and_retains_selection(self):
        rows = [tr("Switch " + str(i), '<input type="checkbox" aria-label="Select">')
                for i in range(1, 1001)]
        html = page("Scale test", table(("Device", ""), rows, search=True))
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"), args=["--no-sandbox"])
            try:
                tab = browser.new_page()
                tab.set_content(html)
                tab.locator("tbody > tr:visible input").first.check()
                tab.evaluate("""() => {
                    window.changes = 0;
                    new MutationObserver(records => { window.changes += records.length; }).observe(
                        document.querySelector('tbody'), {subtree:true, attributes:true, attributeFilter:['hidden']});
                }""")
                tab.locator("[data-next]").click()
                self.assertEqual(tab.locator("tbody > tr:visible").count(), 30)
                self.assertEqual(tab.evaluate("window.changes"), 60)
                tab.locator("[data-prev]").click()
                self.assertTrue(tab.locator("tbody > tr:visible input").first.is_checked())
                tab.locator("[data-sort-column='0']").click()
                tab.locator("[data-sort-column='0']").click()
                self.assertEqual(tab.locator("tbody > tr:visible").first.locator("td").first.inner_text(), "Switch 1000")
                tab.locator("[data-table-search]").fill("Switch 1")
                self.assertGreater(tab.locator("tbody > tr:visible").count(), 0)
            finally:
                browser.close()
