import csv
import io
import shutil
import unittest

from aruba_central.workspace_ui import page, table, tr, e

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


class FilteredCsvTests(unittest.TestCase):
    @unittest.skipUnless(sync_playwright, "Browser test dependency unavailable")
    def test_export_all_filtered_rows_and_escape_spreadsheet_formulas(self):
        rows = [tr("Office", e('=HYPERLINK("https://example.invalid")'), "Inspect")
                for _ in range(35)] + [tr("Lab", "excluded", "Inspect")]
        html = page("Export", table(("Site", "Value", ""), rows, search=True))
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=shutil.which("google-chrome") or shutil.which("chromium"), args=["--no-sandbox"])
            try:
                tab = browser.new_page(accept_downloads=True)
                tab.set_content(html)
                tab.locator("[data-table-search]").fill("Office")
                self.assertEqual(tab.locator("tbody > tr:visible").count(), 30)
                with tab.expect_download() as download:
                    tab.locator("[data-export-csv]").click()
                data = download.value.path().read_text(encoding="utf-8-sig")
                records = list(csv.reader(io.StringIO(data)))
                self.assertEqual(records[0], ["Site", "Value"])
                self.assertEqual(len(records), 36)
                self.assertTrue(all(row[0] == "Office" and row[1].startswith("'=") for row in records[1:]))
                tab.locator("[data-table-search]").fill("no match")
                self.assertTrue(tab.locator("[data-export-csv]").is_disabled())
            finally:
                browser.close()
