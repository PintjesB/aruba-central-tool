"""Browser regression for the shared inspector. Run with Playwright and Chromium."""
import unittest
import shutil
import importlib.util

from workspace_ui import page, table, tr, inspect, raw, setting_value, diff_table
from workspace_views import vlan_explanation


class SettingDisplayTests(unittest.TestCase):
    def test_values_preserve_types_and_escape_central_data(self):
        html = setting_value({"description": "<script>alert(1)</script>", "flags": [False, None, "", {}, []]})
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        for label in ("False", "Null", "Empty string", "Empty object", "Empty list"):
            self.assertIn(label, html)
        self.assertIn("value-object", html)
        self.assertIn("value-list", html)
        self.assertIn("Not returned", diff_table([{"path": ["flag"], "reference_value": False}]))


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


    def test_engineering_workflow_port_mapping_and_library_duplicate_review(self):
        import json
        import tempfile
        from pathlib import Path
        from playwright.sync_api import sync_playwright
        from config_app import Workspace
        from test_consolidation import fixture
        from workspace_views import port_group_label
        data = fixture()
        entry = data["results"]["ACCESS_SWITCH"]
        settings = {"switchport": {"access-vlan": 10}, "routing": False}
        def captured(profiles):
            return {"status": "list_parsed", "profiles": profiles}
        def scope(sid, profiles):
            return {"scope": sid, "scope_kind": "device",
                    "local_view": captured(profiles), "effective_view": captured(profiles)}
        entry["modules"]["ethernet-interfaces"] = {"device_scope_only": True, "scope_results": [
            scope("3", {"1/1/1": {"name": "1/1/1", **settings},
                        "1/1/2": {"name": "1/1/2", "description": "desk", **settings}}),
            scope("4", {"1/1/3": {"name": "1/1/3", **settings}})]}
        profiles = {name: {"profile-name": name, **settings} for name in ("Access-A", "Access-B")}
        data["library"]["modules"]["sw-port-profiles"] = captured(profiles)
        entry["modules"]["sw-port-profiles"] = {"scope_results": [scope("3", profiles), scope("4", {})]}
        self.assertEqual(port_group_label(settings), "Access VLAN 10")
        with tempfile.TemporaryDirectory() as directory, sync_playwright() as pw:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(data))
            workspace = Workspace(directory)
            executable = shutil.which("google-chrome") or shutil.which("chromium")
            browser = pw.chromium.launch(executable_path=executable, args=["--no-sandbox"])
            try:
                view = browser.new_page(viewport={"width": 1280, "height": 800})
                view.set_content(workspace.advanced({"snapshot": name, "workflow": "ports"}))
                self.assertEqual(view.locator("section[data-panel]").count(), 1)
                self.assertEqual(view.locator("section[data-panel]").get_attribute("data-panel"), "ports")
                self.assertIn("Access VLAN 10", view.locator("section[data-panel]").inner_text())
                self.assertIn("3 ports", view.locator("section[data-panel]").inner_text())
                view.get_by_role("button", name="Review mapping").click()
                view.locator("[data-port-profile]").select_option("Access-B")
                self.assertEqual(view.locator("#workspace-inspector-body [data-port-target]").all_text_contents(), ["Access-B"] * 3)
                self.assertIn("Port dependencies", view.locator("#workspace-inspector-body").inner_text())
                view.locator("#workspace-close").click()
                view.set_content(workspace.advanced({"snapshot": name, "workflow": "duplicates"}))
                self.assertEqual(view.locator("section[data-panel]").get_attribute("data-panel"), "duplicates")
                self.assertIn("Access-A", view.locator("section[data-panel]").inner_text())
                view.get_by_role("button", name="Plan consolidation").click()
                view.locator("[data-keep]").select_option("Access-A")
                self.assertIn("Access-B", view.locator("[data-migration-summary]").inner_text())
                self.assertIn("Affected device visibility", view.locator("[data-migration-summary]").inner_text())
                self.assertIn("Unresolved recipient observations", view.locator("[data-migration-summary]").inner_text())
                self.assertNotIn("Access-A:", view.locator("[data-migration-summary]").inner_text())
            finally:
                browser.close()


    def test_workspace_navigation_filters_and_preview(self):
        import copy
        import json
        import tempfile
        from pathlib import Path
        from playwright.sync_api import sync_playwright
        from config_app import Workspace
        from test_consolidation import fixture

        data = fixture()
        second = copy.deepcopy(data["results"]["ACCESS_SWITCH"])
        second["modules"] = {"system-info": second["modules"]["system-info"]}
        for scope in second["scopes"]:
            scope["id"] = str(int(scope["id"]) + 100)
            scope["name"] = "AP " + scope["name"]
        for scope in second["modules"]["system-info"]["scope_results"]:
            scope["scope"] = str(int(scope["scope"]) + 100)
        data["results"]["CAMPUS_AP"] = second
        with tempfile.TemporaryDirectory() as directory, sync_playwright() as pw:
            name = "config-audit-example.json"
            (Path(directory) / name).write_text(json.dumps(data))
            w = Workspace(directory)
            q = {"snapshot": name}
            executable = shutil.which("google-chrome") or shutil.which("chromium")
            browser = pw.chromium.launch(executable_path=executable, args=["--no-sandbox"])
            try:
                screens = {
                    "overview": w.home(q), "overrides": w.overrides(q), "advisor": w.advisor(q),
                    "engineering": w.advanced(q), "configuration": w.report(q), "inventory": w.scopes(q),
                    "library": w.library(q), "collection": w.library({**q, "module": "layer2-vlan"}),
                    "compare": w.comparison(q), "coverage": w.coverage(q),
                }
                for screen, html in screens.items():
                    with self.subTest(screen=screen):
                        view = browser.new_page(viewport={"width": 1280, "height": 800})
                        view.set_default_timeout(5000)
                        errors = []
                        view.on("pageerror", lambda error: errors.append(str(error)))
                        view.set_content(html)
                        self.assertEqual(view.locator(".snapshot-picker").count(), 1)
                        self.assertEqual(view.locator("main h1").count(), 1)
                        self.assertEqual(view.locator("[aria-current=page]").count(), 1)
                        self.assertEqual(view.locator("#snapshot-slot .snapshot-picker").count(), 1)
                        self.assertLessEqual(view.evaluate("document.documentElement.scrollWidth"), 1282)
                        if screen in ("overview", "overrides", "advisor"):
                            # Synthetic fixture only. Captured for visual design review.
                            import os
                            preview_dir = os.environ.get("CENTRAL_UI_PREVIEW_DIR")
                            if preview_dir:
                                Path(preview_dir).mkdir(parents=True, exist_ok=True)
                                view.screenshot(path=str(Path(preview_dir) / (screen + ".png")))
                        if screen == "overview":
                            self.assertEqual(view.locator(".opportunity-row").count(), 3)
                            self.assertIn("finding=remove_override", view.locator(".opportunity-row").first.get_attribute("href"))
                            view.locator("#workspace-menu").click()
                            self.assertTrue(view.locator("html").evaluate("(el)=>el.classList.contains('compact-nav')"))
                            self.assertEqual(view.locator('.sidebar a[data-nav="Library"]').get_attribute("aria-label"), "Library")
                            view.locator("#workspace-menu").click()
                            view.keyboard.press("Control+k")
                            self.assertTrue(view.locator("#workspace-palette").is_visible())
                            view.locator("#command-query").fill("library")
                            self.assertEqual(view.locator("#command-results a").count(), 2)
                            self.assertEqual(view.locator('#command-results a[href*="/library?snapshot="]').count(), 1)
                            self.assertEqual(view.locator('#command-results a[href*="/assignments?snapshot="]').count(), 1)
                            view.keyboard.press("Escape")
                            self.assertFalse(view.locator("#workspace-palette").is_visible())
                            view.locator("#workspace-theme").click()
                            self.assertEqual(view.locator("html").get_attribute("data-theme"), "dark")
                            view.locator("#workspace-theme").click()
                            self.assertEqual(view.locator("html").get_attribute("data-theme"), "light")
                        if screen in ("overrides", "compare", "configuration"):
                            form = view.locator("form[data-scope-filters]")
                            self.assertEqual(form.count(), 1)
                            self.assertEqual(form.locator("button[type=submit]").count(), 1)
                            form.locator("[name=persona]").select_option("CAMPUS_AP")
                            self.assertEqual(form.locator("[name=module] option").evaluate_all("(items) => items.map(o => o.value)"), ["", "system-info"])
                            if screen == "overrides":
                                self.assertIn("103", form.locator("[name=device] option").evaluate_all("(items) => items.map(o => o.value)"))
                                self.assertNotIn("3", form.locator("[name=device] option").evaluate_all("(items) => items.map(o => o.value)"))
                        if screen == "advisor":
                            self.assertEqual(view.locator("#action-tabs").count(), 0)
                            view.locator("#finding-type").select_option("remove_override")
                            visible = view.locator("#advisor-table tbody > tr:visible")
                            self.assertGreater(visible.count(), 0)
                            self.assertTrue(all(x == "remove_override" for x in visible.evaluate_all("(rows) => rows.map(r=>r.dataset.action)")))
                            view.locator("#select-visible").click()
                            self.assertTrue(view.locator("#open-preview").is_disabled())
                            view.locator("#finding-type").select_option("reuse_library")
                            view.locator("#select-visible").click()
                            view.locator("#open-preview").click()
                            self.assertTrue(view.locator("#plan-dialog").is_visible())
                            self.assertEqual(view.locator(".plan-content").evaluate("(el)=>getComputedStyle(el).overflowY"), "auto")
                            self.assertTrue(view.locator("#export-plan").is_enabled())
                            view.keyboard.press("Escape")
                            self.assertFalse(view.locator("#plan-dialog").is_visible())
                            self.assertIn("Bulk review summary", view.locator("#preview").inner_text())
                            # Synthetic conflicting selection: both proposals touch
                            # the same identity at the same scope.
                            view.locator("#finding-type").select_option("")
                            view.locator("#clear-selection").click()
                            view.evaluate("""() => {
                                const checks=[...document.querySelectorAll('.choose:not(:disabled)')];
                                const a=checks[0], b=checks[1];
                                const plan=JSON.parse(a.dataset.plan);
                                a.dataset.plan=JSON.stringify({...plan,action:'reuse_library'});
                                b.dataset.plan=JSON.stringify({...plan,id:'conflicting-test',action:'reuse_library'});
                                a.checked=b.checked=true;
                                a.dispatchEvent(new Event('change'));
                            }""")
                            view.locator("#open-preview").click()
                            self.assertIn("Resolve overlapping proposals", view.locator("#preview").inner_text())
                            self.assertTrue(view.locator("#export-plan").is_disabled())
                            view.keyboard.press("Escape")
                            # Distinct selected proposals connected by observed
                            # effective dependencies are ordered prerequisite first.
                            view.locator("#clear-selection").click()
                            view.evaluate("""() => {
                                const checks=[...document.querySelectorAll('.choose:not(:disabled)')];
                                const a=checks[0], b=checks[1];
                                const plan=JSON.parse(a.dataset.plan);
                                const base={...plan, action:'reuse_library', fallbacks:[], sources:[]};
                                const dep=(source,target)=>({persona:plan.persona,source_module:plan.module,
                                    source,target_module:plan.module,target,status:'observed',
                                    source_view:'effective',device:'Test device'});
                                a.dataset.plan=JSON.stringify({...base,id:'consumer',identity:'consumer',
                                    dependency_review:{dependencies:[dep('consumer','prerequisite')]}});
                                b.dataset.plan=JSON.stringify({...base,id:'prerequisite',identity:'prerequisite',
                                    dependency_review:{dependencies:[]}});
                                a.checked=b.checked=true;a.dispatchEvent(new Event('change'));
                            }""")
                            view.locator("#open-preview").click()
                            self.assertIn("prerequisite", view.locator("#preview").inner_text())
                            phases = view.locator("#preview section > ol > li")
                            self.assertTrue(phases.nth(0).inner_text().index("prerequisite") < phases.nth(0).inner_text().index("consumer"))
                            self.assertTrue(phases.nth(2).inner_text().index("consumer") < phases.nth(2).inner_text().index("prerequisite"))
                            self.assertTrue(view.locator("#export-plan").is_enabled())
                            view.keyboard.press("Escape")
                            view.evaluate("""() => {
                                const checks=[...document.querySelectorAll('.choose:not(:disabled)')];
                                const b=checks[1], plan=JSON.parse(b.dataset.plan);
                                plan.dependency_review.dependencies=[{persona:plan.persona,source_module:plan.module,
                                    source:'prerequisite',target_module:plan.module,target:'consumer',
                                    status:'observed',source_view:'effective',device:'Test device'}];
                                b.dataset.plan=JSON.stringify(plan);b.dispatchEvent(new Event('change'));
                            }""")
                            view.locator("#open-preview").click()
                            self.assertIn("Dependency cycle or blocked order", view.locator("#preview").inner_text())
                            self.assertTrue(view.locator("#export-plan").is_disabled())
                            view.keyboard.press("Escape")
                        self.assertEqual(errors, [])
                        view.set_viewport_size({"width": 390, "height": 844})
                        self.assertLessEqual(view.evaluate("document.documentElement.scrollWidth"), 392)
                        if screen == "overview":
                            view.locator("#workspace-menu").click()
                            self.assertEqual(view.locator("#workspace-menu").get_attribute("aria-expanded"), "true")
                            self.assertTrue(view.locator("#workspace-nav-close").is_visible())
                            view.locator("#workspace-nav-close").click()
                            self.assertEqual(view.locator("#workspace-menu").get_attribute("aria-expanded"), "false")
                        view.close()
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
