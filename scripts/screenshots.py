"""Capture README screenshots from a running dev server: python scripts/screenshots.py <report-id> [dark|light]"""
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

rid = sys.argv[1]
theme = sys.argv[2] if len(sys.argv) > 2 else "dark"
out = Path(sys.argv[3] if len(sys.argv) > 3 else "docs/screenshots")
out.mkdir(parents=True, exist_ok=True)
base = "http://localhost:5173"
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 1280, "height": 900}, device_scale_factor=2, color_scheme=theme)
    pg = ctx.new_page()
    pg.add_init_script(f"localStorage.setItem('phishlens-theme', '{theme}')")
    pg.goto(base + "/"); pg.wait_for_timeout(700)
    pg.screenshot(path=str(out / f"analyze-{theme}.png"))
    pg.goto(f"{base}/report/{rid}"); pg.wait_for_timeout(900)
    pg.screenshot(path=str(out / f"report-{theme}.png"), full_page=True)
    for tab in ["Headers", "Links", "Sources"]:
        pg.get_by_role("tab", name=tab).first.click(); pg.wait_for_timeout(300)
        pg.screenshot(path=str(out / f"report-{tab.lower()}-{theme}.png"), full_page=True)
    pg.goto(base + "/sources"); pg.wait_for_timeout(600)
    pg.screenshot(path=str(out / f"sources-{theme}.png"), full_page=True)
    m = b.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2, color_scheme=theme).new_page()
    m.add_init_script(f"localStorage.setItem('phishlens-theme', '{theme}')")
    m.goto(f"{base}/report/{rid}"); m.wait_for_timeout(900)
    m.screenshot(path=str(out / f"mobile-{theme}.png"), full_page=True)
    b.close()
print("ok")
