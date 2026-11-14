"""The top menu in a real browser (Playwright + Chromium, see test_visual_browser.py for how
the browser is found and when the test is skipped): at 1200px the header is one row (brand,
menu, context and account switch side by side), and the "More" dropdown opens by mouse and
keyboard, closes on Escape / outside click, and its links work.
Placeholders only: 10.0.x.x, example names."""

from __future__ import annotations

import threading

import pytest
from werkzeug import serving

from iplens.db import closing
from iplens.web import create_app
from tests.test_visual_browser import _free_port, browser  # noqa: F401  (fixture)

VPC = "vpc-0example0000001"
SA = "subnet-0000000a"
MORE = ["Trends", "Diff", "CIDR Planner", "Scope", "Ownership"]


@pytest.fixture
def server(home, snapshot_builder):
    port = _free_port()
    app = create_app(home, testing=True, port=port)
    db = app.extensions["iplens"]["paths"].db_path
    with closing(db) as conn:
        # A long account name: the context must truncate, not wrap the header.
        conn.execute("UPDATE accounts SET display_name=?", ("example-" + "long-account-" * 6,))
    b = snapshot_builder(db)
    b.vpc(VPC, "10.0.0.0/16")
    b.subnet(SA, VPC, "10.0.1.0/24")
    b.eni("eni-0abc1234", SA, ["10.0.1.10"], owner_ref="i-0123456789abcdef0")
    srv = serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    thread.join(timeout=10)


@pytest.fixture
def page(browser):  # noqa: F811
    p = browser.new_page(viewport={"width": 1200, "height": 800})
    errors: list[str] = []
    p.on("pageerror", lambda exc: errors.append(str(exc)))
    yield p
    assert errors == []
    p.close()


BOXES = """() => {
  const h = document.querySelector('header.shell-header');
  const box = (el) => { const r = el.getBoundingClientRect();
                        return {top: r.top, bottom: r.bottom, left: r.left, right: r.right}; };
  return {
    header: box(h), scrollWidth: h.scrollWidth, clientWidth: h.clientWidth,
    brand: box(h.querySelector('.brand')), nav: box(h.querySelector('nav')),
    ctx: box(h.querySelector('.ctx')), account: box(h.querySelector('.account-switch')),
    ctxClipped: h.querySelector('.ctx').scrollWidth > h.querySelector('.ctx').clientWidth,
  };
}"""


@pytest.mark.parametrize("path", ["/", "/scope"])
def test_header_is_one_row_at_1200px(page, server, path):
    page.goto(f"{server}{path}")
    b = page.evaluate(BOXES)
    assert b["header"]["bottom"] - b["header"]["top"] < 60, b
    assert b["scrollWidth"] <= b["clientWidth"], b  # nothing pushed past the edge
    # Brand, menu, context and account switch side by side, left to right, on one line.
    parts = [b["brand"], b["nav"], b["ctx"], b["account"]]
    assert all(p["top"] < b["header"]["bottom"] and p["bottom"] > b["header"]["top"] for p in parts)
    assert all(a["right"] <= c["left"] for a, c in zip(parts, parts[1:], strict=False)), b
    assert b["account"]["right"] <= b["header"]["right"]
    assert b["ctxClipped"]  # the long context truncates instead of wrapping


def test_header_stays_one_row_with_mcp_badge_and_scope(page, server):
    """The fullest header: MCP badge and scope indicator as well (same markup as base.html,
    added in the page so no MCP server or scope has to be set up)."""
    page.goto(server)
    page.evaluate(
        """() => {
      const sw = document.querySelector('.shell-header .account-switch');
      sw.insertAdjacentHTML('beforebegin',
        '<a id="mcp-badge" class="mcp-badge badge ok" href="#">MCP running · remote</a>' +
        '<form class="scope-indicator"><a href="#">scope: 12 filters</a>' +
        '<button type="button" class="secondary">clear</button></form>');
    }"""
    )
    b = page.evaluate(BOXES)
    assert b["header"]["bottom"] - b["header"]["top"] < 60, b
    assert b["scrollWidth"] <= b["clientWidth"], b
    badge = page.locator("#mcp-badge").bounding_box()
    scope = page.locator(".scope-indicator").bounding_box()
    assert b["ctx"]["right"] <= badge["x"] < scope["x"] < b["account"]["left"]


def test_header_still_wraps_below_1200px(page, server):
    page.set_viewport_size({"width": 900, "height": 800})
    page.goto(server)
    b = page.evaluate(BOXES)
    assert b["account"]["top"] >= b["nav"]["bottom"] - 1  # unchanged: the rest goes below


def test_more_dropdown_by_mouse(page, server):
    page.goto(server)
    more = page.locator("details.nav-more")
    summary = more.locator("summary")
    assert summary.inner_text().startswith("More")
    assert not summary.evaluate("s => s.classList.contains('active')")
    assert not page.is_visible(".nav-more-list a")

    summary.click()
    assert more.evaluate("d => d.open")
    links = more.locator(".nav-more-list a")
    assert links.all_inner_texts() == MORE
    assert all(links.nth(i).is_visible() for i in range(len(MORE)))

    page.click("main")  # outside click closes it
    assert not more.evaluate("d => d.open")

    summary.click()
    summary.click()  # second activation closes it
    assert not more.evaluate("d => d.open")

    summary.click()
    more.locator(".nav-more-list a", has_text="CIDR Planner").click()
    page.wait_for_url("**/cidr-planner")
    # The open grouped page shows in the closed summary (name + accent underline) and in the list.
    summary = page.locator("details.nav-more summary")
    assert "CIDR Planner" in summary.inner_text()
    assert summary.evaluate("s => s.classList.contains('active')")
    accent = page.evaluate(
        "(() => { const d = document.createElement('div'); d.style.color = 'var(--accent)';"
        " document.body.append(d); const c = getComputedStyle(d).color; d.remove(); return c; })()"
    )
    assert summary.evaluate("s => getComputedStyle(s).borderBottomColor") == accent
    page.locator("details.nav-more summary").click()
    current = page.locator('.nav-more-list a[aria-current="page"]')
    assert current.all_inner_texts() == ["CIDR Planner"]
    assert current.evaluate("a => a.classList.contains('active')")


def test_more_dropdown_by_keyboard(page, server):
    page.goto(server)
    summary = page.locator("details.nav-more summary")
    summary.focus()
    page.keyboard.press("Enter")
    assert page.evaluate("document.querySelector('details.nav-more').open")
    # Tab walks through the five items in order.
    seen = []
    for _ in MORE:
        page.keyboard.press("Tab")
        seen.append(page.evaluate("document.activeElement.textContent.trim()"))
    assert seen == MORE
    page.keyboard.press("Escape")
    assert not page.evaluate("document.querySelector('details.nav-more').open")
    assert page.evaluate("document.activeElement.tagName") == "SUMMARY"

    page.keyboard.press("Space")  # open again, then Space closes it (second activation)
    assert page.evaluate("document.querySelector('details.nav-more').open")
    page.keyboard.press("Space")
    assert not page.evaluate("document.querySelector('details.nav-more').open")

    page.keyboard.press("Enter")
    page.keyboard.press("Tab")
    page.keyboard.press("Enter")  # follow "Trends"
    page.wait_for_url("**/trends")


def test_more_dropdown_works_without_javascript(browser, server):  # noqa: F811
    ctx = browser.new_context(java_script_enabled=False, viewport={"width": 1200, "height": 800})
    p = ctx.new_page()
    p.goto(server)
    p.click("details.nav-more summary")
    p.click(".nav-more-list a:text-is('Ownership')")
    p.wait_for_url("**/terraform")
    ctx.close()
