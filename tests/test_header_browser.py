"""The top menu in a real browser (Playwright + Chromium, see test_visual_browser.py for how
the browser is found and when the test is skipped): at 1200px the header is one row (brand,
menu, context and account switch side by side) and never wider than the window, even with
the MCP badge, the scope indicator, a long account name and wide glyphs; and the "More"
dropdown opens by mouse and keyboard, closes on Escape / outside click, and its links work.
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
LONG_NAME = "example-" + "long-account-" * 6
SHORT_NAME = "example"


@pytest.fixture
def server(request, home, snapshot_builder):
    """The app with one snapshot. The account name is LONG_NAME (the context must truncate,
    not wrap the header) unless the test passes another one with indirect parametrization."""
    port = _free_port()
    app = create_app(home, testing=True, port=port)
    db = app.extensions["iplens"]["paths"].db_path
    with closing(db) as conn:
        conn.execute("UPDATE accounts SET display_name=?", (getattr(request, "param", LONG_NAME),))
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
    p = browser.new_page(viewport={"width": 1200, "height": 800}, device_scale_factor=1)
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
    pageScrollWidth: document.documentElement.scrollWidth,
    brand: box(h.querySelector('.brand')), nav: box(h.querySelector('nav')),
    ctx: box(h.querySelector('.ctx')), account: box(h.querySelector('.account-switch')),
    ctxClipped: h.querySelector('.ctx').scrollWidth > h.querySelector('.ctx').clientWidth,
  };
}"""


# The MCP badge and the scope indicator, same markup as base.html (an MCP server and a scope
# would otherwise have to be set up). The badge has no data-state, so mcp.js never repaints it.
EXTRAS = (
    '<a id="mcp-badge" class="mcp-badge badge ok" href="#" title="MCP server: running">'
    "MCP running · remote</a>"
    '<form class="scope-indicator"><a href="#">scope: 12 filters</a>'
    '<button type="button" class="secondary">clear</button></form>'
)
# CI's Chromium falls back to DejaVu Sans, ~4% wider than the fonts on a typical dev machine,
# and that was enough to overflow a header that fit locally. The worst case pins the header to
# DejaVu Sans (on Ubuntu runners and most Linux installs) and widens it a little more, so it
# is at least as wide as CI's on every machine.
WIDE_FONT = '.shell-header { font-family: "DejaVu Sans", sans-serif; letter-spacing: .02em; }'


def _open(page, url, extras=False, css=""):
    """Load `url` with the extra header markup / CSS written into the HTML itself, so it is
    there from the first layout (no script edits after load, nothing to race), then wait for
    the fonts before anything is measured."""

    def edit(route):
        if route.request.resource_type != "document":
            route.continue_()
            return
        resp = route.fetch()
        html = resp.text()
        if extras:
            switch = '<form class="account-switch"'
            html = html.replace(switch, EXTRAS + switch, 1)
        if css:
            html = html.replace("</head>", f"<style>{css}</style></head>", 1)
        route.fulfill(response=resp, body=html)

    page.route("**/*", edit)
    page.goto(url)
    page.evaluate("document.fonts.ready.then(() => true)")
    if extras:
        assert page.locator(".shell-header #mcp-badge").count() == 1
        assert page.locator(".shell-header .scope-indicator").count() == 1


def _fits(b):
    assert b["header"]["right"] <= 1200, b
    assert b["scrollWidth"] <= b["clientWidth"], b  # nothing pushed past the edge
    assert b["pageScrollWidth"] <= 1200, b  # no horizontal scroll on the page


@pytest.mark.parametrize("path", ["/", "/scope"])
def test_header_is_one_row_at_1200px(page, server, path):
    _open(page, f"{server}{path}")
    b = page.evaluate(BOXES)
    _fits(b)
    assert b["header"]["bottom"] - b["header"]["top"] < 60, b
    # Brand, menu, context and account switch side by side, left to right, on one line.
    parts = [b["brand"], b["nav"], b["ctx"], b["account"]]
    assert all(p["top"] < b["header"]["bottom"] and p["bottom"] > b["header"]["top"] for p in parts)
    assert all(a["right"] <= c["left"] for a, c in zip(parts, parts[1:], strict=False)), b
    assert b["account"]["right"] <= b["header"]["right"]
    assert b["ctxClipped"]  # the long context truncates instead of wrapping


def test_header_stays_one_row_with_mcp_badge_and_scope(page, server):
    """The fullest header: MCP badge and scope indicator as well, with the long account name."""
    _open(page, server, extras=True)
    b = page.evaluate(BOXES)
    _fits(b)
    assert b["header"]["bottom"] - b["header"]["top"] < 60, b
    badge = page.locator("#mcp-badge").bounding_box()
    scope = page.locator(".scope-indicator").bounding_box()
    assert b["ctx"]["right"] <= badge["x"] < scope["x"] < b["account"]["left"]
    assert scope["x"] + scope["width"] <= b["account"]["left"]


# No horizontal overflow at exactly 1200px, case by case. "worst" is everything at once in
# glyphs wider than any fallback font, on the page whose More summary is widest ("Scope").
CASES = {
    "plain": (SHORT_NAME, "/", False, ""),
    "mcp-and-scope": (SHORT_NAME, "/", True, ""),
    "long-account": (LONG_NAME, "/", False, ""),
    "long-account-mcp-and-scope": (LONG_NAME, "/", True, ""),
    "worst": (LONG_NAME, "/scope", True, WIDE_FONT),
}


@pytest.mark.parametrize(
    ("server", "path", "extras", "css"),
    list(CASES.values()),
    ids=list(CASES),
    indirect=["server"],
)
def test_header_never_overflows_at_1200px(page, server, path, extras, css):
    _open(page, f"{server}{path}", extras=extras, css=css)
    b = page.evaluate(BOXES)
    _fits(b)
    assert b["header"]["bottom"] - b["header"]["top"] < 60, b  # still one row
    # Every piece is inside the header and none is squeezed to nothing; brand, menu and the
    # scope indicator are never shrunk (all 9 menu entries stay whole).
    sizes = page.evaluate(
        """() => Array.from(document.querySelector('header.shell-header').children, (el) => {
          const r = el.getBoundingClientRect();
          return {cls: el.className || el.tagName, left: r.left, right: r.right, width: r.width,
                  clipped: el.scrollWidth > el.clientWidth};
        })"""
    )
    for s in sizes:
        assert s["left"] >= 0 and s["right"] <= 1200, sizes
        if s["cls"] != "ctx":
            assert s["width"] >= 32, sizes
        if s["cls"] in ("brand", "NAV", "scope-indicator"):
            assert not s["clipped"], sizes
    entries = page.locator("header nav > a, header nav > details > summary")
    assert entries.count() == 9
    for i in range(9):
        assert entries.nth(i).evaluate("e => e.scrollWidth <= e.clientWidth")


SPACING = """() => { const h = getComputedStyle(document.querySelector('header.shell-header'));
  const a = getComputedStyle(document.querySelector('header nav > a'));
  return [h.columnGap, h.paddingLeft, a.paddingLeft]; }"""


def test_header_spacing_is_only_tightened_from_1200_to_1439px(page, server):
    page.set_viewport_size({"width": 1440, "height": 800})
    _open(page, server, extras=True)
    assert page.evaluate(SPACING) == ["12px", "20px", "14.4px"]  # --sp-3, theme 1.25rem / .9rem
    b = page.evaluate(BOXES)
    assert b["scrollWidth"] <= b["clientWidth"], b
    page.set_viewport_size({"width": 1200, "height": 800})
    assert page.evaluate(SPACING) == ["8px", "16px", "14.4px"]  # --sp-2 / --sp-4; links unchanged


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
