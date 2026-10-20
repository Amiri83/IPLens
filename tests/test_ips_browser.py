"""IP List live filter in a real browser (Playwright + Chromium, see test_visual_browser.py
for how the browser is found and when the test is skipped): typing filters without a submit,
the one clear (x) control and Esc reset the search. Placeholders only: 10.0.x.x, example names."""

from __future__ import annotations

import threading

import pytest
from werkzeug import serving

from iplens.db import closing
from iplens.web import create_app
from tests.test_visual_browser import _free_port, browser  # noqa: F401  (fixture)

VPC = "vpc-0example0000001"
SA = "subnet-0000000a"


@pytest.fixture
def server(home, snapshot_builder):
    port = _free_port()
    app = create_app(home, testing=True, port=port)
    db = app.extensions["iplens"]["paths"].db_path
    b = snapshot_builder(db)
    b.vpc(VPC, "10.0.0.0/16")
    b.subnet(SA, VPC, "10.0.1.0/24")
    b.eni("eni-0abc1234", SA, ["10.0.1.10", "10.0.1.11"], owner_ref="i-0abc1234")
    b.eni("eni-0abc5678", SA, ["10.0.1.20"], owner_ref="i-0abc5678")
    with closing(db) as conn:
        conn.execute(
            "UPDATE enis SET instance_id=owner_ref, instance_name=? WHERE eni_id=?",
            ("test-server-a", "eni-0abc1234"),
        )
    srv = serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    thread.join(timeout=10)


def _ips(page) -> list[str]:
    return page.eval_on_selector_all(
        "#ip-results tbody tr td.mono:first-child",
        "tds => tds.map(td => td.firstChild.data.trim())",
    )


def test_ip_search_filters_as_you_type_and_clears(browser, server):  # noqa: F811
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.goto(f"{server}/ips")
    assert _ips(page) == ["10.0.1.10", "10.0.1.11", "10.0.1.20"]
    assert page.is_hidden("#q-clear")
    loads = []
    page.on("load", lambda _p: loads.append(1))

    page.type("#q", "test-server", delay=20)  # no Enter, no button
    page.wait_for_function("document.querySelectorAll('#ip-results tbody tr').length === 2")
    assert _ips(page) == ["10.0.1.10", "10.0.1.11"]
    assert page.is_visible("#q-clear")
    assert "q=test-server" in page.url  # the URL follows (reload / Export keep the search)

    page.click("#q-clear")
    page.wait_for_function("document.querySelectorAll('#ip-results tbody tr').length === 3")
    assert page.input_value("#q") == "" and page.is_hidden("#q-clear")

    page.fill("#q", "10.0.1.20")
    page.wait_for_function("document.querySelectorAll('#ip-results tbody tr').length === 1")
    page.press("#q", "Escape")
    page.wait_for_function("document.querySelectorAll('#ip-results tbody tr').length === 3")

    assert loads == [] and errors == []  # filtered in place, never a page load
    assert page.locator("#ip-filter button", has_text="Cancel").count() == 0
    assert page.locator("#ip-filter button", has_text="Hide").count() == 0
    page.close()
