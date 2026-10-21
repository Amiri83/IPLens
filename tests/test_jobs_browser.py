"""Job progress box in a real browser (Playwright + Chromium, see test_visual_browser.py for
how the browser is found and when the test is skipped): once a job has finished, Cancel and
Hide are hidden and only Close is left. The ``hidden`` attribute must win over the
``button`` display rule in style.css. A hidden box stays hidden on other pages and tabs
(the "Discovery running…" badge shows instead), and the hide request survives a page
change (keepalive). "Retry skipped" asks for only the skipped resource types.
Placeholders only: example names, no AWS calls."""

from __future__ import annotations

import threading
from urllib.parse import parse_qs

import pytest
from werkzeug import serving

from iplens.db import closing
from iplens.web import create_app
from tests.test_visual_browser import _free_port, browser  # noqa: F401  (fixture)

WATCH_KEY = "iplens-job-watch"  # jobs.js: the job this tab started
# Records the fetch options of the progress box's hide / show requests.
RECORD_POSTS = """
window.__jobPosts = [];
const realFetch = window.fetch;
window.fetch = (target, options) => {
  const path = String(target).split("/").pop();
  if (path === "hide" || path === "show") {
    window.__jobPosts.push({ path: path, keepalive: Boolean(options && options.keepalive) });
  }
  return realFetch(target, options);
};
"""


@pytest.fixture
def server(home):
    port = _free_port()
    app = create_app(home, testing=True, port=port)
    db = app.extensions["iplens"]["paths"].db_path
    with closing(db) as conn:
        ref = int(
            conn.execute("SELECT value FROM settings WHERE key='active_account'").fetchone()[0]
        )
    job = app.extensions["iplens"]["jobs"].start(
        ref, "crawl", lambda ctx: ctx.message("ok", "Crawled example-service"), background=False
    )
    srv = serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", job["id"]
    srv.shutdown()
    thread.join(timeout=10)


def test_finished_job_hides_cancel_and_hide(browser, server):  # noqa: F811
    base, job_id = server
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    # A job this tab started and that finished meanwhile is shown once more with its result.
    page.add_init_script(f"sessionStorage.setItem({WATCH_KEY!r}, {job_id!r})")
    page.goto(f"{base}/")
    page.wait_for_selector("#job-modal", state="visible")
    page.wait_for_function("document.getElementById('job-state').textContent === 'finished'")

    assert page.is_hidden("#job-cancel")
    assert page.is_hidden("#job-hide")
    assert page.is_visible("#job-close")
    assert errors == []
    page.close()


@pytest.fixture
def skipped_server(home):
    """A finished Refresh-kind job in which one resource type was skipped at its timeout."""
    port = _free_port()
    app = create_app(home, testing=True, port=port)
    db = app.extensions["iplens"]["paths"].db_path
    with closing(db) as conn:
        ref = int(
            conn.execute("SELECT value FROM settings WHERE key='active_account'").fetchone()[0]
        )

    def work(ctx):
        ctx.plan_resources(["ec2:DescribeVpcs", "tag:GetResources"], 120, 900)
        ctx.resource("ec2:DescribeVpcs", "running")
        ctx.resource("ec2:DescribeVpcs", "done")
        ctx.resource("tag:GetResources", "running")
        ctx.resource("tag:GetResources", "skipped", "timeout after 120s")

    job = app.extensions["iplens"]["jobs"].start(ref, "refresh", work, background=False)
    srv = serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", job["id"]
    srv.shutdown()
    thread.join(timeout=10)


def test_refresh_box_shows_limits_resources_and_skipped(browser, skipped_server):  # noqa: F811
    base, job_id = skipped_server
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.add_init_script(f"sessionStorage.setItem({WATCH_KEY!r}, {job_id!r})")
    page.goto(f"{base}/")
    page.wait_for_selector("#job-skipped", state="visible")

    banner = page.text_content("#job-limits")
    assert banner == "Each resource times out after 120s; total limit 15 min — change in Settings"
    assert page.get_attribute("#job-limits a", "href") == "/settings#discovery"
    rows = page.locator("#job-resources tr")
    assert rows.count() == 2
    assert rows.nth(0).text_content() == "ec2:DescribeVpcsdone0s / 120s"
    assert rows.nth(1).text_content() == "tag:GetResourcesskipped (timeout after 120s)0s / 120s"
    assert page.text_content("#job-skipped-list") == "tag:GetResources: timeout after 120s"
    assert page.is_visible("#job-retry")
    assert page.text_content("#job-elapsed").endswith(" / 15 min")
    assert errors == []
    page.close()


def test_retry_skipped_requests_only_the_skipped_types(browser, skipped_server):  # noqa: F811
    base, job_id = skipped_server
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    # Answer the Refresh here: the test checks the request, no job is started.
    page.route(
        f"{base}/refresh",
        lambda route: route.fulfill(status=500, content_type="application/json", body="{}"),
    )
    page.add_init_script(f"sessionStorage.setItem({WATCH_KEY!r}, {job_id!r})")
    page.goto(f"{base}/")
    page.wait_for_selector("#job-retry", state="visible")
    with page.expect_request(lambda r: r.url == f"{base}/refresh") as req:
        page.click("#job-retry")
    form = parse_qs(req.value.post_data)
    assert form["only"] == ["tag:GetResources"]  # not the collected ec2:DescribeVpcs
    assert form["background"] == ["1"]
    assert errors == []
    page.close()


@pytest.fixture
def running_server(home):
    """A server whose account has a Refresh-kind job running until the test ends."""
    port = _free_port()
    app = create_app(home, testing=True, port=port)
    db = app.extensions["iplens"]["paths"].db_path
    with closing(db) as conn:
        ref = int(
            conn.execute("SELECT value FROM settings WHERE key='active_account'").fetchone()[0]
        )
    gate = threading.Event()
    manager = app.extensions["iplens"]["jobs"]
    job = manager.start(ref, "refresh", lambda ctx: gate.wait(60))
    srv = serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    gate.set()
    manager.wait(job["id"], 10)
    srv.shutdown()
    thread.join(timeout=10)


def test_hidden_job_box_stays_hidden_on_another_tab(browser, running_server):  # noqa: F811
    base = running_server
    context = browser.new_context()  # one cookie jar, two tabs
    page = context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.add_init_script(RECORD_POSTS)
    page.goto(f"{base}/")
    page.wait_for_selector("#job-modal", state="visible")
    with page.expect_response(lambda r: r.url.endswith("/hide")):
        page.click("#job-hide")
    assert page.is_hidden("#job-modal")
    # The hide request outlives an immediate navigation to another page.
    assert page.evaluate("window.__jobPosts") == [{"path": "hide", "keepalive": True}]

    # Switch tabs: the box stays hidden and the badge says discovery is running.
    page.goto(f"{base}/ips")
    page.wait_for_selector("#job-badge", state="visible")
    assert page.text_content("#job-badge").startswith("Discovery running…")
    assert page.is_hidden("#job-modal")
    # A second browser tab of the same session follows the server-side state.
    other = context.new_page()
    other.goto(f"{base}/settings")
    other.wait_for_selector("#job-badge", state="visible")
    assert other.is_hidden("#job-modal")

    # The badge reopens it; from then on it shows again on other tabs too.
    with page.expect_response(lambda r: r.url.endswith("/show")):
        page.click("#job-badge")
    assert page.is_visible("#job-modal")
    other.goto(f"{base}/")
    other.wait_for_selector("#job-modal", state="visible")
    assert errors == []
    context.close()
