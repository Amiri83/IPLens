"""Job progress box in a real browser (Playwright + Chromium, see test_visual_browser.py for
how the browser is found and when the test is skipped): once a job has finished, Cancel and
Hide are hidden and only Close is left. The ``hidden`` attribute must win over the
``button`` display rule in style.css. Placeholders only: example names, no AWS calls."""

from __future__ import annotations

import threading

import pytest
from werkzeug import serving

from iplens.db import closing
from iplens.web import create_app
from tests.test_visual_browser import _free_port, browser  # noqa: F401  (fixture)

WATCH_KEY = "iplens-job-watch"  # jobs.js: the job this tab started


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
