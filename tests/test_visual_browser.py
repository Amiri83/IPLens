"""Extended view in a real browser (Playwright + Chromium): changing the layout lays the
diagram out afresh, Fit shows every visible node, and no layout raises. Playwright is part of
the ``dev`` extras; its Chromium comes from ``python -m playwright install chromium``, from
``IPLENS_CHROMIUM`` (a Chromium / Chrome for Testing executable) or from
``/opt/pw-browsers/chromium``. Without a browser the test is skipped, unless
``IPLENS_REQUIRE_BROWSER=1`` (CI / QA) turns that into a failure so it never skips silently.
Placeholders only: 10.0.x.x, 123456789012, example names."""

from __future__ import annotations

import os
import socket
import threading

import pytest
from werkzeug import serving

from iplens import viewstate
from iplens.db import closing
from iplens.web import create_app

REQUIRED = os.environ.get("IPLENS_REQUIRE_BROWSER", "") not in ("", "0")
FALLBACK_CHROMIUM = "/opt/pw-browsers/chromium"


def _unavailable(reason: str):
    if REQUIRED:
        pytest.fail(f"IPLENS_REQUIRE_BROWSER is set but {reason}", pytrace=False)
    pytest.skip(reason, allow_module_level=True)


try:
    from playwright import sync_api
except ImportError:
    _unavailable('Playwright is not installed (pip install -e ".[dev]")')

VPC = "vpc-0example0000001"
SUBNETS = ("subnet-0000000a", "subnet-0000000b", "subnet-0000000c")
KEY = viewstate.layout_key(VPC, "extended")
VIEWPORT = {"width": 900, "height": 600}
TOLERANCE = 1.5  # px: rounding of rendered bounding boxes


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _chromium() -> str | None:
    """IPLENS_CHROMIUM, else the system-wide fallback, else Playwright's own download."""
    exe = os.environ.get("IPLENS_CHROMIUM")
    if exe:
        return exe
    if os.path.isfile(FALLBACK_CHROMIUM) and os.access(FALLBACK_CHROMIUM, os.X_OK):
        return FALLBACK_CHROMIUM
    return None


@pytest.fixture(scope="module")
def browser():
    exe = _chromium()
    with sync_api.sync_playwright() as pw:
        try:
            # A small /dev/shm (containers) crashes the renderer otherwise.
            b = pw.chromium.launch(
                executable_path=exe, headless=True, args=["--disable-dev-shm-usage"]
            )
        except Exception as exc:  # no browser downloaded / not runnable here
            _unavailable(f"Chromium is not available: {exc}")
        yield b
        b.close()


def _seed(db, snapshot_builder) -> tuple[int, list[str]]:
    """Three subnets of ENIs (two Lambda ENIs per subnet form a group), regional SQS
    queues (a service group), an SNS topic and an external transit gateway, linked by
    crawled evidence. Returns the account and the ids of the resource nodes."""
    b = snapshot_builder(db)
    b.vpc(VPC, "10.0.0.0/16")
    eni_ids = []
    for s, subnet in enumerate(SUBNETS):
        b.subnet(subnet, VPC, f"10.0.{s + 1}.0/24", name=f"example-subnet-{s}")
        for i in range(6):
            eni = f"eni-0example{s}{i:06d}"
            lam = i < 2
            b.eni(
                eni,
                subnet,
                [f"10.0.{s + 1}.{10 + i}"],
                owner_type="lambda" if lam else "ec2",
                owner_ref="fn-example-a" if lam else "",
                name=f"example-host-{s}-{i}",
            )
            b.tag("eni", eni, "app", f"example-app-{s % 2}")
            eni_ids.append(eni)
    nodes = [("sqs:example-queue-0", "sqs", "regional"), ("sqs:example-queue-1", "sqs", "regional")]
    nodes += [("sqs:example-queue-2", "sqs", "regional"), ("sns:example-topic", "sns", "regional")]
    nodes += [("tgw:tgw-0example0000001", "tgw", "external")]
    edges = [
        (f"eni:{eni_ids[0]}", "sqs:example-queue-0", "configured", "env", "example line"),
        (f"eni:{eni_ids[6]}", "sqs:example-queue-1", "configured", "env", "example line"),
        ("sns:example-topic", f"eni:{eni_ids[12]}", "configured", "sub", "example line"),
        ("sns:example-topic", "sqs:example-queue-2", "configured", "sub", "example line"),
        (f"vpc:{VPC}", "tgw:tgw-0example0000001", "configured", "route", "10.0.0.0/8 to tgw"),
        (f"eni:{eni_ids[3]}", f"eni:{eni_ids[9]}", "configured", "sg", "example line"),
    ]
    with closing(db) as conn:
        conn.executemany(
            "INSERT INTO ext_nodes(snapshot_id, node_id, service, name, arn, area, broad_access) "
            "VALUES(?,?,?,?,?,?,0)",
            [(b.id, nid, svc, nid.split(":", 1)[1], "", area) for nid, svc, area in nodes],
        )
        conn.executemany(
            "INSERT INTO ext_edges(snapshot_id, source, target, evidence, label, detail) "
            "VALUES(?,?,?,?,?,?)",
            [(b.id, *e) for e in edges],
        )
        conn.execute(
            "INSERT INTO ext_crawls(snapshot_id, crawled_at, warnings, sources) VALUES(?,?,?,?)",
            (b.id, "2026-01-01T00:00:00+00:00", "[]", "{}"),
        )
        # Dragged positions saved under Grid: restored on load, never after a layout change.
        positions = {f"res:{e}": {"x": 37.0 * i, "y": 999.0} for i, e in enumerate(eni_ids)}
        viewstate.save_layout(conn, b.account_ref, KEY, positions, "grid")
    return b.account_ref, [f"res:{e}" for e in eni_ids]


@pytest.fixture
def server(home, snapshot_builder):
    port = _free_port()
    app = create_app(home, testing=True, port=port)
    db = app.extensions["iplens"]["paths"].db_path
    ref, res_ids = _seed(db, snapshot_builder)
    srv = serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield {"url": f"http://127.0.0.1:{port}", "db": db, "ref": ref, "res": res_ids}
    srv.shutdown()
    thread.join(timeout=10)


CY = "document.getElementById('cy')._cyreg.cy"
VISIBLE = f"(id) => {CY}.getElementById(id).visible()"
POSITIONS = f"""(ids) => ids.map((id) => {{
  const p = {CY}.getElementById(id).position();
  return [p.x, p.y];
}})"""
# Visible nodes whose rendered box (labels included) leaves the viewport.
OUTSIDE = f"""(tol) => {{
  const cy = {CY};
  const w = cy.width(), h = cy.height();
  return cy.nodes(":visible").filter((n) => {{
    const b = n.renderedBoundingBox({{ includeLabels: true, includeOverlays: false }});
    return b.x1 < -tol || b.y1 < -tol || b.x2 > w + tol || b.y2 > h + tol;
  }}).map((n) => n.id());
}}"""


def _open(browser, url):
    page = browser.new_page(viewport=VIEWPORT)
    errors: list[str] = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.goto(url)
    page.wait_for_function(
        f"document.getElementById('cy')._cyreg && {CY}.nodes('.res').length > 0", timeout=15000
    )
    return page, errors


def _select_layout(page, name: str) -> None:
    page.select_option("#layout", name)
    page.wait_for_timeout(100)
    assert page.is_hidden("#cy-layout-error"), page.text_content("#cy-layout-error")


def _fit_shows_everything(page) -> None:
    # Zoomed in and panned away first, so Fit really has to bring every node back.
    page.evaluate(f"() => {{ {CY}.zoom(3); {CY}.pan({{ x: -4000, y: -4000 }}); }}")
    assert page.evaluate(OUTSIDE, TOLERANCE)  # nodes are off screen now
    page.click("#zoom-fit")
    assert page.evaluate(OUTSIDE, TOLERANCE) == []


@pytest.mark.parametrize(
    "query, lanes",
    [("", False), ("&group=tag&tag=app", True)],
    ids=["boxes", "swimlanes"],
)
def test_extended_layout_change_and_fit(browser, server, query, lanes):
    url = f"{server['url']}/visual?vpc={VPC}&view=extended{query}"
    page, errors = _open(browser, url)
    ids = [i for i in server["res"] if page.evaluate(VISIBLE, i)]
    assert len(ids) >= 6
    assert page.evaluate(f"() => {CY}.nodes('.lane').length > 0") is lanes
    assert page.evaluate(f"() => {CY}.nodes('.ext, .group.svc').length > 0")  # regional nodes
    assert page.input_value("#layout") == "grid"
    saved = {node: [37.0 * i, 999.0] for i, node in enumerate(server["res"])}
    loaded = page.evaluate(POSITIONS, ids)
    if not lanes:  # swimlanes are always laid out afresh
        assert loaded == [saved[i] for i in ids], "saved Grid positions restored on load"

    _select_layout(page, "dagre")
    dagre = page.evaluate(POSITIONS, ids)
    assert dagre != loaded
    _fit_shows_everything(page)

    _select_layout(page, "grid")
    grid = page.evaluate(POSITIONS, ids)
    assert grid != dagre
    assert grid != [saved[i] for i in ids], "a layout change ignores saved positions"
    _fit_shows_everything(page)

    _select_layout(page, "dagre")
    assert page.evaluate(POSITIONS, ids) == dagre  # deterministic, fresh each time
    _fit_shows_everything(page)

    assert errors == []
    page.close()
    # The saved Grid positions are kept on the server.
    with closing(server["db"]) as conn:
        assert viewstate.get_layout(conn, server["ref"], KEY, "grid")
