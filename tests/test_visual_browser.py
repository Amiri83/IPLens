"""Visual page in a real browser (Playwright + Chromium). Extended view: changing the layout
lays the diagram out afresh, Fit shows every visible node, and no layout raises. Both views:
the tag filter panel (scope, OR / AND, untagged, containers, presets). Playwright is part of
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


# -- tag filters (IP and Extended view) -----------------------------------------------------

TF_VPC = "vpc-0abc1234"
TF_SUBNETS = ("subnet-a", "subnet-b")
# eni -> (subnet, owner type, tags)
TF_ENIS = {
    "eni-0abc0001": ("subnet-a", "ec2", {"Env": "prod", "Team": "team-a"}),
    "eni-0abc0002": ("subnet-a", "ec2", {"env": "dev", "Team": "team-b"}),
    "eni-0abc0003": ("subnet-a", "ec2", {}),
    "eni-0abc0004": ("subnet-a", "lambda", {"Env": "dev"}),
    "eni-0abc0005": ("subnet-b", "ec2", {"Env": "dev", "Team": "team-a"}),
}


@pytest.fixture
def tf_server(home, snapshot_builder):
    port = _free_port()
    app = create_app(home, testing=True, port=port)
    db = app.extensions["iplens"]["paths"].db_path
    b = snapshot_builder(db)
    b.vpc(TF_VPC, "192.0.2.0/24")
    for i, subnet in enumerate(TF_SUBNETS):
        b.subnet(subnet, TF_VPC, f"192.0.2.{64 * i}/26", name=f"test-subnet-{i}")
    for n, (eni, (subnet, owner, tags)) in enumerate(TF_ENIS.items()):
        lam = owner == "lambda"
        b.eni(
            eni,
            subnet,
            [f"192.0.2.{64 * TF_SUBNETS.index(subnet) + 10 + n}"],
            owner_type=owner,
            owner_ref="fn-a" if lam else "",
            name=f"test-server-{n}",
            instance_id=None if lam else f"i-0abc123{n}",
        )
        for k, v in tags.items():
            b.tag("eni", eni, k, v)
    srv = serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield {"url": f"http://127.0.0.1:{port}", "db": db, "ref": b.account_ref}
    srv.shutdown()
    thread.join(timeout=10)


SHOWN = f"() => {CY}.nodes('.res').filter((n) => n.visible()).map((n) => n.data('eni')).sort()"


def _options(page, selector):
    return page.eval_on_selector_all(f"{selector} option", "os => os.map((o) => o.value)")


def _add_filter(page, type_, key, values=(), untagged=False):
    page.select_option("#tf-type", type_)
    page.fill("#tf-key", key)
    if values:
        page.select_option("#tf-values", list(values))
    if untagged:
        page.check("#tf-untagged")
    page.click("#tf-add")


def _remove_filters(page):
    while page.locator(".tf-chip button").count():
        page.locator(".tf-chip button").first.click()


def test_tag_filters_in_the_ip_view(browser, tf_server):
    page, errors = _open(browser, f"{tf_server['url']}/visual?vpc={TF_VPC}")
    every = sorted(TF_ENIS)
    assert page.evaluate(SHOWN) == every
    assert "EC2: 4 of 4 shown" in page.text_content("#tf-counts")

    # Key suggestions and values come from the tags found on the chosen type.
    page.select_option("#tf-type", "ec2")
    assert _options(page, "#tf-keys") == ["Env", "Team"]  # Env / env are one key
    page.fill("#tf-key", "ENV")
    assert _options(page, "#tf-values") == ["dev", "prod"]

    # Scope: only EC2 is filtered, the Lambda ENI stays; untagged EC2 is hidden.
    _add_filter(page, "ec2", "env", ["prod"])
    assert page.evaluate(SHOWN) == ["eni-0abc0001", "eni-0abc0004"]
    assert page.locator(".tf-chip").count() == 1
    counts = page.text_content("#tf-counts")
    assert "EC2: 1 of 4 shown" in counts and "Lambda: 1 of 1 shown" in counts
    # Containers stay, even subnet-b with nothing left inside.
    for box in ("vpc", "subnet:subnet-a", "subnet:subnet-b"):
        assert page.evaluate(VISIBLE, box), box
    assert page.evaluate(f"() => {CY}.getElementById('subnet:subnet-b').width()") > 0
    page.check("#tf-hide-empty")
    assert not page.evaluate(VISIBLE, "subnet:subnet-b")
    assert page.evaluate(VISIBLE, "subnet:subnet-a") and page.evaluate(VISIBLE, "vpc")
    page.uncheck("#tf-hide-empty")
    assert page.evaluate(VISIBLE, "subnet:subnet-b")

    # OR within a filter, AND with a second filter on the same type.
    _remove_filters(page)
    assert page.evaluate(SHOWN) == every
    _add_filter(page, "ec2", "Env", ["prod", "dev"])
    assert page.evaluate(SHOWN) == ["eni-0abc0001", "eni-0abc0002", "eni-0abc0004", "eni-0abc0005"]
    _add_filter(page, "ec2", "team", ["team-a"])
    assert page.evaluate(SHOWN) == ["eni-0abc0001", "eni-0abc0004", "eni-0abc0005"]

    # Untagged kept on request.
    _remove_filters(page)
    _add_filter(page, "ec2", "Env", ["prod"], untagged=True)
    assert page.evaluate(SHOWN) == ["eni-0abc0001", "eni-0abc0003", "eni-0abc0004"]

    # Hide empty: only subnet-a keeps a resource.
    _remove_filters(page)
    _add_filter(page, "ec2", "Team", ["team-b"])
    _add_filter(page, "lambda", "Env", untagged=True)  # untagged only: hides the tagged one
    assert page.evaluate(SHOWN) == ["eni-0abc0002"]
    page.check("#tf-hide-empty")
    assert page.evaluate(VISIBLE, "vpc") and not page.evaluate(VISIBLE, "subnet:subnet-b")

    # Presets: save, reload the page, load, delete.
    page.fill("#tf-preset-name", "team-b")
    page.click("#tf-save")
    page.wait_for_function("document.querySelectorAll('#tf-preset option').length === 2")
    page.close()
    with closing(tf_server["db"]) as conn:
        (preset,) = viewstate.list_presets(conn, tf_server["ref"])
    assert preset["name"] == "team-b" and preset["hide_empty"] is True
    assert [f["resource_type"] for f in preset["filters"]] == ["ec2", "lambda"]

    page, errors2 = _open(browser, f"{tf_server['url']}/visual?vpc={TF_VPC}")
    assert page.evaluate(SHOWN) == every  # nothing is filtered until a preset is loaded
    page.select_option("#tf-preset", "team-b")
    page.click("#tf-load")
    assert page.evaluate(SHOWN) == ["eni-0abc0002"]
    assert page.is_checked("#tf-hide-empty") and page.locator(".tf-chip").count() == 2
    page.click("#tf-delete")
    page.wait_for_function("document.querySelectorAll('#tf-preset option').length === 1")
    with closing(tf_server["db"]) as conn:
        assert viewstate.list_presets(conn, tf_server["ref"]) == []
    assert errors == [] and errors2 == []
    page.close()


def test_tag_filters_in_the_extended_view(browser, tf_server):
    page, errors = _open(browser, f"{tf_server['url']}/visual?vpc={TF_VPC}&view=extended")
    _add_filter(page, "ec2", "Env", ["dev"])
    assert page.evaluate(SHOWN) == ["eni-0abc0002", "eni-0abc0004", "eni-0abc0005"]
    _add_filter(page, "lambda", "Env", untagged=True)  # untagged only: hides the tagged one
    _add_filter(page, "ec2", "Team", ["team-a"])
    assert page.evaluate(SHOWN) == ["eni-0abc0005"]
    assert page.evaluate(VISIBLE, "subnet:subnet-a")  # nothing left inside, still drawn
    page.check("#tf-hide-empty")
    assert not page.evaluate(VISIBLE, "subnet:subnet-a")
    assert page.evaluate(VISIBLE, "subnet:subnet-b") and page.evaluate(VISIBLE, "vpc")
    assert errors == []
    page.close()
