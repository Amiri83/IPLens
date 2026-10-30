"""Visual page in a real browser (Playwright + Chromium). Extended view: changing the layout
lays the diagram out afresh, Fit shows every visible node, and no layout raises. Logical view:
one node per resource, no IPs, merged edges, the comma-separated name filter. Every view:
the tag filter panel (scope, OR / AND, untagged, containers, presets). Playwright is part of
the ``dev`` extras; its Chromium comes from ``python -m playwright install chromium``, from
``IPLENS_CHROMIUM`` (a Chromium / Chrome for Testing executable) or from
``/opt/pw-browsers/chromium``. Without a browser the test is skipped, unless
``IPLENS_REQUIRE_BROWSER=1`` (CI / QA) turns that into a failure so it never skips silently.
Placeholders only: 10.0.x.x, 123456789012, example names."""

from __future__ import annotations

import json
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


def _value_boxes(page, checked=None):
    """Values of the tag value checkboxes (only the (un)checked ones with ``checked``)."""
    return page.eval_on_selector_all(
        "#tf-values-list input[type=checkbox]",
        "(bs, c) => bs.filter((b) => c === null || b.checked === c).map((b) => b.value)",
        checked,
    )


def _value_label(page, value):
    return page.locator("#tf-values-list label.tf-value").filter(
        has=page.locator(f'input[value="{value}"]')
    )


def _add_filter(page, key, values=(), untagged=False):
    page.fill("#tf-key", key)
    for v in values:
        _value_label(page, v).click()  # a plain click on the row toggles the value
    if untagged:
        page.check("#tf-untagged")
    page.click("#tf-add")


def _remove_filters(page):
    while page.locator(".tf-chip button").count():
        page.locator(".tf-chip button").first.click()


def _name_filter(page, text):
    page.fill("#tf-name", text)
    page.press("#tf-name", "Enter")  # applies at once (else after a short pause)


def test_tag_filters_in_the_ip_view(browser, tf_server):
    page, errors = _open(browser, f"{tf_server['url']}/visual?vpc={TF_VPC}")
    every = sorted(TF_ENIS)
    assert page.evaluate(SHOWN) == every
    counts = page.text_content("#tf-counts")
    assert "All: 5 of 5 shown" in counts and "EC2: 4 of 4 shown" in counts
    assert page.locator("#tf-type").count() == 0  # no resource type picker

    # Key suggestions and values come from the tags found on every resource.
    assert _options(page, "#tf-keys") == ["Env", "Team"]  # Env / env are one key
    page.fill("#tf-key", "ENV")
    assert _value_boxes(page) == ["dev", "prod"]

    # A filter applies to every type: the Lambda ENI (Env=dev) goes too.
    _add_filter(page, "env", ["prod"])
    assert page.evaluate(SHOWN) == ["eni-0abc0001"]
    assert page.locator(".tf-chip").count() == 1
    assert page.text_content(".tf-chip").startswith("Env = prod")  # the key as found
    counts = page.text_content("#tf-counts")
    assert "All: 1 of 5 shown" in counts
    assert "EC2: 1 of 4 shown" in counts and "Lambda: 0 of 1 shown" in counts
    # Containers stay, even subnet-b with nothing left inside.
    for box in ("vpc", "subnet:subnet-a", "subnet:subnet-b"):
        assert page.evaluate(VISIBLE, box), box
    assert page.evaluate(f"() => {CY}.getElementById('subnet:subnet-b').width()") > 0
    page.check("#tf-hide-empty")
    assert not page.evaluate(VISIBLE, "subnet:subnet-b")
    assert page.evaluate(VISIBLE, "subnet:subnet-a") and page.evaluate(VISIBLE, "vpc")
    page.uncheck("#tf-hide-empty")
    assert page.evaluate(VISIBLE, "subnet:subnet-b")

    # OR within a filter, AND with a second filter.
    _remove_filters(page)
    assert page.evaluate(SHOWN) == every
    _add_filter(page, "Env", ["prod", "dev"])
    assert page.evaluate(SHOWN) == ["eni-0abc0001", "eni-0abc0002", "eni-0abc0004", "eni-0abc0005"]
    _add_filter(page, "team", ["team-a"])
    assert page.evaluate(SHOWN) == ["eni-0abc0001", "eni-0abc0005"]  # the Lambda has no Team

    # Untagged kept on request.
    _remove_filters(page)
    _add_filter(page, "Env", ["prod"], untagged=True)
    assert page.evaluate(SHOWN) == ["eni-0abc0001", "eni-0abc0003"]

    # Name filter: comma-separated terms, any case, name or ENI id; a chip; AND with tags.
    _remove_filters(page)
    _name_filter(page, "server-1, SERVER-4")
    assert page.evaluate(SHOWN) == ["eni-0abc0002", "eni-0abc0005"]
    assert page.text_content(".tf-chip").startswith("name: server-1 | server-4")
    assert "All: 2 of 5 shown" in page.text_content("#tf-counts")
    _add_filter(page, "Team", ["team-a"])
    assert page.evaluate(SHOWN) == ["eni-0abc0005"]
    _remove_filters(page)
    assert page.input_value("#tf-name") == "" and page.evaluate(SHOWN) == every
    _name_filter(page, "0ABC0003")
    assert page.evaluate(SHOWN) == ["eni-0abc0003"]
    page.fill("#tf-name", "")  # applied after a short pause, without Enter
    page.wait_for_function(f"({SHOWN})().length === 5")

    # Hide empty: only subnet-a keeps a resource.
    _add_filter(page, "Team", ["team-b", "team-a"])
    _name_filter(page, "server-1, server-4")
    _add_filter(page, "Env", ["dev"])
    assert page.evaluate(SHOWN) == ["eni-0abc0002", "eni-0abc0005"]
    _remove_filters(page)
    _add_filter(page, "Team", ["team-b"])
    _name_filter(page, "server")
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
    assert preset["filters"] == [
        {"tag_key": "Team", "values": ["team-b"], "include_untagged": False}
    ]
    assert preset["name_filter"] == "server"

    page, errors2 = _open(browser, f"{tf_server['url']}/visual?vpc={TF_VPC}")
    assert page.evaluate(SHOWN) == every  # nothing is filtered until a preset is loaded
    page.select_option("#tf-preset", "team-b")
    page.click("#tf-load")
    assert page.evaluate(SHOWN) == ["eni-0abc0002"]
    assert page.is_checked("#tf-hide-empty") and page.locator(".tf-chip").count() == 2
    assert page.input_value("#tf-name") == "server"
    page.click("#tf-delete")
    page.wait_for_function("document.querySelectorAll('#tf-preset option').length === 1")
    with closing(tf_server["db"]) as conn:
        assert viewstate.list_presets(conn, tf_server["ref"]) == []
    assert errors == [] and errors2 == []
    page.close()


def test_tag_filters_in_the_extended_view(browser, tf_server):
    page, errors = _open(browser, f"{tf_server['url']}/visual?vpc={TF_VPC}&view=extended")
    _add_filter(page, "Env", ["dev"])
    assert page.evaluate(SHOWN) == ["eni-0abc0002", "eni-0abc0004", "eni-0abc0005"]
    _name_filter(page, "server-3, server-4")
    assert page.evaluate(SHOWN) == ["eni-0abc0004", "eni-0abc0005"]
    _add_filter(page, "Team", ["team-a"])
    assert page.evaluate(SHOWN) == ["eni-0abc0005"]
    assert "All: 1 of 5 shown" in page.text_content("#tf-counts")
    assert page.evaluate(VISIBLE, "subnet:subnet-a")  # nothing left inside, still drawn
    page.check("#tf-hide-empty")
    assert not page.evaluate(VISIBLE, "subnet:subnet-a")
    assert page.evaluate(VISIBLE, "subnet:subnet-b") and page.evaluate(VISIBLE, "vpc")
    assert errors == []
    page.close()


# -- Logical view ------------------------------------------------------------------------------


@pytest.fixture
def logical_server(home, snapshot_builder):
    from tests.test_logical import seed

    port = _free_port()
    app = create_app(home, testing=True, port=port)
    db = app.extensions["iplens"]["paths"].db_path
    seed(db, snapshot_builder)
    srv = serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    thread.join(timeout=10)


SHOWN_IDS = f"() => {CY}.nodes('.res').filter((n) => n.visible()).map((n) => n.id()).sort()"
LABEL = f"(id) => {CY}.getElementById(id).data('label')"


def test_logical_view(browser, logical_server):
    from tests.test_logical import VPC as LG_VPC

    page, errors = _open(browser, f"{logical_server}/visual?vpc={LG_VPC}&view=logical")
    every = sorted(
        f"res:{n}"
        for n in (
            "elb:lb-a",
            "nat:nat-a",
            "lambda:fn-a",
            "ecs:cluster-a/svc-a",
            "ec2:i-0abc1234",
            "eni:eni-0abc0051",
            "eni:eni-0abc0052",
        )
    )
    assert page.evaluate(SHOWN_IDS) == every
    assert page.evaluate(f"() => {CY}.nodes('.subnet').length") == 0
    # Name, type and AZ count; no IPs.
    assert page.evaluate(LABEL, "res:lambda:fn-a") == "fn-a\nLambda\n3 AZ"
    assert page.evaluate(LABEL, "res:nat:nat-a") == "nat-a\nNAT gateway\n1 AZ"
    no_ips = "(n) => !/192\\.0\\.2\\./.test(n.data('label') + n.data('title'))"
    assert page.evaluate(f"() => {CY}.nodes('.res').every({no_ips})")
    # One line per merged connection (LB→targets, ECS→LB ticked by default).
    edges = page.evaluate(
        f"() => {CY}.edges().map((e) => [e.data('etype'), e.source().id(), e.target().id()]).sort()"
    )
    assert edges == [
        ["ecs_lb", "res:ecs:cluster-a/svc-a", "res:elb:lb-a"],
        ["targets", "res:elb:lb-a", "res:ec2:i-0abc1234"],
        ["targets", "res:elb:lb-a", "res:lambda:fn-a"],
    ]
    assert "7 logical resource(s) from 12 ENI(s) in 3 AZ(s)" in page.text_content("#cy-status")

    # The multi-term name filter: "," = OR, "+" = AND, trimmed, any case, empty terms ignored.
    _name_filter(page, "FN-A , nat-a")
    assert page.evaluate(SHOWN_IDS) == ["res:lambda:fn-a", "res:nat:nat-a"]
    # "+" = AND, binding tighter than ",": (Env=dev AND Lambda) OR nat-a.
    assert page.text_content("#tf-name-hint") == ", = OR\xa0\xa0+ = AND"
    _name_filter(page, "dev + LAMBDA, nat-a")
    assert page.evaluate(SHOWN_IDS) == ["res:lambda:fn-a", "res:nat:nat-a"]
    assert "name: dev + lambda | nat-a" in page.text_content("#tf-chips")
    _name_filter(page, "dev+nat")
    assert page.evaluate(SHOWN_IDS) == []
    _name_filter(page, "fn-a,,")
    assert page.evaluate(SHOWN_IDS) == ["res:lambda:fn-a"]
    assert page.evaluate(f"() => {CY}.edges(':visible').length") == 0  # its LB is hidden
    assert "All: 1 of 7 shown" in page.text_content("#tf-counts")
    page.check("#tf-hide-empty")
    assert page.evaluate(VISIBLE, "vpc")
    _name_filter(page, "nothing-matches")
    assert not page.evaluate(VISIBLE, "vpc")
    _name_filter(page, "")
    # The children of a box shown again can take a frame to report visible.
    page.wait_for_function(f"() => ({SHOWN_IDS})().length === {len(every)}", timeout=3000)
    assert page.evaluate(SHOWN_IDS) == every

    for name in ("dagre", "circle", "grid"):
        _select_layout(page, name)
        _fit_shows_everything(page)
    assert errors == []
    page.close()


def test_tag_values_checkbox_list(browser, tf_server):
    """Plain clicks toggle values (no Ctrl / Cmd); Select all / Select none."""
    page, errors = _open(browser, f"{tf_server['url']}/visual?vpc={TF_VPC}")
    assert page.is_disabled("#tf-values-all") and page.is_disabled("#tf-values-none")
    page.fill("#tf-key", "Team")
    assert _value_boxes(page) == ["team-a", "team-b"]
    _value_label(page, "team-a").click()
    _value_label(page, "team-b").click()  # a second plain click adds, never replaces
    assert _value_boxes(page, True) == ["team-a", "team-b"]
    _value_label(page, "team-a").click()  # and a click again removes
    assert _value_boxes(page, True) == ["team-b"]
    page.click("#tf-values-none")
    assert _value_boxes(page, True) == [] and page.is_disabled("#tf-add")
    page.click("#tf-values-all")
    assert _value_boxes(page, True) == ["team-a", "team-b"] and page.is_enabled("#tf-add")
    page.click("#tf-add")
    assert page.evaluate(SHOWN) == ["eni-0abc0001", "eni-0abc0002", "eni-0abc0005"]
    assert _value_boxes(page, True) == []  # cleared for the next filter
    assert errors == []
    page.close()


def test_tag_values_checkbox_list_on_a_touch_screen(browser, tf_server):
    """Mobile: taps toggle values, and every value row is a large enough target."""
    ctx = browser.new_context(
        viewport={"width": 390, "height": 844}, has_touch=True, is_mobile=True
    )
    page = ctx.new_page()
    page.goto(f"{tf_server['url']}/visual?vpc={TF_VPC}")
    page.wait_for_function(
        f"document.getElementById('cy')._cyreg && {CY}.nodes('.res').length > 0", timeout=15000
    )
    page.fill("#tf-key", "Env")
    for value in ("dev", "prod"):
        row = _value_label(page, value)
        assert row.bounding_box()["height"] >= 44 - TOLERANCE  # touch target
        row.tap()
    assert _value_boxes(page, True) == ["dev", "prod"]
    _value_label(page, "dev").tap()
    assert _value_boxes(page, True) == ["prod"]
    assert page.locator("#tf-values-all").bounding_box()["height"] >= 44 - TOLERANCE
    page.tap("#tf-add")
    assert page.evaluate(SHOWN) == ["eni-0abc0001"]
    ctx.close()


# -- shared Lambda ENI and Transit Gateways (IP view) ---------------------------------------

FX_VPC = "vpc-0abc5678"
FX_TGW = "tgw-0abc1234"
FX_SHARED = "eni-0abc0010"  # shared by fn-a (Env=dev, first owner) and fn-b (Env=uat)
FX_DEV = "eni-0abc0011"  # fn-a only
FX_ATT_ENI = "eni-0abc0012"  # the Transit Gateway attachment's ENI
FX_ATT = "tgw-attach-0abc1234"
FX_RTB = "rtb-0abc1234"
PROPAGATION = "TGW route table tgw-rtb-0abc1234 learns routes propagated from the VPC"


def _fx_server(home, snapshot_builder, param):
    """A shared Lambda ENI, and from discovery a Transit Gateway attachment (its ENI) and
    subnet-a's route table routing 198.51.100.0/24 to the TGW. ``param``: ``crawl`` (None:
    no Extended crawl, else its warnings; the crawl repeats the attachment and route and
    adds a propagation) and ``found`` (the snapshot's own warnings)."""
    port = _free_port()
    app = create_app(home, testing=True, port=port)
    db = app.extensions["iplens"]["paths"].db_path
    b = snapshot_builder(db)
    b.vpc(FX_VPC, "192.0.2.0/24").subnet("subnet-a", FX_VPC, "192.0.2.0/26", name="test-subnet")
    b.eni(FX_SHARED, "subnet-a", ["192.0.2.10"], owner_type="lambda", owner_ref="fn-a")
    b.eni(FX_DEV, "subnet-a", ["192.0.2.11"], owner_type="lambda", owner_ref="fn-a")
    b.eni(FX_ATT_ENI, "subnet-a", ["192.0.2.12"], owner_type="tgw_attachment", owner_ref=FX_ATT)
    b.tag("lambda", "fn-a", "Env", "dev").tag("lambda", "fn-b", "Env", "uat")
    with closing(db) as conn:
        conn.execute(
            "UPDATE enis SET owner_names=? WHERE eni_id=?", ('["fn-a", "fn-b"]', FX_SHARED)
        )
        conn.execute(
            "UPDATE snapshots SET warnings=? WHERE id=?", (json.dumps(param["found"]), b.id)
        )
        conn.execute(
            "INSERT INTO tgw_attachments VALUES(?,?,?,?,?,?)",
            (b.id, FX_ATT, FX_TGW, "vpc", FX_VPC, "available"),
        )
        conn.execute(
            "INSERT INTO route_tables VALUES(?,?,?,?,?)", (b.id, FX_RTB, FX_VPC, 0, '["subnet-a"]')
        )
        conn.execute(
            "INSERT INTO tgw_routes VALUES(?,?,?,?,?)",
            (b.id, FX_RTB, "198.51.100.0/24", FX_TGW, "active"),
        )
        if param["crawl"] is not None:
            lines = [
                ("route", f"route table {FX_RTB} (subnet-a): 198.51.100.0/24 → {FX_TGW}"),
                ("attachment", f"TGW attachment {FX_ATT} (vpc {FX_VPC}, available)"),
                ("propagation", PROPAGATION),
            ]
            conn.executemany(
                "INSERT INTO ext_edges(snapshot_id, source, target, evidence, label, detail) "
                "VALUES(?,?,?,?,?,?)",
                [(b.id, f"vpc:{FX_VPC}", f"tgw:{FX_TGW}", "configured", *ln) for ln in lines],
            )
            conn.execute(
                "INSERT INTO ext_crawls(snapshot_id, crawled_at, warnings, sources) "
                "VALUES(?,?,?,?)",
                (b.id, "2026-01-01T00:00:00+00:00", json.dumps(param["crawl"]), "{}"),
            )
    srv = serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread, f"http://127.0.0.1:{port}"


@pytest.fixture
def fx_server(request, home, snapshot_builder):
    srv, thread, url = _fx_server(home, snapshot_builder, request.param)
    yield url
    srv.shutdown()
    thread.join(timeout=10)


CRAWLED = {"crawl": [], "found": []}
NO_CRAWL = {"crawl": None, "found": []}


@pytest.mark.parametrize("fx_server", [CRAWLED], indirect=True)
def test_shared_lambda_eni_matches_any_owner(browser, fx_server):
    page, errors = _open(browser, f"{fx_server}/visual?vpc={FX_VPC}")
    page.fill("#tf-key", "Env")
    assert _value_boxes(page) == ["dev", "uat"]  # uat comes from the second owner only
    _add_filter(page, "Env", ["uat"])
    assert page.evaluate(SHOWN) == [FX_SHARED]
    _remove_filters(page)
    _add_filter(page, "Env", ["dev"])
    assert page.evaluate(SHOWN) == [FX_SHARED, FX_DEV]
    # The name filter matches every owner's name, not only the first one shown.
    _remove_filters(page)
    _name_filter(page, "FN-B")
    assert page.evaluate(SHOWN) == [FX_SHARED]
    assert errors == []
    page.close()


TGW_NODE = f"x:tgw:{FX_TGW}"
OUTSIDE_VPC = f"""() => {{
  const cy = {CY};
  const vpc = cy.getElementById('vpc').boundingBox({{ includeLabels: false }});
  const gw = cy.getElementById('{TGW_NODE}');
  const b = gw.boundingBox({{ includeLabels: false }});
  return gw.parent().empty() && (b.x1 > vpc.x2 || b.x2 < vpc.x1 || b.y1 > vpc.y2 || b.y2 < vpc.y1);
}}"""


TGW_EDGES = f"""() => {CY}.edges('.edge-tgw')
  .map((e) => [e.source().id(), e.target().id(), e.data('label'), e.data('title')])
  .sort((a, b) => (a[0] < b[0] ? -1 : 1))"""
ATT_EDGE = [f"res:{FX_ATT_ENI}", TGW_NODE, f"{FX_ATT} · available"]
ROUTE_EDGE = [
    "subnet:subnet-a",
    TGW_NODE,
    "route",
    f"[route] route table {FX_RTB}: 198.51.100.0/24 → {FX_TGW}",
]


def _click_edge(page, selector):
    mid = page.evaluate(f"() => {CY}.edges('{selector}').renderedMidpoint()")
    page.locator("#cy").scroll_into_view_if_needed()
    box = page.locator("#cy").bounding_box()
    page.mouse.click(box["x"] + mid["x"], box["y"] + mid["y"])
    page.wait_for_selector("#cy-tip:not([hidden])")
    return page.text_content("#cy-tip")


@pytest.mark.parametrize("fx_server", [NO_CRAWL], indirect=True)
def test_transit_gateway_links_without_a_crawl(browser, fx_server):
    """Discovery alone: one TGW node outside the VPC box, an edge from the attachment ENI
    (its own type and icon) and one from the subnet routing to the TGW."""
    page, errors = _open(browser, f"{fx_server}/visual?vpc={FX_VPC}")
    assert page.evaluate(VISIBLE, TGW_NODE)
    assert page.evaluate(f"() => {CY}.nodes('.tgw').length") == 1
    edges = page.evaluate(TGW_EDGES)
    assert [e[:3] for e in edges] == [ATT_EDGE, ROUTE_EDGE[:3]]
    assert edges[1][3] == ROUTE_EDGE[3]
    att = f"() => {CY}.getElementById('res:{FX_ATT_ENI}').data()"
    assert page.evaluate(att + ".iconFile") == "ext/tgw-attachment.svg"
    assert page.evaluate(att + ".raw.type") == "tgw_attachment"
    assert "TGW attachment: 1 of 1 shown" in page.text_content("#tf-counts")
    for layout in ("grid", "dagre", "grid"):
        _select_layout(page, layout)
        assert page.evaluate(OUTSIDE_VPC), layout
    # The subnet edge's tooltip: destination and route table.
    assert "198.51.100.0/24" in _click_edge(page, '[source = "subnet:subnet-a"]')
    # The note offers what the crawl adds; nothing was denied.
    assert page.is_visible("#tgw-note")
    assert page.text_content("#tgw-note") == (
        "Run Extended crawl to also see Transit Gateway route table propagations"
    )
    # A filtered-out attachment ENI takes its edge along; the TGW node stays.
    _name_filter(page, "fn-")
    assert [e[0] for e in page.evaluate(TGW_EDGES)] == ["subnet:subnet-a"]
    assert page.evaluate(VISIBLE, TGW_NODE)
    assert errors == []
    page.close()


@pytest.mark.parametrize("fx_server", [CRAWLED], indirect=True)
def test_transit_gateway_outside_the_vpc_in_the_ip_view(browser, fx_server):
    """With a crawl: discovery's edges, plus a VPC edge with only what the crawl adds."""
    page, errors = _open(browser, f"{fx_server}/visual?vpc={FX_VPC}")
    assert page.evaluate(VISIBLE, TGW_NODE)
    edges = page.evaluate(TGW_EDGES)
    assert [e[:3] for e in edges] == [
        ATT_EDGE,
        ROUTE_EDGE[:3],
        ["vpc", TGW_NODE, "propagation"],
    ]
    assert edges[2][3] == f"[propagation] {PROPAGATION}"  # no duplicate route / attachment
    for layout in ("grid", "dagre", "circle", "grid"):
        _select_layout(page, layout)
        assert page.evaluate(OUTSIDE_VPC), layout
    _fit_shows_everything(page)
    # Click (or tap) an edge: its lines in the tooltip.
    assert "propagation] TGW route table" in _click_edge(page, '[source = "vpc"]')
    assert page.is_hidden("#tgw-note")  # crawled, nothing denied
    with page.expect_download() as dl:  # the export accepts the TGW node and edges
        page.click("#export-svg")
    assert dl.value.suggested_filename.endswith(".svg")
    assert errors == []
    page.close()


@pytest.mark.parametrize(
    "fx_server",
    [
        {
            "crawl": [
                "ec2:DescribeTransitGatewayAttachments skipped (AccessDenied)",
                "xray: other",
            ],
            "found": ["ec2:DescribeRouteTables skipped (UnauthorizedOperation)"],
        }
    ],
    indirect=True,
)
def test_transit_gateway_note_lists_denied_calls(browser, fx_server):
    page, errors = _open(browser, f"{fx_server}/visual?vpc={FX_VPC}")
    assert page.is_visible("#tgw-note")
    note = page.text_content("#tgw-note")
    assert "discovery was denied" in note and "the Extended crawl was denied" in note
    items = page.eval_on_selector_all("#tgw-note li", "ls => ls.map((li) => li.textContent)")
    assert items == [
        "ec2:DescribeRouteTables skipped (UnauthorizedOperation)",
        "ec2:DescribeTransitGatewayAttachments skipped (AccessDenied)",
    ]
    assert page.evaluate(VISIBLE, TGW_NODE)  # what was found is still drawn
    assert errors == []
    page.close()


# -- Effective access ------------------------------------------------------------------------


@pytest.fixture
def access_server(home, snapshot_builder):
    """fn-a (Lambda) and service-a (ECS) towards an ECR endpoint (2 AZ) that admits only
    the ECS tasks (tests/test_access.py)."""
    from tests.test_access import _endpoint_snapshot

    port = _free_port()
    app = create_app(home, testing=True, port=port)
    _endpoint_snapshot(app.extensions["iplens"]["paths"].db_path, snapshot_builder)
    srv = serving.make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    thread.join(timeout=10)


REACH = f"""() => {CY}.edges('.edge-reach')
  .map((e) => [e.source().id(), e.target().id(), e.hasClass('blocked')]).sort()"""


def test_show_blocked_toggle(browser, access_server):
    from tests.test_access import ECR_API, FN, TASK
    from tests.test_access import VPC as AC_VPC

    page, errors = _open(browser, f"{access_server}/visual?vpc={AC_VPC}")
    # Default: effective connections only.
    assert not page.is_checked("#show-blocked")
    assert page.evaluate(REACH) == [[f"res:{TASK}", f"res:{ECR_API}", False]]
    assert page.text_content("[data-edge-count='reach']") == "(1 · 1 blocked)"

    page.check("#show-blocked")
    assert page.evaluate(REACH) == [
        [f"res:{FN}", f"res:{ECR_API}", True],
        [f"res:{TASK}", f"res:{ECR_API}", False],
    ]
    assert "blocked=1" in page.url
    style = page.evaluate(
        f"() => {{ const e = {CY}.edges('.blocked'); "
        "return [e.style('line-style'), e.style('line-color')]; }"
    )
    assert style == ["dashed", "rgb(198,40,40)"]
    # A click on the blocked edge shows which rule blocked it.
    mid = page.evaluate(f"() => {CY}.edges('.blocked').renderedMidpoint()")
    page.locator("#cy").scroll_into_view_if_needed()
    box = page.locator("#cy").bounding_box()
    page.mouse.click(box["x"] + mid["x"], box["y"] + mid["y"])
    page.wait_for_selector("#edge-detail:not([hidden])")
    assert "blocked" in page.text_content("#edge-detail-title")
    assert "blocked by ingress: no rule of sg-00ecrapi" in page.text_content("#edge-detail-lines")

    page.uncheck("#show-blocked")
    assert len(page.evaluate(REACH)) == 1 and "blocked=1" not in page.url
    # The Multi-AZ badge in the IP view: the endpoint has an ENI in two AZs.
    assert "\n2 AZ\n" in page.evaluate(LABEL, f"res:{ECR_API}")
    assert "AZ" not in page.evaluate(LABEL, f"res:{FN}")
    # The ECS edge is unverified (no Extended crawl: route and IAM not checked).
    assert page.evaluate(f"() => {CY}.edges('.edge-reach.unverified').length") == 1
    assert errors == []
    page.close()

    # The Logical view draws the same: one effective edge, the blocked one on request.
    page, errors = _open(browser, f"{access_server}/visual?vpc={AC_VPC}&view=logical&blocked=1")
    assert page.is_checked("#show-blocked")
    assert page.evaluate(REACH) == [
        ["res:ecs:cluster-a/service-a", "res:vpc_endpoint:vpce-0example0001", False],
        ["res:lambda:fn-a", "res:vpc_endpoint:vpce-0example0001", True],
    ]
    assert page.evaluate(LABEL, "res:vpc_endpoint:vpce-0example0001").endswith("\n2 AZ")
    assert errors == []
    page.close()


def test_unverified_edges_and_verified_only(browser, access_server):
    from tests.test_access import ECR_API, TASK
    from tests.test_access import VPC as AC_VPC

    page, errors = _open(browser, f"{access_server}/visual?vpc={AC_VPC}")
    # No Extended crawl: the banner, and the effective edge is drawn dashed grey.
    assert "IAM not checked – run Extended crawl" in page.text_content("#iam-banner")
    assert page.evaluate(REACH) == [[f"res:{TASK}", f"res:{ECR_API}", False]]
    style = page.evaluate(
        f"() => {{ const e = {CY}.edges('.unverified'); "
        "return [e.length, e.style('line-style'), e.style('line-color')]; }"
    )
    assert style == [1, "dashed", "rgb(158,158,158)"]
    # A tap lists the layers not checked.
    page.evaluate(f"() => {{ {CY}.edges('.unverified').emit('onetap'); return true; }}")
    page.wait_for_selector("#edge-detail:not([hidden])")
    assert "unverified" in page.text_content("#edge-detail-title")
    assert "Unverified: route not checked, IAM not checked" in page.text_content(
        "#edge-detail-lines"
    )

    # Verified only: nothing here is fully verified.
    page.check("#verified-only")
    assert page.evaluate(REACH) == []
    assert "verified=1" in page.url
    page.uncheck("#verified-only")
    assert len(page.evaluate(REACH)) == 1 and "verified=1" not in page.url
    assert errors == []
    page.close()
