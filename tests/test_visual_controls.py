"""Visual page controls shared by the IP and Extended views: layout choice (grid by
default) and expanded groups per account and view, and the toolbar wiring in
static/visual.js (source checks, plus a node + vendored cytoscape.js run of the block
layout). Placeholders only."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from iplens import viewstate
from iplens.db import closing, init_db

STATIC = Path(__file__).parent.parent / "iplens" / "static"
VISUAL_JS = STATIC / "visual.js"
VPC = "vpc-0example000000a"


@pytest.fixture
def conn(tmp_path):
    db = tmp_path / "state.db"
    init_db(db)
    with closing(db) as c:
        c.executemany(
            "INSERT INTO accounts(region, auth_mode) VALUES('us-east-1', 'env')", [(), ()]
        )
        yield c


def test_default_layout_is_grid_in_each_view(conn):
    assert viewstate.DEFAULT_LAYOUT == "grid"
    assert list(viewstate.LAYOUTS)[0] == "grid"
    for view in viewstate.VIEWS:
        assert viewstate.get_view_layout(conn, 1, view) == "grid"


def test_layout_and_groups_stored_per_account_and_view(conn):
    viewstate.save_view_layout(conn, 1, "ip", "circle")
    viewstate.save_view_layout(conn, 1, "extended", "dagre")
    viewstate.save_view_layout(conn, 1, "ip", "breadthfirst")  # overwrites
    viewstate.save_prefs(conn, 1, show_legend=False)  # other prefs leave it alone
    assert viewstate.get_view_layout(conn, 1, "ip") == "breadthfirst"
    assert viewstate.get_view_layout(conn, 1, "extended") == "dagre"
    assert viewstate.get_view_layout(conn, 2, "ip") == "grid"
    assert viewstate.get_prefs(conn, 1)["show_legend"] is False
    assert viewstate.get_prefs(conn, 2)["show_legend"] is True

    viewstate.save_expanded(conn, 1, "extended", VPC, ["svc:sqs", "svc:sns", "svc:sqs"])
    assert viewstate.get_expanded(conn, 1, "extended", VPC) == ["svc:sns", "svc:sqs"]
    assert viewstate.get_expanded(conn, 1, "ip", VPC) == []
    assert viewstate.get_expanded(conn, 2, "extended", VPC) == []
    assert viewstate.get_expanded(conn, 1, "extended", "vpc-0example000000b") == []


def test_layout_validation(conn):
    with pytest.raises(ValueError, match="layout"):
        viewstate.save_view_layout(conn, 1, "ip", "spiral")
    with pytest.raises(ValueError, match="view"):
        viewstate.save_view_layout(conn, 1, "other", "grid")
    # A layout that no longer exists falls back to the default.
    conn.execute("INSERT INTO visual_view_prefs VALUES(1, 'ip', 'retired')")
    assert viewstate.get_view_layout(conn, 1, "ip") == "grid"


@pytest.mark.parametrize(
    "raw, error",
    [("nope", "JSON"), ('{"a": 1}', "list"), ("[1]", "group id"), ('[""]', "group id")],
)
def test_parse_expanded_rejects(raw, error):
    with pytest.raises(ValueError, match=error):
        viewstate.parse_expanded(raw)


def test_parse_expanded_dedupes_and_caps():
    assert viewstate.parse_expanded('["b", "a", "b"]') == ["a", "b"]
    assert viewstate.parse_expanded("") == []
    with pytest.raises(ValueError, match="at most"):
        viewstate.parse_expanded(json.dumps([f"g{i}" for i in range(viewstate.MAX_POSITIONS + 1)]))


def test_positions_keyed_per_view():
    assert viewstate.layout_key(VPC, "ip") == VPC
    assert viewstate.layout_key(VPC, "extended") == f"{VPC}:extended"
    assert viewstate.layout_key("", "extended") == ""


def test_positions_saved_per_layout(conn):
    key = viewstate.layout_key(VPC, "extended")
    grid = {"res:eni-0example0000001": {"x": 10.0, "y": 20.0}}
    dagre = {"res:eni-0example0000001": {"x": -5.0, "y": 7.5}}
    viewstate.save_layout(conn, 1, key, grid, "grid")
    viewstate.save_layout(conn, 1, key, dagre, "dagre")  # keeps the Grid positions
    assert viewstate.get_layout(conn, 1, key, "grid") == grid
    assert viewstate.get_layout(conn, 1, key, "dagre") == dagre
    assert viewstate.get_layout(conn, 1, key, "circle") == {}
    assert viewstate.get_layouts(conn, 1, key) == {"grid": grid, "dagre": dagre}
    assert viewstate.get_layout(conn, 2, key, "grid") == {}
    with pytest.raises(ValueError, match="layout"):
        viewstate.save_layout(conn, 1, key, grid, "spiral")
    assert viewstate.reset_layout(conn, 1, key)  # forgets every layout of the view
    assert viewstate.get_layouts(conn, 1, key) == {}


def test_positions_saved_before_layouts_belong_to_the_chosen_layout(conn):
    legacy = {"res:eni-0example0000001": {"x": 1.0, "y": 2.0}}
    conn.execute(
        "INSERT INTO visual_layouts(account_ref, vpc_id, positions) VALUES(1, ?, ?)",
        (VPC, json.dumps(legacy)),
    )
    assert viewstate.get_layout(conn, 1, VPC, "dagre") == legacy
    assert viewstate.get_layouts(conn, 1, VPC, "dagre") == {"dagre": legacy}
    viewstate.save_layout(conn, 1, VPC, {}, "grid")  # the legacy row is upgraded
    assert viewstate.get_layouts(conn, 1, VPC) == {"grid": {}}


# -- visual.js wiring (source checks) -------------------------------------------------------


def _js() -> str:
    return VISUAL_JS.read_text(encoding="utf-8")


def _handler(src: str, element_id: str) -> str:
    """Source of the click / change handler registered on ``element_id``."""
    start = src.index(f'document.getElementById("{element_id}").addEventListener(')
    return src[start : src.index("\n    });", start)]


def test_toolbar_buttons_are_wired_for_both_views():
    src = _js()
    for element_id in ("zoom-in", "zoom-out", "zoom-fit", "expand-all", "collapse-all"):
        assert f'document.getElementById("{element_id}").addEventListener("click"' in src
    # Wired once inside render(), not behind an "if (ext)" / IP-only branch.
    assert "if (ext) {\n      // Click a node" in src
    reset = _handler(src, "reset-layout")
    assert "focusId = null" in reset and "focusReset.disabled = true" in reset
    assert "relayout()" in reset and "fitShown()" in reset
    assert 'layoutSelect.addEventListener("change"' in src
    assert "savePrefs({ view: view, layout: layoutSelect.value })" in src
    assert "expanded: JSON.stringify(Array.from(expandedGroups))" in src
    assert 'savePrefs({ show_legend: showLegendBox.checked ? "1" : "0" })' in src
    # Both views go through the same layout dispatcher.
    assert "const routes = runLayout(cy, edges, drawn);" in src  # Extended view
    assert "\n        runLayout(cy, edges);" in src  # IP view


def test_fit_and_layout_change_wiring():
    src = _js()
    # Fit shows everything; only the page load stops at a readable zoom.
    assert 'getElementById("zoom-fit").addEventListener("click", () => fitShown());' in src
    assert src.count("fitShown(true)") == 1
    assert "if (!firstLoad || !ext ||" in src
    # Saved positions belong to one layout; a layout change lays out afresh.
    assert "if (savedLayout !== layoutSelect.value) return cy.collection();" in src
    change = src[src.index('layoutSelect.addEventListener("change"') :]
    assert change.index("savedLayout = null;") < change.index("relayout();")
    assert "layout: savedLayout, positions: JSON.stringify(saved)" in src
    # A failing layout is logged and shown, not swallowed.
    run = src[src.index("\n  function runLayout(") : src.index("// -- focus (single click)")]
    assert "console.error(" in run and "layoutError.hidden = false" in run
    assert "console.warn(" not in run


# -- block layout run under node with the vendored cytoscape.js ----------------------------

_FUNCTIONS = ("isServiceNode", "shownInLayout", "layoutRank", "byLayoutRank", "gridCells")
_CONSTANTS = (
    "COLS",
    "CELL_W",
    "CELL_H",
    "CELL_GAP",
    "SUBNETS_PER_ROW",
    "BLOCK_GAP_X",
    "BLOCK_GAP_Y",
)

_NODE_SCRIPT = r"""
const fs = require("fs");
const [code, cyPath, dPath] = process.argv.slice(1);
global.window = global;
const cytoscape = require(cyPath);
const D = require(dPath);
eval(fs.readFileSync(code, "utf8"));
const hit = (a, b) => a.x1 < b.x2 && b.x1 < a.x2 && a.y1 < b.y2 && b.y1 < a.y2;
const out = {};
for (const name of ["grid", "circle", "concentric", "breadthfirst"]) {
  for (const lanes of [false, true]) {
    const els = [];
    const add = (id, parent, classes, extra) => els.push({
      data: { id: id, parent: parent, ...extra }, classes: classes,
    });
    const top = lanes ? "lane:0" : undefined;
    const svcParent = lanes ? "lane:1" : undefined;
    if (lanes) {
      add("lane:0", undefined, "lane", { order: 0 });
      add("lane:1", undefined, "lane", { order: 1 });
    }
    add("vpc", top, "vpc", {});
    for (let s = 0; s < 4; s++) {
      add(`subnet:${s}`, "vpc", "subnet", { order: s });
      for (let r = 0; r < 5; r++) add(`res:${s}-${r}`, `subnet:${s}`, "res", { order: r });
    }
    add("subnet:empty", "vpc", "subnet", { order: 9 });
    add("box:svc:sqs", svcParent, "svcbox", {});
    for (let q = 0; q < 4; q++) add(`x:sqs:q${q}`, "box:svc:sqs", "ext", { service: "sqs" });
    for (let q = 0; q < 3; q++) add(`x:sns:t${q}`, svcParent, "ext", { service: "sns" });
    add("x:sqs:gone", "box:svc:sqs", "ext hidden", { service: "sqs" });
    els.push({ data: { id: "e1", source: "x:sns:t0", target: "x:sns:t1" } });
    const cy = cytoscape({
      headless: true, styleEnabled: true, elements: els,
      style: [
        { selector: "node", style: { width: 44, height: 44 } },
        { selector: ":parent", style: { padding: 20 } },
        { selector: ".hidden", style: { display: "none" } },
      ],
    });
    blockLayout(cy, name);
    const bb = (id) => cy.getElementById(id).boundingBox({ useCache: false });
    const boxes = ["subnet:0", "subnet:1", "subnet:2", "subnet:3", "subnet:empty", "box:svc:sqs"];
    const bad = [];
    const check = (a, b) => { if (hit(bb(a), bb(b))) bad.push(`${a}~${b}`); };
    boxes.forEach((a, i) => boxes.slice(i + 1).forEach((b) => check(a, b)));
    ["x:sns:t0", "x:sns:t1", "x:sns:t2"].forEach((id) => {
      boxes.concat(["vpc"]).forEach((b) => check(id, b));
    });
    check("box:svc:sqs", "vpc");
    if (lanes) check("lane:0", "lane:1");
    const finite = cy.nodes().every((n) => Number.isFinite(n.position("x") + n.position("y")));
    out[`${name}${lanes ? "+lanes" : ""}`] = { bad, finite };
  }
}
// cytoscape keeps a timer running: exit once the result is written.
process.stdout.write(JSON.stringify(out), () => process.exit(0));
"""


def _extract(src: str) -> str:
    """The block layout and its helpers out of visual.js, as one script."""
    parts = []
    for name in _CONSTANTS:
        m = re.search(rf"^  const {name} = [^;]+;", src, re.M)
        assert m, name
        parts.append(m.group(0))
    for name in (*_FUNCTIONS, "blockLayout"):
        start = src.index(f"\n  function {name}(") + 1
        end = src.index("\n  }\n", start) + len("\n  }\n")
        parts.append(src[start:end])
    return "\n".join(parts)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_block_layout_keeps_boxes_together(tmp_path):
    script = tmp_path / "block_layout.js"
    script.write_text(_extract(_js()), encoding="utf-8")
    result = subprocess.run(  # noqa: S603 - fixed argv, shipped files only
        [
            shutil.which("node"),
            "-e",
            _NODE_SCRIPT,
            str(script),
            str(STATIC / "vendor" / "cytoscape.min.js"),
            str(STATIC / "declutter.js"),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    got = json.loads(result.stdout)
    assert set(got) == {
        f"{n}{s}" for n in ("grid", "circle", "concentric", "breadthfirst") for s in ("", "+lanes")
    }
    for layout, res in got.items():
        assert res["bad"] == [], layout
        assert res["finite"], layout
