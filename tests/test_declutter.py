"""Extended view decluttering rules (iplens.declutter) and their browser mirror
(static/declutter.js): evidence defaults, one edge per pair, focus neighbourhoods and
merged group edges. Placeholders only."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from iplens import viewstate
from iplens.db import closing, init_db
from iplens.declutter import (
    AGG_MIN,
    DEFAULT_EVIDENCE,
    EDGE_W_MAX,
    edge_width,
    merge_edges,
    neighbourhood,
    parse_evidence,
    service_tier,
)

DECLUTTER_JS = Path(__file__).parent.parent / "iplens" / "static" / "declutter.js"

FN_A, FN_B = "x:lambda:fn-a", "x:lambda:fn-b"
QUEUE_A, QUEUE_B, QUEUE_C = "x:sqs:queue-a", "x:sqs:queue-b", "x:sqs:queue-c"
RULE_A, TOPIC_A, TABLE_A = "x:events:rule-a", "x:sns:topic-a", "x:dynamodb:table-a"


def _edge(source, target, *lines, type_="ext"):
    return {
        "source": source,
        "target": target,
        "type": type_,
        "lines": [{"evidence": ev, "label": label, "text": text} for ev, label, text in lines],
    }


# -- evidence filter defaults --------------------------------------------------------------


def test_default_evidence_is_configured_and_observed():
    assert DEFAULT_EVIDENCE == ("observed", "configured")
    assert parse_evidence(None) == DEFAULT_EVIDENCE
    assert parse_evidence("referenced, observed") == ("observed", "referenced")
    assert parse_evidence("") == ()  # nothing ticked is a valid choice
    with pytest.raises(ValueError, match="guessed"):
        parse_evidence("observed,guessed")


def test_evidence_selection_stored_per_account(tmp_path):
    db = tmp_path / "state.db"
    init_db(db)
    with closing(db) as conn:
        conn.executemany(
            "INSERT INTO accounts(region, auth_mode) VALUES('us-east-1', 'env')", [(), ()]
        )
        assert viewstate.get_evidence(conn, 1) == DEFAULT_EVIDENCE  # no row yet
        viewstate.save_evidence(conn, 1, ("permitted", "observed"))
        viewstate.save_prefs(conn, 1, shorten_names=True)  # other toggles leave it alone
        assert viewstate.get_evidence(conn, 1) == ("observed", "permitted")
        assert viewstate.get_evidence(conn, 2) == DEFAULT_EVIDENCE
        viewstate.save_evidence(conn, 2, ())
        assert viewstate.get_evidence(conn, 2) == ()
        assert viewstate.get_prefs(conn, 1)["shorten_names"] is True


# -- one edge per node pair ----------------------------------------------------------------


def test_dedupe_keeps_strongest_shown_evidence_with_badge_and_all_lines():
    edges = [
        _edge(
            FN_A,
            QUEUE_A,
            ("referenced", "env", "environment variable QUEUE_URL"),
            ("permitted", "IAM", "role role-fn-a allows sqs:SendMessage"),
            ("configured", "trigger", "event source mapping"),
        )
    ]
    [e] = merge_edges(edges, DEFAULT_EVIDENCE)
    assert (e["source"], e["target"]) == (FN_A, QUEUE_A)
    assert e["evidence"] == "configured" and e["label"] == "trigger"
    assert e["count"] == 1 and e["extra"] == 2  # "+2" badge
    # The detail lists every line, strongest first; hidden levels are marked, not dropped.
    assert [ln["evidence"] for ln in e["lines"]] == ["configured", "permitted", "referenced"]
    assert [ln["shown"] for ln in e["lines"]] == [True, False, False]

    # Ticking "permitted" does not change the drawn (strongest) level.
    [e] = merge_edges(edges, ("configured", "permitted"))
    assert e["evidence"] == "configured" and e["extra"] == 2


def test_dedupe_merges_both_directions_into_one_edge():
    edges = [
        _edge(FN_A, QUEUE_A, ("configured", "trigger", "event source mapping")),
        _edge(QUEUE_A, FN_A, ("observed", "X-Ray", "X-Ray service graph: 12 call(s)")),
        _edge("eni-0000000001", FN_A, ("configured", "x", "a base edge"), type_="targets"),
    ]
    out = merge_edges(edges, DEFAULT_EVIDENCE)
    assert len(out) == 2
    pair = next(e for e in out if QUEUE_A in (e["source"], e["target"]))
    # Drawn in the direction of its strongest line, arrows both ways.
    assert (pair["source"], pair["target"]) == (QUEUE_A, FN_A)
    assert pair["evidence"] == "observed" and pair["bidir"] is True
    assert pair["count"] == 1 and pair["extra"] == 1
    assert [ln["reverse"] for ln in pair["lines"]] == [False, True]


def test_pairs_with_only_opt_in_evidence_are_hidden_by_default():
    edges = [
        _edge(FN_A, TABLE_A, ("permitted", "IAM", "role role-fn-a allows dynamodb")),
        _edge(FN_A, TOPIC_A, ("referenced", "env", "environment variable TOPIC_ARN")),
    ]
    assert merge_edges(edges, DEFAULT_EVIDENCE) == []
    shown = merge_edges(edges, ("observed", "configured", "permitted", "referenced"))
    assert {(e["target"], e["evidence"]) for e in shown} == {
        (TABLE_A, "permitted"),
        (TOPIC_A, "referenced"),
    }


# -- focus mode ------------------------------------------------------------------------------


CHAIN = [
    {"source": RULE_A, "target": FN_A},
    {"source": FN_A, "target": QUEUE_A},
    {"source": FN_A, "target": TOPIC_A},
    {"source": QUEUE_A, "target": FN_B},
    {"source": FN_B, "target": TABLE_A},
]


def test_neighbourhood_one_and_two_hops():
    assert neighbourhood(CHAIN, FN_A, 0) == {FN_A}
    assert neighbourhood(CHAIN, FN_A, 1) == {RULE_A, FN_A, QUEUE_A, TOPIC_A}
    assert neighbourhood(CHAIN, FN_A, 2) == {RULE_A, FN_A, QUEUE_A, TOPIC_A, FN_B}
    # Direction is ignored: the target of an edge reaches its source.
    assert neighbourhood(CHAIN, TABLE_A, 1) == {TABLE_A, FN_B}
    assert neighbourhood(CHAIN, "x:sqs:not-drawn", 2) == {"x:sqs:not-drawn"}


# -- aggregation -------------------------------------------------------------------------------


GROUPS = {
    "eni-0000000001": "group:subnet:subnet-0000000a:lambda",
    "eni-0000000002": "group:subnet:subnet-0000000a:lambda",
    "eni-0000000003": "group:subnet:subnet-0000000a:lambda",
    QUEUE_A: "svc:sqs",
    QUEUE_B: "svc:sqs",
    QUEUE_C: "svc:sqs",
}


def _grouped(node_id):
    return GROUPS.get(node_id, node_id)


def test_edges_between_collapsed_groups_merge_with_count_and_width():
    conf = ("configured", "trigger", "event source mapping")
    edges = [
        _edge("eni-0000000001", QUEUE_A, conf),
        _edge("eni-0000000001", QUEUE_B, conf, ("permitted", "IAM", "role allows sqs")),
        _edge("eni-0000000002", QUEUE_B, conf),
        _edge("eni-0000000003", QUEUE_C, conf),
        _edge(QUEUE_C, "eni-0000000002", ("observed", "X-Ray", "X-Ray service graph")),
        _edge("eni-0000000001", "eni-0000000002", conf),  # inside one group: not drawn
        _edge("eni-0000000003", TABLE_A, conf),  # to an ungrouped node: its own edge
    ]
    out = merge_edges(edges, DEFAULT_EVIDENCE, _grouped)
    assert len(out) == 2
    group_edge = next(e for e in out if e["target"] != TABLE_A and e["source"] != TABLE_A)
    assert {group_edge["source"], group_edge["target"]} == {
        "group:subnet:subnet-0000000a:lambda",
        "svc:sqs",
    }
    assert group_edge["count"] == 5  # member pairs behind the one drawn edge
    assert group_edge["width"] == edge_width(5) > edge_width(1)
    assert group_edge["evidence"] == "observed"
    assert len(group_edge["lines"]) == 6 and group_edge["extra"] == 1
    single = next(e for e in out if TABLE_A in (e["source"], e["target"]))
    assert single["count"] == 1 and single["width"] == edge_width(1)
    assert edge_width(1000) == EDGE_W_MAX
    assert AGG_MIN == 2


def test_service_tiers_run_sources_compute_targets():
    assert service_tier("events") == service_tier("apigateway") == 0
    assert service_tier("lambda") == service_tier("ecs") == 1
    assert service_tier("sqs") == service_tier("dynamodb") == service_tier("tgw") == 2
    # SNS / S3 are a source when they feed compute, else a target.
    assert service_tier("sns", feeds_compute=True) == service_tier("s3", True) == 0
    assert service_tier("sns") == service_tier("s3") == 2


# -- the browser mirror agrees ------------------------------------------------------------------

_NODE_SCRIPT = """
const D = require(process.argv[1]);
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
const map = input.groups;
const endpoint = (id) => (Object.prototype.hasOwnProperty.call(map, id) ? map[id] : id);
const out = input.cases.map((c) => ({
  merged: D.mergeEdges(c.edges, c.levels, c.grouped ? endpoint : undefined),
}));
const hood = input.hops.map(([s, n]) => Array.from(D.neighbourhood(input.chain, s, n)).sort());
const tiers = input.tiers.map(([s, f]) => D.serviceTier(s, f));
process.stdout.write(JSON.stringify({ out, hood, tiers, defaults: D.DEFAULT_EVIDENCE,
  aggMin: D.AGG_MIN, widths: [1, 3, 100].map(D.edgeWidth) }));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_declutter_js_mirrors_python():
    conf = ("configured", "trigger", "event source mapping")
    cases = [
        {
            "edges": [
                _edge(FN_A, QUEUE_A, ("referenced", "env", "env"), ("configured", "t", "esm")),
                _edge(QUEUE_A, FN_A, ("observed", "X-Ray", "X-Ray service graph")),
                _edge(FN_A, TABLE_A, ("permitted", "IAM", "role allows dynamodb")),
            ],
            "levels": list(DEFAULT_EVIDENCE),
            "grouped": False,
        },
        {
            "edges": [
                _edge("eni-0000000001", QUEUE_A, conf),
                _edge("eni-0000000002", QUEUE_B, conf, ("permitted", "IAM", "allows sqs")),
                _edge("eni-0000000003", QUEUE_C, conf),
                _edge("eni-0000000001", "eni-0000000002", conf),
            ],
            "levels": ["configured", "permitted"],
            "grouped": True,
        },
    ]
    hops = [[FN_A, 1], [FN_A, 2], [TABLE_A, 1]]
    tiers = [["events", False], ["lambda", False], ["sns", True], ["sns", False], ["sqs", False]]
    payload = {"cases": cases, "groups": GROUPS, "chain": CHAIN, "hops": hops, "tiers": tiers}
    result = subprocess.run(  # noqa: S603 - fixed argv, local test fixture only
        [shutil.which("node"), "-e", _NODE_SCRIPT, str(DECLUTTER_JS)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    js = json.loads(result.stdout)
    for case, got in zip(cases, js["out"], strict=True):
        endpoint = _grouped if case["grouped"] else None
        assert got["merged"] == merge_edges(case["edges"], case["levels"], endpoint)
    assert js["hood"] == [sorted(neighbourhood(CHAIN, s, n)) for s, n in hops]
    assert js["tiers"] == [service_tier(s, f) for s, f in tiers]
    assert tuple(js["defaults"]) == DEFAULT_EVIDENCE and js["aggMin"] == AGG_MIN
    assert js["widths"] == [edge_width(n) for n in (1, 3, 100)]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("script", ["visual.js", "declutter.js"])
def test_visual_scripts_parse(script):
    path = DECLUTTER_JS.parent / script
    result = subprocess.run(  # noqa: S603 - fixed argv, shipped file
        [shutil.which("node"), "--check", str(path)], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
