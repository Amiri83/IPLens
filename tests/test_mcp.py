"""``iplens mcp``: the read-only MCP tools against a fixture database, redaction, the
server wiring and the guarantee that the MCP code path never talks to AWS or writes.

All data is synthetic: documentation address ranges (192.0.2.0/24, 198.51.100.0/24), the
AWS documentation account id and made-up resource ids / names.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from iplens import fitcheck, mcptools
from iplens import rules as rules_mod
from iplens.checkcli import main as check_main
from iplens.db import closing, init_db
from iplens.mcptools import Redactor, ToolInputError, Tools, unique_labels
from tests.conftest import SnapshotBuilder, add_test_account, ip_range

ACCOUNT_ID = "123456789012"
OTHER_ACCOUNT_ID = "210987654321"
VPC_A, VPC_B = "vpc-0000000a", "vpc-0000000b"
SUBNET_A, SUBNET_B, SUBNET_C = "subnet-0000000a", "subnet-0000000b", "subnet-0000000c"
SG = "sg-0000000a"
INSTANCE = "i-0abc1234"
LAMBDA_ARN = f"arn:aws:lambda:us-east-1:{ACCOUNT_ID}:function:fn-a"

# Every tool with arguments that succeed against the fixture database.
ALL_CALLS = [
    ("list_subnets", {}),
    ("find_subnet", {"need_ips": 20}),
    ("subnet_detail", {"subnet": SUBNET_A}),
    ("lookup_ip", {"ip": "192.0.2.12"}),
    ("lookup_ip", {"ip": "192.0.2.70"}),
    ("changes", {}),
    ("fit_check", {"subnet": SUBNET_A, "need": 5}),
    ("suggestions", {}),
]


def _set_account(db: Path, ref: int, name: str, aws_id: str) -> None:
    with closing(db) as conn:
        conn.execute(
            "UPDATE accounts SET display_name=?, aws_account_id=?, last_seen_account_id=? "
            "WHERE id=?",
            (name, aws_id, aws_id, ref),
        )


def _base(b: SnapshotBuilder) -> SnapshotBuilder:
    return (
        b.vpc(VPC_A, "192.0.2.0/24", name="test-vpc-a")
        .vpc(VPC_B, "198.51.100.0/24", name="test-vpc-b")
        .subnet(SUBNET_A, VPC_A, "192.0.2.0/26", "us-east-1a", name="test-subnet-a")
        .subnet(SUBNET_B, VPC_A, "192.0.2.64/26", "us-east-1b", name="test-subnet-b")
        .subnet(SUBNET_C, VPC_B, "198.51.100.0/28", "us-east-1a", name="test-subnet-c")
    )


def build_db(db: Path) -> None:
    """Two snapshots of one account: the latest adds an ALB, a Lambda ENI, an idle ENI
    filling most of a /28 and an ASG that can scale out."""
    ref = add_test_account(db) if not _accounts(db) else _accounts(db)[0]
    _set_account(db, ref, "test-account", ACCOUNT_ID)
    now = datetime.now(UTC)
    old = _base(SnapshotBuilder(db, taken_at=now - timedelta(days=2), account_id=ACCOUNT_ID))
    old.eni(
        "eni-0000000a",
        SUBNET_A,
        ["192.0.2.10", "192.0.2.11"],
        instance_id=INSTANCE,
        instance_name="test-server-a",
    )
    new = _base(SnapshotBuilder(db, taken_at=now, account_id=ACCOUNT_ID))
    new.security_group(SG, name="test-sg-a", vpc_id=VPC_A)
    new.eni(
        "eni-0000000a",
        SUBNET_A,
        ["192.0.2.10", "192.0.2.11", "192.0.2.12"],
        instance_id=INSTANCE,
        instance_name="test-server-a",
    )
    new.eni("eni-0000000b", SUBNET_A, ["192.0.2.20"], owner_type="elb", owner_ref="alb-a")
    new.load_balancer("alb-a", VPC_A)
    new.eni(
        "eni-0000000c",
        SUBNET_B,
        ["192.0.2.70"],
        owner_type="lambda",
        owner_ref="fn-a",
        sgs=(SG,),
        description=f"AWS Lambda VPC ENI-fn-a {LAMBDA_ARN}",
    )
    new.eni(
        "eni-0000000d",
        SUBNET_C,
        ip_range("198.51.100.0", 4, 9),
        status="available",
        description="detached",
    )
    with closing(db) as conn:
        conn.execute(
            "INSERT INTO asgs(snapshot_id, name, min_size, desired, max_size, subnet_ids, "
            "instances) VALUES(?, 'asg-a', 0, 0, 10, ?, '[]')",
            (new.id, json.dumps([SUBNET_B])),
        )


def _accounts(db: Path) -> list[int]:
    with closing(db) as conn:
        return [r["id"] for r in conn.execute("SELECT id FROM accounts ORDER BY id")]


@pytest.fixture
def mcp_home(tmp_path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    init_db(home / "iplens.db")
    build_db(home / "iplens.db")
    return home


@pytest.fixture
def db(mcp_home) -> Path:
    return mcp_home / "iplens.db"


@pytest.fixture
def tools(db) -> Tools:
    return Tools(db)


def _latest_taken_at(db: Path) -> str:
    with closing(db) as conn:
        return conn.execute("SELECT taken_at FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()[0]


# -- the tools ------------------------------------------------------------------------------


def test_every_result_carries_its_snapshot(tools, db):
    taken = _latest_taken_at(db)
    for name, args in ALL_CALLS:
        out = tools.call(name, **args)
        assert out["snapshot_taken_at"] == taken, name
        assert out["snapshot"]["taken_at"] == taken
        assert out["snapshot"]["account"] == "test-account"
        assert out["snapshot"]["account_id"] == ACCOUNT_ID
        assert out["redacted"] is False
        json.dumps(out)  # plain JSON


def test_list_subnets(tools):
    out = tools.call("list_subnets")
    assert out["total"] == 3 and out["next_offset"] is None
    by_id = {s["id"]: s for s in out["items"]}
    a = by_id[SUBNET_A]
    assert (a["name"], a["cidr"], a["az"], a["vpc"]) == (
        "test-subnet-a",
        "192.0.2.0/26",
        "us-east-1a",
        VPC_A,
    )
    assert (a["usable"], a["used"], a["idle"], a["free"]) == (59, 4, 0, 55)
    # The ALB reserves 8 IPs at max scale.
    assert a["headroom"] == {
        "status": "ok",
        "demand_at_max_scale": 8,
        "left_at_max_scale": 47,
        "left_pct": 79.7,
    }
    c = by_id[SUBNET_C]
    assert (c["used"], c["idle"], c["free"]) == (0, 9, 2)
    assert c["headroom"]["status"] == "tight"


def test_list_subnets_filters_and_pages(tools):
    assert [s["id"] for s in tools.call("list_subnets", vpc=VPC_B)["items"]] == [SUBNET_C]
    by_name = tools.call("list_subnets", vpc="test-vpc-a")
    assert {s["id"] for s in by_name["items"]} == {SUBNET_A, SUBNET_B}
    assert by_name["filters"]["vpc"] == VPC_A
    assert {s["id"] for s in tools.call("list_subnets", az="us-east-1a")["items"]} == {
        SUBNET_A,
        SUBNET_C,
    }
    first = tools.call("list_subnets", limit=2)
    assert (len(first["items"]), first["next_offset"]) == (2, 2)
    rest = tools.call("list_subnets", limit=2, offset=first["next_offset"])
    assert len(rest["items"]) == 1 and rest["next_offset"] is None
    seen = [s["id"] for s in first["items"] + rest["items"]]
    assert sorted(seen) == sorted([SUBNET_A, SUBNET_B, SUBNET_C])
    with pytest.raises(ToolInputError, match="no VPC"):
        tools.call("list_subnets", vpc="vpc-0000000f")


def test_find_subnet_best_first(tools):
    out = tools.call("find_subnet", need_ips=20)
    # b: 58 free - 10 (ASG max) - 20 = 28; a: 55 - 8 (ALB) - 20 = 27; c: 2 free, no fit.
    assert [(f["id"], f["headroom_left"]) for f in out["items"]] == [
        (SUBNET_B, 28),
        (SUBNET_A, 27),
    ]
    assert out["items"][0]["headroom_demand"] == 10
    assert [f["id"] for f in tools.call("find_subnet", need_ips=48)["items"]] == [SUBNET_B]
    assert tools.call("find_subnet", need_ips=49)["items"] == []
    assert [f["id"] for f in tools.call("find_subnet", need_ips=1, vpc=VPC_B)["items"]] == [
        SUBNET_C
    ]
    assert [f["id"] for f in tools.call("find_subnet", need_ips=1, az="us-east-1b")["items"]] == [
        SUBNET_B
    ]
    with pytest.raises(ToolInputError, match="need must be"):
        tools.call("find_subnet", need_ips=-1)


def test_subnet_detail(tools):
    out = tools.call("subnet_detail", subnet="test-subnet-a")  # by name
    assert out["subnet"]["id"] == SUBNET_A
    assert out["usage"]["used"] == 4 and out["usage"]["free"] == 55
    top = out["top_consumers"]["items"]
    assert top[0]["resource"] == "test-server-a" and top[0]["ips"] == 3 and top[0]["enis"] == 1
    assert top[1]["resource"] == "alb-a" and top[1]["ips"] == 1
    hr = out["headroom"]
    assert hr["status"] == "ok"
    assert hr["contributors"] == [
        {
            "kind": "alb",
            "name": "alb-a",
            "ips": 8,
            "assumption": "8 IPs per ALB per subnet",
        }
    ]
    fc = out["forecast"]
    assert fc["status"] == "insufficient" and fc["points"] == 2
    assert tools.call("subnet_detail", subnet=SUBNET_B)["headroom"]["contributors"][0]["name"] == (
        "asg-a"
    )
    with pytest.raises(ToolInputError, match="no subnet"):
        tools.call("subnet_detail", subnet="subnet-0000000f")


def test_lookup_ip(tools):
    used = tools.call("lookup_ip", ip="192.0.2.12")
    assert used["state"] == "used"
    (m,) = used["matches"]
    assert m["eni_id"] == "eni-0000000a"
    assert m["resource"] == "test-server-a" and m["instance_id"] == INSTANCE
    assert m["subnet"] == {"id": SUBNET_A, "name": "test-subnet-a"}
    assert m["vpc"] == VPC_A and m["type"] == "EC2"
    lam = tools.call("lookup_ip", ip="192.0.2.70")["matches"][0]
    assert lam["owner_type"] == "lambda" and lam["security_groups"] == [SG]
    assert tools.call("lookup_ip", ip="198.51.100.5")["state"] == "idle"
    free = tools.call("lookup_ip", ip="192.0.2.30")
    assert free["state"] == "free" and free["subnet"]["id"] == SUBNET_A
    assert tools.call("lookup_ip", ip="192.0.2.1")["state"] == "reserved"
    assert tools.call("lookup_ip", ip="192.0.2.63")["state"] == "reserved"
    assert tools.call("lookup_ip", ip="203.0.113.5")["state"] == "not-in-any-subnet"
    with pytest.raises(ToolInputError, match="not an IPv4"):
        tools.call("lookup_ip", ip="not-an-ip")


def test_changes(tools, db):
    out = tools.call("changes")
    with closing(db) as conn:
        old_id, new_id = [r[0] for r in conn.execute("SELECT id FROM snapshots ORDER BY id")]
    assert (out["from"]["id"], out["to"]["id"]) == (old_id, new_id)
    t = out["totals"]
    assert t["ip_delta"] == 12  # 2 IPs before, 14 now
    assert (t["enis_added"], t["enis_changed"], t["enis_removed"]) == (3, 1, 0)
    deltas = {s["id"]: s["delta"] for s in out["subnets"]["items"]}
    assert deltas == {SUBNET_C: 9, SUBNET_A: 2, SUBNET_B: 1}
    assert out["top_consumers"][0]["new"] == 9
    kinds = {c["eni_id"]: c["kind"] for c in out["eni_changes"]["items"]}
    assert kinds["eni-0000000a"] == "changed" and kinds["eni-0000000d"] == "added"
    # The same diff by snapshot id and by date.
    assert tools.call("changes", since=str(old_id))["totals"] == t
    day_ago = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    assert tools.call("changes", since=day_ago)["totals"] == t
    assert tools.call("changes", limit=1)["subnets"]["total"] == 3
    for bad in ("latest-2", "latest-0", str(new_id), "yesterday"):
        with pytest.raises(ToolInputError):
            tools.call("changes", since=bad)


def test_changes_needs_two_snapshots(tmp_path):
    db = tmp_path / "one.db"
    init_db(db)
    add_test_account(db)
    _base(SnapshotBuilder(db, account_id=ACCOUNT_ID))
    with pytest.raises(ToolInputError, match="fewer than two"):
        Tools(db).call("changes")


def test_fit_check_reuses_iplens_check(tools, db, tmp_path, capsys):
    fits = tools.call("fit_check", subnet=SUBNET_A, need=47)
    assert fits["result"] == "fits" and fits["exit_code"] == 0
    (row,) = fits["subnets"]
    assert (row["free"], row["headroom_demand"], row["plan_demand"], row["left"]) == (55, 8, 47, 0)
    short = tools.call("fit_check", subnet="test-subnet-a", need=48)
    assert short["result"] == "does-not-fit" and short["subnets"][0]["status"] == "short"
    low = tools.call("fit_check", subnet=SUBNET_A, need=47, min_free_pct=10)
    assert low["subnets"][0]["status"] == "below-min"
    assert tools.call("fit_check", subnet=SUBNET_B, need=48)["result"] == "fits"
    no_surge = tools.call("fit_check", subnet=SUBNET_B, need=48, include_surge=False)
    assert no_surge["include_surge"] is False

    # Same numbers as `iplens check` on the CI snapshot export of the same snapshot.
    with closing(db) as conn:
        snap = conn.execute("SELECT * FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
        doc = fitcheck.export_snapshot(conn, snap)
    path = tmp_path / "ci.json"
    path.write_text(json.dumps(doc))
    argv = ["--subnet", SUBNET_A, "--need", "48", "--snapshot", str(path), "--format", "json"]
    assert check_main(argv) == 1
    cli = json.loads(capsys.readouterr().out)
    assert cli["subnets"] == short["subnets"]
    assert (cli["result"], cli["exit_code"]) == (short["result"], short["exit_code"])

    with pytest.raises(ToolInputError, match="no subnet"):
        tools.call("fit_check", subnet="subnet-0000000f", need=1)
    with pytest.raises(ToolInputError, match="min_free_pct"):
        tools.call("fit_check", subnet=SUBNET_A, need=1, min_free_pct=101)


def test_fit_check_applies_saved_rules(tools, db):
    with closing(db) as conn:
        rules_mod.save_rule(
            conn,
            rules_mod.Rule(
                name="keep-a-free", kind="subnet_reserved", params={"subnet_ids": [SUBNET_A]}
            ),
        )
    out = tools.call("fit_check", subnet=SUBNET_A, need=1)
    assert out["result"] == "does-not-fit"
    assert out["violations"][0]["rule"] == "keep-a-free"


def _week_of_history(tmp_path: Path) -> Path:
    """A database whose detached ENI (in test-subnet-c) already was 6.5 days ago."""
    db = tmp_path / "week.db"
    init_db(db)
    _set_account(db, add_test_account(db), "test-account", ACCOUNT_ID)
    now = datetime.now(UTC)
    for taken_at in (now - timedelta(days=6.5), now):
        b = _base(SnapshotBuilder(db, taken_at=taken_at, account_id=ACCOUNT_ID))
        b.eni(
            "eni-0000000d",
            SUBNET_C,
            ip_range("198.51.100.0", 4, 3),
            status="available",
            description="test-scratch",
        )
    return db


def test_suggestions_tool(tools, tmp_path):
    # Two days of history: no detached ENI suggestion yet, a note says why.
    out = tools.call("suggestions")
    assert not [s for s in out["items"] if s["kind"] == "detached_eni"]
    assert any(
        n.startswith("Detached ENIs (1 detached now): not checked yet") for n in out["notes"]
    )

    out = Tools(_week_of_history(tmp_path)).call("suggestions", kind="detached_eni")
    assert out["filters"] == {"kind": "detached_eni", "include_blocked": True}
    (s,) = out["items"]
    assert s["title"] == "Delete detached ENI eni-0000000d" and s["ips_saved"] == 3
    assert s["status"] == "allowed" and s["blocked_by"] == []
    since = (datetime.now(UTC) - timedelta(days=6.5)).strftime("%Y-%m-%d")
    assert s["since"] == since and f"detached since {since}" in s["detail"]
    assert out["ips_saved"]["allowed"] >= 3

    with pytest.raises(ToolInputError, match="unknown kind 'nope'"):
        tools.call("suggestions", kind="nope")
    with pytest.raises(ToolInputError, match="endpoint_days must be 1 to 365"):
        tools.call("suggestions", endpoint_days=0)


def test_suggestions_tool_applies_rules_and_redacts(tmp_path):
    db = _week_of_history(tmp_path)
    with closing(db) as conn:
        rules_mod.save_rule(
            conn,
            rules_mod.Rule(
                name="keep-scratch", kind="protected_eni", params={"pattern": "scratch"}
            ),
        )
    out = Tools(db, redact=True).call("suggestions", kind="detached_eni")
    (s,) = out["items"]
    assert s["status"] == "blocked" and s["blocked_by"][0]["rule"] == "keep-scratch"
    assert s["title"] == "Delete detached ENI <eni>" and s["eni_ids"] == ["<eni>"]
    assert s["subnets"] == ["test-subnet-c"]
    assert not LEAKS.search(json.dumps(out, ensure_ascii=False))
    allowed = Tools(db).call("suggestions", include_blocked=False)["items"]
    assert all(i["status"] == "allowed" for i in allowed)
    assert not [i for i in allowed if i["kind"] == "detached_eni"]


def _endpoint_history(tmp_path: Path, runs: tuple[tuple[int, int], ...]) -> Path:
    """An idle interface endpoint in test-vpc-a and one flow log query (days ago,
    minutes) per older daily snapshot."""
    db = tmp_path / f"endpoints-{len(runs)}.db"
    init_db(db)
    _set_account(db, add_test_account(db), "test-account", ACCOUNT_ID)
    now = datetime.now(UTC)
    for days_ago, minutes in (*runs, (0, 0)):
        b = _base(
            SnapshotBuilder(db, taken_at=now - timedelta(days=days_ago), account_id=ACCOUNT_ID)
        )
        b.eni("eni-000000e1", SUBNET_A, ["192.0.2.40"], owner_type="vpc_endpoint")
        b.endpoint(
            "vpce-000000001", VPC_A, "com.amazonaws.us-east-1.kms", [SUBNET_A], ["eni-000000e1"]
        )
        if minutes:
            ran_at = (now - timedelta(days=days_ago)).replace(hour=12, minute=0, second=0)
            with closing(db) as conn:
                conn.execute(
                    "INSERT INTO flow_runs(snapshot_id, vpc_id, ran_at, window_minutes, rows) "
                    "VALUES(?,?,?,?,0)",
                    (b.id, VPC_A, ran_at.isoformat(timespec="seconds"), minutes),
                )
    return db


def test_suggestions_tool_unused_endpoint_coverage(tmp_path):
    out = Tools(_endpoint_history(tmp_path, ((1, 60),)), redact=True).call(
        "suggestions", kind="unused_endpoint"
    )
    assert out["items"] == []
    assert (
        "Unused endpoints in test-vpc-a: not enough flow log coverage "
        "(1h over 1 day, need 24h over 3 days)"
    ) in out["notes"]
    assert not LEAKS.search(json.dumps(out, ensure_ascii=False))

    db = _endpoint_history(tmp_path, ((3, 480), (2, 480), (1, 480)))
    out = Tools(db, redact=True).call("suggestions", kind="unused_endpoint")
    (s,) = out["items"]
    assert s["title"].startswith("Possibly unused interface endpoint ")
    assert "covering 24h over 3 days" in s["detail"] and s["eni_ids"] == ["<eni>"]
    assert not LEAKS.search(json.dumps(out, ensure_ascii=False))


def test_account_selection(db):
    other = add_test_account(db)  # also becomes the active account in the UI
    _set_account(db, other, "test-account-b", OTHER_ACCOUNT_ID)
    (
        SnapshotBuilder(db, account_ref=other, account_id=OTHER_ACCOUNT_ID)
        .vpc("vpc-0000000c", "192.0.2.128/25", name="test-vpc-c")
        .subnet("subnet-0000000d", "vpc-0000000c", "192.0.2.128/26", name="test-subnet-d")
    )
    first = _accounts(db)[0]

    def subnets(account):
        return [s["id"] for s in Tools(db, account).call("list_subnets")["items"]]

    assert subnets(None) == ["subnet-0000000d"]  # the UI's active account
    mine = {SUBNET_A, SUBNET_B, SUBNET_C}
    assert set(subnets(str(first))) == mine
    assert set(subnets("test-account")) == mine
    assert set(subnets(ACCOUNT_ID)) == mine
    assert subnets("TEST-ACCOUNT-B") == ["subnet-0000000d"]
    with pytest.raises(ToolInputError, match="no account 'nope'"):
        Tools(db, "nope").check()


def test_missing_database(tmp_path):
    with pytest.raises(ToolInputError, match="no IPLens database"):
        Tools(tmp_path / "missing.db").call("list_subnets")


# -- redaction ------------------------------------------------------------------------------

LEAKS = re.compile(
    r"192\.0\.2\.|198\.51\.100\.|\beni-|\bi-0abc|arn:|123456789012|subnet-0000|vpc-0000|sg-0000"
)


def test_redact_hides_identifiers_in_every_tool(db):
    tools = Tools(db, redact=True)
    for name, args in ALL_CALLS:
        out = tools.call(name, **args)
        text = json.dumps(out, ensure_ascii=False)
        assert not LEAKS.search(text), (name, LEAKS.search(text))
        assert out["redacted"] is True
        assert out["snapshot"]["account"] == "test-account"
        assert out["snapshot"]["account_id"] == "<account-id>"


def test_redact_shows_names_consistently(db):
    tools = Tools(db, redact=True)
    subnets = tools.call("list_subnets")["items"]
    a = next(s for s in subnets if s["name"] == "test-subnet-a")
    assert a["id"] == "test-subnet-a"  # the label is the name, usable as input
    assert a["vpc"] == "test-vpc-a"
    assert a["cidr"] == "<cidr>/26"
    detail = tools.call("subnet_detail", subnet=a["id"])
    assert detail["subnet"]["id"] == "test-subnet-a"
    assert detail["top_consumers"]["items"][0]["resource"] == "test-server-a"
    ip = tools.call("lookup_ip", ip="192.0.2.12")
    assert ip["ip"] == "<ip>"
    m = ip["matches"][0]
    assert (m["eni_id"], m["instance_id"]) == ("<eni>", "<instance>")
    assert m["subnet"] == {"id": "test-subnet-a", "name": "test-subnet-a"}
    lam = tools.call("lookup_ip", ip="192.0.2.70")["matches"][0]
    assert lam["security_groups"] == ["test-sg-a"]
    assert "<arn>" in lam["description"]
    changes = tools.call("changes")
    assert {s["id"] for s in changes["subnets"]["items"]} == {
        "test-subnet-a",
        "test-subnet-b",
        "test-subnet-c",
    }
    fit = tools.call("fit_check", subnet="test-subnet-a", need=1)
    assert fit["subnets"][0]["subnet_id"] == "test-subnet-a"
    assert "<ip>" not in json.dumps(tools.call("find_subnet", need_ips=1))  # no IPs in it at all


def test_redact_applies_to_errors(db):
    tools = Tools(db, redact=True)
    with pytest.raises(ToolInputError) as exc:
        tools.call("fit_check", subnet="192.0.2.99", need=1)
    assert "192.0.2" not in str(exc.value) and "<ip>" in str(exc.value)
    with pytest.raises(ToolInputError) as exc:
        Tools(db, "nope", redact=True).check()
    assert ACCOUNT_ID not in str(exc.value) and "<account-id>" in str(exc.value)


def test_redactor_patterns():
    r = Redactor(True, {SUBNET_A: "app-a", "subnet-x": "odd-id"})
    text = (
        f"{SUBNET_A} subnet-0123456789abcdef0 subnet-x vpc-0000000f sg-0000000f eni-0000000a "
        f"{INSTANCE} 192.0.2.7 192.0.2.0/24 {ACCOUNT_ID} {LAMBDA_ARN} us-east-1a v1.2.3"
    )
    assert r.text(text) == (
        "app-a <subnet> odd-id <vpc> <sg> <eni> <instance> <ip> <cidr>/24 <account-id> <arn> "
        "us-east-1a v1.2.3"
    )
    assert r.apply({"192.0.2.7": [SUBNET_A, 3, None]}) == {"<ip>": ["app-a", 3, None]}
    assert Redactor(False, {SUBNET_A: "app-a"}).text(text) == text


def test_unique_labels():
    assert unique_labels(
        [("subnet-3", "app"), ("subnet-1", "app"), ("subnet-2", ""), ("subnet-4", "db")],
        "unnamed-subnet",
    ) == {
        "subnet-1": "app#1",
        "subnet-3": "app#2",
        "subnet-2": "unnamed-subnet",
        "subnet-4": "db",
    }


# -- read-only ------------------------------------------------------------------------------


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_tools_never_write(db, mcp_home):
    before = _digest(db)
    for redact in (False, True):
        for name, args in ALL_CALLS:
            Tools(db, redact=redact).call(name, **args)
    assert _digest(db) == before
    # A WAL-mode reader (the UI's database is one) may create SQLite's shared-memory index
    # and an empty write-ahead log next to it; nothing is ever written into the log.
    wal = db.with_name(db.name + "-wal")
    assert not wal.exists() or wal.stat().st_size == 0
    assert {p.name for p in mcp_home.iterdir()} <= {db.name, f"{db.name}-wal", f"{db.name}-shm"}


def test_connection_is_read_only(db):
    conn = mcptools.open_readonly(db)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM snapshots")
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("CREATE TABLE scratch(x)")
    finally:
        conn.close()


# -- the MCP server -------------------------------------------------------------------------

needs_mcp = pytest.mark.skipif(
    importlib.util.find_spec("mcp") is None, reason="needs the mcp extra"
)


def _run(coro):
    import anyio

    return anyio.run(lambda: coro)


async def _call_all(server) -> list[dict]:
    out = []
    for name, args in ALL_CALLS:
        result = await server.call_tool(name, args)
        assert not result.is_error, (name, result)
        out.append(json.loads(result.content[0].text))
    return out


@needs_mcp
def test_server_lists_read_only_tools(tools):
    from iplens.mcpserver import build_server

    listed = _run(build_server(tools).list_tools())
    assert sorted(t.name for t in listed) == sorted(mcptools.TOOLS)
    for t in listed:
        hints = t.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is True
        assert hints["destructiveHint"] is False
        assert hints["openWorldHint"] is False
        assert t.description


@needs_mcp
def test_server_calls_tools_and_reports_errors(db):
    from mcp.server.mcpserver.exceptions import ToolError

    from iplens.mcpserver import build_server

    server = build_server(Tools(db, redact=True))
    results = _run(_call_all(server))
    assert all(r["redacted"] for r in results)
    assert not LEAKS.search(json.dumps(results, ensure_ascii=False))
    with pytest.raises(ToolError, match="no subnet") as exc:
        _run(server.call_tool("subnet_detail", {"subnet": "192.0.2.99"}))
    assert "192.0.2" not in str(exc.value)


# -- never AWS ------------------------------------------------------------------------------


@needs_mcp
def test_no_boto3_client_is_created(db, monkeypatch):
    """Every client / session constructor of boto3 and botocore fails loudly; every tool
    still answers through the MCP server."""
    import boto3
    import boto3.session
    import botocore.session

    from iplens.mcpserver import build_server

    made: list[str] = []

    def refuse(what):
        def fn(*args, **kwargs):
            made.append(what)
            raise AssertionError(f"the MCP code path created {what}")

        return fn

    monkeypatch.setattr(boto3, "client", refuse("boto3.client"))
    monkeypatch.setattr(boto3, "resource", refuse("boto3.resource"))
    monkeypatch.setattr(boto3.session.Session, "__init__", refuse("boto3 Session"))
    monkeypatch.setattr(botocore.session.Session, "create_client", refuse("botocore client"))
    monkeypatch.setattr(botocore.session, "get_session", refuse("botocore session"))
    for redact in (False, True):
        _run(_call_all(build_server(Tools(db, redact=redact))))
    assert made == []


_NO_AWS_SCRIPT = """
import json, sys
from pathlib import Path

import anyio

from iplens.mcptools import AWS_SDK_MODULES, Tools, block_aws_sdk

if sys.argv[2] == "block":  # any attempt to import the AWS SDK now raises ImportError
    block_aws_sdk()
import iplens.cli  # noqa: F401 - the `iplens mcp` entry point's own imports
from iplens.mcpserver import build_server

calls = json.loads(sys.argv[3])

async def main():
    for redact in (False, True):
        server = build_server(Tools(Path(sys.argv[1]), redact=redact))
        for name, args in calls:
            result = await server.call_tool(name, args)
            assert not result.is_error, (name, result)

anyio.run(main)
print(json.dumps(sorted(m for m in sys.modules if m.split(".")[0] in AWS_SDK_MODULES)))
"""


@needs_mcp
@pytest.mark.parametrize("mode", ["plain", "block"])
def test_mcp_code_path_never_imports_the_aws_sdk(db, mode):
    """In a fresh interpreter: importing the CLI and the server and running every tool
    loads no boto3 / botocore module at all ("block": an import attempt would raise)."""
    proc = subprocess.run(  # noqa: S603 - our own interpreter and script
        [sys.executable, "-c", _NO_AWS_SCRIPT, str(db), mode, json.dumps(ALL_CALLS)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip().splitlines()[-1]) == []


def test_block_aws_sdk_refuses_the_import():
    script = (
        "from iplens.mcptools import block_aws_sdk\n"
        "block_aws_sdk()\n"
        "try:\n    import boto3\nexcept ImportError as e:\n    print('refused:', e)\n"
    )
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60, check=False
    )
    assert proc.returncode == 0, proc.stderr
    assert "refused: iplens mcp never talks to AWS" in proc.stdout


def test_block_aws_sdk_fails_when_already_loaded():
    import boto3  # noqa: F401 - loaded by the rest of the suite anyway

    with pytest.raises(RuntimeError, match="already loaded"):
        mcptools.block_aws_sdk()


# -- the command ----------------------------------------------------------------------------


def _iplens(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "iplens", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        **kwargs,
    )


@needs_mcp
def test_cli_help_and_errors(mcp_home, tmp_path):
    proc = _iplens("mcp", "--help")
    assert proc.returncode == 0 and "--redact" in proc.stdout and "--account" in proc.stdout
    proc = _iplens("mcp", "--home", str(mcp_home), "--account", "nope", "--redact")
    assert proc.returncode == 2
    assert "no account 'nope'" in proc.stderr and ACCOUNT_ID not in proc.stderr
    assert proc.stdout == ""  # stdout is the protocol channel
    proc = _iplens("mcp", "--home", str(tmp_path / "empty"))
    assert proc.returncode == 2 and "no IPLens database" in proc.stderr


def test_cli_without_the_extra_explains_how_to_install(mcp_home):
    script = (
        "import importlib.abc, sys\n"
        "class NoMcp(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] == 'mcp':\n"
        "            raise ImportError(name)\n"
        "sys.meta_path.insert(0, NoMcp())\n"
        "from iplens.cli import main\n"
        "main(['mcp', '--home', sys.argv[1]])\n"
    )
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script, str(mcp_home)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 2
    assert "pip install 'aws-iplens[mcp]'" in proc.stderr


@needs_mcp
def test_stdio_end_to_end(mcp_home):
    """A real MCP client speaking to `python -m iplens mcp` over stdio."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "iplens", "mcp", "--home", str(mcp_home), "--redact"],
    )

    async def session():
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as client,
        ):
            await client.initialize()
            listed = await client.list_tools()
            result = await client.call_tool("find_subnet", {"need_ips": 20})
            return [t.name for t in listed.tools], result

    names, result = _run(session())
    assert sorted(names) == sorted(mcptools.TOOLS)
    assert not result.is_error
    out = json.loads(result.content[0].text)
    assert [f["id"] for f in out["items"]] == ["test-subnet-b", "test-subnet-a"]
    assert out["snapshot"]["account_id"] == "<account-id>"
