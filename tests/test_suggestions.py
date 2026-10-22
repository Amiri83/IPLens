from datetime import UTC, datetime, timedelta

import pytest

from iplens import suggestions as sg
from iplens.db import closing, init_db
from iplens.rules import Rule, normalize_params
from iplens.web import create_app
from tests.conftest import add_test_account, ip_range

VPC = "vpc-0example0000001"
SA, SA2, SB, SC = "subnet-0000000a", "subnet-000000a2", "subnet-0000000b", "subnet-0000000c"
SQS = "com.amazonaws.us-east-1.sqs"
S3 = "com.amazonaws.us-east-1.s3"


@pytest.fixture
def ctx(db_path, snapshot_builder, ips):
    # A week ago the detached ENIs already were: they are suggested now.
    old = snapshot_builder(db_path, taken_at=datetime.now(UTC) - timedelta(days=7))
    old.vpc(VPC, "10.0.0.0/22").subnet(SA, VPC, "10.0.0.0/24", az="us-east-1a")
    old.eni("eni-00000000d1", SA, ["10.0.0.220"], status="available", owner_type="other")
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/22")
    b.subnet(SA, VPC, "10.0.0.0/24", az="us-east-1a")
    b.subnet(SA2, VPC, "10.0.1.0/24", az="us-east-1a")
    b.subnet(SB, VPC, "10.0.2.0/24", az="us-east-1b")
    b.subnet(SC, VPC, "10.0.3.0/24", az="us-east-1b")
    b.eni("eni-0000000ec2", SA, ips("10.0.0.0", 10, 200), owner_ref="i-0example0001")
    b.eni(
        "eni-00000000d1",
        SA,
        ["10.0.0.220", "10.0.0.221"],
        status="available",
        owner_type="other",
        description="example keep detached",
    )
    b.eni(
        "eni-00000000d2",
        SA,
        ["10.0.0.222"],
        status="available",
        owner_type="other",
        requester_managed=True,
    )
    b.eni("eni-00000000l1", SA, ["10.0.0.230"], owner_type="lambda", sgs=("sg-000a",))
    b.eni("eni-00000000l2", SA, ["10.0.0.231"], owner_type="lambda", sgs=("sg-000b",))
    b.eni("eni-00000000l3", SA2, ["10.0.1.10"], owner_type="lambda", sgs=("sg-000a",))
    b.eni("eni-00000000e1", SA, ["10.0.0.240"], owner_type="vpc_endpoint")
    b.eni("eni-00000000e2", SB, ["10.0.2.10"], owner_type="vpc_endpoint")
    b.eni("eni-00000000e3", SB, ["10.0.2.11"], owner_type="vpc_endpoint")
    b.eni("eni-00000000e4", SB, ["10.0.2.12"], owner_type="vpc_endpoint")
    b.eni("eni-0000000nat", SB, ["10.0.2.20"], owner_type="nat")
    b.endpoint("vpce-000000001", VPC, SQS, [SA, SB], ["eni-00000000e1", "eni-00000000e2"])
    b.endpoint("vpce-000000002", VPC, SQS, [SB], ["eni-00000000e3"])
    b.endpoint("vpce-000000003", VPC, S3, [SB], ["eni-00000000e4"])
    b.endpoint(
        "vpce-000000004", VPC, "com.amazonaws.us-east-1.dynamodb", [], [], endpoint_type="Gateway"
    )
    with closing(db_path) as conn:
        return sg.build_context(conn, b.id)


def _by_key(items):
    return {s.key: s for s in items}


def test_generates_expected_suggestions(ctx):
    items = _by_key(sg.generate(ctx, []))

    d = items["detached:eni-00000000d1"]
    assert d.ips_saved == 2 and d.eni_ids == ["eni-00000000d1"]
    assert "detached:eni-00000000d2" not in items  # AWS-managed ENIs are left alone

    combo = items[f"lambda-sg:{VPC}"]
    assert combo.ips_saved == 1 and combo.subnet_ids == [SA]

    spread = items[f"lambda-spread:{VPC}:us-east-1a"]
    assert spread.ips_saved == 1
    assert spread.target_subnets == {SA2: 1}
    assert spread.subnet_ids == [SA]

    novpc = items[f"lambda-novpc:{VPC}"]
    assert novpc.ips_saved == 3 and "lambda_detach_vpc" in novpc.flags

    dup = items[f"dup-endpoint:{VPC}:{SQS}"]
    assert dup.ips_saved == 1 and dup.eni_ids == ["eni-00000000e3"]
    assert "vpce-000000001" in dup.detail
    assert f"dup-endpoint:{VPC}:{S3}" not in items

    gw = items[f"gw-endpoint:{VPC}:{S3}"]
    assert gw.ips_saved == 1 and not gw.flags

    nat = items[f"endpoint-nat:{VPC}"]
    assert nat.ips_saved == 4 and "public_path:vpc_endpoint" in nat.flags

    az = items[f"az:{VPC}"]
    # us-east-1a: 200 ec2 + 3 idle + 3 lambda + 1 endpoint = 207; us-east-1b: 4
    assert az.target_subnets == {SC: (207 - 4) // 2}
    assert az.ips_saved == 0 and "headroom" in az.impact

    assert f"cidr:{VPC}" not in items  # only ~22% of subnet IPs consumed

    assert not any(s.blocked for s in items.values())


def test_rules_block_and_sort(ctx):
    rules = [
        Rule(name="lambda-in-vpc", kind="lambda_vpc_required"),
        Rule(name="internal", kind="internal_only", params={"scope": "both"}),
        Rule(name="reserved-c", kind="subnet_reserved", params={"subnet_ids": [SC]}),
        Rule(name="keep", kind="protected_eni", params={"pattern": "keep"}),
        Rule(name="free-99", kind="min_free_pct", params={"percent": 99.7, "subnet_ids": [SA2]}),
        Rule(name="disabled", kind="subnet_reserved", params={"subnet_ids": [SA]}, enabled=False),
    ]
    items = sg.generate(ctx, rules)
    by_key = _by_key(items)

    def blockers(key):
        return [name for name, _ in by_key[key].blocked_by]

    assert blockers(f"lambda-novpc:{VPC}") == ["lambda-in-vpc"]
    assert blockers(f"endpoint-nat:{VPC}") == ["internal"]
    assert blockers(f"az:{VPC}") == ["reserved-c"]
    assert blockers("detached:eni-00000000d1") == ["keep"]
    assert blockers(f"lambda-spread:{VPC}:us-east-1a") == ["free-99"]
    assert not by_key[f"gw-endpoint:{VPC}:{S3}"].blocked

    flags = [s.blocked for s in items]
    assert flags == sorted(flags)  # allowed first, blocked last
    totals = sg.totals(items)
    assert totals["blocked"] == 3 + 4 + 0 + 2 + 1
    assert totals["allowed"] == 1 + 1 + 1


def test_secondary_cidr(db_path, snapshot_builder, ips):
    b = snapshot_builder(db_path)
    b.vpc("vpc-0example0000002", "10.1.0.0/24")
    b.subnet("subnet-000000f1", "vpc-0example0000002", "10.1.0.0/24")
    b.eni("eni-00000000f1", "subnet-000000f1", ips("10.1.0.0", 4, 200))
    with closing(db_path) as conn:
        items = _by_key(sg.generate(sg.build_context(conn, b.id), []))
    s = items["cidr:vpc-0example0000002"]
    assert s.ips_saved == 0 and s.impact == "adds capacity"
    assert "100.64.0.0/10" in s.detail


@pytest.fixture
def ecs_ctx(db_path, snapshot_builder, ips):
    now = datetime.now(UTC)
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16")
    b.subnet(SA, VPC, "10.0.0.0/24", az="us-east-1a")
    b.subnet(SB, VPC, "10.0.2.0/24", az="us-east-1b")
    # single-IP task ENIs, alternating between the two AZs
    free = {SA: iter(ips("10.0.0.0", 10, 20)), SB: iter(ips("10.0.2.0", 10, 20))}
    eni_ids: dict[str, list[str]] = {}
    for svc, n in (("idle-env", 10), ("busy-env", 10), ("small-env", 2)):
        eni_ids[svc] = [f"eni-{svc}-{i:02d}" for i in range(n)]
        for i, eni_id in enumerate(eni_ids[svc]):
            subnet = SA if i % 2 == 0 else SB
            b.eni(
                eni_id,
                subnet,
                [next(free[subnet])],
                owner_type="ecs",
                owner_ref=f"example-cluster/{svc}",
            )
    b.ecs_service("example-cluster", "idle-env", now - timedelta(days=90), eni_ids["idle-env"])
    b.ecs_service("example-cluster", "busy-env", now - timedelta(days=2), eni_ids["busy-env"])
    b.ecs_service("example-cluster", "small-env", now - timedelta(days=90), eni_ids["small-env"])
    b.ecs_service("example-cluster", "never-deployed", None)
    with closing(db_path) as conn:
        return sg.build_context(conn, b.id)


def test_ecs_idle_environment_suggestion(ecs_ctx):
    items = _by_key(sg.generate(ecs_ctx, []))
    ecs_items = {k: v for k, v in items.items() if v.kind == "ecs_idle_service"}
    # busy-env was deployed recently, small-env holds too few IPs
    assert list(ecs_items) == ["ecs-idle:example-cluster/idle-env"]
    s = ecs_items["ecs-idle:example-cluster/idle-env"]
    assert s.ips_saved == 10 and len(s.eni_ids) == 10
    assert s.subnet_ids == [SA, SB] and s.vpc_id == VPC
    assert "Scale down / delete idle environment" in s.title and "90 days" in s.detail
    assert s.flags == {"ecs_scale_down:example-cluster/idle-env"}
    assert s.kind_label == "Idle ECS environment"


@pytest.mark.parametrize(
    "params, blocked",
    [
        ({"mode": "deny", "pattern": ""}, True),  # deny all scale-downs
        ({"mode": "deny", "pattern": "/idle-"}, True),  # deny matching service
        ({"mode": "deny", "pattern": "^prod-"}, False),  # deny others only
        ({"mode": "allow", "pattern": "/idle-env$"}, False),  # on the allow-list
        ({"mode": "allow", "pattern": "^sandbox/"}, True),  # not on the allow-list
    ],
)
def test_ecs_scale_down_rule_allow_deny(ecs_ctx, params, blocked):
    rule = Rule(
        name="ecs-policy", kind="ecs_scale_down", params=normalize_params("ecs_scale_down", params)
    )
    items = _by_key(sg.generate(ecs_ctx, [rule]))
    s = items["ecs-idle:example-cluster/idle-env"]
    assert s.blocked is blocked
    assert ([n for n, _ in s.blocked_by] == ["ecs-policy"]) is blocked
    # the rule never touches non-ECS suggestions
    assert not any(v.blocked for v in items.values() if v.kind != "ecs_idle_service")


def test_ecs_scale_down_rule_validation():
    assert normalize_params("ecs_scale_down", {}) == {"mode": "deny", "pattern": ""}
    with pytest.raises(ValueError, match="allow mode needs a pattern"):
        normalize_params("ecs_scale_down", {"mode": "allow"})
    with pytest.raises(ValueError, match="mode must be one of"):
        normalize_params("ecs_scale_down", {"mode": "maybe"})


def test_no_az_suggestion_when_balanced(db_path, snapshot_builder, ips):
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16")
    b.subnet(SA, VPC, "10.0.0.0/24", az="us-east-1a")
    b.subnet(SB, VPC, "10.0.2.0/24", az="us-east-1b")
    b.eni("eni-00000000a1", SA, ips("10.0.0.0", 10, 20))
    b.eni("eni-00000000b1", SB, ips("10.0.2.0", 10, 12))
    with closing(db_path) as conn:
        items = sg.generate(sg.build_context(conn, b.id), [])
    assert items == []


# -- history-based suggestions (placeholders: 192.0.2.0/24, example ids) ---------------------

VPC_H = "vpc-0000000a"
SH, SH2 = "subnet-0000000a", "subnet-0000000b"


def _snap(db_path, snapshot_builder, days_ago: float, *, subnets=(SH,)):
    b = snapshot_builder(db_path, taken_at=datetime.now(UTC) - timedelta(days=days_ago))
    b.vpc(VPC_H, "192.0.2.0/24", name="test-vpc-a")
    cidrs = {SH: "192.0.2.0/25", SH2: "192.0.2.128/26"}
    for sid in subnets:
        b.subnet(sid, VPC_H, cidrs[sid], name=f"test-{sid}")
    return b


def _context(db_path, snap_id, **kwargs):
    with closing(db_path) as conn:
        return sg.build_context(conn, snap_id, **kwargs)


def _kind(items, kind):
    return [s for s in items if s.kind == kind]


def _day(days_ago: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%d")


def _fresh_db(tmp_path, name: str):
    db = tmp_path / name
    init_db(db)
    add_test_account(db)
    return db


def test_detached_eni_needs_every_snapshot_of_the_week(db_path, snapshot_builder):
    # Daily snapshots over 8 days: eni-...a1 detached throughout, a2 attached 3 days ago,
    # a3 only in the last 2 days.
    for ago in range(8, -1, -1):
        b = _snap(db_path, snapshot_builder, ago)
        b.eni("eni-000000a1", SH, ["192.0.2.10", "192.0.2.11"], status="available")
        b.eni(
            "eni-000000a2",
            SH,
            ["192.0.2.12"],
            status="in-use" if ago == 3 else "available",
            description="test-server-a",
        )
        if ago <= 1:
            b.eni("eni-000000a3", SH, ["192.0.2.13"], status="available")
    ctx = _context(db_path, b.id)
    (s,) = _kind(sg.generate(ctx, []), "detached_eni")
    assert s.key == "detached:eni-000000a1" and s.ips_saved == 2
    assert s.since == _day(8) and f"detached since {_day(8)}" in s.detail
    assert "in every snapshot of the last 7 days" in s.detail
    assert any("2 ENI(s) detached now were attached (or absent)" in n for n in ctx.notes)


def test_detached_eni_since_is_the_start_of_the_current_run(db_path, snapshot_builder):
    # Detached 20 days ago, attached 12 days ago, detached again from 9 days ago on.
    for ago, status in ((20, "available"), (12, "in-use"), (9, "available"), (4, "available")):
        _snap(db_path, snapshot_builder, ago).eni("eni-000000a1", SH, ["192.0.2.10"], status=status)
    b = _snap(db_path, snapshot_builder, 0)
    b.eni("eni-000000a1", SH, ["192.0.2.10"], status="available")
    # The week's oldest snapshot is 4 days old: the window is not covered yet.
    assert not _kind(sg.generate(_context(db_path, b.id), []), "detached_eni")
    _snap(db_path, snapshot_builder, 6.5).eni(
        "eni-000000a1", SH, ["192.0.2.10"], status="available"
    )
    (s,) = _kind(sg.generate(_context(db_path, b.id), []), "detached_eni")
    assert s.since == _day(9)


def test_detached_eni_short_history_is_a_note(db_path, snapshot_builder):
    for ago in (2, 0):
        b = _snap(db_path, snapshot_builder, ago)
        b.eni("eni-000000a1", SH, ["192.0.2.10"], status="available")
    ctx = _context(db_path, b.id)
    assert not _kind(sg.generate(ctx, []), "detached_eni")
    assert (
        "Detached ENIs (1 detached now): not checked yet; it needs snapshots spanning the last "
        f"7 days and the account's history only goes back to {_day(2)}."
    ) in ctx.notes


def test_detached_eni_history_is_per_account(db_path, snapshot_builder):
    other = add_test_account(db_path)
    old = snapshot_builder(
        db_path, taken_at=datetime.now(UTC) - timedelta(days=6.5), account_ref=other
    )
    old.vpc(VPC_H, "192.0.2.0/24").subnet(SH, VPC_H, "192.0.2.0/25")
    old.eni("eni-000000a1", SH, ["192.0.2.10"], status="available")
    b = _snap(db_path, snapshot_builder, 0)  # the first account: one snapshot only
    b.eni("eni-000000a1", SH, ["192.0.2.10"], status="available")
    assert not _kind(sg.generate(_context(db_path, b.id), []), "detached_eni")


def _underused_history(db_path, snapshot_builder, used_by_day):
    """Snapshots ``days ago``: subnet a (/25, 123 usable) holds ``n`` IPs, subnet b (/26,
    59 usable) 30."""
    b = None
    for ago, n in used_by_day:
        b = _snap(db_path, snapshot_builder, ago, subnets=(SH, SH2))
        if n:
            b.eni("eni-000000a1", SH, ip_range("192.0.2.0", 10, n), description="test-server-a")
        b.eni("eni-000000b1", SH2, ip_range("192.0.2.128", 10, 30))
    return b


def test_underused_subnet_suggests_the_smallest_prefix_for_twice_the_peak(
    db_path, snapshot_builder
):
    # Peak 7 IPs (5.7% of 123): 14 needed, a /28 (11 usable) is too small, a /27 (27) fits.
    b = _underused_history(db_path, snapshot_builder, ((29.5, 3), (20, 7), (10, 5), (0, 4)))
    items = sg.generate(_context(db_path, b.id), [])
    (s,) = _kind(items, "underused_subnet")  # subnet b is ~51% used
    assert s.key == f"underused:{SH}" and s.title == f"Shrink underused subnet {SH} to a /27"
    assert s.ips_saved == 123 - 27 and s.resized == {SH: 27}
    assert s.subnet_ids == [SH] and s.vpc_id == VPC_H
    assert "used at most 7 IP(s) (5.7%)" in s.detail and "4 snapshot(s)" in s.detail
    assert s.kind_label == "Underused subnet"
    assert sg.totals(items)["allowed"] == 123 - 27


def test_underused_subnet_needs_every_snapshot_under_ten_percent(db_path, snapshot_builder):
    # 13 of 123 IPs (10.6%) in one snapshot of the window: not underused.
    b = _underused_history(db_path, snapshot_builder, ((29.5, 3), (15, 13), (0, 4)))
    assert not _kind(sg.generate(_context(db_path, b.id), []), "underused_subnet")


def test_underused_subnet_skips_subnets_newer_than_the_window(db_path, snapshot_builder):
    # Subnet b only appears in the latest snapshot; a is empty throughout.
    _snap(db_path, snapshot_builder, 29.5)
    b = _snap(db_path, snapshot_builder, 0, subnets=(SH, SH2))
    items = _kind(sg.generate(_context(db_path, b.id), []), "underused_subnet")
    assert [s.key for s in items] == [f"underused:{SH}"]
    assert items[0].title.endswith("to a /28") and items[0].ips_saved == 123 - 11


def test_underused_subnet_short_history_is_a_note(tmp_path, snapshot_builder):
    db = _fresh_db(tmp_path, "short.db")
    _snap(db, snapshot_builder, 10)
    b = _snap(db, snapshot_builder, 0)
    ctx = _context(db, b.id)
    assert not _kind(sg.generate(ctx, []), "underused_subnet")
    assert (
        "Underused subnets: not checked yet; it needs snapshots spanning the last 30 days and "
        f"the account's history only goes back to {_day(10)}."
    ) in ctx.notes


def test_underused_subnet_rules(db_path, snapshot_builder):
    b = _underused_history(db_path, snapshot_builder, ((29.5, 5), (0, 5)))
    free = Rule(name="free-60", kind="min_free_pct", params={"percent": 60, "subnet_ids": [SH]})
    (s,) = _kind(sg.generate(_context(db_path, b.id), [free]), "underused_subnet")
    # A /28 (11 usable) holding 5 IPs keeps 54.5% free.
    assert s.blocked_by == [("free-60", f"{SH} resized would have 54.5% free (< 60%)")]
    frozen = Rule(name="frozen", kind="subnet_reserved", params={"subnet_ids": [SH]})
    items = sg.generate(_context(db_path, b.id), [frozen])
    (s,) = _kind(items, "underused_subnet")
    assert [n for n, _ in s.blocked_by] == ["frozen"]
    assert sg.totals(items) == {"allowed": 0, "blocked": 123 - 11}


@pytest.mark.parametrize(
    "need, prefix", [(0, 28), (11, 28), (12, 27), (27, 27), (28, 26), (65531, 16), (65532, None)]
)
def test_fit_prefix(need, prefix):
    assert sg.fit_prefix(need) == prefix


EP_USED, EP_IDLE = "vpce-000000001", "vpce-000000002"
SQS_H, KMS_H = "com.amazonaws.us-east-1.sqs", "com.amazonaws.us-east-1.kms"
CLIENT_ENI = "eni-000000c1"


def _endpoint_snapshot(db_path, snapshot_builder, ago, *, with_idle=True):
    b = _snap(db_path, snapshot_builder, ago)
    b.eni("eni-000000e1", SH, ["192.0.2.20"], owner_type="vpc_endpoint")
    b.eni(CLIENT_ENI, SH, ["192.0.2.30"], description="test-server-a")
    b.endpoint(EP_USED, VPC_H, SQS_H, [SH], ["eni-000000e1"])
    if with_idle:
        b.eni("eni-000000e2", SH, ["192.0.2.21", "192.0.2.22"], owner_type="vpc_endpoint")
        b.endpoint(EP_IDLE, VPC_H, KMS_H, [SH], ["eni-000000e2"])
    return b


def _flow_run(db_path, snap_id, days_ago, pairs, window_minutes=60):
    """A stored flow log query of the VPC (as flowlogs.run writes it) seeing ``pairs``."""
    ran_at = datetime.now(UTC) - timedelta(days=days_ago)
    with closing(db_path) as conn:
        conn.execute(
            "INSERT INTO flow_runs(snapshot_id, vpc_id, ran_at, window_minutes, rows) "
            "VALUES(?,?,?,?,?)",
            (snap_id, VPC_H, ran_at.isoformat(timespec="seconds"), window_minutes, len(pairs)),
        )
        conn.executemany(
            "INSERT INTO flow_aggregates(snapshot_id, vpc_id, src_eni, dst_eni, protocol, port, "
            "flows, bytes, packets) VALUES(?,?,?,?,'tcp',443,1,100,1)",
            [(snap_id, VPC_H, src, dst) for src, dst in pairs],
        )


def test_unused_endpoint_from_flow_logs(db_path, snapshot_builder):
    old = _endpoint_snapshot(db_path, snapshot_builder, 5)
    _flow_run(db_path, old.id, 5, [(CLIENT_ENI, "eni-000000e1")], window_minutes=1440)
    b = _endpoint_snapshot(db_path, snapshot_builder, 0)
    _flow_run(db_path, b.id, 0, [(CLIENT_ENI, "outside")])
    ctx = _context(db_path, b.id)
    (s,) = _kind(sg.generate(ctx, []), "unused_endpoint")  # SQS had traffic 5 days ago
    assert s.key == f"unused-endpoint:{EP_IDLE}" and s.ips_saved == 2
    assert s.eni_ids == ["eni-000000e2"] and s.subnet_ids == [SH] and s.vpc_id == VPC_H
    assert s.title == f"Remove unused interface endpoint {EP_IDLE} ({KMS_H})"
    assert "in the last 14 days: 2 flow log queries" in s.detail
    assert f"(25 h of traffic, the first on {_day(5)})" in s.detail
    assert s.kind_label == "Unused endpoint"
    assert not any("Unused endpoints" in n for n in ctx.notes)
    # A protected ENI rule vetoes it like any other suggestion.
    keep = Rule(name="keep-kms", kind="protected_eni", params={"pattern": "eni-000000e2"})
    (s,) = _kind(sg.generate(ctx, [keep]), "unused_endpoint")
    assert s.blocked_by == [("keep-kms", "eni-000000e2 is protected")]


def test_unused_endpoint_without_flow_logs_is_a_note(db_path, snapshot_builder):
    b = _endpoint_snapshot(db_path, snapshot_builder, 0)
    ctx = _context(db_path, b.id)
    assert not _kind(sg.generate(ctx, []), "unused_endpoint")
    assert (
        f"Unused endpoints in {VPC_H}: skipped, no flow log data from the last 14 days (flow "
        "logs not enabled for the VPC, or not queried yet: Visual → Extended view → Flow logs)."
    ) in ctx.notes


def test_unused_endpoint_window(db_path, snapshot_builder):
    # The only flow log query is 20 days old: outside the default 14 days, inside 30.
    old = _endpoint_snapshot(db_path, snapshot_builder, 20)
    _flow_run(db_path, old.id, 20, [])
    b = _endpoint_snapshot(db_path, snapshot_builder, 0)
    ctx = _context(db_path, b.id)
    assert not _kind(sg.generate(ctx, []), "unused_endpoint")
    assert any(n.startswith(f"Unused endpoints in {VPC_H}: skipped") for n in ctx.notes)
    items = _kind(sg.generate(_context(db_path, b.id, endpoint_days=30), []), "unused_endpoint")
    assert {s.key for s in items} == {f"unused-endpoint:{EP_USED}", f"unused-endpoint:{EP_IDLE}"}
    assert all("in the last 30 days: 1 flow log query " in s.detail for s in items)


def test_unused_endpoint_newer_than_the_queries_is_not_checked(db_path, snapshot_builder):
    old = _endpoint_snapshot(db_path, snapshot_builder, 3, with_idle=False)
    _flow_run(db_path, old.id, 3, [(CLIENT_ENI, "eni-000000e1")])
    b = _endpoint_snapshot(db_path, snapshot_builder, 0)
    ctx = _context(db_path, b.id)
    assert not _kind(sg.generate(ctx, []), "unused_endpoint")
    assert (
        f"Unused endpoints: {EP_IDLE} is newer than the flow log queries of the last 14 days; "
        "not checked."
    ) in ctx.notes


def test_new_kinds_on_the_page_and_in_the_report(tmp_path, snapshot_builder):
    home = tmp_path / "home"
    home.mkdir()
    db = _fresh_db(home, "iplens.db")
    _endpoint_snapshot(db, snapshot_builder, 29.5)
    b = _endpoint_snapshot(db, snapshot_builder, 0)
    _flow_run(db, b.id, 0, [(CLIENT_ENI, "eni-000000e1")])
    client = create_app(home, testing=True).test_client()
    page = client.get("/suggestions").data.decode()
    assert "Underused subnet" in page and f"Shrink underused subnet {SH} to a /28" in page
    assert f"Remove unused interface endpoint {EP_IDLE}" in page
    report = client.get("/report").data.decode()
    assert f"Remove unused interface endpoint {EP_IDLE}" in report
    assert f"Shrink underused subnet {SH} to a /28" in report


def test_notes_on_the_page_and_in_the_report(tmp_path, snapshot_builder):
    home = tmp_path / "home"
    home.mkdir()
    db = _fresh_db(home, "iplens.db")
    _endpoint_snapshot(db, snapshot_builder, 0)
    client = create_app(home, testing=True).test_client()
    note = f"Unused endpoints in {VPC_H}: skipped"
    assert note in client.get("/suggestions").data.decode()
    assert note in client.get("/report").data.decode()
