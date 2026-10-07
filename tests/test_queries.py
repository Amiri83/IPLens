from iplens import queries
from iplens.db import closing

VPC = "vpc-0example0000001"
SA = "subnet-0000000a"
SB = "subnet-0000000b"


def _seed(db_path, builder):
    b = builder(db_path)
    b.vpc(VPC, "10.0.0.0/16")
    b.subnet(SA, VPC, "10.0.1.0/28", az="us-east-1a", name="example-a")
    b.subnet(SB, VPC, "10.0.4.0/22", az="us-east-1b")
    b.eni(
        "eni-0000000001",
        SA,
        ["10.0.1.4", "10.0.1.5"],
        owner_type="ec2",
        owner_ref="i-0example0001",
        description="example web",
    )
    b.eni(
        "eni-0000000002",
        SA,
        ["10.0.1.9"],
        status="available",
        owner_type="other",
        description="example detached",
    )
    b.eni("eni-0000000003", SB, ["10.0.6.10"], owner_type="lambda", owner_ref="example-fn")
    return b


def test_subnet_stats(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    with closing(db_path) as conn:
        stats = {s.subnet_id: s for s in queries.subnet_stats(conn, b.id)}
    a = stats[SA]
    assert (a.size, a.reserved, a.used, a.idle, a.free) == (16, 5, 2, 1, 8)
    assert round(a.free_pct, 1) == round(100 * 8 / 11, 1)
    assert stats[SB].size == 1024 and stats[SB].used == 1


def test_vpc_tree_orders_subnets(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    with closing(db_path) as conn:
        tree = queries.vpc_tree(conn, b.id)
    assert [v.vpc_id for v in tree] == [VPC]
    assert [s.subnet_id for s in tree[0].subnets] == [SA, SB]
    assert tree[0].size == 65536
    assert tree[0].consumed == 2 + 1 + 5 + 1 + 5


def test_subnet_grid_states(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    with closing(db_path) as conn:
        st = queries.get_subnet(conn, b.id, SA)
        grid = queries.subnet_grid(conn, b.id, st)
    states = {c["ip"]: c["state"] for c in grid["cells"]}
    assert len(states) == 16 and grid["pages"] == 1
    assert [states[f"10.0.1.{i}"] for i in (0, 1, 2, 3, 15)] == ["reserved"] * 5
    assert states["10.0.1.4"] == "used"
    assert states["10.0.1.9"] == "idle"
    assert states["10.0.1.6"] == "free"
    used_cell = next(c for c in grid["cells"] if c["ip"] == "10.0.1.4")
    assert used_cell["eni"] == "eni-0000000001"


def test_subnet_grid_pagination(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    with closing(db_path) as conn:
        st = queries.get_subnet(conn, b.id, SB)
        assert queries.get_subnet(conn, b.id, "subnet-ffffffff") is None
        first = queries.subnet_grid(conn, b.id, st, page=0)
        third = queries.subnet_grid(conn, b.id, st, page=2)
        clamped = queries.subnet_grid(conn, b.id, st, page=99)
    assert first["pages"] == 1 and len(first["cells"]) == 1024
    assert third["page"] == 0
    assert clamped["page"] == 0


def test_subnet_grid_large_subnet_paginates(db_path, snapshot_builder):
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16").subnet("subnet-0000000c", VPC, "10.0.16.0/20")
    b.eni("eni-00000000c1", "subnet-0000000c", ["10.0.20.1"])
    with closing(db_path) as conn:
        st = queries.get_subnet(conn, b.id, "subnet-0000000c")
        p1 = queries.subnet_grid(conn, b.id, st, page=1)
    assert p1["pages"] == 4
    assert p1["start"] == "10.0.20.0" and p1["end"] == "10.0.23.255"
    assert next(c for c in p1["cells"] if c["ip"] == "10.0.20.1")["state"] == "used"
    assert p1["cells"][-1]["state"] == "free"


def test_search_ips(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    with closing(db_path) as conn:
        rows, total = queries.search_ips(conn, b.id)
        assert total == 4 and [r["ip"] for r in rows][0] == "10.0.1.4"
        rows, total = queries.search_ips(conn, b.id, q="example-fn")
        assert total == 1 and rows[0]["owner_type"] == "lambda"
        _, total = queries.search_ips(conn, b.id, owner="ec2")
        assert total == 2
        rows, total = queries.search_ips(conn, b.id, state="idle")
        assert total == 1 and rows[0]["ip"] == "10.0.1.9"
        rows, total = queries.search_ips(conn, b.id, limit=1, offset=1)
        assert total == 4 and rows[0]["ip"] == "10.0.1.5"
        _, total = queries.search_ips(conn, b.id, q="'; DROP TABLE ips; --")
        assert total == 0


def test_eni_detail_and_owner_breakdown(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    with closing(db_path) as conn:
        d = queries.eni_detail(conn, b.id, "eni-0000000001")
        assert [i["ip"] for i in d["ips"]] == ["10.0.1.4", "10.0.1.5"]
        assert d["security_groups"] == ["sg-0001"]
        assert queries.eni_detail(conn, b.id, "eni-missing") is None
        assert queries.owner_breakdown(conn, b.id) == {"ec2": 2, "other": 1, "lambda": 1}
        assert len(queries.subnet_enis(conn, b.id, SA)) == 2
