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


VPC2 = "vpc-0example0000002"
SC = "subnet-0000000c"


def _seed_ip_list(db_path, builder):
    """Two VPCs; addresses chosen so lexical and numeric order differ."""
    b = _seed(db_path, builder)
    b.vpc(VPC2, "10.1.0.0/16", name="example-vpc-two")
    b.subnet(SC, VPC2, "10.1.0.0/24", name="example-c")
    b.eni(
        "eni-0000000004",
        SA,
        ["10.0.1.10"],
        owner_type="elb",
        owner_ref="example-alb",
        description="ELB app/example-alb/0123456789abcdef",
    )
    b.load_balancer("example-alb", VPC)
    b.eni("eni-0000000005", SB, ["10.0.4.100"], owner_type="vpc_endpoint", owner_ref="vpce-0001")
    b.endpoint("vpce-0001", VPC, "com.amazonaws.us-east-1.s3", [SB], ["eni-0000000005"])
    b.eni("eni-0000000006", SC, ["10.1.0.9"], owner_type="rds", name="example-db")
    b.eni("eni-0000000007", SC, ["10.1.0.20"], owner_type="ec2", description="100% _literal_")
    return b


def _ips(rows):
    return [r["ip"] for r in rows]


def test_ip_list_sorts_numerically(db_path, snapshot_builder):
    b = _seed_ip_list(db_path, snapshot_builder)
    with closing(db_path) as conn:
        rows = queries.ip_list(conn, b.id)
    assert _ips(rows) == [
        "10.0.1.4",
        "10.0.1.5",
        "10.0.1.9",
        "10.0.1.10",
        "10.0.4.100",
        "10.0.6.10",
        "10.1.0.9",
        "10.1.0.20",
    ]
    assert _ips(rows) != sorted(_ips(rows))  # lexical order would be different


def test_ip_list_filters(db_path, snapshot_builder):
    b = _seed_ip_list(db_path, snapshot_builder)
    F = queries.IpFilter
    with closing(db_path) as conn:

        def run(**kw):
            return _ips(queries.ip_list(conn, b.id, F(**kw)))

        assert run(vpc=VPC2) == ["10.1.0.9", "10.1.0.20"]
        assert run(subnet=SA) == ["10.0.1.4", "10.0.1.5", "10.0.1.9", "10.0.1.10"]
        assert run(vpc=VPC, subnet=SC) == []
        assert run(owner="ec2") == ["10.0.1.4", "10.0.1.5", "10.1.0.20"]
        assert run(owner="elb", vpc=VPC) == ["10.0.1.10"]
        assert run(state="idle") == ["10.0.1.9"]
        assert len(run(state="used")) == 7
        # free text hits subnet name, VPC name, resource names and endpoint services
        assert run(q="example-c") == ["10.1.0.9", "10.1.0.20"]
        assert run(q="example-vpc-two") == ["10.1.0.9", "10.1.0.20"]
        assert run(q="example-fn") == ["10.0.6.10"]
        assert run(q="s3") == ["10.0.4.100"]
        assert run(q="10.0.1.1") == ["10.0.1.10"]
        assert run(q="example", owner="rds", vpc=VPC2) == ["10.1.0.9"]
        # LIKE wildcards are literal, values are bound
        assert run(q="100%") == ["10.1.0.20"]
        assert run(q="_literal_") == ["10.1.0.20"]
        assert run(q="%") == ["10.1.0.20"]
        assert run(q="'; DROP TABLE ips; --") == []
        assert len(queries.ip_list(conn, b.id)) == 8


def test_ip_list_enrichment(db_path, snapshot_builder):
    b = _seed_ip_list(db_path, snapshot_builder)
    with closing(db_path) as conn:
        rows = {r["ip"]: r for r in queries.ip_list(conn, b.id)}
    labels = {"elb": "ALB/NLB", "rds": "RDS", "vpc_endpoint": "VPC endpoint"}
    alb = rows["10.0.1.10"]
    assert (alb["lb_type"], alb["vpc_name"], alb["subnet_name"]) == (
        "application",
        "example-vpc",
        "example-a",
    )
    assert queries.resource_type_label(alb, labels) == "ALB"
    assert alb["resource_name"] == "example-alb"
    ep = rows["10.0.4.100"]
    assert ep["resource_name"] == "s3" and ep["owner_ref"] == "vpce-0001"
    assert queries.resource_type_label(ep, labels) == "VPC endpoint"
    assert rows["10.1.0.9"]["resource_name"] == "example-db"
    nlb = {"owner_type": "elb", "lb_type": None, "interface_type": "network_load_balancer"}
    assert queries.resource_type_label(nlb, labels) == "NLB"


def test_visual_data_nested_shape(db_path, snapshot_builder):
    b = _seed_ip_list(db_path, snapshot_builder)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, labels={"elb": "ALB/NLB"})
        other = queries.visual_data(conn, b.id, VPC2)
        assert queries.visual_data(conn, b.id, "vpc-0missing") is None
    assert data["snapshot_id"] == b.id
    assert [v["vpc_id"] for v in data["vpcs"]] == [VPC, VPC2]
    vpc = data["vpc"]
    assert vpc["vpc_id"] == VPC and vpc["cidrs"] == ["10.0.0.0/16"]
    assert [s["subnet_id"] for s in vpc["subnets"]] == [SA, SB]
    sa = vpc["subnets"][0]
    assert {"cidr", "az", "name", "size", "used", "idle", "free", "items"} <= sa.keys()
    assert (sa["cidr"], sa["used"], sa["idle"], sa["free"]) == ("10.0.1.0/28", 3, 1, 7)
    # one node per ENI, ordered by type (endpoints/LBs first), all kind=resource
    assert [i["eni_id"] for i in sa["items"]] == [
        "eni-0000000004",
        "eni-0000000001",
        "eni-0000000002",
    ]
    alb, web = sa["items"][0], sa["items"][1]
    assert alb["kind"] == "resource" and alb["type_label"] == "ALB"
    assert alb["icon"] == "Res_Elastic-Load-Balancing_Application-Load-Balancer_48.svg"
    assert web["ips"] == ["10.0.1.4", "10.0.1.5"] and web["icon"] == "Arch_Amazon-EC2_48.svg"
    assert web["ref"] == "i-0example0001" and web["subnet_id"] == SA
    ep = vpc["subnets"][1]["items"][0]
    assert (ep["type"], ep["name"], ep["icon"]) == (
        "vpc_endpoint",
        "s3",
        "Res_Amazon-VPC_Endpoints_48.svg",
    )
    assert data["icons"]["vpc"] == queries.VPC_ICON
    assert other["vpc"]["vpc_id"] == VPC2
    sc_items = other["vpc"]["subnets"][0]["items"]
    # an ENI with neither Name tag nor ref falls back to its ENI id as the node name
    assert [(i["type"], i["name"]) for i in sc_items] == [
        ("ec2", "eni-0000000007"),
        ("rds", "example-db"),
    ]


def test_visual_data_groups_more_than_ten_of_a_type(db_path, snapshot_builder):
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16").subnet(SB, VPC, "10.0.4.0/22")
    for n in range(11):
        b.eni(f"eni-00000ecs{n:02d}", SB, [f"10.0.4.{10 + n}"], owner_type="ecs")
    for n in range(10):
        b.eni(f"eni-00000fn{n:02d}", SB, [f"10.0.5.{10 + n}"], owner_type="lambda")
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, labels={"ecs": "ECS task"})
    items = data["vpc"]["subnets"][0]["items"]
    assert data["vpc"]["subnets"][0]["resource_count"] == 21
    groups = [i for i in items if i["kind"] == "group"]
    assert len(groups) == 1
    g = groups[0]
    assert (g["type"], g["count"], g["ip_count"]) == ("ecs", 11, 11)
    # unnamed members fall back to their ENI id; the label lists the first few
    assert g["name"] == "11 × ECS task: eni-00000ecs00, eni-00000ecs01, eni-00000ecs02, …"
    assert g["id"] == f"group:{SB}:ecs"
    assert [m["ips"][0] for m in g["members"]] == [f"10.0.4.{10 + n}" for n in range(11)]
    assert all(m["kind"] == "resource" for m in g["members"])
    # exactly 10 lambdas stay as individual nodes
    lambdas = [i for i in items if i["type"] == "lambda"]
    assert len(lambdas) == 10 and all(i["kind"] == "resource" for i in lambdas)


def test_visual_data_without_vpcs(db_path, snapshot_builder):
    b = snapshot_builder(db_path)
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id)
    assert data["vpcs"] == [] and data["vpc"] is None


def test_eni_detail_and_owner_breakdown(db_path, snapshot_builder):
    b = _seed(db_path, snapshot_builder)
    with closing(db_path) as conn:
        d = queries.eni_detail(conn, b.id, "eni-0000000001")
        assert [i["ip"] for i in d["ips"]] == ["10.0.1.4", "10.0.1.5"]
        assert d["security_groups"] == ["sg-0001"]
        assert queries.eni_detail(conn, b.id, "eni-missing") is None
        assert queries.owner_breakdown(conn, b.id) == {"ec2": 2, "other": 1, "lambda": 1}
        assert len(queries.subnet_enis(conn, b.id, SA)) == 2
