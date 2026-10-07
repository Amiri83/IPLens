import pytest

from iplens import rules as r
from iplens.db import closing
from iplens.suggestions import Suggestion, build_context

VPC = "vpc-0example0000001"
SA = "subnet-0000000a"
SB = "subnet-0000000b"


def _sugg(**kw):
    base = {"key": "k", "kind": "detached_eni", "title": "t", "detail": "d", "vpc_id": VPC}
    base.update(kw)
    return Suggestion(**base)


@pytest.fixture
def ctx(db_path, snapshot_builder, ips):
    b = snapshot_builder(db_path)
    b.vpc(VPC, "10.0.0.0/16")
    b.subnet(SA, VPC, "10.0.1.0/27", az="us-east-1a")   # 27 usable
    b.subnet(SB, VPC, "10.0.2.0/24", az="us-east-1b")
    b.eni("eni-00000000a1", SA, ips("10.0.1.0", 4, 20))
    b.eni("eni-00000000a2", SA, ["10.0.1.30"], status="available",
          description="example keep-me interface")
    b.lambda_fn("example-in-vpc", VPC, [SB], ["sg-0001"])
    b.lambda_fn("example-no-vpc", None)
    b.load_balancer("example-public-alb", VPC, scheme="internet-facing")
    b.load_balancer("example-internal-alb", VPC, scheme="internal")
    with closing(db_path) as conn:
        return build_context(conn, b.id)


@pytest.mark.parametrize("kind, params, expected", [
    ("lambda_vpc_required", {"junk": 1}, {}),
    ("internal_only", {}, {"scope": "both"}),
    ("internal_only", {"scope": "vpc_endpoint"}, {"scope": "vpc_endpoint"}),
    ("subnet_reserved", {"subnet_ids": f"{SA}, {SB}"}, {"subnet_ids": [SA, SB]}),
    ("min_free_pct", {"percent": "15", "subnet_ids": ""}, {"percent": 15.0, "subnet_ids": []}),
    ("protected_eni", {"pattern": " keep-me "}, {"pattern": "keep-me"}),
])
def test_normalize_params(kind, params, expected):
    assert r.normalize_params(kind, params) == expected


@pytest.mark.parametrize("kind, params, msg", [
    ("nope", {}, "unknown rule kind"),
    ("internal_only", {"scope": "everything"}, "scope"),
    ("subnet_reserved", {"subnet_ids": ""}, "at least one"),
    ("subnet_reserved", {"subnet_ids": "not-a-subnet"}, "invalid subnet"),
    ("min_free_pct", {"percent": "abc"}, "number"),
    ("min_free_pct", {"percent": 150}, "between"),
    ("protected_eni", {"pattern": ""}, "pattern"),
])
def test_normalize_params_rejects(kind, params, msg):
    with pytest.raises(ValueError, match=msg):
        r.normalize_params(kind, params)


def test_crud(db_path):
    with closing(db_path) as conn:
        rid = r.save_rule(conn, r.Rule(name="keep-free", kind="min_free_pct",
                                       params={"percent": 20}))
        got = r.get_rule(conn, rid)
        assert got.params == {"percent": 20.0, "subnet_ids": []} and got.enabled
        got.enabled = False
        r.save_rule(conn, got)
        assert not r.get_rule(conn, rid).enabled
        with pytest.raises(ValueError, match="already exists"):
            r.save_rule(conn, r.Rule(name="keep-free", kind="lambda_vpc_required"))
        with pytest.raises(ValueError, match="name"):
            r.save_rule(conn, r.Rule(name="  ", kind="lambda_vpc_required"))
        r.delete_rule(conn, rid)
        assert r.list_rules(conn) == []


def test_yaml_round_trip_and_import(db_path):
    original = [
        r.Rule(name="lambda-in-vpc", kind="lambda_vpc_required", description="policy"),
        r.Rule(name="reserved", kind="subnet_reserved", params={"subnet_ids": [SA]}),
        r.Rule(name="free-20", kind="min_free_pct", params={"percent": 20}, enabled=False),
    ]
    for rule in original:
        r.validate(rule)
    text = r.export_yaml(original)
    assert "lambda-in-vpc" in text
    parsed = r.parse_yaml(text)
    assert [(p.name, p.kind, p.params, p.enabled) for p in parsed] == [
        (o.name, o.kind, o.params, o.enabled) for o in original
    ]
    with closing(db_path) as conn:
        r.save_rule(conn, r.Rule(name="free-20", kind="min_free_pct", params={"percent": 5}))
        r.save_rule(conn, r.Rule(name="extra", kind="lambda_vpc_required"))
        assert r.import_rules(conn, parsed) == 3
        by_name = {x.name: x for x in r.list_rules(conn)}
        assert set(by_name) == {"lambda-in-vpc", "reserved", "free-20", "extra"}
        assert by_name["free-20"].params["percent"] == 20.0
        r.import_rules(conn, parsed[:1], replace=True)
        assert [x.name for x in r.list_rules(conn)] == ["lambda-in-vpc"]


@pytest.mark.parametrize("text, msg", [
    ("rules: [", "invalid YAML"),
    ("rules: 3", "top-level"),
    ("rules:\n  - just-a-string", "mapping"),
    ("rules:\n  - {name: a, kind: lambda_vpc_required}\n  - {name: a, kind: lambda_vpc_required}",
     "duplicate"),
    ("rules:\n  - {name: a, kind: min_free_pct, params: {percent: x}}", "rule #1"),
])
def test_parse_yaml_errors(text, msg):
    with pytest.raises(ValueError, match=msg):
        r.parse_yaml(text)


def test_parse_yaml_accepts_bare_list():
    assert r.parse_yaml("- {name: a, kind: lambda_vpc_required}")[0].name == "a"


def test_blocks(ctx):
    lam = r.Rule(name="lam", kind="lambda_vpc_required")
    assert lam.blocks(_sugg(flags={"lambda_detach_vpc"}), ctx)
    assert lam.blocks(_sugg(), ctx) is None

    internal = r.Rule(name="int", kind="internal_only", params={"scope": "vpc_endpoint"})
    assert internal.blocks(_sugg(flags={"public_path:vpc_endpoint"}), ctx)
    lb_only = r.Rule(name="int2", kind="internal_only", params={"scope": "load_balancer"})
    assert lb_only.blocks(_sugg(flags={"public_path:vpc_endpoint"}), ctx) is None

    reserved = r.Rule(name="res", kind="subnet_reserved", params={"subnet_ids": [SB]})
    assert reserved.blocks(_sugg(subnet_ids=[SB]), ctx)
    assert reserved.blocks(_sugg(target_subnets={SB: 1}), ctx)
    assert reserved.blocks(_sugg(subnet_ids=[SA]), ctx) is None

    # SA: 27 usable, 21 consumed -> 6 free
    free = r.Rule(name="free", kind="min_free_pct", params={"percent": 15})
    assert free.blocks(_sugg(target_subnets={SA: 2}), ctx)          # 4/27 = 14.8%
    assert free.blocks(_sugg(target_subnets={SA: 1}), ctx) is None  # 5/27 = 18.5%
    scoped = r.Rule(name="free2", kind="min_free_pct", params={"percent": 15, "subnet_ids": [SB]})
    assert scoped.blocks(_sugg(target_subnets={SA: 5}), ctx) is None

    protect = r.Rule(name="prot", kind="protected_eni", params={"pattern": "keep-me"})
    assert protect.blocks(_sugg(eni_ids=["eni-00000000a2"]), ctx)
    assert protect.blocks(_sugg(eni_ids=["eni-00000000a1"]), ctx) is None
    bad_regex = r.Rule(name="prot2", kind="protected_eni", params={"pattern": "eni-[a1"})
    assert bad_regex.blocks(_sugg(eni_ids=["eni-[a1"]), ctx)

    lam.enabled = False
    assert lam.blocks(_sugg(flags={"lambda_detach_vpc"}), ctx) is None


def test_violations(ctx):
    assert r.Rule(name="l", kind="lambda_vpc_required").violations(ctx) == [
        "Lambda example-no-vpc is not VPC-attached"
    ]
    v = r.Rule(name="i", kind="internal_only").violations(ctx)
    assert v == ["Load balancer example-public-alb is internet-facing"]
    assert r.Rule(name="i", kind="internal_only",
                  params={"scope": "vpc_endpoint"}).violations(ctx) == []
    v = r.Rule(name="f", kind="min_free_pct", params={"percent": 30}).violations(ctx)
    assert len(v) == 1 and SA in v[0]
    v = r.Rule(name="s", kind="subnet_reserved",
               params={"subnet_ids": [SA, "subnet-0000ffff"]}).violations(ctx)
    assert v == ["reserved subnet subnet-0000ffff not found in snapshot"]
    assert r.Rule(name="x", kind="lambda_vpc_required", enabled=False).violations(ctx) == []
