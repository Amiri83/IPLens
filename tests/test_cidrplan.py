"""CIDR planner: free blocks, fragmentation, fit, secondary CIDR checks, Terraform text.

Synthetic data only: 10.0.x.x / 100.64.x.x ranges, made-up VPC / route ids.
"""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Network as N

import pytest

from iplens import cidrplan
from iplens.cidrplan import FitRequest
from iplens.db import closing
from iplens.queries import latest_snapshot, vpc_tree
from iplens.web import create_app

VPC = "vpc-0example"
OTHER_VPC = "vpc-0other"


def _nets(*cidrs: str) -> list[N]:
    return [N(c) for c in cidrs]


# -- free-block math ----------------------------------------------------------------------


def test_free_blocks_empty_cidr_is_one_block():
    assert cidrplan.free_blocks(N("10.0.0.0/16"), []) == [N("10.0.0.0/16")]


def test_free_blocks_between_subnets_are_maximal_aligned_blocks():
    free = cidrplan.free_blocks(N("10.0.0.0/22"), _nets("10.0.0.0/24", "10.0.2.0/25"))
    assert free == _nets("10.0.1.0/24", "10.0.2.128/25", "10.0.3.0/24")
    for b in free:  # every block is aligned on its own size
        assert int(b.network_address) % b.num_addresses == 0


def test_free_blocks_fully_allocated_and_outside_networks_ignored():
    cidr = N("10.0.0.0/24")
    assert cidrplan.free_blocks(cidr, _nets("10.0.0.0/25", "10.0.0.128/25")) == []
    assert cidrplan.free_blocks(cidr, _nets("10.0.5.0/24")) == [cidr]


def test_fits_per_size_counts_aligned_blocks_and_first_one():
    free = _nets("10.0.1.0/24", "10.0.2.128/25", "10.0.3.0/24")
    per = cidrplan.fits_per_size(free)
    assert per[24] == (2, "10.0.1.0/24")
    assert per[25] == (5, "10.0.1.0/25")
    assert per[28] == (40, "10.0.1.0/28")
    assert per[23] == (0, "")  # 10.0.2.128 .. 10.0.3.255 is free but not an aligned /23
    assert per[20] == (0, "")


def test_fragmentation_score():
    # One contiguous range scores 0, even when it is not a single CIDR block.
    assert cidrplan.fragmentation(_nets("10.0.1.0/24", "10.0.2.0/23")) == 0.0
    assert cidrplan.fragmentation([]) == 0.0
    # Two equal gaps: half the free space is outside the largest range.
    assert cidrplan.fragmentation(_nets("10.0.0.0/24", "10.0.2.0/24")) == pytest.approx(0.5)
    # Many small scattered gaps score high.
    scattered = [N(f"10.0.{i}.0/28") for i in range(0, 32, 2)]
    assert cidrplan.fragmentation(scattered) > 0.9


def test_cidr_maps_per_cidr_primary_first(db_path, snapshot_builder):
    b = snapshot_builder(db_path).vpc(VPC, "10.0.0.0/22", "100.64.0.0/24")
    b.subnet("subnet-a", VPC, "10.0.0.0/24", "us-east-1a").subnet(
        "subnet-b", VPC, "100.64.0.0/25", "us-east-1b"
    )
    with closing(db_path) as conn:
        vpc = vpc_tree(conn, b.id)[0]
    primary, secondary = cidrplan.cidr_maps(vpc)
    assert primary.primary and not secondary.primary
    assert primary.allocated == 256 and primary.free_total == 768
    assert primary.largest_free == "10.0.2.0/23"
    assert [g.cidr for g in primary.segments] == ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/23"]
    assert primary.fragmentation == 0.0
    assert [str(f) for f in secondary.free] == ["100.64.0.128/25"]
    assert sum(g.pct for g in primary.segments) == pytest.approx(100.0)


# -- fit / alignment ------------------------------------------------------------------------


def test_fit_proposes_aligned_cidrs_on_size():
    free = cidrplan.free_blocks(N("10.0.0.0/22"), _nets("10.0.0.0/25"))
    reqs = [FitRequest(26, "us-east-1a"), FitRequest(24, "us-east-1b"), FitRequest(28)]
    result = cidrplan.fit(free, reqs)
    assert result.fits
    got = [N(p.cidr) for p in result.placements]
    for net, req in zip(got, reqs, strict=True):
        assert net.prefixlen == req.prefix
        assert int(net.network_address) % net.num_addresses == 0
        assert any(net.subnet_of(b) for b in free)
    # No two placements overlap, and none touches the existing subnet.
    for i, a in enumerate(got):
        assert not a.overlaps(N("10.0.0.0/25"))
        assert all(not a.overlaps(b) for b in got[i + 1 :])
    # Best fit: the /26 and /28 come out of the /25 gap, keeping the /23 whole.
    assert got[0].subnet_of(N("10.0.0.128/25")) and got[2].subnet_of(N("10.0.0.128/25"))
    assert result.placements[0].usable == 64 - 5


def test_fit_reports_missing_and_needed_secondary_size():
    free = _nets("10.0.0.0/24")
    result = cidrplan.fit(free, [FitRequest(24), FitRequest(24), FitRequest(25)])
    assert not result.fits
    assert [p.cidr for p in result.placements] == ["10.0.0.0/24", "", ""]
    assert result.needed_prefix() == 23  # 256 + 128 addresses need a /23
    assert cidrplan.fit([], [FitRequest(28)]).needed_prefix() == 28


def test_fit_does_not_modify_free_list():
    free = _nets("10.0.0.0/24")
    cidrplan.fit(free, [FitRequest(26)])
    assert free == _nets("10.0.0.0/24")


# -- AWS restrictions ---------------------------------------------------------------------


def test_aws_rejects_overlap_with_primary_and_bad_sizes():
    vpc = _nets("10.0.0.0/16")
    v = cidrplan.aws_restrictions(N("10.0.128.0/17"), vpc)
    assert v.status == "rejected" and "primary CIDR 10.0.0.0/16" in v.rejects[0]
    assert cidrplan.aws_restrictions(N("10.2.0.0/15"), vpc).status == "rejected"
    assert cidrplan.aws_restrictions(N("10.1.0.0/29"), vpc).status == "rejected"
    assert cidrplan.aws_restrictions(N("10.1.0.0/16"), vpc).status == "ok"


def test_aws_rejects_other_rfc1918_and_reserved_ranges():
    vpc = _nets("10.0.0.0/16")
    assert "172.16.0.0/12" in cidrplan.aws_restrictions(N("172.20.0.0/16"), vpc).rejects[0]
    assert cidrplan.aws_restrictions(N("192.168.0.0/16"), vpc).status == "rejected"
    assert cidrplan.aws_restrictions(N("198.19.0.0/16"), vpc).status == "rejected"
    assert cidrplan.aws_restrictions(N("169.254.0.0/16"), vpc).status == "rejected"
    # 172.31.0.0/16 is refused next to a 172.16.0.0/12 primary, the rest of the block is not.
    vpc172 = _nets("172.20.0.0/16")
    assert cidrplan.aws_restrictions(N("172.31.0.0/16"), vpc172).status == "rejected"
    assert cidrplan.aws_restrictions(N("172.21.0.0/16"), vpc172).status == "ok"
    # A shared-space primary rules out every RFC 1918 block.
    assert cidrplan.aws_restrictions(N("10.1.0.0/16"), _nets("100.64.0.0/16")).rejects


def test_shared_address_space_is_flagged_and_whole_slash10_rejected():
    vpc = _nets("10.0.0.0/16")
    v = cidrplan.aws_restrictions(N("100.64.0.0/16"), vpc)
    assert v.status == "warning" and "RFC 6598" in v.warnings[0]
    whole = cidrplan.aws_restrictions(N("100.64.0.0/10"), vpc)
    assert whole.status == "rejected" and "/16 to /28" in whole.rejects[0]


def test_aws_warns_at_cidr_quota():
    vpc = [N(f"10.0.{i}.0/24") for i in range(5)]
    v = cidrplan.aws_restrictions(N("10.1.0.0/16"), vpc)
    assert v.status == "warning" and "quota" in v.warnings[0]


# -- overlap across accounts / routes -------------------------------------------------------


def _other_account(db_path, name: str = "example-other") -> int:
    with closing(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO accounts(display_name, region, auth_mode) VALUES(?, 'us-east-1', 'env')",
            (name,),
        )
        return int(cur.lastrowid)


def _route(db_path, snap_id: int, vpc: str, dest: str, target: str) -> None:
    kind = target.split("-", 1)[0]
    with closing(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO ext_crawls(snapshot_id, crawled_at) VALUES(?, ?)",
            (snap_id, datetime.now(UTC).isoformat()),
        )
        conn.execute(
            "INSERT INTO ext_edges(snapshot_id, source, target, evidence, label, detail) "
            "VALUES(?, ?, ?, 'configured', 'route', ?)",
            (
                snap_id,
                f"vpc:{vpc}",
                f"{kind}:{target}",
                f"route table rtb-0example (subnet-a): {dest} → {target}",
            ),
        )


@pytest.fixture
def estate(db_path, snapshot_builder):
    """This account: VPC 10.0.0.0/16 routing 10.2.0.0/16 to a TGW and 10.3.0.0/16 to a
    peering connection. Another account: VPC 10.1.0.0/16 with a 10.0.0.0/8 summary route."""
    mine = snapshot_builder(db_path).vpc(VPC, "10.0.0.0/16")
    mine.subnet("subnet-a", VPC, "10.0.0.0/24")
    _route(db_path, mine.id, VPC, "10.2.0.0/16", "tgw-0example")
    _route(db_path, mine.id, VPC, "10.3.0.0/16", "pcx-0example")
    _route(db_path, mine.id, VPC, "0.0.0.0/0", "tgw-0example")
    _route(db_path, mine.id, VPC, "pl-0example", "tgw-0example")
    ref = _other_account(db_path)
    other = snapshot_builder(db_path, account_ref=ref, account_id="000000000000")
    other.vpc(OTHER_VPC, "10.1.0.0/16")
    _route(db_path, other.id, OTHER_VPC, "10.0.0.0/8", "tgw-0example")
    with closing(db_path) as conn:
        known = cidrplan.known_networks(conn)
    return known


def test_known_networks_cover_all_accounts_and_routes(estate):
    kinds = {(str(k.cidr), k.kind, k.vpc_id) for k in estate}
    assert ("10.0.0.0/16", "vpc", VPC) in kinds
    assert ("10.1.0.0/16", "vpc", OTHER_VPC) in kinds
    assert ("10.2.0.0/16", "tgw-route", VPC) in kinds
    assert ("10.3.0.0/16", "pcx-route", VPC) in kinds
    assert ("10.0.0.0/8", "tgw-route", OTHER_VPC) in kinds
    # Default routes and prefix lists are skipped.
    assert not any(k.cidr.prefixlen == 0 for k in estate)
    assert {k.account for k in estate if k.vpc_id == OTHER_VPC} == {"example-other"}


def test_known_networks_use_latest_snapshot_per_account(db_path, snapshot_builder):
    snapshot_builder(db_path).vpc("vpc-0old", "10.9.0.0/16")
    snapshot_builder(db_path).vpc(VPC, "10.0.0.0/16")
    with closing(db_path) as conn:
        assert {k.vpc_id for k in cidrplan.known_networks(conn)} == {VPC}


def test_candidate_colliding_with_other_account_vpc_is_rejected(estate):
    v = cidrplan.check_candidate(N("10.1.0.0/16"), VPC, _nets("10.0.0.0/16"), estate)
    assert v.status == "rejected"
    assert any(OTHER_VPC in r and "example-other" in r for r in v.rejects)
    # A larger candidate containing the other VPC is rejected too.
    assert cidrplan.check_candidate(N("10.0.0.0/8"), VPC, _nets("10.0.0.0/16"), estate).rejects


def test_candidate_colliding_with_tgw_or_peering_route_is_rejected(estate):
    vpc = _nets("10.0.0.0/16")
    tgw = cidrplan.check_candidate(N("10.2.0.0/16"), VPC, vpc, estate)
    assert tgw.status == "rejected" and any("Transit Gateway" in r for r in tgw.rejects)
    pcx = cidrplan.check_candidate(N("10.3.128.0/17"), VPC, vpc, estate)
    assert pcx.status == "rejected" and any("VPC peering" in r for r in pcx.rejects)


def test_candidate_inside_summary_route_only_warns(estate):
    v = cidrplan.check_candidate(N("10.4.0.0/16"), VPC, _nets("10.0.0.0/16"), estate)
    assert v.status == "warning"
    assert any("broader summary route" in w and "10.0.0.0/8" in w for w in v.warnings)


def test_secondary_candidates_skip_collisions_and_include_shared_space(estate):
    cands = cidrplan.secondary_candidates(VPC, _nets("10.0.0.0/16"), estate, prefix=16)
    rfc = [c for c in cands if c.pool == "10.0.0.0/8"]
    shared = [c for c in cands if c.pool == "100.64.0.0/10"]
    assert [c.cidr for c in rfc] == ["10.4.0.0/16", "10.5.0.0/16", "10.6.0.0/16"]
    assert all(c.status == "warning" for c in rfc)  # under the 10.0.0.0/8 summary route
    assert [c.cidr for c in shared][0] == "100.64.0.0/16"
    assert all("RFC 6598" in c.warnings[0] for c in shared)
    assert not any(c.status == "rejected" for c in cands)


def test_secondary_candidates_avoid_shared_space_in_use(db_path, snapshot_builder):
    ref = _other_account(db_path)
    snapshot_builder(db_path, account_ref=ref).vpc(OTHER_VPC, "100.64.0.0/16")
    with closing(db_path) as conn:
        known = cidrplan.known_networks(conn)
    cands = cidrplan.secondary_candidates(VPC, _nets("10.0.0.0/16"), known, prefix=16)
    shared = [c.cidr for c in cands if c.pool == "100.64.0.0/10"]
    assert shared[0] == "100.65.0.0/16"


# -- Terraform text -----------------------------------------------------------------------


def test_terraform_snippets():
    tf = cidrplan.tf_secondary(VPC, "100.64.0.0/16")
    assert 'resource "aws_vpc_ipv4_cidr_block_association" "secondary_100_64_0_0_16"' in tf
    assert f'vpc_id     = "{VPC}"' in tf and 'cidr_block = "100.64.0.0/16"' in tf
    result = cidrplan.fit(_nets("10.0.0.0/24"), [FitRequest(26, "us-east-1a"), FitRequest(20)])
    subnets = cidrplan.tf_subnets(VPC, result.placements)
    assert subnets.count('resource "aws_subnet"') == 1
    assert 'cidr_block        = "10.0.0.0/26"' in subnets
    assert 'availability_zone = "us-east-1a"' in subnets
    linked = cidrplan.tf_subnets(VPC, result.placements, association="100.64.0.0/16")
    assert "aws_vpc_ipv4_cidr_block_association.secondary_100_64_0_0_16.vpc_id" in linked


def test_plan_overflows_into_secondary_cidr(estate, db_path):
    with closing(db_path) as conn:
        snap = latest_snapshot(conn, 1)
        vpc = vpc_tree(conn, snap["id"])[0]
    p = cidrplan.plan(vpc, estate, [FitRequest(17, "us-east-1a"), FitRequest(17)], prefix=16)
    assert not p.fit.fits  # 10.0.0.0/24 is taken, so only one /17 fits
    assert p.overflow is not None and p.overflow.cidr == "10.4.0.0/16"
    assert p.overflow_fit.fits
    assert "aws_vpc_ipv4_cidr_block_association" in p.overflow_tf
    with pytest.raises(ValueError):
        cidrplan.plan(vpc, estate, custom="10.0.0.1/16")


# -- page ---------------------------------------------------------------------------------


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


def test_planner_page(app, snapshot_builder):
    client = app.test_client()
    assert client.get("/cidr-planner").status_code == 200  # no data yet
    db = app.extensions["iplens"]["paths"].db_path
    b = snapshot_builder(db).vpc(VPC, "10.0.0.0/16", "100.64.0.0/24")
    b.subnet("subnet-a", VPC, "10.0.0.0/24", "us-east-1a")
    page = client.get("/cidr-planner").data.decode()
    assert "CIDR map" in page and "10.0.1.0/24" in page and "fragmentation" in page
    assert "secondary" in page and "100.64.0.0/24" in page
    page = client.get(
        f"/cidr-planner?vpc={VPC}&size=24&az=us-east-1b&size=8&az=&check=100.64.0.0/10"
    ).data.decode()
    assert "fits" in page and "availability_zone = &#34;us-east-1b&#34;" in page
    assert "/16 to /28" in page  # the checked /10 is rejected
    page = client.get(f"/cidr-planner?vpc={VPC}&check=not-a-cidr").data.decode()
    assert "Not an IPv4 network" in page


def test_planner_page_reports_does_not_fit(app, snapshot_builder):
    db = app.extensions["iplens"]["paths"].db_path
    b = snapshot_builder(db).vpc(VPC, "10.0.0.0/24")
    b.subnet("subnet-a", VPC, "10.0.0.0/25")
    page = app.test_client().get(f"/cidr-planner?vpc={VPC}&size=24&az=").data.decode()
    assert "doesn't fit" in page and "need a secondary CIDR" in page
    assert "aws_vpc_ipv4_cidr_block_association" in page
