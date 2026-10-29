"""Transit Gateway links of the Visual page's IP view from normal discovery: the collector's
ec2:DescribeTransitGatewayAttachments / ec2:DescribeRouteTables (moto), attachment ENIs as
their own resource type, attachment ENI -> TGW and subnet -> TGW edges without an Extended
crawl, the crawl merged in without duplicates, and denied calls in the note. Placeholders
only (192.0.2.N, 123456789012, tgw-0abc1234, ...)."""

from __future__ import annotations

import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from iplens import collector as collector_mod
from iplens import queries
from iplens.attribution import OWNER_LABELS
from iplens.aws import AwsGateway
from iplens.collector import (
    ROUTE_TABLES_RESOURCE,
    TGW_ATTACHMENTS_RESOURCE,
    Collector,
    retry_plan,
    route_table_rows,
)
from iplens.db import closing
from iplens.extgraph import EXT_ICONS, TGW_NO_CRAWL, tgw_links
from iplens.queries import TYPE_ICONS
from iplens.web import create_app

REGION = "us-east-1"
VPC = "vpc-0abc5678"
TGW = "tgw-0abc1234"
TGW_B = "tgw-0abc5678"
ATT = "tgw-attach-0abc1234"


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name=REGION))


# -- discovery (moto) ------------------------------------------------------------------------


@pytest.fixture
def aws_tgw():
    """A VPC attached to a Transit Gateway: its attachment ENI, a subnet whose route table
    routes 198.51.100.0/24 to the TGW, and a subnet left on the main route table."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="192.0.2.0/24")["Vpc"]["VpcId"]
        routed = ec2.create_subnet(VpcId=vpc, CidrBlock="192.0.2.0/26")["Subnet"]["SubnetId"]
        plain = ec2.create_subnet(VpcId=vpc, CidrBlock="192.0.2.64/26")["Subnet"]["SubnetId"]
        tgw = ec2.create_transit_gateway()["TransitGateway"]["TransitGatewayId"]
        att = ec2.create_transit_gateway_vpc_attachment(
            TransitGatewayId=tgw, VpcId=vpc, SubnetIds=[routed]
        )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
        rtb = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
        ec2.associate_route_table(RouteTableId=rtb, SubnetId=routed)
        ec2.create_route(
            RouteTableId=rtb, DestinationCidrBlock="198.51.100.0/24", TransitGatewayId=tgw
        )
        eni = ec2.create_network_interface(
            SubnetId=routed,
            PrivateIpAddress="192.0.2.10",
            Description=f"Network Interface for Transit Gateway Attachment {att}",
        )["NetworkInterface"]["NetworkInterfaceId"]
        yield {
            "vpc": vpc,
            "routed": routed,
            "plain": plain,
            "tgw": tgw,
            "att": att,
            "rtb": rtb,
            "eni": eni,
        }


def _table(db_path, table: str, snap_id: int) -> list[dict]:
    with closing(db_path) as conn:
        return [
            dict(r)
            for r in conn.execute(
                f"SELECT * FROM {table} WHERE snapshot_id=?",  # noqa: S608 - test constants
                (snap_id,),
            )
        ]


def test_discovery_stores_attachments_and_route_tables(aws_tgw, db_path):
    result = Collector(_gateway(), db_path).run()
    assert result.skipped == []
    atts = _table(db_path, "tgw_attachments", result.snapshot_id)
    assert [
        (a["attachment_id"], a["tgw_id"], a["resource_type"], a["resource_id"]) for a in atts
    ] == [(aws_tgw["att"], aws_tgw["tgw"], "vpc", aws_tgw["vpc"])]
    tables = {r["route_table_id"]: r for r in _table(db_path, "route_tables", result.snapshot_id)}
    assert json.loads(tables[aws_tgw["rtb"]]["subnet_ids"]) == [aws_tgw["routed"]]
    assert any(t["is_main"] and t["vpc_id"] == aws_tgw["vpc"] for t in tables.values())
    routes = _table(db_path, "tgw_routes", result.snapshot_id)
    assert [(r["route_table_id"], r["destination"], r["tgw_id"]) for r in routes] == [
        (aws_tgw["rtb"], "198.51.100.0/24", aws_tgw["tgw"])
    ]
    # The attachment ENI is its own resource type, named after its attachment.
    (eni,) = [
        e for e in _table(db_path, "enis", result.snapshot_id) if e["eni_id"] == aws_tgw["eni"]
    ]
    assert (eni["owner_type"], eni["owner_ref"]) == ("tgw_attachment", aws_tgw["att"])


def test_ip_view_links_without_an_extended_crawl(aws_tgw, db_path):
    snap = Collector(_gateway(), db_path).run().snapshot_id
    with closing(db_path) as conn:
        tgw = tgw_links(conn, snap, aws_tgw["vpc"])
        data = queries.visual_data(conn, snap, aws_tgw["vpc"], OWNER_LABELS)
    node = f"x:tgw:{aws_tgw['tgw']}"
    assert [n["id"] for n in tgw["nodes"]] == [node]
    assert tgw["nodes"][0]["icon"] == EXT_ICONS["tgw"]
    edges = {e["source"]: e for e in tgw["edges"]}
    assert set(edges) == {f"res:{aws_tgw['eni']}", f"subnet:{aws_tgw['routed']}"}
    att = edges[f"res:{aws_tgw['eni']}"]
    assert att["target"] == node and att["type"] == "tgw"
    assert att["label"].startswith(f"{aws_tgw['att']} · ")  # attachment id · state
    route = edges[f"subnet:{aws_tgw['routed']}"]
    assert route["title"] == (
        f"[route] route table {aws_tgw['rtb']}: 198.51.100.0/24 → {aws_tgw['tgw']}"
    )
    # Without a crawl, the note only offers what the crawl adds; nothing was denied.
    assert tgw["note"] == TGW_NO_CRAWL and tgw["warnings"] == []
    items = [i for s in data["vpc"]["subnets"] for i in s["items"]]
    (res,) = [i for i in items if i["eni_id"] == aws_tgw["eni"]]
    assert res["type"] == "tgw_attachment" and res["icon"] == TYPE_ICONS["tgw_attachment"]
    assert data["type_labels"]["tgw_attachment"] == "TGW attachment"


@pytest.mark.parametrize(
    ("op", "what", "kept"),
    [
        ("describe_route_tables", ROUTE_TABLES_RESOURCE, "res:"),
        ("describe_transit_gateway_attachments", TGW_ATTACHMENTS_RESOURCE, "subnet:"),
    ],
)
def test_denied_discovery_call_reaches_the_tgw_note(aws_tgw, db_path, monkeypatch, op, what, kept):
    real = collector_mod._paginate

    def paginate(client, name, key, **kwargs):
        if name == op:
            raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "x"}}, name)
        return real(client, name, key, **kwargs)

    monkeypatch.setattr(collector_mod, "_paginate", paginate)
    result = Collector(_gateway(), db_path).run()
    assert result.skipped == [(what, "UnauthorizedOperation")]
    with closing(db_path) as conn:
        tgw = tgw_links(conn, result.snapshot_id, aws_tgw["vpc"])
    assert tgw["warnings"] == [f"{what} skipped (UnauthorizedOperation)"]
    assert "discovery was denied access" in tgw["note"] and TGW_NO_CRAWL in tgw["note"]
    # What the other call found is still drawn.
    assert [e["source"].split(":")[0] + ":" for e in tgw["edges"]] == [kept]


def test_retry_skipped_copies_or_collects_the_tgw_tables():
    merged = {t: s for s, tables, _tags in collector_mod._MERGED for t in tables}
    assert merged["tgw_attachments"] == frozenset({TGW_ATTACHMENTS_RESOURCE})
    assert merged["route_tables"] == merged["tgw_routes"] == frozenset({ROUTE_TABLES_RESOURCE})
    assert ROUTE_TABLES_RESOURCE in retry_plan([ROUTE_TABLES_RESOURCE])


def test_route_table_rows():
    rows = route_table_rows(
        [
            {
                "RouteTableId": "rtb-0abc0001",
                "VpcId": VPC,
                "Associations": [
                    {"Main": True},
                    {"SubnetId": "subnet-b"},
                    {"SubnetId": "subnet-a"},
                ],
                "Routes": [
                    {"DestinationCidrBlock": "192.0.2.0/24", "GatewayId": "local"},
                    {"DestinationCidrBlock": "198.51.100.0/24", "TransitGatewayId": TGW},
                    {"DestinationIpv6CidrBlock": "2001:db8::/32", "TransitGatewayId": TGW},
                    {
                        "DestinationPrefixListId": "pl-0abc1234",
                        "TransitGatewayId": TGW_B,
                        "State": "blackhole",
                    },
                ],
            }
        ]
    )
    assert rows == [
        (
            ("rtb-0abc0001", VPC, 1, '["subnet-a", "subnet-b"]'),
            [
                ("198.51.100.0/24", TGW, ""),
                ("2001:db8::/32", TGW, ""),
                ("pl-0abc1234", TGW_B, "blackhole"),
            ],
        )
    ]


# -- links from stored rows: main route table, crawl merge -----------------------------------


def _discovered(snapshot_builder, db_path):
    """subnet-a: explicit route table (two destinations to TGW, a prefix list to TGW_B);
    subnet-b: the main route table (none to a TGW); the attachment ENI in subnet-a."""
    b = snapshot_builder(db_path)
    b.vpc(VPC, "192.0.2.0/24").subnet("subnet-a", VPC, "192.0.2.0/26")
    b.subnet("subnet-b", VPC, "192.0.2.64/26")
    b.eni("eni-0abc0001", "subnet-a", ["192.0.2.10"], owner_type="tgw_attachment", owner_ref=ATT)
    b.eni("eni-0abc0002", "subnet-b", ["192.0.2.70"], name="test-server-a")
    with closing(db_path) as conn:
        conn.executemany(
            "INSERT INTO tgw_attachments VALUES(?,?,?,?,?,?)",
            [
                (b.id, ATT, TGW, "vpc", VPC, "available"),
                (b.id, "tgw-attach-0abc9999", TGW, "vpc", "vpc-0other000", "available"),
            ],
        )
        conn.executemany(
            "INSERT INTO route_tables VALUES(?,?,?,?,?)",
            [
                (b.id, "rtb-0abc0001", VPC, 0, '["subnet-a"]'),
                (b.id, "rtb-0abc0002", VPC, 1, "[]"),
            ],
        )
        conn.executemany(
            "INSERT INTO tgw_routes VALUES(?,?,?,?,?)",
            [
                (b.id, "rtb-0abc0001", "198.51.100.0/24", TGW, "active"),
                (b.id, "rtb-0abc0001", "203.0.113.0/24", TGW, "active"),
                (b.id, "rtb-0abc0001", "pl-0abc1234", TGW_B, "blackhole"),
            ],
        )
    return b


def test_subnet_edges_list_destinations_and_route_table(db_path, snapshot_builder):
    b = _discovered(snapshot_builder, db_path)
    with closing(db_path) as conn:
        tgw = tgw_links(conn, b.id, VPC)
    assert [n["name"] for n in tgw["nodes"]] == [TGW, TGW_B]  # one node per TGW
    edges = {(e["source"], e["target"]): e for e in tgw["edges"]}
    assert set(edges) == {
        ("res:eni-0abc0001", f"x:tgw:{TGW}"),
        ("subnet:subnet-a", f"x:tgw:{TGW}"),
        ("subnet:subnet-a", f"x:tgw:{TGW_B}"),
    }
    assert edges[("res:eni-0abc0001", f"x:tgw:{TGW}")]["label"] == f"{ATT} · available"
    assert edges[("subnet:subnet-a", f"x:tgw:{TGW}")]["title"].splitlines() == [
        f"[route] route table rtb-0abc0001: 198.51.100.0/24 → {TGW}",
        f"[route] route table rtb-0abc0001: 203.0.113.0/24 → {TGW}",
    ]
    assert edges[("subnet:subnet-a", f"x:tgw:{TGW_B}")]["title"] == (
        f"[route] route table rtb-0abc0001: pl-0abc1234 → {TGW_B} (blackhole)"
    )

    # subnet-b follows the main route table once it routes to a Transit Gateway.
    with closing(db_path) as conn:
        conn.execute(
            "INSERT INTO tgw_routes VALUES(?,?,?,?,?)",
            (b.id, "rtb-0abc0002", "0.0.0.0/0", TGW, "active"),
        )
        tgw = tgw_links(conn, b.id, VPC)
    sources = {e["source"] for e in tgw["edges"]}
    assert "subnet:subnet-b" in sources


def test_attachment_without_eni_links_the_vpc(db_path, snapshot_builder):
    b = _discovered(snapshot_builder, db_path)
    with closing(db_path) as conn:
        conn.execute("DELETE FROM enis WHERE eni_id='eni-0abc0001'")
        tgw = tgw_links(conn, b.id, VPC)
    (vpc_edge,) = [e for e in tgw["edges"] if e["source"] == "vpc"]
    assert vpc_edge["title"] == f"[attachment] TGW attachment {ATT} (available), no ENI found"


@pytest.mark.parametrize(
    ("owner_ref", "linked"), [("", True), ("tgw-attach-0abc0000", False)], ids=["no-id", "other"]
)
def test_attachment_eni_without_a_known_id(db_path, snapshot_builder, owner_ref, linked):
    """An attachment ENI whose description names no attachment goes to the VPC's only
    attachment; one naming an attachment not listed is not guessed."""
    b = _discovered(snapshot_builder, db_path)
    with closing(db_path) as conn:
        conn.execute("UPDATE enis SET owner_ref=? WHERE eni_id='eni-0abc0001'", (owner_ref,))
        tgw = tgw_links(conn, b.id, VPC)
    sources = {e["source"] for e in tgw["edges"]}
    assert ("res:eni-0abc0001" in sources) is linked
    assert ("vpc" in sources) is not linked  # the attachment then has no ENI found


def test_crawl_is_merged_without_duplicates(db_path, snapshot_builder):
    b = _discovered(snapshot_builder, db_path)
    crawl_lines = [
        ("attachment", f"TGW attachment {ATT} (vpc {VPC}, available)"),  # drawn: dropped
        ("route", f"route table rtb-0abc0001 (subnet-a): 198.51.100.0/24 → {TGW}"),  # dropped
        ("route", f"route table rtb-0abc0003 (unused): 192.0.2.128/25 → {TGW}"),  # kept
        ("propagation", f"TGW route table tgw-rtb-0abc0001 learns routes propagated from {VPC}"),
    ]
    with closing(db_path) as conn:
        conn.executemany(
            "INSERT INTO ext_edges(snapshot_id, source, target, evidence, label, detail) "
            "VALUES(?,?,?,?,?,?)",
            [(b.id, f"vpc:{VPC}", f"tgw:{TGW}", "configured", lb, d) for lb, d in crawl_lines],
        )
        conn.execute(
            "INSERT INTO ext_crawls(snapshot_id, crawled_at, warnings, sources) VALUES(?,?,?,?)",
            (b.id, "2026-01-01T00:00:00+00:00", "[]", "{}"),
        )
        tgw = tgw_links(conn, b.id, VPC)
    assert [n["name"] for n in tgw["nodes"]] == [TGW, TGW_B]
    (vpc_edge,) = [e for e in tgw["edges"] if e["source"] == "vpc"]
    assert vpc_edge["target"] == f"x:tgw:{TGW}"
    assert [ln["text"] for ln in vpc_edge["lines"]] == [crawl_lines[3][1], crawl_lines[2][1]]
    assert len(tgw["edges"]) == 4  # ENI, two subnet edges, the crawl's VPC edge
    assert tgw["note"] == "" and tgw["warnings"] == []


def test_discovery_and_crawl_denials_are_both_listed(db_path, snapshot_builder):
    b = _discovered(snapshot_builder, db_path)
    found = f"{ROUTE_TABLES_RESOURCE} skipped (AccessDenied)"
    crawled = f"{TGW_ATTACHMENTS_RESOURCE} skipped (AccessDeniedException)"
    with closing(db_path) as conn:
        conn.execute(
            "UPDATE snapshots SET warnings=? WHERE id=?",
            (json.dumps([found, "lambda:ListFunctions skipped (AccessDenied)"]), b.id),
        )
        conn.execute(
            "INSERT INTO ext_crawls(snapshot_id, crawled_at, warnings, sources) VALUES(?,?,?,?)",
            (b.id, "2026-01-01T00:00:00+00:00", json.dumps([crawled]), "{}"),
        )
        tgw = tgw_links(conn, b.id, VPC)
    assert tgw["warnings"] == [found, crawled]
    assert "discovery was denied" in tgw["note"] and "the Extended crawl was denied" in tgw["note"]


def test_data_json_carries_the_discovered_links(home, snapshot_builder):
    app = create_app(home, testing=True)
    client = app.test_client()
    client.get("/")
    b = _discovered(snapshot_builder, app.extensions["iplens"]["paths"].db_path)
    data = client.get(f"/visual/data.json?vpc={VPC}").get_json()
    assert {e["source"] for e in data["tgw"]["edges"]} == {"res:eni-0abc0001", "subnet:subnet-a"}
    page = client.get(f"/visual?vpc={VPC}").get_data(as_text=True)
    assert "icons/ext/tgw-attachment.svg" in page  # legend icon of the new resource type
    assert b.id == data["snapshot_id"]
