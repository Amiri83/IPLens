"""Extended view: Amazon MSK (ListClustersV2) and Lambda event source mappings from MSK or
self-managed Kafka become "Kafka: <cluster or bootstrap host>" nodes; crawled nodes linked
to nothing are listed as "not linked".

Placeholder data only (10.0.x.x, 123456789012, example names and hosts)."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from iplens import queries
from iplens.aws import is_read_only_operation
from iplens.db import closing
from iplens.extended import ExtendedCrawler, kafka_bootstrap_host, node_for_arn
from iplens.extgraph import extended_data
from iplens.web import create_app

REGION, ACCOUNT = "us-east-1", "123456789012"
VPC, SUBNET, FN_ENI = "vpc-0example0000001", "subnet-0000000a", "eni-00000000fa"
FN_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:fn-a"
MSK_ARN = f"arn:aws:kafka:{REGION}:{ACCOUNT}:cluster/example-msk/00000000-0000-example-0"
IDLE_ARN = f"arn:aws:kafka:{REGION}:{ACCOUNT}:cluster/example-msk-idle/00000000-0000-example-1"
BOOTSTRAP = ["b-1.kafka.example.internal:9092", "b-2.kafka.example.internal:9092"]


def _denied(op: str) -> ClientError:
    return ClientError({"Error": {"Code": "AccessDeniedException", "Message": "example"}}, op)


class _Pages:
    def __init__(self, key: str, items: list[Any]):
        self.key, self.items = key, items

    def paginate(self, **_kw):
        return iter([{self.key: self.items}])


class _FakeClient:
    """Paginated list calls from ``pages``; every other call is denied."""

    def __init__(self, pages: dict[str, tuple[str, list[Any]]]):
        self.pages = pages
        self.ops: list[str] = []

    def get_paginator(self, op: str) -> _Pages:
        self.ops.append(op)
        if op not in self.pages:
            raise _denied(op)
        return _Pages(*self.pages[op])

    def __getattr__(self, op: str):
        def call(**_kw):
            raise _denied(op)

        return call


class _FakeGateway:
    region = REGION

    def __init__(self, clients: dict[str, _FakeClient]):
        self.clients = clients

    def client(self, service: str) -> _FakeClient:
        return self.clients.setdefault(service, _FakeClient({}))


def _mappings() -> list[dict[str, Any]]:
    return [
        {
            "FunctionArn": FN_ARN,
            "EventSourceArn": MSK_ARN,
            "State": "Enabled",
            "Topics": ["orders"],
        },
        {
            "FunctionArn": FN_ARN,
            "SelfManagedEventSource": {"Endpoints": {"KAFKA_BOOTSTRAP_SERVERS": BOOTSTRAP}},
            "State": "Enabled",
            "Topics": ["events"],
        },
    ]


def _gateway(with_msk: bool = True) -> _FakeGateway:
    lam = _FakeClient(
        {
            "list_functions": ("Functions", [{"FunctionName": "fn-a", "FunctionArn": FN_ARN}]),
            "list_event_source_mappings": ("EventSourceMappings", _mappings()),
        }
    )
    clusters = [
        {"ClusterName": "example-msk", "ClusterArn": MSK_ARN, "ClusterType": "PROVISIONED"},
        {"ClusterName": "example-msk-idle", "ClusterArn": IDLE_ARN, "ClusterType": "SERVERLESS"},
    ]
    kafka = _FakeClient({"list_clusters_v2": ("ClusterInfoList", clusters)} if with_msk else {})
    return _FakeGateway({"lambda": lam, "kafka": kafka})


def _snapshot(snapshot_builder, db_path):
    b = snapshot_builder(db_path).vpc(VPC, "10.0.0.0/16").subnet(SUBNET, VPC, "10.0.1.0/24")
    b.eni(FN_ENI, SUBNET, ["10.0.1.20"], owner_type="lambda", owner_ref="fn-a")
    return b


def _edges(db_path, snap_id) -> set[tuple[str, str, str, str]]:
    with closing(db_path) as conn:
        return {
            (r["source"], r["target"], r["evidence"], r["label"])
            for r in conn.execute("SELECT * FROM ext_edges WHERE snapshot_id=?", (snap_id,))
        }


def test_kafka_helpers():
    assert is_read_only_operation("kafka", "ListClustersV2")
    assert node_for_arn(MSK_ARN) == ("kafka", "example-msk")
    assert kafka_bootstrap_host(_mappings()[1]) == "b-1.kafka.example.internal"
    assert kafka_bootstrap_host({"SelfManagedEventSource": {"Endpoints": {}}}) == ""


def test_msk_and_self_managed_kafka_event_sources(db_path, snapshot_builder):
    b = _snapshot(snapshot_builder, db_path)
    gw = _gateway()
    result = ExtendedCrawler(gw, db_path, b.id).run()  # type: ignore[arg-type]
    assert result.sources["kafka:ListClustersV2"] == 2
    assert "list_clusters_v2" in gw.clients["kafka"].ops  # the MSK list call covering both types
    edges = _edges(db_path, b.id)
    assert ("kafka:example-msk", "lambda:fn-a", "configured", "event source") in edges
    assert (
        "kafka:b-1.kafka.example.internal",
        "lambda:fn-a",
        "configured",
        "event source",
    ) in edges
    with closing(db_path) as conn:
        nodes = {r["node_id"]: r for r in conn.execute("SELECT * FROM ext_nodes")}
        details = [r["detail"] for r in conn.execute("SELECT detail FROM ext_edges")]
    assert nodes["kafka:example-msk"]["arn"] == MSK_ARN
    assert nodes["kafka:b-1.kafka.example.internal"]["area"] == "external"
    assert any("MSK cluster example-msk topic(s) orders triggers fn-a" in d for d in details)
    assert any("self-managed Kafka b-1.kafka.example.internal" in d for d in details)

    # Payload: "Kafka: <name>" nodes linked to the function's ENI; the idle cluster is
    # crawled but linked to nothing, so it is listed as not linked.
    with closing(db_path) as conn:
        data = queries.visual_data(conn, b.id, VPC)
        ext = extended_data(conn, b.id, data)
    nodes = {n["id"]: n for n in ext["nodes"]}
    msk = nodes["x:kafka:example-msk"]
    assert msk["label_name"] == "Kafka: example-msk" and msk["icon"] == "ext/kafka.svg"
    assert nodes["x:kafka:b-1.kafka.example.internal"]["label_name"].startswith("Kafka: b-1.")
    assert {(e["source"], e["target"]) for e in ext["edges"]} >= {("x:kafka:example-msk", FN_ENI)}
    hidden = {n["id"]: n for n in ext["hidden"]}
    assert (
        "x:kafka:example-msk-idle" in hidden
        and hidden["x:kafka:example-msk-idle"]["linked"] is False
    )
    assert ext["hidden_nodes"] == len(ext["hidden"]) >= 1


def test_missing_msk_permission_is_a_warning(db_path, snapshot_builder):
    b = _snapshot(snapshot_builder, db_path)
    result = ExtendedCrawler(_gateway(with_msk=False), db_path, b.id).run()  # type: ignore[arg-type]
    assert "kafka:ListClustersV2 skipped (AccessDeniedException)" in result.warnings
    # The event source mapping still names the cluster by its ARN.
    assert ("kafka:example-msk", "lambda:fn-a", "configured", "event source") in _edges(
        db_path, b.id
    )


def test_extended_page_has_the_not_linked_panel(home, snapshot_builder):
    app = create_app(home, testing=True)
    client = app.test_client()
    db = app.extensions["iplens"]["paths"].db_path
    _snapshot(snapshot_builder, db)
    page = client.get(f"/visual?vpc={VPC}&view=extended").data.decode()
    assert 'id="unlinked-panel"' in page and "Show all crawled nodes" in page
    assert "Not linked" in page and 'data-job="crawl"' in page
    assert 'id="unlinked-panel"' not in client.get(f"/visual?vpc={VPC}").data.decode()
    resp = client.get("/static/icons/ext/kafka.svg")
    assert resp.status_code == 200 and b"<svg" in resp.data
    resp.close()
