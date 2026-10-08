"""Extended view: read-only guard allowlist, service crawl evidence, flow logs, payload
and exports. Placeholder data only (10.0.x.x, 123456789012, fn-a, queue-a, ...)."""

from __future__ import annotations

import io
import json
import logging
import zipfile
from datetime import UTC, datetime
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from iplens import flowlogs
from iplens.aws import AwsGateway, ReadOnlyViolation, is_read_only_operation
from iplens.db import closing
from iplens.diagram import export_filename, parse_view, view_to_drawio, view_to_svg
from iplens.extended import (
    MAX_PATTERN_MATCHES,
    Catalog,
    ExtendedCrawler,
    ExtGraph,
    latest_crawl,
)
from iplens.extgraph import EXT_ICONS
from iplens.queries import VPC_ICON
from iplens.web import create_app

REGION = "us-east-1"
ACCOUNT = "123456789012"
ENV_VALUE = "placeholder-env-value-0000"  # an env var value that must never be stored
SECRET_VALUE = "placeholder-secret-value-0000"  # a secret value that must never be read
POLICY_SID = "PlaceholderSidNeverStored"  # policy documents are never stored either


def _gw() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name=REGION))


def _dump(db_path) -> str:
    with closing(db_path) as conn:
        return "\n".join(conn.iterdump())


# -- read-only guard -------------------------------------------------------------------


@pytest.mark.parametrize(
    "service, op, allowed",
    [
        ("logs", "StartQuery", True),
        ("logs", "GetQueryResults", True),
        ("logs", "StopQuery", True),
        ("logs", "FilterLogEvents", True),
        ("logs", "DescribeLogGroups", True),
        ("ec2", "DescribeRouteTables", True),
        ("logs", "PutLogEvents", False),
        ("logs", "CreateLogGroup", False),
        ("logs", "PutQueryDefinition", False),
        ("logs", "StartLiveTail", False),
        ("athena", "StartQueryExecution", False),
        ("ec2", "CreateRoute", False),
        ("sqs", "PutQueueAttributes", False),
        ("secretsmanager", "GetSecretValue", False),
        ("secretsmanager", "BatchGetSecretValue", False),
        ("ssm", "GetParameter", False),
    ],
)
def test_guard_allowlist(service, op, allowed):
    assert is_read_only_operation(service, op) is allowed


@mock_aws
def test_guard_allows_logs_queries_and_blocks_put_create():
    raw = boto3.client("logs", region_name=REGION)
    raw.create_log_group(logGroupName="flow-logs-a")
    logs = _gw().client("logs")
    qid = logs.start_query(
        logGroupNames=["flow-logs-a"],
        startTime=0,
        endTime=60,
        queryString="fields @timestamp | limit 1",
    )["queryId"]
    assert logs.get_query_results(queryId=qid)["status"]
    logs.filter_log_events(logGroupName="flow-logs-a")
    with pytest.raises(ReadOnlyViolation):
        logs.create_log_group(logGroupName="flow-logs-b")
    with pytest.raises(ReadOnlyViolation):
        logs.put_log_events(
            logGroupName="flow-logs-a",
            logStreamName="s",
            logEvents=[{"timestamp": 0, "message": "x"}],
        )
    with pytest.raises(ReadOnlyViolation):
        _gw().client("secretsmanager").get_secret_value(SecretId="secret-a")
    names = [g["logGroupName"] for g in raw.describe_log_groups()["logGroups"]]
    assert names == ["flow-logs-a"]


# -- reference matching --------------------------------------------------------------


def test_catalog_matches_known_names_and_arns_only():
    cat = Catalog()
    qarn = f"arn:aws:sqs:{REGION}:{ACCOUNT}:queue-a"
    sarn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:secret-a-AbCdEf"
    cat.add("sqs:queue-a", "queue-a", arn=qarn)
    cat.add("secretsmanager:secret-a", "secret-a", arn=sarn)
    cat.add("s3:bucket-a", "bucket-a", arn="arn:aws:s3:::bucket-a")
    assert cat.match("queue-a") == {"sqs:queue-a"}
    assert cat.match(qarn) == {"sqs:queue-a"}
    assert cat.match("s3://bucket-a/prefix/key") == {"s3:bucket-a"}
    # A secret ARN without its random suffix still names the secret.
    assert cat.match(f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:secret-a") == {
        "secretsmanager:secret-a"
    }
    assert cat.match(ENV_VALUE) == set()
    assert cat.match("ab") == set() and cat.match(42) == set()


def test_iam_patterns_star_and_wide_patterns_are_broad():
    cat = Catalog()
    for i in range(MAX_PATTERN_MATCHES + 1):
        cat.add(f"sqs:queue-{i}", arn=f"arn:aws:sqs:{REGION}:{ACCOUNT}:queue-{i}")
    assert cat.match_pattern("*") is None
    assert cat.match_pattern("arn:aws:sqs:*:*:*") is None
    assert cat.match_pattern(f"arn:aws:sqs:{REGION}:{ACCOUNT}:queue-*") is None  # too wide
    assert cat.match_pattern(f"arn:aws:sqs:{REGION}:{ACCOUNT}:queue-1") == {"sqs:queue-1"}
    assert cat.match_pattern(f"arn:aws:sqs:{REGION}:{ACCOUNT}:queue-2?") == {
        "sqs:queue-20",
        "sqs:queue-21",
        "sqs:queue-22",
        "sqs:queue-23",
        "sqs:queue-24",
        "sqs:queue-25",
    }


def test_graph_edges_need_two_distinct_ends():
    g = ExtGraph()
    a = g.node("lambda", "fn-a")
    g.edge(a, a, "configured", "x", "self")
    g.edge(a, "", "configured", "x", "nothing")
    assert not g.edges


# -- crawl -----------------------------------------------------------------------------


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("handler.py", "def handler(event, context):\n    return None\n")
    return buf.getvalue()


def _seed_aws() -> dict[str, str]:
    """Moto resources wired together in every way the crawl understands."""
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/17")["Vpc"]["VpcId"]
    peer = ec2.create_vpc(CidrBlock="10.0.128.0/17")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    rtb = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.associate_route_table(RouteTableId=rtb, SubnetId=subnet)
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    pcx = ec2.create_vpc_peering_connection(VpcId=vpc, PeerVpcId=peer)["VpcPeeringConnection"][
        "VpcPeeringConnectionId"
    ]
    ec2.create_route(
        RouteTableId=rtb, DestinationCidrBlock="10.0.128.0/17", VpcPeeringConnectionId=pcx
    )
    tgw = ec2.create_transit_gateway()["TransitGateway"]["TransitGatewayId"]
    ec2.create_transit_gateway_vpc_attachment(TransitGatewayId=tgw, VpcId=vpc, SubnetIds=[subnet])

    iam = boto3.client("iam", region_name=REGION)
    assume = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName="role-fn-a", AssumeRolePolicyDocument=json.dumps(assume))
    role_arn = role["Role"]["Arn"]

    sqs = boto3.client("sqs", region_name=REGION)
    dlq_url = sqs.create_queue(QueueName="queue-a-dlq")["QueueUrl"]
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    queue_url = sqs.create_queue(
        QueueName="queue-a",
        Attributes={
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 3})
        },
    )["QueueUrl"]
    queue_arn = f"arn:aws:sqs:{REGION}:{ACCOUNT}:queue-a"

    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(
        TableName="table-a",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    table_arn = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/table-a"

    sm = boto3.client("secretsmanager", region_name=REGION)
    sm.create_secret(Name="secret-a", SecretString=SECRET_VALUE)

    iam.put_role_policy(
        RoleName="role-fn-a",
        PolicyName="policy-fn-a",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": POLICY_SID,
                        "Effect": "Allow",
                        "Action": ["sqs:SendMessage"],
                        "Resource": queue_arn,
                    },
                    {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": table_arn},
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                ],
            }
        ),
    )

    lam = boto3.client("lambda", region_name=REGION)
    fn_arn = lam.create_function(
        FunctionName="fn-a",
        Runtime="python3.12",
        Role=role_arn,
        Handler="handler.handler",
        Code={"ZipFile": _zip()},
        Environment={
            "Variables": {
                "QUEUE_URL": queue_url,
                "TABLE": "table-a",
                "SECRET_ID": "secret-a",
                "DB_PASSWORD": ENV_VALUE,
            }
        },
    )["FunctionArn"]
    lam.create_event_source_mapping(EventSourceArn=queue_arn, FunctionName="fn-a")

    sns = boto3.client("sns", region_name=REGION)
    topic = sns.create_topic(Name="topic-a")["TopicArn"]
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)

    events = boto3.client("events", region_name=REGION)
    events.put_rule(Name="rule-a", ScheduleExpression="rate(5 minutes)")
    events.put_targets(Rule="rule-a", Targets=[{"Id": "t1", "Arn": fn_arn}])

    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="bucket-a")
    s3.put_bucket_notification_configuration(
        Bucket="bucket-a",
        NotificationConfiguration={
            "QueueConfigurations": [{"QueueArn": queue_arn, "Events": ["s3:ObjectCreated:*"]}]
        },
    )
    return {"vpc": vpc, "subnet": subnet, "tgw": tgw, "pcx": pcx, "igw": igw}


def _snapshot(snapshot_builder, db_path, vpc: str, subnet: str):
    b = snapshot_builder(db_path)
    b.vpc(vpc, "10.0.0.0/17").subnet(subnet, vpc, "10.0.1.0/24")
    b.eni("eni-0000000001", subnet, ["10.0.1.10"])
    b.eni("eni-0000000002", subnet, ["10.0.1.20"])
    return b


def _edges(db_path, snap_id) -> set[tuple[str, str, str, str]]:
    with closing(db_path) as conn:
        return {
            (r["source"], r["target"], r["evidence"], r["label"])
            for r in conn.execute(
                "SELECT source, target, evidence, label FROM ext_edges WHERE snapshot_id=?",
                (snap_id,),
            )
        }


@mock_aws
def test_crawl_records_each_evidence_level(db_path, snapshot_builder, caplog):
    ids = _seed_aws()
    b = _snapshot(snapshot_builder, db_path, ids["vpc"], ids["subnet"])
    caplog.set_level(logging.DEBUG, logger="iplens")
    result = ExtendedCrawler(_gw(), db_path, b.id).run()

    edges = _edges(db_path, b.id)
    configured = {(s, t, lbl) for s, t, ev, lbl in edges if ev == "configured"}
    permitted = {(s, t) for s, t, ev, _ in edges if ev == "permitted"}
    referenced = {(s, t) for s, t, ev, _ in edges if ev == "referenced"}

    # configured: SNS subscription, SQS DLQ, event source mapping, EventBridge target,
    # S3 notification, routes, TGW attachment and peering.
    assert ("sns:topic-a", "sqs:queue-a", "subscription") in configured
    assert ("sqs:queue-a", "sqs:queue-a-dlq", "DLQ") in configured
    assert ("sqs:queue-a", "lambda:fn-a", "event source") in configured
    assert ("events:rule-a", "lambda:fn-a", "rule target") in configured
    assert ("s3:bucket-a", "sqs:queue-a", "notification") in configured
    assert (f"vpc:{ids['vpc']}", "internet:igw", "route") in configured
    assert (f"vpc:{ids['vpc']}", f"pcx:{ids['pcx']}", "route") in configured
    assert (f"vpc:{ids['vpc']}", f"pcx:{ids['pcx']}", "peering") in configured
    assert (f"vpc:{ids['vpc']}", f"tgw:{ids['tgw']}", "attachment") in configured
    # permitted: the function role's policy names the queue and the table.
    assert ("lambda:fn-a", "sqs:queue-a") in permitted
    assert ("lambda:fn-a", "dynamodb:table-a") in permitted
    # referenced: env vars name the queue (URL), the table and the secret (names).
    assert {
        ("lambda:fn-a", "sqs:queue-a"),
        ("lambda:fn-a", "dynamodb:table-a"),
        ("lambda:fn-a", "secretsmanager:secret-a"),
    } <= referenced

    with closing(db_path) as conn:
        nodes = {
            r["node_id"]: r
            for r in conn.execute("SELECT * FROM ext_nodes WHERE snapshot_id=?", (b.id,))
        }
        facts = [r["detail"] for r in conn.execute("SELECT detail FROM ext_facts")]
        crawl = latest_crawl(conn, b.id)
    # Resource "*" is a broad-access badge, never expanded into edges.
    assert nodes["lambda:fn-a"]["broad_access"] == 1
    assert not any(t.startswith("s3:") for s, t in permitted)
    assert any(f.startswith("broad access: role role-fn-a") for f in facts)
    assert nodes["internet:igw"]["area"] == "external"
    assert nodes["sqs:queue-a"]["area"] == "regional"
    assert any("route table" in f and ids["subnet"] in f for f in facts)
    assert crawl is not None and crawl["sources"]["lambda:ListFunctions"] == 1
    assert result.nodes == len(nodes) and result.edges == len(edges)

    # Values are matched, never kept: env var values, secret values and policy
    # documents appear nowhere in the database or the log.
    dump = _dump(db_path)
    logged = "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("iplens"))
    assert "extended crawl finished" in logged
    for value in (ENV_VALUE, SECRET_VALUE, POLICY_SID):
        assert value not in dump
        assert value not in logged
    assert "DB_PASSWORD" not in dump  # the variable named nothing known
    assert "environment variable QUEUE_URL of function fn-a names SQS queue queue-a" in dump


def _deny(service: str):
    def handler(model=None, **_: Any) -> None:
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "example"}}, model.name
        )

    return service, handler


class _PartialGateway(AwsGateway):
    """A gateway whose credentials lack permissions for some services."""

    def __init__(self, denied: set[str]):
        super().__init__(boto3.session.Session(region_name=REGION))
        self.denied = denied

    def client(self, service: str) -> Any:
        c = super().client(service)
        if service in self.denied:
            c.meta.events.register("before-call", _deny(service)[1])
        return c


@mock_aws
def test_missing_permissions_become_warnings(db_path, snapshot_builder):
    ids = _seed_aws()
    b = _snapshot(snapshot_builder, db_path, ids["vpc"], ids["subnet"])
    result = ExtendedCrawler(_PartialGateway({"sns", "iam", "config"}), db_path, b.id).run()
    assert "sns:ListTopics skipped (AccessDeniedException)" in result.warnings
    assert "iam:GetRolePolicy skipped (AccessDeniedException)" in result.warnings
    assert any(w.startswith("config:") for w in result.warnings)
    edges = _edges(db_path, b.id)
    # Everything else still ran.
    assert ("sqs:queue-a", "lambda:fn-a", "event source") in {(s, t, lbl) for s, t, _, lbl in edges}
    assert not any(ev == "permitted" for _, _, ev, _ in edges)
    assert not any(s.startswith("sns:") for s, _, _, _ in edges)


class _Pages:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_kw):
        return iter(self.pages)


class _FakeXray:
    def __init__(self, services):
        self.services = services

    def get_paginator(self, op):
        assert op == "get_service_graph"
        return _Pages([{"Services": self.services}])


def test_xray_service_graph_is_observed_evidence(db_path, snapshot_builder):
    b = snapshot_builder(db_path).vpc("vpc-0example0000001", "10.0.0.0/16")
    crawler = ExtendedCrawler(None, db_path, b.id)  # type: ignore[arg-type]
    crawler.graph.node("lambda", "fn-a", f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:fn-a")
    crawler.graph.node("dynamodb", "table-a", f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/table-a")
    services = [
        {
            "ReferenceId": 1,
            "Name": "fn-a",
            "Type": "AWS::Lambda::Function",
            "Edges": [{"ReferenceId": 2, "SummaryStatistics": {"TotalCount": 7}}],
        },
        {"ReferenceId": 2, "Name": "table-a", "Type": "AWS::DynamoDB::Table", "Edges": []},
    ]
    crawler._client = lambda _service: _FakeXray(services)  # type: ignore[method-assign]
    assert crawler._xray() == 1
    (edge,) = crawler.graph.edges
    assert edge[:4] == ("lambda:fn-a", "dynamodb:table-a", "observed", "X-Ray")
    assert "7 request(s)" in edge[4]

    crawler._client = lambda _service: _FakeXray([])  # type: ignore[method-assign]
    assert crawler._xray() == 0
    assert "X-Ray: no traces in the last hour; skipped" in crawler.result.warnings


# -- flow logs -------------------------------------------------------------------------


class _FakeEc2:
    def get_paginator(self, op):
        assert op == "describe_flow_logs"
        return _Pages(
            [
                {
                    "FlowLogs": [
                        {"LogDestinationType": "cloud-watch-logs", "LogGroupName": "flow-logs-a"},
                        {"LogDestinationType": "s3", "LogDestination": "arn:aws:s3:::bucket-a"},
                    ]
                }
            ]
        )


class _FakeLogs:
    GB = 1024**3

    def __init__(self, rows):
        self.rows = rows
        self.calls: list[str] = []
        self.polls = 0

    def describe_log_groups(self, logGroupNamePrefix):
        self.calls.append("DescribeLogGroups")
        now_ms = datetime.now(UTC).timestamp() * 1000
        return {
            "logGroups": [
                {
                    "logGroupName": logGroupNamePrefix,
                    "storedBytes": 24 * self.GB,
                    "retentionInDays": 1,
                    "creationTime": now_ms - 30 * 86400 * 1000,
                }
            ]
        }

    def start_query(self, **kw):
        self.calls.append("StartQuery")
        self.started = kw
        return {"queryId": "query-0example"}

    def get_query_results(self, queryId):
        self.calls.append("GetQueryResults")
        self.polls += 1
        if self.polls == 1:
            return {"status": "Running"}
        return {
            "status": "Complete",
            "statistics": {"bytesScanned": 2048.0},
            "results": [[{"field": k, "value": v} for k, v in row.items()] for row in self.rows],
        }

    def stop_query(self, queryId):
        self.calls.append("StopQuery")


class _FakeGateway:
    def __init__(self, logs):
        self.logs = logs

    def client(self, service):
        return {"ec2": _FakeEc2(), "logs": self.logs}[service]


FLOW_ROWS = [
    # eni-1 -> eni-2 on tcp/443, split over two rows that aggregate into one.
    {"srcAddr": "10.0.1.10", "dstAddr": "10.0.1.20", "dstPort": "443", "protocol": "6",
     "flows": "3", "bytes": "1000", "packets": "10"},
    {"srcAddr": "10.0.1.11", "dstAddr": "10.0.1.20", "dstPort": "443", "protocol": "6",
     "flows": "2", "bytes": "500", "packets": "5"},
    # A private peer outside the snapshot is kept only as "outside".
    {"srcAddr": "10.0.9.9", "dstAddr": "10.0.1.20", "dstPort": "53", "protocol": "17",
     "flows": "1", "bytes": "80", "packets": "1"},
    # Neither side known: skipped.
    {"srcAddr": "10.0.8.8", "dstAddr": "10.0.9.9", "dstPort": "22", "protocol": "6",
     "flows": "1", "bytes": "60", "packets": "1"},
]  # fmt: skip


def _flow_snapshot(snapshot_builder, db_path):
    b = snapshot_builder(db_path)
    b.vpc("vpc-0example0000001", "10.0.0.0/16").subnet(
        "subnet-0000000a", "vpc-0example0000001", "10.0.1.0/24"
    )
    b.eni("eni-0000000001", "subnet-0000000a", ["10.0.1.10", "10.0.1.11"])
    b.eni("eni-0000000002", "subnet-0000000a", ["10.0.1.20"])
    return b


def test_flow_log_estimate_before_running():
    logs = _FakeLogs([])
    est = flowlogs.estimate(_FakeGateway(logs), "vpc-0example0000001", ["subnet-0000000a"], "1h")
    # 24 GB retained for 1 day; a 1 hour window scans about 1/24 of it.
    assert est.log_groups == ["flow-logs-a"]
    assert est.estimated_bytes == _FakeLogs.GB
    d = est.as_dict()
    assert d["window_label"] == "1 hour" and d["estimated_label"] == "1.0 GB"
    assert "$0.0050" in d["cost_label"]
    assert logs.calls == ["DescribeLogGroups"]  # estimating never starts a query
    assert flowlogs.parse_window("bogus") == flowlogs.DEFAULT_WINDOW == "1h"


def test_flow_log_run_stores_only_aggregates(db_path, snapshot_builder):
    b = _flow_snapshot(snapshot_builder, db_path)
    logs = _FakeLogs(FLOW_ROWS)
    res = flowlogs.run(
        _FakeGateway(logs),
        db_path,
        b.id,
        "vpc-0example0000001",
        ["subnet-0000000a"],
        "1h",
        sleep=lambda _s: None,
    )
    assert logs.calls == ["StartQuery", "GetQueryResults", "GetQueryResults"]
    assert logs.started["logGroupNames"] == ["flow-logs-a"]  # CloudWatch Logs only, not S3
    assert logs.started["endTime"] - logs.started["startTime"] == 3600
    assert all(is_read_only_operation("logs", op) for op in logs.calls)
    assert (res.pairs, res.skipped, res.bytes_scanned) == (2, 1, 2048)
    with closing(db_path) as conn:
        rows = [
            tuple(r)
            for r in conn.execute(
                "SELECT src_eni, dst_eni, protocol, port, flows, bytes, packets "
                "FROM flow_aggregates ORDER BY port"
            )
        ]
        flow_tables = json.dumps(
            [tuple(r) for r in conn.execute("SELECT * FROM flow_aggregates")]
            + [tuple(r) for r in conn.execute("SELECT * FROM flow_runs")]
        )
    assert rows == [
        ("outside", "eni-0000000002", "udp", 53, 1, 80, 1),
        ("eni-0000000001", "eni-0000000002", "tcp", 443, 5, 1500, 15),
    ]
    # No address of the raw records is stored.
    for addr in ("10.0.1.10", "10.0.1.11", "10.0.1.20", "10.0.9.9", "10.0.8.8"):
        assert addr not in flow_tables


def test_flow_log_query_timeout_stops_query(db_path, snapshot_builder):
    b = _flow_snapshot(snapshot_builder, db_path)

    class Slow(_FakeLogs):
        def get_query_results(self, queryId):
            self.calls.append("GetQueryResults")
            return {"status": "Running"}

    logs = Slow([])
    with pytest.raises(flowlogs.FlowLogError, match="did not finish"):
        flowlogs.run(
            _FakeGateway(logs),
            db_path,
            b.id,
            "vpc-0example0000001",
            [],
            "15m",
            sleep=lambda _s: None,
            timeout_s=4,
        )
    assert logs.calls[-1] == "StopQuery"


# -- Visual page payload and routes ------------------------------------------------------


VPC = "vpc-0example0000001"
SA = "subnet-0000000a"


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


@pytest.fixture
def client(app):
    c = app.test_client()
    c.get("/")
    return c


def _post(client, url, data=None, **kw):
    with client.session_transaction() as s:
        token = s["csrf"]
    return client.post(url, data={**(data or {}), "csrf_token": token}, **kw)


def _app_db(app):
    return app.extensions["iplens"]["paths"].db_path


@pytest.fixture
def ext_seeded(app, snapshot_builder):
    db = _app_db(app)
    b = _flow_snapshot(snapshot_builder, db)
    rows = [
        # Two evidence lines between the same nodes: the strongest wins.
        ("lambda:fn-a", "sqs:queue-a", "referenced", "env", "environment variable QUEUE_URL"),
        ("lambda:fn-a", "sqs:queue-a", "permitted", "IAM", "role role-fn-a allows sqs"),
        ("eni:eni-0000000001", "eni:eni-0000000002", "configured", "x", "configured line"),
        (f"vpc:{VPC}", "tgw:tgw-0example0000001", "configured", "route", "10.0.0.0/8 → tgw"),
        ("vpc:vpc-0other00000000", "tgw:tgw-0example0000001", "configured", "route", "other"),
    ]
    with closing(db) as conn:
        conn.executemany(
            "INSERT INTO ext_edges(snapshot_id, source, target, evidence, label, detail) "
            "VALUES(?,?,?,?,?,?)",
            [(b.id, *r) for r in rows],
        )
        conn.executemany(
            "INSERT INTO ext_nodes(snapshot_id, node_id, service, name, arn, area, broad_access) "
            "VALUES(?,?,?,?,?,?,?)",
            [
                (b.id, "lambda:fn-a", "lambda", "fn-a", "", "regional", 1),
                (b.id, "sqs:queue-a", "sqs", "queue-a", "", "regional", 0),
                (b.id, "tgw:tgw-0example0000001", "tgw", "tgw-0example0000001", "", "external", 0),
                (b.id, "sns:topic-unlinked", "sns", "topic-unlinked", "", "regional", 0),
            ],
        )
        conn.execute(
            "INSERT INTO ext_crawls(snapshot_id, crawled_at, warnings, sources) VALUES(?,?,?,?)",
            (b.id, "2026-01-01T00:00:00+00:00", '["xray: example warning"]', "{}"),
        )
        conn.execute(
            "INSERT INTO flow_aggregates(snapshot_id, vpc_id, src_eni, dst_eni, protocol, port, "
            "flows, bytes, packets) VALUES(?,?,?,?,?,?,?,?,?)",
            (b.id, VPC, "eni-0000000001", "eni-0000000002", "tcp", 443, 5, 1500, 15),
        )
        conn.execute(
            "INSERT INTO flow_runs(snapshot_id, vpc_id, ran_at, window_minutes, log_groups, "
            "bytes_scanned, rows) VALUES(?,?,?,?,?,?,?)",
            (b.id, VPC, "2026-01-01T00:00:00+00:00", 60, '["flow-logs-a"]', 2048, 1),
        )
    return b


def test_ip_view_stays_default(client, ext_seeded):
    page = client.get(f"/visual?vpc={VPC}").data.decode()
    assert 'aria-current="page">IP view' in page
    assert "Crawl services" not in page and 'data-mode="ip"' in page
    data = client.get(f"/visual/data.json?vpc={VPC}").get_json()
    assert "extended" not in data


def test_extended_view_page(client, ext_seeded):
    page = client.get(f"/visual?vpc={VPC}&view=extended").data.decode()
    assert 'aria-current="page">Extended view' in page
    assert "Re-crawl services" in page and "xray: example warning" in page
    for label in ("Observed", "Configured", "Permitted (IAM)", "Referenced (env var)"):
        assert label in page
    assert 'id="flow-logs"' in page and "broad access" in page
    assert 'data-mode="extended"' in page


def test_extended_payload_ranks_and_merges_evidence(client, ext_seeded):
    data = client.get(f"/visual/data.json?vpc={VPC}&view=extended").get_json()
    ext = data["extended"]
    edges = {(e["source"], e["target"]): e for e in ext["edges"]}
    lam = edges[("x:lambda:fn-a", "x:sqs:queue-a")]
    assert lam["evidence"] == "permitted" and lam["label"] == "IAM"
    assert [ln["evidence"] for ln in lam["lines"]] == ["permitted", "referenced"]
    eni = edges[("eni-0000000001", "eni-0000000002")]
    assert eni["evidence"] == "observed"
    assert [ln["evidence"] for ln in eni["lines"]] == ["observed", "configured"]
    assert "5 flow(s)" in eni["lines"][0]["text"]
    assert edges[("vpc", "x:tgw:tgw-0example0000001")]["evidence"] == "configured"
    # Edges of other VPCs are dropped; crawled nodes linked to nothing are hidden.
    assert len(edges) == 3 and ext["hidden_nodes"] == 1
    nodes = {n["id"]: n for n in ext["nodes"]}
    assert nodes["x:tgw:tgw-0example0000001"]["area"] == "external"
    assert nodes["x:sqs:queue-a"]["area"] == "regional"
    assert nodes["x:lambda:fn-a"]["broad_access"] is True
    assert {s["service"] for s in ext["services"]} == {"lambda", "sqs", "tgw"}
    counts = {lvl["level"]: lvl["count"] for lvl in ext["evidence_levels"]}
    assert counts["observed"] == 1 and counts["referenced"] == 1
    assert ext["flow"]["pairs"] == 1 and ext["crawl"]["warnings"] == ["xray: example warning"]


def test_flow_log_run_requires_confirmation(client, ext_seeded):
    resp = _post(client, "/visual/flowlogs/run", {"vpc": VPC, "window": "1h"})
    assert resp.status_code == 400


def test_flow_log_routes_use_gateway(app, client, ext_seeded):
    logs = _FakeLogs(FLOW_ROWS)
    app.extensions["iplens"]["gateway_factory"] = lambda _acct: _FakeGateway(logs)
    est = _post(client, "/visual/flowlogs/estimate", {"vpc": VPC, "window": "1h"}).get_json()
    assert est["ok"] and est["estimated_label"] == "1.0 GB"
    assert "StartQuery" not in logs.calls
    run = _post(
        client, "/visual/flowlogs/run", {"vpc": VPC, "window": "1h", "confirm": "1"}
    ).get_json()
    assert run["ok"] and run["pairs"] == 2


@mock_aws
def test_crawl_route(app, client, snapshot_builder):
    ids = _seed_aws()
    _snapshot(snapshot_builder, _app_db(app), ids["vpc"], ids["subnet"])
    resp = _post(client, "/visual/extended/crawl", {"vpc": ids["vpc"]}, follow_redirects=True)
    page = resp.data.decode()
    assert "Crawled services for snapshot" in page
    assert SECRET_VALUE not in page and ENV_VALUE not in page
    data = client.get(f"/visual/data.json?vpc={ids['vpc']}&view=extended").get_json()
    targets = {e["target"] for e in data["extended"]["edges"]}
    assert "x:internet:igw" in targets and f"x:tgw:{ids['tgw']}" in targets


# -- exports -------------------------------------------------------------------------------


def _ext_view() -> dict:
    return {
        "vpc_id": VPC,
        "mode": "extended",
        "nodes": [
            {
                "id": "vpc",
                "kind": "vpc",
                "label": "example-vpc",
                "x": 0,
                "y": 0,
                "w": 400,
                "h": 300,
                "icon": VPC_ICON,
            },
            {
                "id": "area:regional",
                "kind": "area",
                "label": "Regional services",
                "x": 560,
                "y": 0,
                "w": 300,
                "h": 300,
            },
            {
                "id": "area:external",
                "kind": "area",
                "label": "External",
                "x": -300,
                "y": 0,
                "w": 200,
                "h": 300,
            },
            {
                "id": "x:sqs:queue-a",
                "kind": "res",
                "parent": "area:regional",
                "label": "queue-a\nSQS queue",
                "x": 600,
                "y": 40,
                "w": 44,
                "h": 44,
                "icon": EXT_ICONS["sqs"],
            },
            {
                "id": "x:internet:igw",
                "kind": "res",
                "parent": "area:external",
                "label": "Internet (IGW)",
                "x": -260,
                "y": 40,
                "w": 44,
                "h": 44,
                "icon": EXT_ICONS["internet"],
            },
        ],
        "edges": [
            {
                "source": "vpc",
                "target": "x:internet:igw",
                "type": "ev_configured",
                "label": "route",
            },
            {"source": "vpc", "target": "x:sqs:queue-a", "type": "ev_observed", "label": "X-Ray"},
            {"source": "x:sqs:queue-a", "target": "vpc", "type": "ev_permitted", "label": "IAM"},
            {
                "source": "x:sqs:queue-a",
                "target": "x:internet:igw",
                "type": "ev_referenced",
                "label": "env",
            },
        ],
    }


def test_exports_include_extended_areas_and_evidence():
    view = parse_view(json.dumps(_ext_view()))
    assert view.mode == "extended"
    assert export_filename(view, "svg") == f"iplens-{VPC}-extended.svg"
    svg = view_to_svg(view)
    assert 'class="area"' in svg and "Regional services" in svg and "queue-a" in svg
    for level in ("observed", "configured", "permitted", "referenced"):
        assert f"edge-ev_{level}" in svg
    drawio = view_to_drawio(view)
    assert "Regional services" in drawio and "mxgraph.aws4.sqs" in drawio
    assert "strokeColor=#1A7F37" in drawio and "dashPattern=2 3" in drawio


def _lane_view() -> dict:
    """Focused, aggregated swimlane view as the Visual page posts it."""
    return {
        "vpc_id": VPC,
        "mode": "extended",
        "nodes": [
            {"id": "lane:0", "kind": "lane", "label": "app=app-a", "x": 0, "y": 0, "w": 900},
            {
                "id": "group:lane:0:lambda",
                "kind": "group",
                "parent": "lane:0",
                "label": "▸ 3 × Lambda function: fn-a, fn-b, fn-c",
                "x": 40,
                "y": 60,
                "w": 44,
                "h": 44,
                "icon": EXT_ICONS["lambda"],
            },
            {
                "id": "box:svc:lane:0:sqs",
                "kind": "area",
                "parent": "lane:0",
                "label": "▾ SQS queue ×2 · click here to collapse",
                "x": 500,
                "y": 30,
                "w": 300,
                "h": 120,
            },
            {
                "id": "x:sqs:queue-a",
                "kind": "res",
                "parent": "box:svc:lane:0:sqs",
                "label": "queue-a\nSQS queue",
                "x": 540,
                "y": 60,
                "w": 44,
                "h": 44,
                "icon": EXT_ICONS["sqs"],
            },
        ],
        "edges": [
            {
                "source": "group:lane:0:lambda",
                "target": "x:sqs:queue-a",
                "type": "ev_configured",
                "label": "trigger ×4 +2",
                "width": 8,
                "bidir": True,
            }
        ],
    }


def test_exports_reflect_lanes_aggregation_and_merged_edges():
    view = parse_view(json.dumps(_lane_view()))
    assert view.edges[0].width == 8 and view.edges[0].bidir
    svg = view_to_svg(view)
    assert 'class="lane"' in svg and "app=app-a" in svg and 'class="area"' in svg
    assert 'stroke-width="8"' in svg and 'marker-start="url(#arrow-start-ev_configured)"' in svg
    assert "trigger ×4 +2" in svg
    drawio = view_to_drawio(view)
    assert "swimlane;" in drawio and "strokeWidth=8;" in drawio and "startArrow=block" in drawio
    # Without width / bidir an edge keeps its evidence style.
    doc = _lane_view()
    del doc["edges"][0]["width"], doc["edges"][0]["bidir"]
    svg = view_to_svg(parse_view(json.dumps(doc)))
    assert 'stroke-width="2"' in svg and "marker-start" not in svg


@pytest.mark.parametrize("width", ["8", True, float("inf")])
def test_export_rejects_bad_edge_width(width):
    doc = _lane_view()
    doc["edges"][0]["width"] = width
    with pytest.raises(ValueError):
        parse_view(json.dumps(doc))


def test_extended_page_has_focus_controls_and_declutter_script(client, ext_seeded):
    page = client.get(f"/visual?vpc={VPC}&view=extended").data.decode()
    for marker in ('id="focus-search"', 'id="focus-hops"', 'id="focus-reset"', "declutter.js"):
        assert marker in page
    assert '<option value="1">1 hop</option>' in page
    assert '<option value="2">2 hops</option>' in page
    assert "https://" not in page.split("<script", 1)[1]  # vendored scripts only, no CDN
    ip_page = client.get(f"/visual?vpc={VPC}").data.decode()
    assert 'id="focus-search"' not in ip_page


def test_export_rejects_unknown_evidence_type():
    doc = _ext_view()
    doc["edges"][0]["type"] = "ev_guessed"
    with pytest.raises(ValueError, match="edge type"):
        parse_view(json.dumps(doc))
