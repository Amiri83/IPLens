"""Retry skipped saves a complete snapshot.

The retried resource types are collected again; the rows of every other resource type
are copied from the source snapshot in the same transaction and the ENIs are attributed
on the merged data, so the retry's snapshot (the new latest one) is as complete as a full
Refresh: Overview, Diff and Trends see no false removals. Without its source snapshot the
retry is a full Refresh. Placeholders only: 192.0.2.N addresses, example names, moto."""

from __future__ import annotations

import io
import json
import zipfile

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from iplens import collector as collector_mod
from iplens import queries
from iplens.attribution import OWNER_LABELS
from iplens.aws import AwsGateway
from iplens.collector import Collector
from iplens.db import closing
from iplens.diff import diff_snapshots

REGION = "us-east-1"
SNAPSHOT_TABLES = (
    "vpcs",
    "subnets",
    "enis",
    "ips",
    "lambdas",
    "endpoints",
    "load_balancers",
    "ecs_services",
    "ecs_task_enis",
    "lb_targets",
    "ecs_service_lbs",
    "sg_refs",
    "sg_cidr_rules",
    "security_groups",
    "resource_tags",
    "own_resources",
    "own_tags",
)


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", "def handler(event, context):\n    return 1\n")
    return buf.getvalue()


@pytest.fixture
def aws_env():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(
            CidrBlock="192.0.2.0/24",
            TagSpecifications=[
                {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": "example-vpc"}]}
            ],
        )["Vpc"]["VpcId"]
        sa = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="192.0.2.0/26", AvailabilityZone="us-east-1a"
        )["Subnet"]["SubnetId"]
        sb = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="192.0.2.64/26", AvailabilityZone="us-east-1b"
        )["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(
            GroupName="sg-a",
            Description="example",
            VpcId=vpc_id,
            TagSpecifications=[
                {"ResourceType": "security-group", "Tags": [{"Key": "team", "Value": "team-a"}]}
            ],
        )["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "192.0.2.0/24"}],
                }
            ],
        )
        image_id = ec2.describe_images()["Images"][0]["ImageId"]
        ec2.run_instances(
            ImageId=image_id,
            MinCount=1,
            MaxCount=1,
            SubnetId=sa,
            PrivateIpAddress="192.0.2.10",
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-a"}]}
            ],
        )
        ec2.create_network_interface(
            SubnetId=sa,
            PrivateIpAddress="192.0.2.20",
            Groups=[sg],
            Description="example detached",
            TagSpecifications=[
                {
                    "ResourceType": "network-interface",
                    "Tags": [{"Key": "project", "Value": "project-a"}],
                }
            ],
        )
        ec2.create_network_interface(
            SubnetId=sb,
            PrivateIpAddress="192.0.2.70",
            Groups=[sg],
            Description="AWS Lambda VPC ENI-fn-a",
        )
        rtb = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        ec2.create_vpc_endpoint(
            VpcId=vpc_id,
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[rtb["RouteTables"][0]["RouteTableId"]],
        )
        role_arn = boto3.client("iam", region_name=REGION).create_role(
            RoleName="example-lambda-role",
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}),
        )["Role"]["Arn"]
        boto3.client("lambda", region_name=REGION).create_function(
            FunctionName="fn-a",
            Runtime="python3.12",
            Role=role_arn,
            Handler="handler.handler",
            Code={"ZipFile": _zip()},
            VpcConfig={"SubnetIds": [sb], "SecurityGroupIds": [sg]},
            Tags={"team": "team-a"},
        )
        boto3.client("elbv2", region_name=REGION).create_load_balancer(
            Name="lb-a", Subnets=[sa, sb], Scheme="internal", Type="application"
        )
        yield


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name=REGION))


def _rows(db_path, snap_id: int) -> dict[str, list[tuple]]:
    """Every row of a snapshot, by table, without the snapshot id."""
    out = {}
    with closing(db_path) as conn:
        for table in SNAPSHOT_TABLES:
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE snapshot_id=?",  # noqa: S608 - test constants
                (snap_id,),
            ).fetchall()
            out[table] = sorted(
                tuple(v for k, v in zip(r.keys(), tuple(r), strict=True) if k != "snapshot_id")
                for r in rows
            )
    return out


def _deny(op: str, monkeypatch) -> None:
    """``op`` fails with AccessDenied, as if the role lacked the permission."""
    real = collector_mod._paginate

    def paginate(client, name, key, **kwargs):
        if name == op:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "x"}}, name)
        return real(client, name, key, **kwargs)

    monkeypatch.setattr(collector_mod, "_paginate", paginate)


def _calls(monkeypatch) -> list[str]:
    calls: list[str] = []
    real = collector_mod._paginate

    def paginate(client, op, key, **kwargs):
        calls.append(op)
        return real(client, op, key, **kwargs)

    monkeypatch.setattr(collector_mod, "_paginate", paginate)
    return calls


@pytest.mark.parametrize(
    ("retried", "skipped_tables"),
    [
        (["ec2:DescribeVpcEndpoints"], ("endpoints",)),
        (["ec2:DescribeSecurityGroups"], ("security_groups", "sg_cidr_rules")),
        (["tag:GetResources"], ("own_resources", "own_tags")),
        (["lambda:ListTags"], ("lambdas",)),
    ],
)
def test_retry_snapshot_has_the_source_rows_of_the_other_types(
    aws_env, db_path, monkeypatch, retried, skipped_tables
):
    source = Collector(_gateway(), db_path).run().snapshot_id
    expected = _rows(db_path, source)
    for table in ("enis", "ips", "lambdas", "endpoints", "load_balancers", "security_groups"):
        assert expected[table], table  # the source has rows of every kind
    assert expected["sg_cidr_rules"] and expected["resource_tags"] and expected["own_tags"]
    with closing(db_path) as conn:
        enis = conn.execute(
            "SELECT owner_type, owner_names, instance_name FROM enis WHERE snapshot_id=?",
            (source,),
        ).fetchall()
    assert any(e["instance_name"] == "web-a" for e in enis)
    assert ("lambda", '["fn-a"]') in {(e["owner_type"], e["owner_names"]) for e in enis}

    calls = _calls(monkeypatch)
    result = Collector(_gateway(), db_path, only=retried, source_snapshot=source).run()
    assert result.skipped == []
    # Not collected again: copied from the source snapshot.
    assert "describe_load_balancers" not in calls and "describe_instances" not in calls
    with closing(db_path) as conn:
        assert queries.latest_snapshot(conn)["id"] == result.snapshot_id
    # Unchanged AWS: the merged snapshot is row for row the source (retried types,
    # copied types and the ENIs attributed on the merged data alike).
    assert _rows(db_path, result.snapshot_id) == expected
    assert result.ips == len(expected["ips"])
    for table in skipped_tables:
        assert _rows(db_path, result.snapshot_id)[table], table


def test_diff_from_source_to_retry_shows_no_removals(aws_env, db_path, monkeypatch):
    # The source snapshot: ec2:DescribeVpcEndpoints was not saved.
    real = collector_mod._paginate
    _deny("describe_vpc_endpoints", monkeypatch)
    source = Collector(_gateway(), db_path).run()
    assert ("ec2:DescribeVpcEndpoints", "AccessDenied") in source.skipped
    before = _rows(db_path, source.snapshot_id)
    assert before["endpoints"] == []

    monkeypatch.setattr(collector_mod, "_paginate", real)
    retry = Collector(
        _gateway(),
        db_path,
        only=[name for name, _reason in source.skipped],
        source_snapshot=source.snapshot_id,
    ).run()
    after = _rows(db_path, retry.snapshot_id)
    assert after["endpoints"]  # the retried type is now there
    for table in SNAPSHOT_TABLES:
        if table != "endpoints":
            assert after[table] == before[table], table

    with closing(db_path) as conn:
        d = diff_snapshots(conn, source.snapshot_id, retry.snapshot_id, OWNER_LABELS)
        overview_before = queries.owner_breakdown(conn, source.snapshot_id)
        overview_after = queries.owner_breakdown(conn, retry.snapshot_id)
    assert d.totals["enis_removed"] == 0 and d.totals["ips_removed"] == 0
    assert d.totals["enis_changed"] == 0 and d.totals["ips_changed"] == 0
    assert d.totals["ip_delta"] == 0 and d.empty
    assert overview_after == overview_before


@pytest.mark.parametrize("source", [None, 9999, "failed"])
def test_retry_without_its_source_snapshot_is_a_full_refresh(aws_env, db_path, monkeypatch, source):
    if source == "failed":
        with closing(db_path) as conn:
            source = conn.execute(
                "INSERT INTO snapshots(taken_at, region, status) "
                "VALUES('2026-01-01T00:00:00+00:00', 'us-east-1', 'failed')"
            ).lastrowid
    calls = _calls(monkeypatch)
    result = Collector(
        _gateway(), db_path, only=["ec2:DescribeVpcEndpoints"], source_snapshot=source
    ).run()
    for op in ("describe_security_groups", "describe_load_balancers", "describe_instances"):
        assert op in calls
    rows = _rows(db_path, result.snapshot_id)
    assert rows["security_groups"] and rows["load_balancers"] and rows["lambdas"]
    assert not [w for w in result.warnings if "copied from snapshot" in w]
    if source is not None:
        assert (
            f"Retry of skipped resources: snapshot {source} (the source of the other resource "
            "types) no longer exists; ran a full Refresh instead"
        ) in result.warnings


def test_source_deleted_during_the_retry_falls_back_to_a_full_refresh(
    aws_env, db_path, monkeypatch
):
    source = Collector(_gateway(), db_path).run().snapshot_id
    expected = _rows(db_path, source)
    deleted = []
    real = Collector._fetch_tagged_resources

    def fetch(self):
        if not deleted:  # the user deletes the source snapshot meanwhile
            with closing(db_path) as conn:
                conn.execute("DELETE FROM snapshots WHERE id=?", (source,))
            deleted.append(source)
        return real(self)

    monkeypatch.setattr(Collector, "_fetch_tagged_resources", fetch)
    result = Collector(_gateway(), db_path, only=["tag:GetResources"], source_snapshot=source).run()
    assert deleted == [source]
    assert any("ran a full Refresh instead" in w for w in result.warnings)
    with closing(db_path) as conn:
        status = conn.execute(
            "SELECT status FROM snapshots WHERE id=?", (result.snapshot_id,)
        ).fetchone()[0]
    assert status == "ok"
    assert _rows(db_path, result.snapshot_id) == expected
