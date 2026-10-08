import io
import json
import zipfile

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from iplens import queries
from iplens.aws import AwsGateway
from iplens.collector import Collector, sg_cidr_rows, sg_ref_rows, target_ref
from iplens.db import closing

REGION = "us-east-1"


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
            CidrBlock="10.0.0.0/16",
            TagSpecifications=[
                {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": "example-vpc"}]}
            ],
        )["Vpc"]["VpcId"]
        sa = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a"
        )["Subnet"]["SubnetId"]
        sb = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b"
        )["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(GroupName="example-sg", Description="example", VpcId=vpc_id)[
            "GroupId"
        ]
        image_id = ec2.describe_images()["Images"][0]["ImageId"]
        inst = ec2.run_instances(
            ImageId=image_id, MinCount=1, MaxCount=1, SubnetId=sa, PrivateIpAddress="10.0.1.10"
        )["Instances"][0]
        detached = ec2.create_network_interface(
            SubnetId=sa,
            PrivateIpAddress="10.0.1.50",
            Groups=[sg],
            Description="example detached",
            SecondaryPrivateIpAddressCount=2,
        )["NetworkInterface"]["NetworkInterfaceId"]
        lambda_eni = ec2.create_network_interface(
            SubnetId=sb,
            PrivateIpAddress="10.0.2.20",
            Groups=[sg],
            Description="AWS Lambda VPC ENI-example-fn",
        )["NetworkInterface"]["NetworkInterfaceId"]
        nat_eni = ec2.create_network_interface(
            SubnetId=sb,
            PrivateIpAddress="10.0.2.30",
            Description="Interface for NAT Gateway nat-0example0001",
        )["NetworkInterface"]["NetworkInterfaceId"]

        role_arn = boto3.client("iam", region_name=REGION).create_role(
            RoleName="example-lambda-role",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )["Role"]["Arn"]
        lam = boto3.client("lambda", region_name=REGION)
        lam.create_function(
            FunctionName="example-fn",
            Runtime="python3.12",
            Role=role_arn,
            Handler="handler.handler",
            Code={"ZipFile": _zip()},
            VpcConfig={"SubnetIds": [sb], "SecurityGroupIds": [sg]},
        )
        lam.create_function(
            FunctionName="example-public-fn",
            Runtime="python3.12",
            Role=role_arn,
            Handler="handler.handler",
            Code={"ZipFile": _zip()},
        )
        boto3.client("elbv2", region_name=REGION).create_load_balancer(
            Name="example-alb",
            Subnets=[sa, sb],
            Scheme="internet-facing",
            Type="application",
        )
        yield {
            "vpc_id": vpc_id,
            "sa": sa,
            "sb": sb,
            "instance_id": inst["InstanceId"],
            "detached": detached,
            "lambda_eni": lambda_eni,
            "nat_eni": nat_eni,
        }


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name=REGION))


def test_collect_snapshot(aws_env, db_path):
    result = Collector(_gateway(), db_path).run()
    assert result.warnings == []
    assert result.vpcs >= 1 and result.enis >= 4

    with closing(db_path) as conn:
        snap = queries.latest_snapshot(conn)
        assert snap["id"] == result.snapshot_id
        assert snap["account_id"] == "123456789012"
        assert snap["region"] == REGION

        vpc = conn.execute("SELECT * FROM vpcs WHERE vpc_id=?", (aws_env["vpc_id"],)).fetchone()
        assert vpc["name"] == "example-vpc"
        assert json.loads(vpc["cidrs"]) == ["10.0.0.0/16"]

        enis = {
            r["eni_id"]: r
            for r in conn.execute("SELECT * FROM enis WHERE vpc_id=?", (aws_env["vpc_id"],))
        }
        assert enis[aws_env["detached"]]["status"] == "available"
        assert enis[aws_env["lambda_eni"]]["owner_type"] == "lambda"
        assert enis[aws_env["lambda_eni"]]["owner_ref"] == "example-fn"
        assert enis[aws_env["nat_eni"]]["owner_type"] == "nat"
        inst_enis = [e for e in enis.values() if e["instance_id"] == aws_env["instance_id"]]
        assert inst_enis and inst_enis[0]["owner_type"] == "ec2"
        assert inst_enis[0]["owner_ref"] == aws_env["instance_id"]

        detached_ips = [
            r["ip"]
            for r in conn.execute(
                "SELECT ip FROM ips WHERE eni_id=? ORDER BY ip_int", (aws_env["detached"],)
            )
        ]
        assert len(detached_ips) == 3 and "10.0.1.50" in detached_ips

        fns = {r["name"]: r for r in conn.execute("SELECT * FROM lambdas")}
        assert fns["example-fn"]["vpc_id"] == aws_env["vpc_id"]
        assert fns["example-public-fn"]["vpc_id"] is None

        lb = conn.execute("SELECT * FROM load_balancers WHERE name='example-alb'").fetchone()
        assert lb["scheme"] == "internet-facing"

        stats = {s.subnet_id: s for s in queries.subnet_stats(conn, snap["id"])}
        a = stats[aws_env["sa"]]
        assert a.idle == 3
        assert a.used >= 1
        assert a.free == a.size - a.reserved - a.used - a.idle


def test_collect_prunes_old_snapshots(aws_env, db_path):
    for _ in range(3):
        Collector(_gateway(), db_path).run()
    with closing(db_path) as conn:
        assert queries.prune_snapshots(conn, keep=1) == 2
        assert len(queries.recent_snapshots(conn)) == 1
        remaining = queries.latest_snapshot(conn)["id"]
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM enis WHERE snapshot_id != ?", (remaining,)
            ).fetchone()[0]
            == 0
        )


def test_optional_permissions_become_warnings(aws_env, db_path, monkeypatch):
    gw = _gateway()
    real_client = gw.client

    def client(service):
        if service == "lambda":
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "ListFunctions"
            )
        return real_client(service)

    monkeypatch.setattr(gw, "client", client)
    result = Collector(gw, db_path).run()
    assert any("lambda:ListFunctions" in w for w in result.warnings)
    with closing(db_path) as conn:
        assert queries.latest_snapshot(conn)["id"] == result.snapshot_id


def test_account_alias_persisted_per_snapshot(aws_env, db_path):
    first = Collector(_gateway(), db_path).run()
    # Setup only, outside the read-only gateway.
    boto3.client("iam", region_name=REGION).create_account_alias(AccountAlias="example-alias")
    second = Collector(_gateway(), db_path).run()

    assert (first.account_alias, second.account_alias) == ("", "example-alias")
    assert second.warnings == []
    with closing(db_path) as conn:
        rows = dict(conn.execute("SELECT id, account_alias FROM snapshots").fetchall())
    assert rows == {first.snapshot_id: "", second.snapshot_id: "example-alias"}


def test_account_alias_permission_denied_falls_back_to_account_id(
    aws_env, db_path, monkeypatch, caplog
):
    boto3.client("iam", region_name=REGION).create_account_alias(AccountAlias="example-alias")
    gw = _gateway()
    real_client = gw.client

    def client(service):
        c = real_client(service)
        if service == "iam":

            def deny(**_):
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListAccountAliases"
                )

            c.meta.events.register("before-call.iam.ListAccountAliases", deny)
        return c

    monkeypatch.setattr(gw, "client", client)
    with caplog.at_level("WARNING", logger="iplens"):
        result = Collector(gw, db_path).run()

    assert result.warnings == ["iam:ListAccountAliases skipped (AccessDenied)"]
    assert "iam:ListAccountAliases skipped" in caplog.text
    with closing(db_path) as conn:
        snap = queries.latest_snapshot(conn)
    assert snap["id"] == result.snapshot_id and snap["status"] == "ok"
    assert snap["account_id"] == "123456789012"
    assert snap["account_alias"] == ""
    assert result.enis >= 4  # the rest of the snapshot is unaffected


@pytest.fixture
def moto_ecs_awsvpc(monkeypatch):
    """moto 5.2.x: ECS awsvpc run_task reads NetworkInterface.private_dns_name, which the
    EC2 ENI model does not define. Provide it so tasks get real moto ENIs."""
    from moto.ec2.models.elastic_network_interfaces import NetworkInterface

    if not hasattr(NetworkInterface, "private_dns_name"):
        monkeypatch.setattr(
            NetworkInterface,
            "private_dns_name",
            property(lambda self: f"ip-{self.private_ip_address.replace('.', '-')}.ec2.internal"),
            raising=False,
        )


def _ecs_service_with_tasks(
    subnet_id: str, count: int = 2, load_balancers: list[dict] | None = None
) -> None:
    ecs = boto3.client("ecs", region_name=REGION)
    ecs.create_cluster(clusterName="example-cluster")
    ecs.register_task_definition(
        family="example-task",
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[{"name": "app", "image": "example/app:latest", "memory": 512}],
    )
    ecs.create_service(
        cluster="example-cluster",
        serviceName="example-svc",
        taskDefinition="example-task",
        desiredCount=count,
        launchType="FARGATE",
        loadBalancers=load_balancers or [],
    )
    net = {"awsvpcConfiguration": {"subnets": [subnet_id], "securityGroups": []}}
    ecs.run_task(
        cluster="example-cluster",
        taskDefinition="example-task",
        count=count,
        launchType="FARGATE",
        group="service:example-svc",
        networkConfiguration=net,
    )
    ecs.run_task(
        cluster="example-cluster",
        taskDefinition="example-task",
        count=1,
        launchType="FARGATE",
        networkConfiguration=net,
    )  # standalone task


def test_ecs_enrichment_maps_task_enis(aws_env, db_path, moto_ecs_awsvpc):
    _ecs_service_with_tasks(aws_env["sa"])
    result = Collector(_gateway(), db_path).run()
    assert result.warnings == []

    with closing(db_path) as conn:
        svc = conn.execute(
            "SELECT * FROM ecs_services WHERE snapshot_id=?", (result.snapshot_id,)
        ).fetchone()
        assert (svc["cluster"], svc["service"], svc["desired_count"]) == (
            "example-cluster",
            "example-svc",
            2,
        )
        assert svc["last_deployment"]

        mapped = conn.execute(
            "SELECT m.service, e.owner_type, e.owner_ref FROM ecs_task_enis m "
            "JOIN enis e ON e.snapshot_id = m.snapshot_id AND e.eni_id = m.eni_id "
            "WHERE m.snapshot_id=? ORDER BY m.service",
            (result.snapshot_id,),
        ).fetchall()
        assert len(mapped) == 3
        assert all(r["owner_type"] == "ecs" for r in mapped)
        assert all(r["owner_ref"].startswith("example-cluster/example-svc/") for r in mapped[1:])
        assert len({r["owner_ref"] for r in mapped[1:]}) == 2  # one per task
        assert mapped[0]["service"] == "" and mapped[0]["owner_ref"].startswith("example-cluster/")
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM ips WHERE snapshot_id=? AND owner_type='ecs'",
                (result.snapshot_id,),
            ).fetchone()[0]
            == 3
        )


@pytest.mark.parametrize("denied_op", ["ListClusters", "DescribeTasks"])
def test_ecs_permission_denied_is_a_warning(
    aws_env, db_path, monkeypatch, moto_ecs_awsvpc, denied_op
):
    _ecs_service_with_tasks(aws_env["sa"])
    gw = _gateway()
    real_client = gw.client

    def client(service):
        c = real_client(service)
        if service == "ecs":

            def deny(event_name=None, **_):
                if event_name.endswith(f".{denied_op}"):
                    raise ClientError(
                        {"Error": {"Code": "AccessDeniedException", "Message": "no"}}, denied_op
                    )

            c.meta.events.register("before-call.ecs", deny)
        return c

    monkeypatch.setattr(gw, "client", client)
    result = Collector(gw, db_path).run()
    assert result.warnings == [
        f"ECS enrichment skipped: ecs:{denied_op} (AccessDeniedException); "
        "ECS task ENIs are attributed heuristically"
    ]
    with closing(db_path) as conn:
        assert queries.latest_snapshot(conn)["id"] == result.snapshot_id
        # partial ECS data is discarded, never half-written
        for table in ("ecs_services", "ecs_task_enis"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0  # noqa: S608
        assert conn.execute("SELECT COUNT(*) FROM enis WHERE owner_type='ecs'").fetchone()[0] == 0


def _alb_target_groups(aws_env) -> dict[str, str]:
    """Setup only: an instance and an IP target group behind example-alb's listener."""
    elbv2 = boto3.client("elbv2", region_name=REGION)
    lbs = elbv2.describe_load_balancers(Names=["example-alb"])["LoadBalancers"]
    lb_arn = lbs[0]["LoadBalancerArn"]
    arns = {}
    for name, ttype in (("example-web-tg", "instance"), ("example-svc-tg", "ip")):
        arns[name] = elbv2.create_target_group(
            Name=name, Protocol="HTTP", Port=80, VpcId=aws_env["vpc_id"], TargetType=ttype
        )["TargetGroups"][0]["TargetGroupArn"]
    for port, name in ((80, "example-web-tg"), (8080, "example-svc-tg")):
        elbv2.create_listener(
            LoadBalancerArn=lb_arn,
            Protocol="HTTP",
            Port=port,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": arns[name]}],
        )
    elbv2.register_targets(
        TargetGroupArn=arns["example-web-tg"], Targets=[{"Id": aws_env["instance_id"], "Port": 80}]
    )
    elbv2.register_targets(
        TargetGroupArn=arns["example-svc-tg"], Targets=[{"Id": "10.0.1.99", "Port": 8080}]
    )
    return arns


def test_lb_targets_and_ecs_service_lbs(aws_env, db_path, moto_ecs_awsvpc):
    arns = _alb_target_groups(aws_env)
    _ecs_service_with_tasks(
        aws_env["sa"],
        load_balancers=[
            {"targetGroupArn": arns["example-svc-tg"], "containerName": "app", "containerPort": 80}
        ],
    )
    result = Collector(_gateway(), db_path).run()
    assert result.warnings == []
    with closing(db_path) as conn:
        targets = {
            tuple(r)
            for r in conn.execute(
                "SELECT lb_name, target_group, target_type, target_id, port FROM lb_targets "
                "WHERE snapshot_id=?",
                (result.snapshot_id,),
            )
        }
        assert targets == {
            ("example-alb", "example-web-tg", "instance", aws_env["instance_id"], 80),
            ("example-alb", "example-svc-tg", "ip", "10.0.1.99", 8080),
        }
        svc_lbs = [
            tuple(r)
            for r in conn.execute(
                "SELECT cluster, service, lb_name, target_group FROM ecs_service_lbs "
                "WHERE snapshot_id=?",
                (result.snapshot_id,),
            )
        ]
        assert svc_lbs == [("example-cluster", "example-svc", "example-alb", "example-svc-tg")]


def test_sg_refs_collected(aws_env, db_path):
    ec2 = boto3.client("ec2", region_name=REGION)
    alb_sg = ec2.create_security_group(
        GroupName="example-alb-sg", Description="example", VpcId=aws_env["vpc_id"]
    )["GroupId"]
    web_sg = ec2.create_security_group(
        GroupName="example-web-sg", Description="example", VpcId=aws_env["vpc_id"]
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=web_sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "UserIdGroupPairs": [{"GroupId": alb_sg}],
            }
        ],
    )
    result = Collector(_gateway(), db_path).run()
    assert result.warnings == []
    with closing(db_path) as conn:
        refs = {
            tuple(r)
            for r in conn.execute(
                "SELECT group_id, direction, ref_group_id, ports FROM sg_refs WHERE snapshot_id=?",
                (result.snapshot_id,),
            )
        }
    assert (web_sg, "ingress", alb_sg, "tcp/80") in refs


def test_sg_cidr_rules_collected(aws_env, db_path):
    ec2 = boto3.client("ec2", region_name=REGION)
    vpce_sg = ec2.create_security_group(
        GroupName="example-vpce-sg", Description="example", VpcId=aws_env["vpc_id"]
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=vpce_sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.1.0/24"}, {"CidrIp": "10.0.2.0/24"}],
            },
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.3.0/24"}]},
        ],
    )
    result = Collector(_gateway(), db_path).run()
    assert result.warnings == []
    with closing(db_path) as conn:
        rules = {
            tuple(r)
            for r in conn.execute(
                "SELECT cidr, ip_protocol, from_port, to_port FROM sg_cidr_rules "
                "WHERE snapshot_id=? AND group_id=?",
                (result.snapshot_id, vpce_sg),
            )
        }
    assert rules == {
        ("10.0.1.0/24", "tcp", 443, 443),
        ("10.0.2.0/24", "tcp", 443, 443),
        ("10.0.3.0/24", "-1", None, None),
    }


def test_endpoint_reach_from_collected_rules(aws_env, db_path):
    """End to end: endpoint SG ingress collected from EC2 -> reach edges on the Visual page."""
    ec2 = boto3.client("ec2", region_name=REGION)

    def sg(name: str) -> str:
        return ec2.create_security_group(
            GroupName=name, Description="example", VpcId=aws_env["vpc_id"]
        )["GroupId"]

    def eni(subnet: str, ip: str, group: str, description: str = "example") -> str:
        return ec2.create_network_interface(
            SubnetId=subnet, PrivateIpAddress=ip, Groups=[group], Description=description
        )["NetworkInterface"]["NetworkInterfaceId"]

    app_sg, ssh_sg, other_sg, vpce_sg = (
        sg(n) for n in ("example-app", "example-ssh", "example-other", "example-vpce")
    )
    app = eni(aws_env["sa"], "10.0.1.60", app_sg)  # allowed by SG
    by_cidr = eni(aws_env["sb"], "10.0.2.60", other_sg)  # allowed by CIDR
    ssh_only = eni(aws_env["sa"], "10.0.1.70", ssh_sg)  # allowed on tcp/22 only
    vpce = eni(aws_env["sa"], "10.0.1.80", vpce_sg, "VPC Endpoint Interface vpce-0example0001")
    ec2.authorize_security_group_ingress(
        GroupId=vpce_sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "UserIdGroupPairs": [{"GroupId": app_sg}],
                "IpRanges": [{"CidrIp": "10.0.2.48/28"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "UserIdGroupPairs": [{"GroupId": ssh_sg}],
                "IpRanges": [{"CidrIp": "10.0.1.64/28"}],
            },
        ],
    )
    result = Collector(_gateway(), db_path).run()
    with closing(db_path) as conn:
        data = queries.visual_data(conn, result.snapshot_id, aws_env["vpc_id"])
    reach = {(e["source"], e["target"]) for e in data["edges"] if e["type"] == "reach"}
    assert (app, vpce) in reach
    assert (by_cidr, vpce) in reach
    assert (ssh_only, vpce) not in reach
    assert {target for _, target in reach} == {vpce}


def test_lb_target_permission_denied_is_a_warning(aws_env, db_path, monkeypatch):
    _alb_target_groups(aws_env)
    gw = _gateway()
    real_client = gw.client

    def client(service):
        c = real_client(service)
        if service == "elbv2":

            def deny(event_name=None, **_):
                if event_name.endswith(".DescribeTargetHealth"):
                    raise ClientError(
                        {"Error": {"Code": "AccessDenied", "Message": "no"}},
                        "DescribeTargetHealth",
                    )

            c.meta.events.register("before-call", deny)
        return c

    monkeypatch.setattr(gw, "client", client)
    result = Collector(gw, db_path).run()
    assert any("elasticloadbalancing:DescribeTargetHealth" in w for w in result.warnings)
    with closing(db_path) as conn:
        assert queries.latest_snapshot(conn)["id"] == result.snapshot_id
        assert conn.execute("SELECT COUNT(*) FROM lb_targets").fetchone()[0] == 0


@pytest.mark.parametrize(
    "target_type, target_id, expected",
    [
        ("instance", "i-0example0001", "i-0example0001"),
        ("ip", "10.0.1.20", "10.0.1.20"),
        ("lambda", "arn:aws:lambda:us-east-1:123456789012:function:example-fn", "example-fn"),
        ("lambda", "arn:aws:lambda:us-east-1:123456789012:function:example-fn:live", "example-fn"),
        (
            "alb",
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/example-alb/0abc",
            "example-alb",
        ),
    ],
)
def test_target_ref(target_type, target_id, expected):
    assert target_ref(target_type, target_id) == expected


def test_sg_ref_rows():
    groups = [
        {
            "GroupId": "sg-0000web",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8000,
                    "ToPort": 8100,
                    "UserIdGroupPairs": [{"GroupId": "sg-0000alb"}],
                },
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": []},
            ],
            "IpPermissionsEgress": [
                {"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-000vpce"}]},
                {
                    "IpProtocol": "icmp",
                    "FromPort": -1,
                    "ToPort": -1,
                    "UserIdGroupPairs": [{"GroupId": "sg-000vpce"}],
                },
            ],
        }
    ]
    assert sg_ref_rows(groups) == [
        ("sg-0000web", "egress", "sg-000vpce", "all"),
        ("sg-0000web", "egress", "sg-000vpce", "icmp"),
        ("sg-0000web", "ingress", "sg-0000alb", "tcp/8000-8100"),
    ]


def test_sg_cidr_rows():
    groups = [
        {
            "GroupId": "sg-000vpce",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}, {"CidrIp": "10.0.1.0/24"}],
                    "UserIdGroupPairs": [{"GroupId": "sg-0000web"}],
                },
                {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.2.0/24"}]},
                {"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1, "IpRanges": [{}]},
            ],
            # egress CIDR rules are not stored
            "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        }
    ]
    assert sg_cidr_rows(groups) == [
        ("sg-000vpce", "10.0.0.0/16", "tcp", 443, 443),
        ("sg-000vpce", "10.0.1.0/24", "tcp", 443, 443),
        ("sg-000vpce", "10.0.2.0/24", "-1", None, None),
    ]


def test_failed_collection_is_recorded(aws_env, db_path, monkeypatch):
    gw = _gateway()
    real_client = gw.client

    def client(service):
        c = real_client(service)
        if service == "ec2":

            def denied(*_a, **_k):
                raise ClientError(
                    {"Error": {"Code": "UnauthorizedOperation", "Message": "no"}}, "DescribeVpcs"
                )

            monkeypatch.setattr(c, "get_paginator", denied)
        return c

    monkeypatch.setattr(gw, "client", client)
    with pytest.raises(ClientError):
        Collector(gw, db_path).run()
    with closing(db_path) as conn:
        assert queries.latest_snapshot(conn) is None
        row = queries.recent_snapshots(conn)[0]
        assert row["status"] == "failed"
        assert "UnauthorizedOperation" in row["error"]


def test_security_group_names_and_resource_tags_collected(aws_env, db_path):
    ec2 = boto3.client("ec2", region_name=REGION)
    named = ec2.create_security_group(
        GroupName="example-vpce-group",
        Description="example",
        VpcId=aws_env["vpc_id"],
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [
                    {"Key": "Name", "Value": "example-vpce-sg"},
                    {"Key": "team", "Value": "platform"},
                ],
            }
        ],
    )["GroupId"]
    unnamed = ec2.create_security_group(
        GroupName="example-unnamed", Description="example", VpcId=aws_env["vpc_id"]
    )["GroupId"]
    ec2.create_tags(
        Resources=[aws_env["detached"]],
        Tags=[{"Key": "team", "Value": "app"}, {"Key": "env", "Value": "dev"}],
    )
    vpce = ec2.create_vpc_endpoint(
        VpcId=aws_env["vpc_id"],
        ServiceName=f"com.amazonaws.{REGION}.sts",
        VpcEndpointType="Interface",
        SubnetIds=[aws_env["sa"]],
        SecurityGroupIds=[named],
        TagSpecifications=[
            {"ResourceType": "vpc-endpoint", "Tags": [{"Key": "team", "Value": "platform"}]}
        ],
    )["VpcEndpoint"]["VpcEndpointId"]
    elbv2 = boto3.client("elbv2", region_name=REGION)
    lb_arn = elbv2.describe_load_balancers(Names=["example-alb"])["LoadBalancers"][0][
        "LoadBalancerArn"
    ]
    elbv2.add_tags(ResourceArns=[lb_arn], Tags=[{"Key": "team", "Value": "web"}])
    lam = boto3.client("lambda", region_name=REGION)
    fn_arn = lam.get_function(FunctionName="example-fn")["Configuration"]["FunctionArn"]
    lam.tag_resource(Resource=fn_arn, Tags={"team": "app"})

    result = Collector(_gateway(), db_path).run()
    assert result.warnings == []
    with closing(db_path) as conn:
        groups = {
            r["group_id"]: (r["name"], r["group_name"])
            for r in conn.execute(
                "SELECT * FROM security_groups WHERE snapshot_id=?", (result.snapshot_id,)
            )
        }
        tags = {
            (r["resource_type"], r["resource_id"], r["key"]): r["value"]
            for r in conn.execute(
                "SELECT * FROM resource_tags WHERE snapshot_id=?", (result.snapshot_id,)
            )
        }
        names = queries.sg_names(conn, result.snapshot_id)
    assert groups[named] == ("example-vpce-sg", "example-vpce-group")
    assert groups[unnamed] == ("", "example-unnamed")
    assert names[named] == "example-vpce-sg" and names[unnamed] == "example-unnamed"
    assert tags[("eni", aws_env["detached"], "team")] == "app"
    assert tags[("eni", aws_env["detached"], "env")] == "dev"
    assert tags[("sg", named, "team")] == "platform"
    assert tags[("endpoint", vpce, "team")] == "platform"
    assert tags[("lb", "example-alb", "team")] == "web"
    assert tags[("lambda", "example-fn", "team")] == "app"


def test_tag_permissions_denied_are_warnings(aws_env, db_path, monkeypatch):
    gw = _gateway()
    real_client = gw.client

    def denied(op):
        def call(*_a, **_k):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, op)

        return call

    def client(service):
        c = real_client(service)
        if service == "elbv2":
            monkeypatch.setattr(c, "describe_tags", denied("DescribeTags"))
        if service == "lambda":
            monkeypatch.setattr(c, "list_tags", denied("ListTags"))
        return c

    monkeypatch.setattr(gw, "client", client)
    result = Collector(gw, db_path).run()
    assert "elasticloadbalancing:DescribeTags skipped (AccessDenied)" in result.warnings
    assert "lambda:ListTags skipped (AccessDenied)" in result.warnings
