"""Lambda ENIs shared by several functions and ECS task ENIs resolved by attachment id.

Moto-backed; placeholder data only (10.0.x.x, account 123456789012, fn-a/fn-b/...).
"""

import io
import json
import zipfile

import boto3
import pytest
from moto import mock_aws

from iplens import queries
from iplens.attribution import OWNER_LABELS, lambda_eni_index, lambda_owners
from iplens.aws import AwsGateway
from iplens.collector import Collector
from iplens.db import closing

REGION = "us-east-1"


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", "def handler(event, context):\n    return 1\n")
    return buf.getvalue()


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name=REGION))


def _fn(name, subnets, sgs):
    return {"FunctionName": name, "VpcConfig": {"SubnetIds": subnets, "SecurityGroupIds": sgs}}


# -- unit ---------------------------------------------------------------------------


def test_lambda_index_requires_exact_security_group_set():
    index = lambda_eni_index(
        [
            _fn("fn-b", ["subnet-0000000a"], ["sg-0001", "sg-0002"]),
            _fn("fn-a", ["subnet-0000000a", "subnet-0000000b"], ["sg-0002", "sg-0001"]),
            _fn("fn-c", ["subnet-0000000a"], ["sg-0001"]),  # subset: a different ENI
            {"FunctionName": "fn-public"},  # no VPC
        ]
    )
    assert lambda_owners(index, "subnet-0000000a", ["sg-0001", "sg-0002"]) == ["fn-a", "fn-b"]
    assert lambda_owners(index, "subnet-0000000b", ["sg-0002", "sg-0001"]) == ["fn-a"]
    assert lambda_owners(index, "subnet-0000000a", ["sg-0001"]) == ["fn-c"]
    assert lambda_owners(index, "subnet-0000000a", ["sg-0003"]) == []
    assert lambda_owners(index, None, []) == []


# -- moto: Lambda -------------------------------------------------------------------------


@pytest.fixture
def lambda_env():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        sg1 = ec2.create_security_group(GroupName="example-sg-1", Description="x", VpcId=vpc_id)[
            "GroupId"
        ]
        sg2 = ec2.create_security_group(GroupName="example-sg-2", Description="x", VpcId=vpc_id)[
            "GroupId"
        ]
        role = boto3.client("iam", region_name=REGION).create_role(
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

        def create_fn(name, sgs):
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role,
                Handler="handler.handler",
                Code={"ZipFile": _zip()},
                VpcConfig={"SubnetIds": [subnet], "SecurityGroupIds": sgs},
            )

        def create_eni(ip, sgs, fn):
            return ec2.create_network_interface(
                SubnetId=subnet,
                PrivateIpAddress=ip,
                Groups=sgs,
                Description=f"AWS Lambda VPC ENI-{fn}-00000000-0000-0000-0000-000000000000",
            )["NetworkInterface"]["NetworkInterfaceId"]

        yield {
            "vpc_id": vpc_id,
            "subnet": subnet,
            "sg1": sg1,
            "sg2": sg2,
            "create_fn": create_fn,
            "create_eni": create_eni,
        }


def _eni_rows(db_path, snap_id):
    with closing(db_path) as conn:
        return {
            r["eni_id"]: dict(r)
            for r in conn.execute("SELECT * FROM enis WHERE snapshot_id=?", (snap_id,))
        }


def test_three_functions_share_one_lambda_eni(lambda_env, db_path):
    env = lambda_env
    for name in ("fn-c", "fn-a", "fn-b"):
        env["create_fn"](name, [env["sg1"]])
    # The ENI description only names the function that happened to create it.
    eni = env["create_eni"]("10.0.1.20", [env["sg1"]], "fn-c")

    result = Collector(_gateway(), db_path).run()
    row = _eni_rows(db_path, result.snapshot_id)[eni]
    assert row["owner_type"] == "lambda"
    assert row["owner_ref"] == "fn-a"
    assert json.loads(row["owner_names"]) == ["fn-a", "fn-b", "fn-c"]

    with closing(db_path) as conn:
        ip_rows = queries.ip_list(conn, result.snapshot_id, queries.IpFilter(q="10.0.1.20"))
        assert ip_rows[0]["resource_name"] == "fn-a, fn-b, fn-c"
        assert ip_rows[0]["owner_names"] == ["fn-a", "fn-b", "fn-c"]
        # searching any of the functions finds the shared ENI
        assert [
            r["ip"] for r in queries.ip_list(conn, result.snapshot_id, queries.IpFilter(q="fn-b"))
        ] == ["10.0.1.20"]

        data = queries.visual_data(conn, result.snapshot_id, env["vpc_id"], OWNER_LABELS)
        node = next(
            item for s in data["vpc"]["subnets"] for item in s["items"] if item.get("eni_id") == eni
        )
        assert node["name"] == "fn-a +2 more"
        assert node["label_name"] == "fn-a +2 more"
        assert node["owners"] == ["fn-a", "fn-b", "fn-c"]

        detail = queries.eni_detail(conn, result.snapshot_id, eni)
        assert detail["owner_names"] == ["fn-a", "fn-b", "fn-c"]


def test_two_sg_combinations_in_one_subnet(lambda_env, db_path):
    env = lambda_env
    env["create_fn"]("fn-a", [env["sg1"]])
    env["create_fn"]("fn-b", [env["sg1"]])
    env["create_fn"]("fn-c", [env["sg1"], env["sg2"]])
    eni_1 = env["create_eni"]("10.0.1.21", [env["sg1"]], "fn-a")
    eni_12 = env["create_eni"]("10.0.1.22", [env["sg1"], env["sg2"]], "fn-c")

    result = Collector(_gateway(), db_path).run()
    rows = _eni_rows(db_path, result.snapshot_id)
    assert json.loads(rows[eni_1]["owner_names"]) == ["fn-a", "fn-b"]
    assert json.loads(rows[eni_12]["owner_names"]) == ["fn-c"]
    assert rows[eni_12]["owner_ref"] == "fn-c"


# -- web: shared names on the IP list, ENI page and Visual data ------------------------------


def test_shared_lambda_names_in_web_views(lambda_env, home):
    from iplens.web import create_app

    env = lambda_env
    for name in ("fn-a", "fn-b", "fn-c"):
        env["create_fn"](name, [env["sg1"]])
    eni = env["create_eni"]("10.0.1.20", [env["sg1"]], "fn-a")
    app = create_app(home, testing=True, gateway_factory=lambda _a: _gateway())
    client = app.test_client()
    client.get("/")
    with client.session_transaction() as s:
        token = s["csrf"]
    assert client.post("/refresh", data={"csrf_token": token}).status_code == 302

    assert "fn-a, fn-b, fn-c" in client.get("/ips").data.decode()
    page = client.get(f"/enis/{eni}").data.decode()
    assert "shared by 3 functions" in page
    assert all(f'<li class="mono">{n}</li>' in page for n in ("fn-a", "fn-b", "fn-c"))
    data = client.get(f"/visual/data.json?vpc={env['vpc_id']}").get_json()
    names = [i["name"] for s in data["vpc"]["subnets"] for i in s["items"]]
    assert "fn-a +2 more" in names


# -- moto: ECS ------------------------------------------------------------------------------


@pytest.fixture
def moto_ecs_awsvpc(monkeypatch):
    """moto: ECS awsvpc run_task reads NetworkInterface.private_dns_name (see test_collector)."""
    from moto.ec2.models.elastic_network_interfaces import NetworkInterface

    if not hasattr(NetworkInterface, "private_dns_name"):
        monkeypatch.setattr(
            NetworkInterface,
            "private_dns_name",
            property(lambda self: f"ip-{self.private_ip_address.replace('.', '-')}.ec2.internal"),
            raising=False,
        )


def test_ecs_two_services_in_one_subnet_attributed_by_attachment(db_path, moto_ecs_awsvpc):
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.3.0/24")["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(GroupName="example-ecs-sg", Description="x", VpcId=vpc_id)[
            "GroupId"
        ]
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
        # Same subnet, same security group: only the task attachment tells them apart.
        net = {"awsvpcConfiguration": {"subnets": [subnet], "securityGroups": [sg]}}
        expected: dict[str, str] = {}  # task id -> service
        for service, count in (("svc-a", 2), ("svc-b", 1)):
            ecs.create_service(
                cluster="example-cluster",
                serviceName=service,
                taskDefinition="example-task",
                desiredCount=count,
                launchType="FARGATE",
            )
            tasks = ecs.run_task(
                cluster="example-cluster",
                taskDefinition="example-task",
                count=count,
                launchType="FARGATE",
                group=f"service:{service}",
                networkConfiguration=net,
            )["tasks"]
            for t in tasks:
                expected[t["taskArn"].rsplit("/", 1)[-1]] = service

        # The ENI id each task's attachment names: the only authoritative mapping.
        by_eni: dict[str, str] = {}
        task_arns = ecs.list_tasks(cluster="example-cluster")["taskArns"]
        for t in ecs.describe_tasks(cluster="example-cluster", tasks=task_arns)["tasks"]:
            for att in t["attachments"]:
                for d in att["details"]:
                    if d["name"] == "networkInterfaceId":
                        by_eni[d["value"]] = t["taskArn"].rsplit("/", 1)[-1]
        assert len(by_eni) == 3

        result = Collector(_gateway(), db_path).run()

    rows = _eni_rows(db_path, result.snapshot_id)
    for eni_id, task_id in by_eni.items():
        service = expected[task_id]
        assert rows[eni_id]["owner_type"] == "ecs"
        assert rows[eni_id]["owner_ref"] == f"example-cluster/{service}/{task_id}"
    with closing(db_path) as conn:
        mapped = {
            r["eni_id"]: (r["service"], r["task_id"])
            for r in conn.execute(
                "SELECT * FROM ecs_task_enis WHERE snapshot_id=?", (result.snapshot_id,)
            )
        }
    assert mapped == {e: (expected[t], t) for e, t in by_eni.items()}
    services = [expected[t] for t in by_eni.values()]
    assert sorted(services) == ["svc-a", "svc-a", "svc-b"]
