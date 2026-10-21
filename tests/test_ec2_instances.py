"""EC2 instance ENIs: instance id + Name tag mapping and primary + secondary private IPs."""

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from iplens import queries
from iplens.aws import AwsGateway
from iplens.collector import Collector, eni_private_ips, instance_eni_index
from iplens.db import closing

REGION = "us-east-1"


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name=REGION))


def _reservations():
    """A placeholder instance whose attachment lists a primary and two secondary IPs."""
    ips = [
        {"PrivateIpAddress": "192.0.2.10", "Primary": True},
        {"PrivateIpAddress": "192.0.2.11", "Primary": False},
        {
            "PrivateIpAddress": "192.0.2.12",
            "Primary": False,
            "Association": {"PublicIp": "198.51.100.12"},
        },
    ]
    instance = {
        "InstanceId": "i-0abc1234",
        "Tags": [{"Key": "Name", "Value": "test-server-a"}],
        "NetworkInterfaces": [{"NetworkInterfaceId": "eni-0abc1234", "PrivateIpAddresses": ips}],
    }
    return [{"Instances": [instance]}]


def test_instance_attachment_ips_merge_primary_and_secondary():
    # The ENI view only carries its primary IP; the instance attachment lists all three.
    eni = {"NetworkInterfaceId": "eni-0abc1234", "PrivateIpAddress": "192.0.2.10"}
    inst = instance_eni_index(_reservations())["eni-0abc1234"]
    assert (inst.instance_id, inst.name) == ("i-0abc1234", "test-server-a")
    ips = {p["PrivateIpAddress"]: p for p in eni_private_ips(eni, inst)}
    assert sorted(ips) == ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
    assert [ip for ip, p in ips.items() if p["Primary"]] == ["192.0.2.10"]
    assert ips["192.0.2.12"]["Association"] == {"PublicIp": "198.51.100.12"}
    # Without the instance view the ENI's own IPs are still used.
    assert [p["PrivateIpAddress"] for p in eni_private_ips(eni)] == ["192.0.2.10"]


def _instance_env():
    """Setup only, outside the read-only gateway: a named instance with two secondary IPs."""
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    image_id = ec2.describe_images()["Images"][0]["ImageId"]
    inst = ec2.run_instances(
        ImageId=image_id,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet,
        PrivateIpAddress="10.0.1.10",
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "test-server-a"}]}
        ],
    )["Instances"][0]
    eni_id = inst["NetworkInterfaces"][0]["NetworkInterfaceId"]
    ec2.assign_private_ip_addresses(
        NetworkInterfaceId=eni_id, PrivateIpAddresses=["10.0.1.11", "10.0.1.12"]
    )
    return inst["InstanceId"], eni_id


def test_ec2_instance_secondary_ips_name_and_search(db_path):
    with mock_aws():
        instance_id, eni_id = _instance_env()
        result = Collector(_gateway(), db_path).run()
    snap = result.snapshot_id
    with closing(db_path) as conn:
        row = conn.execute(
            "SELECT instance_id, instance_name, owner_type, owner_ref FROM enis "
            "WHERE snapshot_id=? AND eni_id=?",
            (snap, eni_id),
        ).fetchone()
        assert tuple(row) == (instance_id, "test-server-a", "ec2", instance_id)
        mine = [r for r in queries.ip_list(conn, snap) if r["eni_id"] == eni_id]
        assert [r["ip"] for r in mine] == ["10.0.1.10", "10.0.1.11", "10.0.1.12"]
        assert [r["ip"] for r in mine if r["is_primary"]] == ["10.0.1.10"]
        assert {r["resource_name"] for r in mine} == {"test-server-a"}
        # Search matches the instance id, its Name tag (also partially) and every IP.
        for q in (instance_id, "test-server-a", "server-a"):
            hits = queries.ip_list(conn, snap, queries.IpFilter(q=q))
            assert [r["ip"] for r in hits] == ["10.0.1.10", "10.0.1.11", "10.0.1.12"], q
        for ip in ("10.0.1.10", "10.0.1.11", "10.0.1.12"):
            hits = queries.ip_list(conn, snap, queries.IpFilter(q=ip))
            assert [(r["ip"], r["instance_id"]) for r in hits] == [(ip, instance_id)]


def test_describe_instances_denied_is_a_warning(db_path, monkeypatch):
    with mock_aws():
        instance_id, _eni_id = _instance_env()
        gw = _gateway()
        real_client = gw.client

        def client(service, **kw):
            c = real_client(service, **kw)
            if service == "ec2":

                def deny(**_):
                    raise ClientError(
                        {"Error": {"Code": "UnauthorizedOperation", "Message": "no"}},
                        "DescribeInstances",
                    )

                c.meta.events.register("before-call.ec2.DescribeInstances", deny)
            return c

        monkeypatch.setattr(gw, "client", client)
        result = Collector(gw, db_path).run()
    assert "ec2:DescribeInstances skipped (UnauthorizedOperation)" in result.warnings
    with closing(db_path) as conn:  # the ENI's own data still maps the IPs to the instance
        hits = queries.ip_list(conn, result.snapshot_id, queries.IpFilter(q="10.0.1.11"))
    assert [r["instance_id"] for r in hits] == [instance_id]
