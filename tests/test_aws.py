import boto3
import pytest
from botocore.exceptions import ProfileNotFound
from moto import mock_aws

from iplens.aws import AwsGateway, ReadOnlyViolation, build_session, check_connection
from iplens.settings import Settings

FAKE_SECRET = "example/secret/value/for/tests/only/0000"


@mock_aws
def test_read_only_guard_blocks_mutations():
    gw = AwsGateway(boto3.session.Session(region_name="us-east-1"))
    ec2 = gw.client("ec2")
    assert "Vpcs" in ec2.describe_vpcs()
    with pytest.raises(ReadOnlyViolation):
        ec2.create_vpc(CidrBlock="10.0.0.0/16")
    with pytest.raises(ReadOnlyViolation):
        gw.client("ec2").delete_network_interface(NetworkInterfaceId="eni-0000example")
    # nothing was created
    assert len(boto3.client("ec2", region_name="us-east-1").describe_vpcs()["Vpcs"]) == 1


@mock_aws
def test_read_only_guard_allows_paginators():
    ec2 = AwsGateway(boto3.session.Session(region_name="us-east-1")).client("ec2")
    pages = list(ec2.get_paginator("describe_subnets").paginate())
    assert pages


def test_build_session_keys_and_env():
    s = build_session(
        Settings(
            auth_mode="keys",
            region="eu-west-1",
            access_key_id="AKIAEXAMPLE000000000",
            secret_access_key=FAKE_SECRET,
        )
    )
    creds = s.get_credentials()
    assert creds.access_key == "AKIAEXAMPLE000000000"
    assert s.region_name == "eu-west-1"
    assert build_session(Settings(auth_mode="env", region="us-west-2")).region_name == "us-west-2"
    with pytest.raises(ValueError):
        build_session(Settings(auth_mode="keys", access_key_id="AKIAEXAMPLE000000000"))


def test_build_session_profile(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.write_text("[profile example-readonly]\nregion = us-east-2\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    # botocore lets AWS_DEFAULT_REGION / AWS_REGION override the profile's region.
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    s = build_session(Settings(auth_mode="profile", profile="example-readonly", region=""))
    assert s.profile_name == "example-readonly"
    assert s.region_name == "us-east-2"
    with pytest.raises(ProfileNotFound):
        build_session(Settings(auth_mode="profile", profile="missing", region="us-east-1"))


@mock_aws
def test_check_connection_ok():
    ok, msg = check_connection(Settings(auth_mode="env", region="us-east-1"))
    assert ok
    assert "123456789012" in msg


def test_check_connection_failure_does_not_leak_secret():
    def boom(_settings):
        raise ValueError("bad")

    ok, msg = check_connection(
        Settings(
            auth_mode="keys", access_key_id="AKIAEXAMPLE000000000", secret_access_key=FAKE_SECRET
        ),
        boom,
    )
    assert not ok
    assert FAKE_SECRET not in msg
