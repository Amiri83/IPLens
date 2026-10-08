from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.exceptions import ClientError, ProfileNotFound
from moto import mock_aws

from iplens.accounts import Account, CredentialError
from iplens.aws import (
    AwsGateway,
    ReadOnlyViolation,
    build_session,
    check_connection,
    is_credential_failure,
)

FAKE_SECRET = "example/secret/value/for/tests/only/0000"
FAKE_TEMP_KEY_ID = "ASIAEXAMPLEEXAMPLE00"
FAKE_SESSION_TOKEN = "FakeSessionTokenForTestsOnly0000000000000000000000Example"


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
        Account(
            auth_mode="keys",
            region="eu-west-1",
            access_key_id="AKIAEXAMPLE000000000",
            secret_access_key=FAKE_SECRET,
        )
    )
    creds = s.get_credentials()
    assert creds.access_key == "AKIAEXAMPLE000000000"
    assert s.region_name == "eu-west-1"
    assert build_session(Account(auth_mode="env", region="us-west-2")).region_name == "us-west-2"
    with pytest.raises(ValueError):
        build_session(Account(auth_mode="keys", access_key_id="AKIAEXAMPLE000000000"))


def test_build_session_temporary_uses_session_token():
    s = build_session(
        Account(
            auth_mode="temporary",
            access_key_id=FAKE_TEMP_KEY_ID,
            secret_access_key=FAKE_SECRET,
            session_token=FAKE_SESSION_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    creds = s.get_credentials()
    assert (creds.access_key, creds.token) == (FAKE_TEMP_KEY_ID, FAKE_SESSION_TOKEN)


def test_build_session_refuses_expired_or_lost_credentials():
    expired = Account(
        auth_mode="temporary",
        access_key_id=FAKE_TEMP_KEY_ID,
        secret_access_key=FAKE_SECRET,
        session_token=FAKE_SESSION_TOKEN,
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    with pytest.raises(CredentialError, match="credentials expired, paste new ones"):
        build_session(expired)
    lost = Account(auth_mode="keys", access_key_id=FAKE_TEMP_KEY_ID, memory_only=True)
    with pytest.raises(CredentialError, match="paste them again"):
        build_session(lost)


def test_build_session_profile(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    cfg.write_text("[profile example-readonly]\nregion = us-east-2\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    # botocore lets AWS_DEFAULT_REGION / AWS_REGION override the profile's region.
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    s = build_session(Account(auth_mode="profile", profile="example-readonly", region=""))
    assert s.profile_name == "example-readonly"
    assert s.region_name == "us-east-2"
    with pytest.raises(ProfileNotFound):
        build_session(Account(auth_mode="profile", profile="missing", region="us-east-1"))


@mock_aws
def test_check_connection_ok():
    result = check_connection(Account(auth_mode="env", region="us-east-1"))
    assert result.ok and not result.credentials_problem
    assert "123456789012" in result.message


def test_check_connection_failure_does_not_leak_secret():
    def boom(_account):
        raise ValueError("bad")

    result = check_connection(
        Account(
            auth_mode="keys", access_key_id="AKIAEXAMPLE000000000", secret_access_key=FAKE_SECRET
        ),
        boom,
    )
    assert not result.ok
    assert FAKE_SECRET not in result.message


@pytest.mark.parametrize(
    "code, expected",
    [
        ("ExpiredToken", True),
        ("InvalidClientTokenId", True),
        ("ExpiredTokenException", True),
        ("AccessDenied", False),
    ],
)
def test_is_credential_failure(code, expected):
    exc = ClientError({"Error": {"Code": code, "Message": "example"}}, "DescribeVpcs")
    assert is_credential_failure(exc) is expected
    assert is_credential_failure(CredentialError("example"))
    assert not is_credential_failure(RuntimeError("example"))


def test_check_connection_flags_expired_token():
    def expired(_account):
        raise ClientError(
            {"Error": {"Code": "ExpiredToken", "Message": "The security token is expired"}},
            "GetCallerIdentity",
        )

    result = check_connection(Account(auth_mode="env"), expired)
    assert not result.ok and result.credentials_problem
    assert result.message == "Connection failed: credentials expired, paste new ones"
