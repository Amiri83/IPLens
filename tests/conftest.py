"""Shared fixtures.

All data here is synthetic: RFC1918 10.0.x.x addresses, the moto default
account 123456789012 and made-up resource ids/names.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from iplens.db import closing, init_db


@pytest.fixture(autouse=True)
def _hermetic_aws(monkeypatch, tmp_path):
    """Never let a test reach real AWS or the developer's AWS config."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-credentials"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    # An endpoint override (e.g. a local emulator) makes boto3 bypass moto's interception.
    for var in list(os.environ):
        if var.startswith("AWS_ENDPOINT_URL") or var == "AWS_S3_ENDPOINT":
            monkeypatch.delenv(var)
    monkeypatch.setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true")
    monkeypatch.delenv("IPLENS_SECRET_KEY", raising=False)
    monkeypatch.setenv("IPLENS_HOME", str(tmp_path / "iplens-home"))
    yield
    logger = logging.getLogger("iplens")
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()


@pytest.fixture
def home(tmp_path) -> Path:
    return tmp_path / "home"


@pytest.fixture
def db_path(tmp_path) -> Path:
    p = tmp_path / "test.db"
    init_db(p)
    return p


class SnapshotBuilder:
    """Write a synthetic snapshot straight into SQLite."""

    def __init__(
        self,
        db_path: Path,
        region: str = "us-east-1",
        *,
        account_alias: str = "",
        taken_at: datetime | None = None,
        account_ref: int | None = None,
        account_id: str = "123456789012",
        status: str = "ok",
    ):
        """``account_ref`` defaults to the first IPLens account (the migrated default)."""
        self.db_path = db_path
        self._subnet_vpc: dict[str, str] = {}
        self._subnet_az: dict[str, str] = {}
        taken_at = taken_at or datetime.now(UTC)
        with closing(db_path) as conn:
            if account_ref is None:
                row = conn.execute("SELECT MIN(id) FROM accounts").fetchone()
                account_ref = row[0]
            cur = conn.execute(
                "INSERT INTO snapshots(taken_at, region, account_id, account_alias, status, "
                "account_ref) VALUES(?, ?, ?, ?, ?, ?)",
                (
                    taken_at.isoformat(timespec="seconds"),
                    region,
                    account_id,
                    account_alias,
                    status,
                    account_ref,
                ),
            )
            self.id = int(cur.lastrowid)
            self.account_ref = account_ref

    def vpc(self, vpc_id: str, *cidrs: str, name: str = "example-vpc") -> SnapshotBuilder:
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO vpcs(snapshot_id, vpc_id, name, cidrs, is_default) VALUES(?,?,?,?,0)",
                (self.id, vpc_id, name, json.dumps(list(cidrs))),
            )
        return self

    def subnet(
        self, subnet_id: str, vpc_id: str, cidr: str, az: str = "us-east-1a", name: str = ""
    ) -> SnapshotBuilder:
        self._subnet_vpc[subnet_id] = vpc_id
        self._subnet_az[subnet_id] = az
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO subnets(snapshot_id, subnet_id, vpc_id, name, cidr, az, "
                "available_ip_count) VALUES(?,?,?,?,?,?,NULL)",
                (self.id, subnet_id, vpc_id, name, cidr, az),
            )
        return self

    def eni(
        self,
        eni_id: str,
        subnet_id: str,
        ips: list[str],
        *,
        owner_type: str = "ec2",
        owner_ref: str = "",
        status: str = "in-use",
        sgs: tuple[str, ...] = ("sg-0001",),
        description: str = "",
        requester_managed: bool = False,
        name: str = "",
        instance_id: str | None = None,
    ) -> SnapshotBuilder:
        vpc_id = self._subnet_vpc[subnet_id]
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO enis(snapshot_id, eni_id, subnet_id, vpc_id, az, status, "
                "interface_type, requester_id, requester_managed, description, instance_id, "
                "security_groups, owner_type, owner_ref, name) "
                "VALUES(?,?,?,?,?,?,'interface',NULL,?,?,?,?,?,?,?)",
                (
                    self.id,
                    eni_id,
                    subnet_id,
                    vpc_id,
                    self._subnet_az[subnet_id],
                    status,
                    int(requester_managed),
                    description,
                    instance_id,
                    json.dumps(sorted(sgs)),
                    owner_type,
                    owner_ref,
                    name,
                ),
            )
            for i, ip in enumerate(ips):
                conn.execute(
                    "INSERT INTO ips(snapshot_id, ip, ip_int, eni_id, subnet_id, vpc_id, "
                    "is_primary, public_ip, owner_type) VALUES(?,?,?,?,?,?,?,NULL,?)",
                    (
                        self.id,
                        ip,
                        int(ipaddress.IPv4Address(ip)),
                        eni_id,
                        subnet_id,
                        vpc_id,
                        int(i == 0),
                        owner_type,
                    ),
                )
        return self

    def lambda_fn(self, name: str, vpc_id: str | None, subnet_ids=(), sgs=()) -> SnapshotBuilder:
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO lambdas(snapshot_id, name, vpc_id, subnet_ids, security_groups) "
                "VALUES(?,?,?,?,?)",
                (self.id, name, vpc_id, json.dumps(list(subnet_ids)), json.dumps(list(sgs))),
            )
        return self

    def endpoint(
        self,
        endpoint_id: str,
        vpc_id: str,
        service: str,
        subnet_ids,
        eni_ids,
        endpoint_type: str = "Interface",
    ) -> SnapshotBuilder:
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO endpoints(snapshot_id, endpoint_id, vpc_id, service_name, "
                "endpoint_type, subnet_ids, eni_ids) VALUES(?,?,?,?,?,?,?)",
                (
                    self.id,
                    endpoint_id,
                    vpc_id,
                    service,
                    endpoint_type,
                    json.dumps(list(subnet_ids)),
                    json.dumps(list(eni_ids)),
                ),
            )
        return self

    def load_balancer(
        self, name: str, vpc_id: str, scheme: str = "internal", lb_type: str = "application"
    ) -> SnapshotBuilder:
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO load_balancers(snapshot_id, name, lb_type, scheme, vpc_id) "
                "VALUES(?,?,?,?,?)",
                (self.id, name, lb_type, scheme, vpc_id),
            )
        return self

    def ecs_service(
        self,
        cluster: str,
        service: str,
        last_deployment: datetime | None,
        eni_ids=(),
        desired: int = 1,
    ) -> SnapshotBuilder:
        """Add an ECS service and map already-added ENIs to it as task ENIs."""
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO ecs_services(snapshot_id, cluster, service, desired_count, "
                "running_count, last_deployment) VALUES(?,?,?,?,?,?)",
                (
                    self.id,
                    cluster,
                    service,
                    desired,
                    desired,
                    last_deployment.isoformat(timespec="seconds") if last_deployment else None,
                ),
            )
            for i, eni_id in enumerate(eni_ids):
                conn.execute(
                    "INSERT INTO ecs_task_enis(snapshot_id, eni_id, cluster, service, task_id) "
                    "VALUES(?,?,?,?,?)",
                    (self.id, eni_id, cluster, service, f"0example{i:04d}"),
                )
        return self

    def lb_target(
        self, lb_name: str, target_group: str, target_type: str, target_id: str, port: int = 0
    ) -> SnapshotBuilder:
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO lb_targets(snapshot_id, lb_name, target_group, target_type, "
                "target_id, port) VALUES(?,?,?,?,?,?)",
                (self.id, lb_name, target_group, target_type, target_id, port),
            )
        return self

    def ecs_service_lb(
        self, cluster: str, service: str, lb_name: str, target_group: str = ""
    ) -> SnapshotBuilder:
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO ecs_service_lbs(snapshot_id, cluster, service, lb_name, "
                "target_group) VALUES(?,?,?,?,?)",
                (self.id, cluster, service, lb_name, target_group),
            )
        return self

    def sg_ref(
        self, group_id: str, direction: str, ref_group_id: str, ports: str = "tcp/443"
    ) -> SnapshotBuilder:
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO sg_refs(snapshot_id, group_id, direction, ref_group_id, ports) "
                "VALUES(?,?,?,?,?)",
                (self.id, group_id, direction, ref_group_id, ports),
            )
        return self

    def sg_cidr(
        self,
        group_id: str,
        cidr: str,
        ip_protocol: str = "tcp",
        from_port: int | None = 443,
        to_port: int | None = None,
    ) -> SnapshotBuilder:
        with closing(self.db_path) as conn:
            conn.execute(
                "INSERT INTO sg_cidr_rules(snapshot_id, group_id, cidr, ip_protocol, from_port, "
                "to_port) VALUES(?,?,?,?,?,?)",
                (
                    self.id,
                    group_id,
                    cidr,
                    ip_protocol,
                    from_port,
                    from_port if to_port is None else to_port,
                ),
            )
        return self


@pytest.fixture
def snapshot_builder():
    return SnapshotBuilder


def ip_range(prefix: str, start: int, count: int) -> list[str]:
    base = int(ipaddress.IPv4Address(prefix))
    return [str(ipaddress.IPv4Address(base + start + i)) for i in range(count)]


@pytest.fixture
def ips():
    return ip_range
