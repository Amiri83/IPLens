"""Owner names of managed-service ENIs (iplens.managed): RDS / Aurora, Redshift,
ElastiCache, OpenSearch and MSK.

Each service's clusters / domains are an optional resource type (a missing permission is a
warning, never a failure); an ENI matching one by ENI id / IP, description reference or
subnet + security groups gets its owner name ("Aurora cluster db-a"), every other ENI keeps
today's attribution, and "Retry skipped" copies the rows of the services it does not
collect. Placeholders only: 192.0.2.N addresses, example names, moto (no real AWS)."""

from __future__ import annotations

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from iplens import collector as collector_mod
from iplens import managed, queries
from iplens.attribution import Attribution, attribute_eni
from iplens.aws import AwsGateway
from iplens.collector import MANAGED_SOURCES, Collector, retry_plan
from iplens.db import closing
from iplens.managed import ManagedIndex, ManagedResource, Match

REGION = "us-east-1"


# -- matching (pure) -------------------------------------------------------------------


def _eni(
    eni_id: str = "eni-0abc0001",
    subnet: str = "subnet-a",
    groups: tuple[str, ...] = ("sg-a",),
    description: str = "RDSNetworkInterface",
    vpc: str = "vpc-a",
    requester_managed: bool = True,
) -> dict:
    return {
        "NetworkInterfaceId": eni_id,
        "SubnetId": subnet,
        "VpcId": vpc,
        "Groups": [{"GroupId": g} for g in groups],
        "Description": description,
        "RequesterManaged": requester_managed,
        "InterfaceType": "interface",
    }


def _match(index: ManagedIndex, eni: dict, ips: tuple[str, ...] = ()) -> Match | None:
    return index.match(eni, attribute_eni(eni), ips)


def test_aurora_instance_eni_is_named_after_its_cluster():
    rows = managed.rds_resources(
        [
            {
                "DBInstanceIdentifier": "db-a-1",
                "DBClusterIdentifier": "db-a",
                "Engine": "aurora-postgresql",
                "DBSubnetGroup": {
                    "VpcId": "vpc-a",
                    "Subnets": [{"SubnetIdentifier": "subnet-a"}, {"SubnetIdentifier": "subnet-b"}],
                },
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-a"}],
            },
            {
                "DBInstanceIdentifier": "db-b",
                "Engine": "postgres",
                "DBSubnetGroup": {"VpcId": "vpc-a", "Subnets": [{"SubnetIdentifier": "subnet-a"}]},
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-b"}],
            },
        ],
        [
            {
                "DBClusterIdentifier": "db-a",
                "Engine": "aurora-postgresql",
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-a"}],
            }
        ],
    )
    index = ManagedIndex(rows)
    assert _match(index, _eni()) == Match("Aurora cluster db-a", "db-a")
    assert _match(index, _eni(subnet="subnet-b")) == Match("Aurora cluster db-a", "db-a")
    assert _match(index, _eni(groups=("sg-b",))) == Match("RDS instance db-b", "db-b")
    # No resource with exactly these security groups: today's attribution stays.
    assert _match(index, _eni(groups=("sg-a", "sg-b"))) is None
    assert _match(index, _eni(groups=("sg-other",))) is None
    # Only RDS ENIs: an EC2 instance's ENI with the same subnet and SG is not renamed.
    ec2 = {**_eni(description="example"), "Attachment": {"InstanceId": "i-0abc1234"}}
    assert attribute_eni(ec2).owner_type == "ec2" and _match(index, ec2) is None


def test_rds_cluster_without_instance_rows_matches_by_security_groups():
    rows = managed.rds_resources(
        [],
        [
            {
                "DBClusterIdentifier": "docs-a",
                "Engine": "docdb",
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-a"}],
            }
        ],
    )
    assert _match(ManagedIndex(rows), _eni(subnet="subnet-z")) == Match(
        "DocumentDB cluster docs-a", "docs-a"
    )


def test_ambiguous_candidates_leave_the_eni_unmatched():
    index = ManagedIndex(
        managed.rds_resources(
            [
                {
                    "DBInstanceIdentifier": name,
                    "Engine": "mysql",
                    "DBSubnetGroup": {"Subnets": [{"SubnetIdentifier": "subnet-a"}]},
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-a"}],
                }
                for name in ("db-a", "db-b")
            ],
            [],
        )
    )
    assert _match(index, _eni()) is None


def test_elasticache_and_opensearch_match_their_description_reference():
    index = ManagedIndex(
        managed.elasticache_resources(
            [
                {
                    "CacheClusterId": "cache-a",
                    "Engine": "memcached",
                    "SecurityGroups": [{"SecurityGroupId": "sg-a"}],
                },
                {
                    "CacheClusterId": "rg-a-001",
                    "Engine": "redis",
                    "ReplicationGroupId": "rg-a",
                    "SecurityGroups": [{"SecurityGroupId": "sg-a"}],
                },
            ],
            [{"ReplicationGroupId": "rg-b", "MemberClusters": ["rg-b-001"]}],
        )
        + managed.opensearch_resources(
            [
                {
                    "DomainName": "search-a",
                    "VPCOptions": {"SubnetIds": ["subnet-a"], "SecurityGroupIds": ["sg-a"]},
                },
                {"DomainName": "public-a"},  # no VPC access: no ENIs
            ]
        )
    )
    assert _match(index, _eni(description="ElastiCache cache-a")) == Match(
        "ElastiCache memcached cluster cache-a", "cache-a"
    )
    assert _match(index, _eni(description="ElastiCache rg-a-001")) == Match(
        "ElastiCache replication group rg-a", "rg-a-001"
    )
    # Without DescribeCacheClusters rows: the replication group's member list.
    assert _match(index, _eni(description="ElastiCache rg-b-001")) == Match(
        "ElastiCache replication group rg-b", "rg-b-001"
    )
    # The description names another cache cluster: never matched by security group.
    assert _match(index, _eni(description="ElastiCache cache-z")) is None
    assert _match(index, _eni(description="ES search-a")) == Match(
        "OpenSearch domain search-a", "search-a"
    )


def test_redshift_matches_by_node_ip_in_its_vpc_and_msk_needs_a_service_sign():
    index = ManagedIndex(
        managed.redshift_resources(
            [
                {
                    "ClusterIdentifier": "warehouse-a",
                    "VpcId": "vpc-a",
                    "ClusterNodes": [{"PrivateIPAddress": "192.0.2.30"}],
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-r"}],
                }
            ]
        )
        + managed.msk_resources(
            [
                {
                    "ClusterName": "kafka-a",
                    "ClusterType": "PROVISIONED",
                    "Provisioned": {
                        "BrokerNodeGroupInfo": {
                            "ClientSubnets": ["subnet-a"],
                            "SecurityGroups": ["sg-k"],
                        }
                    },
                },
                {
                    "ClusterName": "kafka-b",
                    "ClusterType": "SERVERLESS",
                    "Serverless": {
                        "VpcConfigs": [{"SubnetIds": ["subnet-b"], "SecurityGroupIds": ["sg-s"]}]
                    },
                },
            ]
        )
    )
    plain = _eni(description="", groups=("sg-x",), requester_managed=False)
    assert _match(index, plain, ("192.0.2.30",)) == Match(
        "Redshift cluster warehouse-a", "warehouse-a"
    )
    assert _match(index, {**plain, "VpcId": "vpc-b"}, ("192.0.2.30",)) is None  # same IP, other VPC
    assert _match(index, _eni(description="", groups=("sg-k",))) == Match(
        "MSK cluster kafka-a", "kafka-a"
    )
    assert _match(
        index, _eni(subnet="subnet-b", description="ENI for kafka", groups=("sg-s",))
    ) == Match("MSK Serverless cluster kafka-b", "kafka-b")
    # A customer-created ENI that happens to share the brokers' subnet and SG stays generic.
    assert _match(index, _eni(description="", groups=("sg-k",), requester_managed=False)) is None
    # An "other" ENI already identified as something else is left alone.
    efs = _eni(description="EFS mount target for fs-0abc1234", groups=("sg-k",))
    assert attribute_eni(efs) == Attribution("other", "EFS") and _match(index, efs) is None


def test_rows_round_trip_through_the_snapshot_tables(db_path):
    row = ManagedResource(
        "opensearch",
        "domain",
        "search-a",
        "OpenSearch domain search-a",
        "search-a",
        "vpc-a",
        ("subnet-a",),
        ("sg-a",),
        refs=("search-a",),
    )
    with closing(db_path) as conn:
        conn.execute(
            "INSERT INTO snapshots(id, taken_at, region, status) VALUES(1, 't', ?, 'ok')",
            (REGION,),
        )
        managed.write(conn, 1, [row])
        assert managed.load(conn, 1, "opensearch") == [row]
        assert managed.load(conn, 1, "rds") == []


# -- the collector (moto) --------------------------------------------------------------


@pytest.fixture
def aws_env():
    """A VPC with an Aurora cluster, a Redshift cluster, an ElastiCache cluster, an
    OpenSearch domain and an MSK cluster, and the ENIs AWS would create for them (moto
    does not create those, so they are added with the services' descriptions)."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="192.0.2.0/24")["Vpc"]["VpcId"]
        sa = ec2.create_subnet(VpcId=vpc, CidrBlock="192.0.2.0/26", AvailabilityZone="us-east-1a")[
            "Subnet"
        ]["SubnetId"]
        sb = ec2.create_subnet(VpcId=vpc, CidrBlock="192.0.2.64/26", AvailabilityZone="us-east-1b")[
            "Subnet"
        ]["SubnetId"]

        def sg(name: str) -> str:
            return ec2.create_security_group(GroupName=name, Description="example", VpcId=vpc)[
                "GroupId"
            ]

        groups = {n: sg(n) for n in ("sg-db", "sg-other", "sg-dw", "sg-cache", "sg-search", "sg-k")}

        def eni(ip: str, group: str, description: str, subnet: str = sa) -> str:
            return ec2.create_network_interface(
                SubnetId=subnet,
                PrivateIpAddress=ip,
                Groups=[groups[group]],
                Description=description,
            )["NetworkInterface"]["NetworkInterfaceId"]

        rds = boto3.client("rds", region_name=REGION)
        rds.create_db_subnet_group(
            DBSubnetGroupName="subnets-a",
            DBSubnetGroupDescription="example",
            SubnetIds=[sa, sb],
        )
        rds.create_db_cluster(
            DBClusterIdentifier="db-a",
            Engine="aurora-postgresql",
            MasterUsername="example",
            MasterUserPassword="example-password",
            DBSubnetGroupName="subnets-a",
            VpcSecurityGroupIds=[groups["sg-db"]],
        )
        rds.create_db_instance(
            DBInstanceIdentifier="db-a-1",
            DBClusterIdentifier="db-a",
            Engine="aurora-postgresql",
            DBInstanceClass="db.r6g.large",
            DBSubnetGroupName="subnets-a",
        )
        boto3.client("redshift", region_name=REGION).create_cluster(
            ClusterIdentifier="warehouse-a",
            NodeType="ra3.xlplus",
            MasterUsername="example",
            MasterUserPassword="Example-password1",
            VpcSecurityGroupIds=[groups["sg-dw"]],
        )
        boto3.client("elasticache", region_name=REGION).create_cache_cluster(
            CacheClusterId="cache-a",
            Engine="memcached",
            CacheNodeType="cache.t3.micro",
            NumCacheNodes=1,
            SecurityGroupIds=[groups["sg-cache"]],
        )
        boto3.client("opensearch", region_name=REGION).create_domain(
            DomainName="search-a",
            VPCOptions={"SubnetIds": [sa], "SecurityGroupIds": [groups["sg-search"]]},
        )
        boto3.client("kafka", region_name=REGION).create_cluster_v2(
            ClusterName="kafka-a",
            Provisioned={
                "BrokerNodeGroupInfo": {
                    "InstanceType": "kafka.m5.large",
                    "ClientSubnets": [sa, sb],
                    "SecurityGroups": [groups["sg-k"]],
                },
                "KafkaVersion": "3.6.0",
                "NumberOfBrokerNodes": 2,
            },
        )
        enis = {
            "aurora": eni("192.0.2.10", "sg-db", "RDSNetworkInterface"),
            "rds-unmatched": eni("192.0.2.11", "sg-other", "RDSNetworkInterface"),
            "redshift": eni("192.0.2.12", "sg-dw", "RedshiftNetworkInterface"),
            "cache": eni("192.0.2.13", "sg-cache", "ElastiCache cache-a"),
            "search": eni("192.0.2.14", "sg-search", "ES search-a"),
            "kafka": eni("192.0.2.70", "sg-k", "ENI for MSK cluster", subnet=sb),
            "plain": eni("192.0.2.15", "sg-other", "example detached"),
        }
        yield enis


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name=REGION))


def _owners(db_path, snap_id: int) -> dict[str, tuple[str, str, str]]:
    """eni id -> (owner_type, owner_ref, owner_name)."""
    with closing(db_path) as conn:
        return {
            r["eni_id"]: (r["owner_type"], r["owner_ref"] or "", r["owner_name"] or "")
            for r in conn.execute(
                "SELECT eni_id, owner_type, owner_ref, owner_name FROM enis WHERE snapshot_id=?",
                (snap_id,),
            )
        }


EXPECTED = {
    "aurora": ("rds", "db-a", "Aurora cluster db-a"),
    "rds-unmatched": ("rds", "", ""),
    "redshift": ("other", "warehouse-a", "Redshift cluster warehouse-a"),
    "cache": ("elasticache", "cache-a", "ElastiCache memcached cluster cache-a"),
    "search": ("opensearch", "search-a", "OpenSearch domain search-a"),
    "kafka": ("other", "kafka-a", "MSK cluster kafka-a"),
    "plain": ("other", "", ""),
}


def test_collector_names_managed_service_enis(aws_env, db_path):
    result = Collector(_gateway(), db_path).run()
    assert result.skipped == [] and result.warnings == []
    owners = _owners(db_path, result.snapshot_id)
    assert {key: owners[eni_id] for key, eni_id in aws_env.items()} == EXPECTED
    with closing(db_path) as conn:
        for service, table in managed.TABLES.items():
            assert conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE snapshot_id=?",  # noqa: S608 - constants
                (result.snapshot_id,),
            ).fetchone()[0], service
        # The IP List shows (and searches) the owner name.
        hits = queries.ip_list(conn, result.snapshot_id, queries.IpFilter(q="Aurora cluster"))
    assert [(r["ip"], r["resource_name"]) for r in hits] == [("192.0.2.10", "Aurora cluster db-a")]


@pytest.mark.parametrize(
    ("op", "what", "key"),
    [
        ("describe_db_instances", "rds:DescribeDBInstances", None),
        ("describe_db_clusters", "rds:DescribeDBClusters", None),
        ("describe_clusters", "redshift:DescribeClusters", "redshift"),
        ("describe_cache_clusters", "elasticache:DescribeCacheClusters", "cache"),
        ("list_clusters_v2", "kafka:ListClustersV2", "kafka"),
    ],
)
def test_missing_permission_is_a_warning_and_the_enis_stay_generic(
    aws_env, db_path, monkeypatch, op, what, key
):
    real = collector_mod._paginate

    def paginate(client, name, k, **kwargs):
        if name == op:
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "x"}}, name)
        return real(client, name, k, **kwargs)

    monkeypatch.setattr(collector_mod, "_paginate", paginate)
    result = Collector(_gateway(), db_path).run()
    assert result.skipped == [(what, "AccessDeniedException")]
    assert f"{what} skipped (AccessDeniedException)" in result.warnings
    owners = _owners(db_path, result.snapshot_id)
    for name, eni_id in aws_env.items():
        expected = EXPECTED[name]
        if name == key:  # today's attribution
            expected = (expected[0], "cache-a" if name == "cache" else "", "")
        assert owners[eni_id] == expected, name
    # Without the clusters, the Aurora ENI still gets its name from the instances (and
    # the other way round).
    assert owners[aws_env["aurora"]][2] == "Aurora cluster db-a"


def test_opensearch_permission_denied_is_a_warning(aws_env, db_path, monkeypatch):
    def denied(self):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "x"}}, "x")

    monkeypatch.setattr(Collector, "_fetch_opensearch_domains", denied)
    result = Collector(_gateway(), db_path).run()
    assert result.skipped == [("es:DescribeDomains", "AccessDeniedException")]
    assert _owners(db_path, result.snapshot_id)[aws_env["search"]] == ("opensearch", "search-a", "")


# -- Retry skipped ---------------------------------------------------------------------


def test_every_managed_table_is_part_of_the_retry_merge():
    merged = {
        table: sources for sources, tables, _tags in collector_mod._MERGED for table in tables
    }
    for service, sources in MANAGED_SOURCES.items():
        assert merged[managed.TABLES[service]] == frozenset(sources)
    # A service's calls are retried together (its rows derive from both).
    assert {"rds:DescribeDBInstances", "rds:DescribeDBClusters"} <= retry_plan(
        ["rds:DescribeDBClusters"]
    )


def test_retry_copies_the_managed_tables_it_does_not_collect(aws_env, db_path, monkeypatch):
    source = Collector(_gateway(), db_path).run().snapshot_id
    with closing(db_path) as conn:
        before = {s: managed.load(conn, source, s) for s in managed.TABLES}
    calls: list[str] = []
    real = collector_mod._paginate

    def paginate(client, op, key, **kwargs):
        calls.append(op)
        return real(client, op, key, **kwargs)

    monkeypatch.setattr(collector_mod, "_paginate", paginate)
    retry = Collector(
        _gateway(), db_path, only=["kafka:ListClustersV2"], source_snapshot=source
    ).run()
    assert retry.skipped == []
    # Not collected again, copied from the source snapshot ...
    assert "describe_db_instances" not in calls and "describe_clusters" not in calls
    assert "list_clusters_v2" in calls
    with closing(db_path) as conn:
        after = {s: managed.load(conn, retry.snapshot_id, s) for s in managed.TABLES}
    assert after == before and all(after.values())
    # ... and the fresh ENIs are named from the copied rows.
    owners = _owners(db_path, retry.snapshot_id)
    assert {key: owners[eni_id] for key, eni_id in aws_env.items()} == EXPECTED
