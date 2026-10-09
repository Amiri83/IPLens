"""AWS-first ownership (iplens.ownership): tag:GetResources, CloudFormation precedence,
CloudTrail creator classification and configurable tag keys.

All data is synthetic: moto's account 123456789012, 10.0.x.x addresses and example names.
"""

import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from iplens import ownership, queries, terraform
from iplens.aws import AwsGateway, is_read_only_operation
from iplens.collector import Collector
from iplens.db import closing
from iplens.ownership import OwnershipConfig, OwnershipIndex, Principal
from iplens.settings import SettingsStore
from iplens.web import create_app

REGION = "us-east-1"
VPC = "vpc-0example0000001"
SA = "subnet-0000000a"


def _gateway() -> AwsGateway:
    return AwsGateway(boto3.session.Session(region_name=REGION))


def _snap(db_path):
    with closing(db_path) as conn:
        return queries.latest_snapshot(conn)["id"]


# -- read-only guard ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("service", "op"),
    [
        ("resourcegroupstaggingapi", "GetResources"),
        ("cloudformation", "ListStacks"),
        ("cloudformation", "ListStackResources"),
        ("cloudtrail", "LookupEvents"),
    ],
)
def test_ownership_operations_are_allowlisted(service, op):
    assert is_read_only_operation(service, op)


def test_cloudtrail_mutations_stay_blocked():
    assert not is_read_only_operation("cloudtrail", "StopLogging")
    assert not is_read_only_operation("cloudformation", "DeleteStack")


# -- key mapping ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("arn", "key"),
    [
        ("arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0example01", ("vpc", "vpc-0example01")),
        ("arn:aws:ec2:us-east-1:123456789012:subnet/subnet-0a", ("subnet", "subnet-0a")),
        ("arn:aws:ec2:us-east-1:123456789012:network-interface/eni-0a", ("eni", "eni-0a")),
        ("arn:aws:ec2:us-east-1:123456789012:instance/i-0example", ("instance", "i-0example")),
        (
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-a/0abc",
            ("lb", "alb-a"),
        ),
        ("arn:aws:lambda:us-east-1:123456789012:function:fn-a", ("lambda", "fn-a")),
        (
            "arn:aws:ecs:us-east-1:123456789012:service/cluster-a/svc-a",
            ("ecs_service", "cluster-a/svc-a"),
        ),
        ("arn:aws:rds:us-east-1:123456789012:db:db-a", ("rds:db", "db-a")),
        ("arn:aws:s3:::bucket-a", ("s3:bucket", "bucket-a")),
        ("not-an-arn", None),
    ],
)
def test_arn_key(arn, key):
    assert ownership.arn_key(arn) == key


def test_cfn_key_normalises_physical_ids():
    lb_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-a/0abc"
    assert ownership.cfn_key("AWS::ElasticLoadBalancingV2::LoadBalancer", lb_arn) == ("lb", "alb-a")
    assert ownership.cfn_key("AWS::EC2::Subnet", "subnet-0a") == ("subnet", "subnet-0a")
    assert ownership.cfn_key("AWS::SQS::Queue", "queue-a") == ("sqs:queue", "queue-a")
    assert ownership.cfn_key("AWS::EC2::Subnet", "") is None


# -- tag:GetResources -----------------------------------------------------------------------


@pytest.fixture
def tagged_env():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(
            CidrBlock="10.0.0.0/16",
            TagSpecifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Project", "Value": "project-a"},
                        {"Key": "Environment", "Value": "dev"},
                        {"Key": "cost-center", "Value": "example-cost-value"},
                    ],
                }
            ],
        )["Vpc"]["VpcId"]
        # More than one tag:GetResources page (100 resources per page).
        groups = [
            ec2.create_security_group(
                GroupName=f"sg-example-{i:03d}",
                Description="example",
                VpcId=vpc,
                TagSpecifications=[
                    {
                        "ResourceType": "security-group",
                        "Tags": [{"Key": "Team", "Value": "team-blue"}],
                    }
                ],
            )["GroupId"]
            for i in range(110)
        ]
        yield {"vpc": vpc, "groups": groups}


def test_get_resources_maps_tags_paginated_and_keeps_only_ownership_values(tagged_env, db_path):
    result = Collector(_gateway(), db_path).run()
    assert result.warnings == []
    snap = _snap(db_path)
    with closing(db_path) as conn:
        resources = {
            (r["kind"], r["resource_id"])
            for r in conn.execute("SELECT * FROM own_resources WHERE snapshot_id=?", (snap,))
        }
        tags = {
            (r["kind"], r["resource_id"], r["key"]): r["value"]
            for r in conn.execute("SELECT * FROM own_tags WHERE snapshot_id=?", (snap,))
        }
        seen = ownership.tag_keys_seen(conn, snap)
        report = ownership.report(conn, snap, OwnershipConfig())
    assert ("vpc", tagged_env["vpc"]) in resources
    # Every page was read.
    assert {("sg", g) for g in tagged_env["groups"]} <= resources
    vpc = tagged_env["vpc"]
    assert tags[("vpc", vpc, "Project")] == "project-a"
    assert tags[("vpc", vpc, "Environment")] == "dev"
    # Other tag keys are kept by key only (for the Settings dropdowns), never by value.
    assert tags[("vpc", vpc, "cost-center")] == ""
    assert "cost-center" in seen and "Project" in seen and "Team" in seen
    counts = {c["source"]: c["count"] for c in report.counts}
    assert counts["iac_tag"] == 1  # the VPC: Project tag
    # Security groups have no Project / Environment tag: tag gaps.
    gap_ids = {g["resource_id"] for g in report.tag_gaps}
    assert set(tagged_env["groups"]) <= gap_ids and vpc not in gap_ids


def test_get_resources_denied_is_a_warning(tagged_env, db_path, monkeypatch):
    gw = _gateway()
    real_client = gw.client

    def client(service, **kw):
        c = real_client(service, **kw)
        if service == "resourcegroupstaggingapi":

            def denied(*_a, **_k):
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "Get")

            monkeypatch.setattr(
                c, "get_paginator", lambda _op: type("P", (), {"paginate": denied})()
            )
        return c

    monkeypatch.setattr(gw, "client", client)
    result = Collector(gw, db_path).run()
    assert "tag:GetResources skipped (AccessDenied)" in result.warnings
    with closing(db_path) as conn:
        assert queries.latest_snapshot(conn)["id"] == result.snapshot_id  # still collected


# -- CloudFormation precedence --------------------------------------------------------------


def test_cloudformation_stack_beats_tags(db_path):
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        template = {
            "Resources": {
                "SubnetA": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {"VpcId": vpc, "CidrBlock": "10.0.1.0/24"},
                }
            }
        }
        cfn = boto3.client("cloudformation", region_name=REGION)
        cfn.create_stack(StackName="stack-a", TemplateBody=json.dumps(template))
        in_stack = cfn.list_stack_resources(StackName="stack-a")["StackResourceSummaries"][0][
            "PhysicalResourceId"
        ]
        tagged_only = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24")["Subnet"]["SubnetId"]
        # Both subnets carry a Project tag; only one is a stack resource.
        ec2.create_tags(
            Resources=[in_stack, tagged_only], Tags=[{"Key": "Project", "Value": "project-a"}]
        )
        result = Collector(_gateway(), db_path).run()
    assert result.warnings == []
    snap = _snap(db_path)
    with closing(db_path) as conn:
        idx = ownership.load_index(conn, snap, OwnershipConfig())
        report = ownership.report(conn, snap, OwnershipConfig())
    assert idx.resolve([("subnet", in_stack)]) == ownership.Owner("cloudformation", "stack-a")
    assert idx.resolve([("subnet", tagged_only)]) == ownership.Owner("iac_tag", "project-a")
    assert idx.resolve([("vpc", vpc)]).source == ownership.UNMANAGED
    assert vpc in {r["resource_id"] for r in report.unmanaged}
    # The stack id ARN of the aws:cloudformation tags is never stored.
    with closing(db_path) as conn:
        keys = {r["key"] for r in conn.execute("SELECT key FROM own_tags")}
    assert not any(k.startswith("aws:") for k in keys)


def test_precedence_order_and_terraform_only_when_enabled():
    tf = {("eni", "eni-0a"): [{"root": "root-a", "address": "aws_network_interface.a", "type": ""}]}
    both = OwnershipIndex(
        config=OwnershipConfig(tf_enabled=True),
        cfn={("eni", "eni-0a"): "stack-a"},
        tags={("eni", "eni-0a"): {"project": "project-a"}},
        tf=tf,
        creators={("eni", "eni-0a"): Principal("user-a", "user")},
    )
    keys = [("eni", "eni-0a")]
    assert both.resolve(keys).source == "cloudformation"
    both.cfn.clear()
    assert both.resolve(keys) == ownership.Owner("iac_tag", "project-a")  # key match ignores case
    both.tags.clear()
    assert both.resolve(keys) == ownership.Owner("terraform", "root-a", "aws_network_interface.a")
    off = OwnershipIndex(config=OwnershipConfig(tf_enabled=False), tf=tf, creators=both.creators)
    assert off.resolve(keys) == ownership.Owner("cloudtrail_human", "manual", "user-a")
    assert OwnershipIndex().resolve(keys) == ownership.Owner()


# -- CloudTrail -----------------------------------------------------------------------------


def _event(name: str, identity: dict) -> dict:
    return {"EventName": name, "CloudTrailEvent": json.dumps({"userIdentity": identity})}


CI_ROLE = {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/deploy-role-a/session-a",
    "sessionContext": {"sessionIssuer": {"type": "Role", "userName": "deploy-role-a"}},
}
HUMAN_USER = {"type": "IAMUser", "userName": "user-a"}


def test_principal_from_event_keeps_names_only():
    assert ownership.principal_from_event(_event("CreateVpc", CI_ROLE)) == Principal(
        "deploy-role-a", "role"
    )
    no_issuer = {"type": "AssumedRole", "arn": CI_ROLE["arn"]}
    assert ownership.principal_from_event(_event("CreateVpc", no_issuer)).name == "deploy-role-a"
    assert ownership.principal_from_event(_event("CreateVpc", HUMAN_USER)) == Principal(
        "user-a", "user"
    )
    assert ownership.principal_from_event(_event("CreateVpc", {"type": "Root"})).kind == "root"
    assert ownership.principal_from_event(_event("CreateVpc", {"type": "AWSService"})) is None
    assert ownership.principal_from_event({"CloudTrailEvent": "not json"}) is None


def test_ci_vs_human_classification_uses_the_patterns():
    patterns = ownership.DEFAULT_CI_PATTERNS
    assert ownership.is_ci("deploy-role-a", patterns)
    assert ownership.is_ci("GitHubActionsRole", patterns)  # case-insensitive
    assert not ownership.is_ci("user-a", patterns)
    assert not ownership.is_ci("deploy-role-a", ("build-*",))
    assert ownership.is_create_event("CreateSubnet") and ownership.is_create_event("RunInstances")
    assert not ownership.is_create_event("ModifyVpcAttribute")


class _FakePaginator:
    def __init__(self, events: dict[str, list[dict]], calls: list[str]):
        self.events, self.calls = events, calls

    def paginate(self, LookupAttributes, **_kw):  # noqa: N803 - boto3 argument name
        value = LookupAttributes[0]["AttributeValue"]
        self.calls.append(value)
        return [{"Events": self.events.get(value, [])}]


class _FakeCloudTrail:
    def __init__(self, events, calls):
        self._paginator = _FakePaginator(events, calls)

    def get_paginator(self, name):
        assert name == "lookup_events"
        return self._paginator


def _cloudtrail_gateway(events, calls):
    gw = _gateway()
    real_client = gw.client

    def client(service, **kw):
        return (
            _FakeCloudTrail(events, calls)
            if service == "cloudtrail"
            else real_client(service, **kw)
        )

    gw.client = client
    return gw


def test_cloudtrail_creator_of_unowned_resources_ci_vs_human(db_path):
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        by_ci = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        by_human = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
        tagged = ec2.create_vpc(
            CidrBlock="10.2.0.0/16",
            TagSpecifications=[
                {"ResourceType": "vpc", "Tags": [{"Key": "Project", "Value": "project-a"}]}
            ],
        )["Vpc"]["VpcId"]
        events = {
            # Newest first: the later change by someone else is not a create event.
            by_ci: [_event("ModifyVpcAttribute", HUMAN_USER), _event("CreateVpc", CI_ROLE)],
            by_human: [_event("CreateVpc", HUMAN_USER)],
        }
        calls: list[str] = []
        config = OwnershipConfig(cloudtrail=True)
        result = Collector(
            _cloudtrail_gateway(events, calls), db_path, ownership_config=config
        ).run()
    assert result.warnings == []
    # Only resources still unowned after CloudFormation / tags are looked up.
    assert tagged not in calls and {by_ci, by_human} <= set(calls)
    snap = _snap(db_path)
    with closing(db_path) as conn:
        idx = ownership.load_index(conn, snap, config)
        stored = [tuple(r) for r in conn.execute("SELECT * FROM own_resources")]
    assert idx.resolve([("vpc", by_ci)]) == ownership.Owner(
        "cloudtrail_ci", "IaC (unknown repo)", "deploy-role-a"
    )
    assert idx.resolve([("vpc", by_human)]) == ownership.Owner(
        "cloudtrail_human", "manual", "user-a"
    )
    assert idx.resolve([("vpc", tagged)]).source == "iac_tag"
    # Only the role name is stored: no session name, no ARN.
    flat = json.dumps(stored)
    assert "session-a" not in flat and "arn:" not in flat
    # The CI patterns are applied when reading, so changing them needs no new Refresh.
    strict = OwnershipConfig(ci_patterns=("build-*",))
    with closing(db_path) as conn:
        idx = ownership.load_index(conn, snap, strict)
    assert idx.resolve([("vpc", by_ci)]).source == "cloudtrail_human"


def test_cloudtrail_is_off_by_default(db_path):
    with mock_aws():
        boto3.client("ec2", region_name=REGION).create_vpc(CidrBlock="10.0.0.0/16")
        calls: list[str] = []
        Collector(_cloudtrail_gateway({}, calls), db_path).run()
    assert calls == []


def test_cloudtrail_denied_is_a_warning(db_path, monkeypatch):
    class Denied:
        def get_paginator(self, _name):
            def paginate(**_kw):
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "Lookup")

            return type("P", (), {"paginate": staticmethod(paginate)})()

    with mock_aws():
        boto3.client("ec2", region_name=REGION).create_vpc(CidrBlock="10.0.0.0/16")
        gw = _gateway()
        real_client = gw.client
        monkeypatch.setattr(
            gw, "client", lambda s, **kw: Denied() if s == "cloudtrail" else real_client(s, **kw)
        )
        result = Collector(gw, db_path, ownership_config=OwnershipConfig(cloudtrail=True)).run()
    assert "cloudtrail:LookupEvents skipped (AccessDenied)" in result.warnings


# -- configurable tag keys (Settings → Ownership) ----------------------------------------------


def test_settings_round_trip(db_path):
    store = SettingsStore(db_path)
    s = store.load()
    assert (s.own_project_key, s.own_env_key, s.own_team_key, s.own_owner_key) == (
        "Project",
        "Environment",
        "Team",
        "Owner",
    )
    assert not s.tf_enrichment and not s.cloudtrail_lookup
    store.save_ownership(
        keys={"project": "repo", "team": "squad", "owner": "", "env": "aws:reserved"},
        ci_patterns="build-*\nDeploy-*",
        tf_enrichment=True,
        cloudtrail_lookup=True,
    )
    s = store.load()
    assert (s.own_project_key, s.own_team_key, s.own_owner_key, s.own_env_key) == (
        "repo",
        "squad",
        "",
        "",  # aws: keys cannot be chosen
    )
    assert s.ci_patterns == ("build-*", "deploy-*")
    assert s.tf_enrichment and s.cloudtrail_lookup
    config = s.ownership_config()
    assert config.project_key == "repo" and config.tf_enabled and config.cloudtrail


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


def _db(app):
    return app.extensions["iplens"]["paths"].db_path


@pytest.fixture
def seeded(app, snapshot_builder):
    b = snapshot_builder(_db(app))
    b.vpc(VPC, "10.0.0.0/16").subnet(SA, VPC, "10.0.1.0/24")
    b.eni("eni-0000000000000001", SA, ["10.0.1.10"], instance_id="i-0example0000001")
    b.eni("eni-0000000000000002", SA, ["10.0.1.20"], instance_id="i-0example0000002")
    b.eni("eni-0000000000000003", SA, ["10.0.1.30"], instance_id="i-0example0000003")
    b.tag("eni", "eni-0000000000000001", "repo", "project-a")
    b.tag("eni", "eni-0000000000000001", "squad", "team-blue")
    b.tag("eni", "eni-0000000000000002", "Project", "project-b")
    return b


def _owners(app, b, config):
    with closing(_db(app)) as conn:
        rows = queries.ip_list(conn, b.id, own=config)
    return {r["eni_id"]: (r["owner"]["source"], r["owner"]["value"], r["own_labels"]) for r in rows}


def test_configured_tag_keys_are_respected(app, client, seeded):
    # Defaults: "Project" is the IaC tag key.
    owners = _owners(app, seeded, SettingsStore(_db(app)).load().ownership_config())
    assert owners["eni-0000000000000001"][:2] == ("", "")
    assert owners["eni-0000000000000002"][:2] == ("iac_tag", "project-b")

    # The Settings dropdowns offer the tag keys seen in the snapshot.
    page = client.get("/settings").data.decode()
    assert 'id="own_project_key"' in page
    assert '<option value="repo"' in page and '<option value="squad"' in page

    _post(
        client,
        "/settings",
        {
            "log_dir": "",
            "own_form": "1",
            "own_project_key": "repo",
            "own_env_key": "",
            "own_team_key": "squad",
            "own_owner_key": "",
            "ci_patterns": "build-*",
        },
    )
    config = SettingsStore(_db(app)).load().ownership_config()
    owners = _owners(app, seeded, config)
    source, value, labels = owners["eni-0000000000000001"]
    assert (source, value) == ("iac_tag", "project-a")
    assert labels["team"] == "team-blue"
    assert owners["eni-0000000000000002"][:2] == ("", "")  # "Project" is no longer the key

    ips = client.get("/ips").data.decode()
    assert "<th>Owner</th>" in ips and "project-a" in ips and "IaC tag" in ips
    filtered = client.get("/ips?own=unmanaged").data.decode()
    assert "10.0.1.20" in filtered and "10.0.1.10" not in filtered

    eni = client.get("/enis/eni-0000000000000001").data.decode()
    assert "Ownership" in eni and "project-a" in eni and "team-blue" in eni

    data = client.get(f"/visual/data.json?vpc={VPC}").get_json()
    nodes = {n["eni_id"]: n for s in data["vpc"]["subnets"] for n in s["items"]}
    assert nodes["eni-0000000000000001"]["owner"]["value"] == "project-a"
    assert nodes["eni-0000000000000001"]["team"] == "team-blue"
    visual = client.get("/visual").data.decode()
    assert 'value="owner"' in visual and 'value="team"' in visual


def test_ownership_page_and_optional_terraform(app, client, seeded):
    with closing(_db(app)) as conn:
        terraform.save_root(
            conn,
            "root-a",
            [
                terraform.TfResource(
                    "aws_network_interface.c",
                    "aws_network_interface",
                    "eni",
                    "eni-0000000000000003",
                )
            ],
        )
    page = client.get("/ownership").data.decode()
    assert "<h1>Ownership</h1>" in page and "By source" in page and "Tag gaps" in page
    assert '<details class="card" id="terraform" >' in page  # collapsed: off by default
    assert client.get("/terraform").status_code == 200  # the former Terraform page URL
    config = SettingsStore(_db(app)).load().ownership_config()
    assert _owners(app, seeded, config)["eni-0000000000000003"][:2] == ("", "")

    _post(client, "/ownership/terraform", {"enabled": "1"})
    page = client.get("/ownership").data.decode()
    assert '<details class="card" id="terraform" open>' in page
    config = SettingsStore(_db(app)).load().ownership_config()
    assert _owners(app, seeded, config)["eni-0000000000000003"][:2] == ("terraform", "root-a")
    # Tags still beat Terraform.
    assert _owners(app, seeded, config)["eni-0000000000000002"][:2] == ("iac_tag", "project-b")
