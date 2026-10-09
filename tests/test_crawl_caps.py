"""Extended crawl: a source that hits its per-source cap leaves a snapshot-level warning
and a "capped" badge on the Extended view. Placeholder data only (10.0.x.x, queue-NN)."""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from iplens import extended
from iplens.aws import AwsGateway
from iplens.db import closing
from iplens.extended import CAPPED_SUFFIX, ExtendedCrawler, latest_crawl
from iplens.web import create_app

REGION = "us-east-1"
VPC = "vpc-0example0000001"
SUBNET = "subnet-0000000a"


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


def _db(app):
    return app.extensions["iplens"]["paths"].db_path


def _crawl(app, snapshot_builder, queues: int, cap: int, monkeypatch) -> ExtendedCrawler:
    monkeypatch.setattr(extended, "MAX_PER_SOURCE", cap)
    sqs = boto3.client("sqs", region_name=REGION)
    for i in range(queues):
        sqs.create_queue(QueueName=f"queue-{i:02d}")
    b = snapshot_builder(_db(app))
    b.vpc(VPC, "10.0.0.0/17").subnet(SUBNET, VPC, "10.0.1.0/24")
    crawler = ExtendedCrawler(AwsGateway(boto3.session.Session(region_name=REGION)), _db(app), b.id)
    crawler.run()
    return crawler


def _capped(crawler: ExtendedCrawler) -> list[str]:
    return [w for w in crawler.result.warnings if w.endswith(CAPPED_SUFFIX)]


@mock_aws
def test_source_over_its_cap_warns_with_name_and_count_and_badges_the_view(
    app, snapshot_builder, monkeypatch
):
    crawler = _crawl(app, snapshot_builder, queues=5, cap=3, monkeypatch=monkeypatch)
    assert _capped(crawler) == ["SQS queues: showing first 3 of more"]
    assert crawler.result.sources["sqs:ListQueues"] == 3
    with closing(_db(app)) as conn:
        nodes = conn.execute("SELECT COUNT(*) FROM ext_nodes WHERE service='sqs'").fetchone()[0]
        crawl = latest_crawl(conn, crawler.snapshot_id)
    assert nodes == 3
    assert crawl is not None and crawl["capped"] == ["SQS queues: showing first 3 of more"]

    client = app.test_client()
    page = client.get(f"/visual?vpc={VPC}&view=extended").data.decode()
    assert 'id="crawl-capped"' in page and "1 capped" in page
    assert "SQS queues: showing first 3 of more" in page
    assert "1 source(s) capped" in page


@mock_aws
def test_source_at_or_below_its_cap_has_no_warning_or_badge(app, snapshot_builder, monkeypatch):
    crawler = _crawl(app, snapshot_builder, queues=3, cap=3, monkeypatch=monkeypatch)
    assert _capped(crawler) == []
    assert crawler.result.sources["sqs:ListQueues"] == 3
    page = app.test_client().get(f"/visual?vpc={VPC}&view=extended").data.decode()
    assert 'id="crawl-capped"' not in page and "capped" not in page


def test_cap_helper_describes_each_bounded_list():
    crawler = ExtendedCrawler.__new__(ExtendedCrawler)
    crawler.result = extended.CrawlResult(1)
    assert crawler._cap("MSK (Kafka) clusters", list(range(4)), 4) == [0, 1, 2, 3]
    assert crawler._cap("Resource Explorer resources", list(range(5)), 4) == [0, 1, 2, 3]
    assert crawler._cap("AWS Config resource histories", ["a", "b"], 1) == ["a"]
    assert crawler.result.warnings == [
        "Resource Explorer resources: showing first 4 of more",
        "AWS Config resource histories: showing first 1 of more",
    ]
