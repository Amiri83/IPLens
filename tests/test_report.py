"""Self-contained HTML report and identifier redaction.

Synthetic data only: 10.0.x.x addresses, account 123456789012, example names.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest

from iplens import report
from iplens.db import closing
from iplens.rules import Rule, save_rule
from iplens.web import create_app

ACCOUNT = "123456789012"
ARN = f"arn:aws:iam::{ACCOUNT}:role/example-role"
VPC = "vpc-0example0000001"
SA, SB, SF = "subnet-0000000a", "subnet-0000000b", "subnet-000000ff"
SECTIONS = ("summary", "consumers", "trend", "suggestions", "headroom", "ownership")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


def _db(app):
    return app.extensions["iplens"]["paths"].db_path


def _seed(app, snapshot_builder, ips, days=(3, 2, 1, 0)):
    """A small history; the latest snapshot has an almost full subnet, an allowed and a
    rule-blocked detached ENI (whose description carries an ARN) and two environments."""
    now = datetime.now(UTC)
    b = None
    for i, ago in enumerate(days):
        b = snapshot_builder(_db(app), taken_at=now - timedelta(days=ago), account_alias="example")
        b.vpc(VPC, "10.0.0.0/16", name="example-vpc")
        b.subnet(SA, VPC, "10.0.1.0/24", az="us-east-1a", name="example-app")
        b.subnet(SB, VPC, "10.0.2.0/24", az="us-east-1b", name="example-data")
        b.subnet(SF, VPC, "10.0.3.0/28", az="us-east-1a", name="example-small")
        b.eni("eni-00000000a1", SA, ips("10.0.1.0", 10, 20 + 5 * i), owner_ref="i-0example0001")
        b.eni("eni-00000000b1", SB, ips("10.0.2.0", 10, 8), owner_ref="i-0example0002")
        b.eni("eni-00000000f1", SF, ips("10.0.3.0", 4, 10), name="ip-10-0-3-4.ec2.internal")
    b.eni(
        "eni-00000000d1",
        SB,
        ["10.0.2.200", "10.0.2.201"],
        status="available",
        owner_type="other",
        description=f"example keep {ARN}",
    )
    b.eni(
        "eni-00000000d2",
        SB,
        ["10.0.2.210", "10.0.2.211", "10.0.2.212"],
        status="available",
        owner_type="other",
        description="example scratch",
    )
    b.tag("subnet", SA, "Environment", "prod").tag("subnet", SF, "Environment", "prod")
    b.tag("subnet", SB, "Environment", "dev")
    b.tag("eni", "eni-00000000a1", "Project", "example-project")
    with closing(_db(app)) as conn:
        save_rule(conn, Rule(name="keep", kind="protected_eni", params={"pattern": "keep"}))
    return b


def _section(page: str, name: str) -> str:
    m = re.search(rf'<section id="{name}".*?</section>', page, re.S)
    assert m, f"section {name} missing"
    return m.group(0)


def test_report_has_every_section_and_is_self_contained(app, snapshot_builder, ips):
    _seed(app, snapshot_builder, ips)
    resp = app.test_client().get("/report")
    assert resp.status_code == 200
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
    page = resp.data.decode()
    for name in SECTIONS:
        _section(page, name)
    # Self-contained: inline CSS and SVG only.
    assert "<style>" in page and "<script" not in page
    assert not re.search(r"\b(?:href|src)=", page)
    assert "http://" not in page.replace("http://www.w3.org", "")
    summary = _section(page, "summary")
    assert SF in summary and "10.0.3.0/28" in summary  # 10 of 11 usable IPs used
    assert "full now" in summary or "full in" in summary or "stable/declining" in summary
    consumers = _section(page, "consumers")
    assert "IaC tag: example-project" in consumers and "prod" in consumers and "dev" in consumers
    assert 'class="trend-line"' in _section(page, "trend")
    sugg = _section(page, "suggestions")
    allowed, blocked = sugg.split('id="suggestions-blocked"')
    assert "eni-00000000d2" in allowed and "eni-00000000d1" not in allowed
    assert "eni-00000000d1" in blocked and "keep" in blocked
    assert ">3<" in allowed.replace("<b>", "").replace("</b>", "")  # IPs saved
    headroom = _section(page, "headroom")
    assert "Secondary CIDR recommendation" in headroom
    assert "aws_vpc_ipv4_cidr_block_association" in headroom
    own = _section(page, "ownership")
    assert "Unmanaged" in own and "IaC tag" in own


def test_report_download_header(app, snapshot_builder, ips):
    _seed(app, snapshot_builder, ips)
    resp = app.test_client().get("/report?download=1&redact=1")
    assert "attachment" in resp.headers["Content-Disposition"]
    assert "-redacted.html" in resp.headers["Content-Disposition"]


def test_environment_filter_limits_the_report(app, snapshot_builder, ips):
    _seed(app, snapshot_builder, ips)
    page = app.test_client().get("/report?env=prod").data.decode()
    assert "environment <span" in page
    summary = _section(page, "summary")
    assert SF in summary
    consumers = _section(page, "consumers")
    assert ">dev<" not in consumers and ">prod<" in consumers
    sugg = _section(page, "suggestions")
    # The detached ENIs live in the dev subnet.
    assert "eni-00000000d1" not in sugg and "eni-00000000d2" not in sugg
    dev = app.test_client().get("/report?env=dev").data.decode()
    assert SF not in _section(dev, "summary") and "eni-00000000d2" in _section(dev, "suggestions")


def test_redacted_report_has_no_raw_identifiers(app, snapshot_builder, ips):
    b = _seed(app, snapshot_builder, ips)
    client = app.test_client()
    plain = client.get("/report").data.decode()
    assert ACCOUNT in plain and "10.0.3.0/28" in plain and ARN in plain
    page = client.get("/report?redact=1").data.decode()
    for name in SECTIONS:
        _section(page, name)
    assert ACCOUNT not in page
    assert "arn:aws" not in page
    assert "ip-10-0-3-4" not in page
    for raw in (VPC, SA, SB, SF, "eni-00000000d1", "eni-00000000d2", "i-0example0001"):
        assert raw not in page
    assert "example (" not in page  # the account alias label
    # Every dotted address left is a well-known range quoted by the CIDR planner.
    for m in IPV4.finditer(page):
        assert m.group(0) in report.WELL_KNOWN_CIDRS, m.group(0)
    with closing(_db(app)) as conn:
        cidrs = [
            r["cidr"] for r in conn.execute("SELECT cidr FROM subnets WHERE snapshot_id=?", (b.id,))
        ]
        addrs = [r["ip"] for r in conn.execute("SELECT ip FROM ips WHERE snapshot_id=?", (b.id,))]
    for raw in [*cidrs, *addrs, "10.0.0.0/16"]:
        assert raw not in page
    # Nor spelled another way (the Terraform label of the recommendation, host names).
    assert not re.search(r"(?<!\d)10[_-]\d{1,3}[_-]\d", page)
    assert "&#34;secondary&#34;" in _section(page, "headroom")
    # Placeholders are consistent: the same request gives the same document, and the
    # VPC appears under one placeholder in the headroom title and its Terraform snippet.
    assert client.get("/report?redact=1").data.decode() == page
    red = report.Redactor(report.redaction_key(app.secret_key))
    assert red.redact(SF).startswith("[subnet:") and red.redact(SF) in _section(page, "summary")
    vpc_token = red.redact(VPC)
    assert _section(page, "headroom").count(vpc_token) == 2
    # Section content survives redaction.
    assert "IaC tag: example-project" in page and 'class="trend-line"' in page


def test_redactor_patterns_and_consistency():
    red = report.Redactor(b"\x00" * 32)
    text = (
        f"acct {ACCOUNT} role {ARN}, host ip-10-0-1-5.ec2.internal ip 10.0.1.5 "
        f"net 10.0.1.0/24 {VPC} sg-0001 eni-00000000a1 tgw-attach-0example1 "
        "keep 100.64.0.0/10 10.0.0.0/8 nat-gateway 2026-01-31 1.2.3 "
        f"&#39;{ARN}&#39; secondary_10_0_1_5_16"
    )
    out = red.redact(text)
    for raw in (ACCOUNT, "arn:aws", "10.0.1.5", "10.0.1.0/24", VPC, "sg-0001", "eni-00000000a1"):
        assert raw not in out
    # An ARN ends at an escaped quote; an address spelled with underscores is caught too.
    assert "]&#39;" in out and "10_0_1_5" not in out
    assert "tgw-attach-0example1" not in out and "[tgw-attach:" in out
    # The host name and the dotted address map to the same placeholder.
    ip_token = red.token("ip", "10.0.1.5")
    assert out.count(ip_token) == 3
    assert red.token("ip", "10.0.1.0") + "/24" in out
    # Well-known ranges and plain words / dates stay.
    for keep in ("100.64.0.0/10", "10.0.0.0/8", "nat-gateway", "2026-01-31", "1.2.3"):
        assert keep in out
    assert red.redact(text) == out  # deterministic
    assert report.Redactor(b"\x01" * 32).redact(text) != out  # keyed


def test_report_without_data(app):
    assert app.test_client().get("/report").status_code == 404


def test_discovery_has_report_form(app, snapshot_builder, ips):
    _seed(app, snapshot_builder, ips)
    page = app.test_client().get("/").data.decode()
    assert 'action="/report"' in page and 'name="redact"' in page
    assert '<option value="prod">prod</option>' in page
