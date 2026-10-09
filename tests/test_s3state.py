"""Terraform S3 backends read without terraform: backend config parsing (block, file,
extra lines, partial configs, workspace prefixes), the state read via moto, the
assume-role path, the pre-flight (abort on bad / expired credentials), git's no-prompt
environment for the terraform fallback, and the timing of a 30-root sync.

Placeholders only: 10.0.x.x, account 123456789012 (moto's default), example names.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from moto import mock_aws

from iplens import s3state, tfrepo
from iplens.accounts import Account
from iplens.aws import AwsGateway, ReadOnlyViolation, is_read_only_operation
from iplens.db import closing
from iplens.web import create_app
from tests import test_tfrepo
from tests.test_tfrepo import (
    ACCOUNT,
    FAKE_KEY_ID,
    FAKE_SECRET,
    TF,
    FakeGateway,
    FakeRunner,
    _confirm,
    _db,
    _discovered,
    _envs,
    _keys_account,
    _post,
    _sync,
    fake_gateway,
)

repo = test_tfrepo.repo  # the synthetic repository fixture (root "network" is on s3)
BUCKET = "example-tfstate-bucket"  # the fixture's backend block
ROLE = f"arn:aws:iam::{ACCOUNT}:role/example-state-reader"
AGENT_SOCK = "/run/user/1000/example-agent.sock"  # never opened: only passed through


@pytest.fixture
def app(home):
    return create_app(
        home,
        testing=True,
        terraform_bin=TF,
        terraform_runner=FakeRunner(),
        gateway_factory=fake_gateway,
    )


@pytest.fixture
def client(app):
    c = app.test_client()
    c.get("/")
    return c


def _v4(*sids: str) -> bytes:
    return json.dumps(
        {
            "version": 4,
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_subnet",
                    "name": f"s{i}",
                    "instances": [
                        {
                            "attributes": {
                                "id": sid,
                                "arn": f"arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/{sid}",
                                "cidr_block": f"10.0.{i}.0/24",
                                "tags": {"secret": FAKE_SECRET},
                            }
                        }
                    ],
                }
                for i, sid in enumerate(sids)
            ],
        }
    ).encode()


def _bucket(name: str = BUCKET, objects: dict[str, bytes] | None = None):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=name)
    for key, body in (objects or {}).items():
        s3.put_object(Bucket=name, Key=key, Body=body)
    return s3


def _s3_sync(app, **kw):
    """A sync with real (moto-backed) gateways and the app's SecretBox."""
    return _sync(
        app,
        kw.pop("runner", FakeRunner()),
        gateway_factory=kw.pop("gateway_factory", AwsGateway.from_account),
        decrypt=app.extensions["iplens"]["box"].decrypt,
        **kw,
    )


# -- backend config parsing --------------------------------------------------------------------


def test_parse_hcl_reads_only_backend_keys_and_assume_role_blocks():
    body = """
  bucket = "state-bucket-a"
  key    = "network/terraform.tfstate"
  region = "us-east-1"
  encrypt = true
  dynamodb_table = "example-locks"
  assume_role { role_arn = "arn:aws:iam::123456789012:role/example-state-reader" }
"""
    assert s3state.parse_hcl(body) == {
        "bucket": "state-bucket-a",
        "key": "network/terraform.tfstate",
        "region": "us-east-1",
        "role_arn": ROLE,
    }
    assert s3state.parse_hcl('key = "${var.x}"\nprofile = example-profile\n') == {
        "profile": "example-profile"
    }


def test_parse_extra_accepts_key_value_lines_and_names_only_keys_in_errors():
    text = '# from CI\nbucket=state-bucket-a\n\nregion = "eu-west-1"\nworkspace_key_prefix=states\n'
    assert s3state.parse_extra(text) == {
        "bucket": "state-bucket-a",
        "region": "eu-west-1",
        "workspace_key_prefix": "states",
    }
    assert s3state.parse_extra("") == {}
    for bad, msg in [
        ("bucket", "expected key=value"),
        ("dynamodb_table=example-locks", "unknown key dynamodb_table"),
        ("bucket=Not_A_Bucket!", "bucket: not a valid value"),
        ("role_arn=example-not-an-arn-0000", "role_arn: not a valid value"),
        ("key=/absolute.tfstate", "key: must be a relative object key"),
        ("region=", "region needs a value"),
    ]:
        with pytest.raises(ValueError, match=msg) as exc:
            s3state.parse_extra(bad)
        value = bad.partition("=")[2]
        assert not value or value not in str(exc.value)  # never echo a value


def test_resolve_precedence_partial_config_and_workspace_keys():
    cfg = s3state.resolve(
        {"bucket": "state-bucket-a", "key": "a.tfstate"},
        {"key": "b.tfstate"},
        {"workspace_key_prefix": "states/"},
        default_region="eu-west-1",
    )
    assert (cfg.bucket, cfg.key, cfg.region) == ("state-bucket-a", "b.tfstate", "eu-west-1")
    assert cfg.object_key("") == cfg.object_key("default") == "b.tfstate"
    assert cfg.object_key("dev") == "states/dev/b.tfstate"
    partial = s3state.resolve({}, {"key": "b.tfstate"}, {})
    assert partial.missing() == ["bucket"] and partial.object_key("dev") == "env:/dev/b.tfstate"
    assert "state-bucket-a" not in repr(cfg)  # values never reach a log line via repr
    assert s3state.mask("state-bucket-a") == "stat…et-a" and s3state.mask("short") == "…"


def test_s3_backend_of_the_fixture_root_merges_block_file_and_extra(repo):
    root = repo / "network"
    dev = {"backend_config": "backend/dev.tfbackend"}
    cfg = tfrepo.s3_backend(root, dev, {})
    assert (cfg.bucket, cfg.key, cfg.region) == (BUCKET, "network/dev.tfstate", "us-east-1")
    assert cfg.object_key("dev") == "env:/dev/network/dev.tfstate"
    prod = tfrepo.s3_backend(root, {"backend_config": ""}, {"workspace_key_prefix": "ws"})
    assert prod.object_key("prod") == "ws/prod/network/terraform.tfstate"


# -- the state read (moto) ---------------------------------------------------------------------


@mock_aws
def test_s3_state_is_read_without_terraform_and_only_ids_are_kept(app, repo, caplog):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("network", "dev"), acct)
    _bucket(objects={"env:/dev/network/dev.tfstate": _v4("subnet-0000000a", "subnet-0000000b")})
    before = test_tfrepo._tree(repo)
    runner = FakeRunner()
    with caplog.at_level(logging.INFO, logger="iplens"):
        (result,) = _s3_sync(app, runner=runner)
    assert (result.status, result.resources) == (tfrepo.OK, 2)
    assert result.detail == "s3 state" and result.seconds > 0
    assert runner.calls == []  # terraform never ran
    assert test_tfrepo._tree(repo) == before
    env = _envs(app, repo_id)[("network", "dev")]
    assert (env["status"], env["state_account"]) == (tfrepo.OK, ACCOUNT)
    with closing(_db(app)) as conn:
        dump = "\n".join(conn.iterdump())
    assert "subnet-0000000a" in dump
    for value in (BUCKET, "network/dev.tfstate", FAKE_SECRET, "10.0.1.0/24"):
        assert value not in dump and value not in caplog.text
    assert "network [dev]: ok (s3 state) in" in caplog.text  # per-root timing


@mock_aws
def test_mixed_sync_runs_s3_and_terraform_pairs_side_by_side(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    for key in (("network", "dev"), ("services", "dev"), ("apps/envs/staging", "staging")):
        _confirm(app, repo_id, key, acct)
    _bucket(objects={"env:/dev/network/dev.tfstate": _v4("subnet-0000000a")})
    runner = FakeRunner(show=test_tfrepo._state(test_tfrepo._subnet("app", "subnet-0000000e")))
    results = _s3_sync(app, runner=runner)
    assert [r.label for r in results] == ["apps [staging]", "network [dev]", "services [dev]"]
    assert [r.status for r in results] == [tfrepo.OK] * 3
    assert [r.detail for r in results] == ["local state file", "s3 state", ""]
    assert {argv[1] for argv, _kw in runner.calls} == {"init", "workspace", "show"}
    assert all(kw["cwd"].endswith("services") for _argv, kw in runner.calls)


@mock_aws
def test_s3_missing_state_and_bucket_statuses(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("network", "dev"), acct)
    (result,) = _s3_sync(app)  # no bucket at all
    assert result.status == tfrepo.ERROR and "not found" in result.detail
    assert BUCKET not in result.detail and s3state.mask(BUCKET) in result.detail
    _bucket(objects={"env:/dev/network/other.tfstate": _v4()})
    (result,) = _s3_sync(app)
    assert result.status == tfrepo.NO_STATE


class _DeniedClient:
    """An S3 client whose every call is AccessDenied / NoSuchKey."""

    def __init__(self, list_code="AccessDenied", get_code="AccessDenied"):
        self.list_code, self.get_code, self.calls = list_code, get_code, []

    def _raise(self, code, op):
        raise ClientError({"Error": {"Code": code, "Message": "example"}}, op)

    def list_objects_v2(self, **kw):
        self.calls.append("list")
        self._raise(self.list_code, "ListObjectsV2")

    def get_object(self, **kw):
        self.calls.append("get")
        self._raise(self.get_code, "GetObject")


def test_access_denied_and_no_such_key_are_reported_per_root():
    cfg = s3state.S3Backend(bucket="state-bucket-a", key="a.tfstate", region="us-east-1")
    denied = _DeniedClient()
    with pytest.raises(
        s3state.StateUnavailable, match=r"no access to bucket stat…et-a \(account\?\)"
    ):
        s3state.read_state(denied, cfg)
    assert denied.calls == ["list", "get"]  # a denied listing still tries the object
    with pytest.raises(s3state.StateMissing):
        s3state.read_state(_DeniedClient(get_code="NoSuchKey"), cfg)


def test_access_denied_status_through_the_sync(app, repo, monkeypatch):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("network", "dev"), acct)
    monkeypatch.setattr(s3state.Clients, "s3", lambda self, account, cfg: _DeniedClient())
    (result,) = _sync(app, FakeRunner())
    assert result.status == tfrepo.ERROR
    assert result.detail == f"no access to bucket {s3state.mask(BUCKET)} (account?)"
    assert _envs(app, repo_id)[("network", "dev")]["status_detail"] == result.detail


@mock_aws
def test_assume_role_path_reads_the_state_with_the_role_session(app, tmp_path, monkeypatch):
    root = tmp_path / "infra" / "edge"
    (root / "backend").mkdir(parents=True)
    (root / "main.tf").write_text(
        'terraform {\n  backend "s3" {\n    bucket = "state-bucket-a"\n'
        f'    key = "edge/terraform.tfstate"\n    role_arn = "{ROLE}"\n  }}\n}}\n'
        'provider "aws" { region = "us-east-1" }\n'
    )
    _bucket("state-bucket-a", {"edge/terraform.tfstate": _v4("subnet-0000000c")})
    assumed: list[tuple[str, AwsGateway]] = []
    original = AwsGateway.assume_role

    def spy(self, role_arn, *a, **kw):
        gw = original(self, role_arn, *a, **kw)
        assumed.append((role_arn, gw))
        return gw

    monkeypatch.setattr(AwsGateway, "assume_role", spy)
    acct = _keys_account(app)
    repo_id = _discovered(app, root.parent)
    _confirm(app, repo_id, ("edge", "default"), acct)
    (result,) = _s3_sync(app)
    assert (result.status, result.resources) == (tfrepo.OK, 1)
    ((role, gw),) = assumed  # once, for the state read
    assert role == ROLE
    creds = gw.session.get_credentials()
    assert creds.access_key != FAKE_KEY_ID and creds.token  # temporary role credentials


def test_read_only_allowlist_adds_only_the_state_read_calls():
    for service, op in [
        ("sts", "AssumeRole"),
        ("sts", "GetCallerIdentity"),
        ("s3", "GetObject"),
        ("s3", "ListObjectsV2"),
    ]:
        assert is_read_only_operation(service, op)
    for service, op in [
        ("s3", "PutObject"),
        ("s3", "DeleteObject"),
        ("s3", "CopyObject"),
        ("sts", "AssumeRoleWithWebIdentity"),
        ("sts", "GetSessionToken"),
        ("dynamodb", "PutItem"),
    ]:
        assert not is_read_only_operation(service, op)


@mock_aws
def test_state_bucket_cannot_be_written_through_the_gateway():
    _bucket("state-bucket-a")
    acct = Account(id=1, auth_mode="keys", access_key_id=FAKE_KEY_ID, secret_access_key="x" * 40)
    client = s3state.Clients().s3(
        acct, s3state.S3Backend(bucket="state-bucket-a", region="us-east-1")
    )
    with pytest.raises(ReadOnlyViolation):
        client.put_object(Bucket="state-bucket-a", Key="a.tfstate", Body=b"{}")


# -- extra backend-config (web) ----------------------------------------------------------------


@mock_aws
def test_extra_backend_config_completes_a_partial_config_and_is_stored_encrypted(
    app, client, tmp_path
):
    root = tmp_path / "infra" / "edge"
    (root / "envs").mkdir(parents=True)
    (root / "backend").mkdir()
    (root / "main.tf").write_text(
        'terraform {\n  backend "s3" {}\n}\nprovider "aws" { region = var.region }\n'
        'locals { env = terraform.workspace }\nvariable "region" {}\n'
    )
    (root / "envs/dev.tfvars").write_text(f'region = "us-east-1"\naccount_id = "{ACCOUNT}"\n')
    (root / "backend/dev.tfbackend").write_text(
        'key = "edge/terraform.tfstate"\nworkspace_key_prefix = "states"\n'
    )
    _bucket("state-bucket-a", {"states/dev/edge/terraform.tfstate": _v4("subnet-0000000d")})
    acct = _keys_account(app)
    repo_id = _discovered(app, root.parent)
    dev = _envs(app, repo_id)[("edge", "dev")]
    _confirm(app, repo_id, ("edge", "dev"), acct)
    (result,) = _s3_sync(app)
    assert result.status == tfrepo.ERROR and "no bucket" in result.detail  # partial config

    url = f"/settings/tfrepos/{repo_id}"
    bad = _post(client, url, {f"extra_{dev['id']}": "bucket=Bad_Bucket!"}, follow_redirects=True)
    assert "Extra backend-config not saved: bucket: not a valid value" in bad.data.decode()
    _post(
        client,
        url,
        {f"account_{dev['id']}": str(acct), f"extra_{dev['id']}": "bucket=state-bucket-a\n"},
    )
    row = _envs(app, repo_id)[("edge", "dev")]
    assert row["backend_extra_keys"] == "bucket" and row["backend_extra_enc"]
    with closing(_db(app)) as conn:
        dump = "\n".join(conn.iterdump())
    assert "state-bucket-a" not in dump
    page = client.get(url).data.decode()
    assert "set: bucket" in page and "state-bucket-a\n" not in page
    assert 'name="extra_' in page and ">state-bucket-a<" not in page

    (result,) = _s3_sync(app)
    assert (result.status, result.resources) == (tfrepo.OK, 1)
    # an empty textarea keeps the values; "clear" drops them
    _post(client, url, {f"account_{dev['id']}": str(acct), f"extra_{dev['id']}": ""})
    assert _envs(app, repo_id)[("edge", "dev")]["backend_extra_keys"] == "bucket"
    _post(client, url, {f"account_{dev['id']}": str(acct), f"extra_clear_{dev['id']}": "1"})
    cleared = _envs(app, repo_id)[("edge", "dev")]
    assert (cleared["backend_extra_keys"], cleared["backend_extra_enc"]) == ("", "")


# -- pre-flight --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error, reason",
    [
        (ClientError({"Error": {"Code": "ExpiredToken"}}, "GetCallerIdentity"), "expired"),
        (ClientError({"Error": {"Code": "InvalidClientTokenId"}}, "GetCallerIdentity"), "invalid"),
    ],
)
def test_preflight_aborts_the_whole_sync_on_bad_credentials(app, repo, error, reason):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    for key in (("network", "dev"), ("services", "dev"), ("apps/envs/staging", "staging")):
        _confirm(app, repo_id, key, acct)
    runner = FakeRunner()
    t0 = time.monotonic()
    with pytest.raises(tfrepo.SyncAborted, match=reason) as exc:
        _sync(app, runner, gateway_factory=lambda _a: FakeGateway(error=error))
    assert time.monotonic() - t0 < 5
    assert exc.value.account_ref == acct
    assert runner.calls == []  # nothing ran: no terraform, no S3 read
    envs = _envs(app, repo_id)
    assert {e["status"] for e in envs.values() if e["confirmed"]} == {tfrepo.ERROR}
    assert all("aborted" in e["status_detail"] for e in envs.values() if e["confirmed"])
    assert FAKE_SECRET not in str(exc.value) and FAKE_KEY_ID not in str(exc.value)


def test_preflight_aborts_on_expired_temporary_credentials_without_calling_aws(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("network", "dev"), acct)
    expired = Account(
        id=acct,
        display_name="env-dev",
        auth_mode="temporary",
        access_key_id="ASIAEXAMPLE000000000",
        secret_access_key=FAKE_SECRET,
        session_token="example-not-a-real-token",
        expires_at=datetime(2000, 1, 1, tzinfo=UTC),
    )
    paths = app.extensions["iplens"]["paths"]
    called = []
    with pytest.raises(tfrepo.SyncAborted, match="env-dev .*expired"):
        tfrepo.sync(
            paths.db_path,
            lambda _ref: expired,
            cache_dir=paths.tf_cache_dir,
            terraform_bin=TF,
            runner=FakeRunner(),
            gateway_factory=lambda a: called.append(a) or FakeGateway(),
        )
    assert called == []  # no AWS call with credentials known to be expired


def test_preflight_unreachable_account_skips_its_pairs_only(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("services", "dev"), acct)
    _confirm(app, repo_id, ("apps/envs/staging", "staging"), acct)  # local: no AWS needed
    error = EndpointConnectionError(endpoint_url="https://sts.example.invalid")
    runner = FakeRunner()
    results = _sync(app, runner, gateway_factory=lambda _a: FakeGateway(error=error))
    by_label = {r.label: r for r in results}
    assert by_label["services [dev]"].status == tfrepo.ERROR
    assert by_label["services [dev]"].detail.startswith("pre-flight: AWS not reachable")
    assert by_label["apps [staging]"].status == tfrepo.OK
    assert runner.calls == []


def test_web_sync_job_reports_the_abort(app, client, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("services", "dev"), acct)
    error = ClientError({"Error": {"Code": "ExpiredToken"}}, "GetCallerIdentity")
    app.extensions["iplens"]["gateway_factory"] = lambda _a: FakeGateway(error=error)
    _post(client, "/accounts/active", {"account_id": str(acct)})
    page = _post(
        client, "/terraform/sync", {"next": "/terraform"}, follow_redirects=True
    ).data.decode()
    assert "Terraform sync aborted" in page and "invalid or expired" in page
    assert f"/accounts/{acct}/edit" in page  # a link to fix the account
    assert FAKE_SECRET not in page


# -- terraform fallback: git never prompts ----------------------------------------------------


class _RecordingPopen:
    """A terraform process that exits at once; records how it was spawned."""

    spawns: list[dict] = []

    def __init__(self, args, **kw):
        self.args, self.kw, self.returncode, self.pid = list(args), kw, 0, 0
        _RecordingPopen.spawns.append(kw)

    def communicate(self, timeout=None):
        out = b'{"format_version": "1.0"}' if self.args[1] == "show" else b""
        return out, b""

    def poll(self):
        return self.returncode


@pytest.mark.parametrize("user_ssh", ["ssh -i /home/example/.ssh/id_example", None])
def test_git_module_fetch_cannot_prompt(app, repo, monkeypatch, user_ssh):
    import functools

    monkeypatch.setenv("GIT_ASKPASS", "/usr/libexec/example-askpass")
    monkeypatch.setenv("SSH_ASKPASS", "/usr/libexec/example-ssh-askpass")
    monkeypatch.setenv("SSH_AUTH_SOCK", AGENT_SOCK)
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "1")
    if user_ssh:
        monkeypatch.setenv("GIT_SSH_COMMAND", user_ssh)
    else:
        monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("services", "dev"), acct)
    _RecordingPopen.spawns = []
    runner = functools.partial(tfrepo.run_process, popen=_RecordingPopen)
    (result,) = _sync(app, runner)
    assert result.status == tfrepo.NO_STATE
    assert len(_RecordingPopen.spawns) == 3  # init, workspace select, show
    for kw in _RecordingPopen.spawns:
        env = kw["env"]
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert "GIT_ASKPASS" not in env and "SSH_ASKPASS" not in env
        assert env["SSH_AUTH_SOCK"] == AGENT_SOCK
        assert env["GIT_SSH_COMMAND"] == (user_ssh or "ssh -o BatchMode=yes -o ConnectTimeout=10")
        assert kw["shell"] is False and kw["stdin"] is not None


def test_terraform_timeout_default_is_120_seconds():
    from iplens.settings import DEFAULT_TF_TIMEOUT

    assert tfrepo.DEFAULT_TIMEOUT == 120.0 and DEFAULT_TF_TIMEOUT == 120


# -- timing ------------------------------------------------------------------------------------

ROOTS = 30


@mock_aws
def test_thirty_s3_roots_sync_well_under_a_minute(app, tmp_path, caplog):
    infra = tmp_path / "infra"
    objects = {}
    for i in range(ROOTS):
        root = infra / f"stack{i:02d}"
        root.mkdir(parents=True)
        (root / "main.tf").write_text(
            'terraform {\n  backend "s3" {\n    bucket = "state-bucket-a"\n'
            f'    key = "stack{i:02d}/terraform.tfstate"\n    region = "us-east-1"\n  }}\n}}\n'
            'provider "aws" { region = "us-east-1" }\n'
        )
        objects[f"stack{i:02d}/terraform.tfstate"] = _v4(f"subnet-{i:08x}")
    _bucket("state-bucket-a", objects)
    acct = _keys_account(app)
    repo_id = _discovered(app, infra)
    with closing(_db(app)) as conn:
        envs = tfrepo.list_envs(conn, repo_id=repo_id)
        tfrepo.save_mapping(conn, repo_id, {e["id"]: acct for e in envs})
    assert len(envs) == ROOTS
    runner = FakeRunner()
    t0 = time.monotonic()
    with caplog.at_level(logging.INFO, logger="iplens"):
        results = _s3_sync(app, runner=runner)
    elapsed = time.monotonic() - t0
    assert [r.status for r in results] == [tfrepo.OK] * ROOTS and runner.calls == []
    assert elapsed < 60
    print(
        f"\n{ROOTS} s3 roots synced in {elapsed:.2f}s "
        f"(slowest pair {max(r.seconds for r in results):.2f}s)"
    )
    assert f"terraform sync finished: {ROOTS} pair(s) ({ROOTS} s3, 0 terraform)" in caplog.text
