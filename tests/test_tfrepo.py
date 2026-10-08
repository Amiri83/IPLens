"""Terraform repos: discovery on a fixture repo, the command allowlist, the sync
(with a fake runner — terraform is never executed here), mapping storage and drift.

Placeholders only: 10.0.x.x, accounts 123456789012 / 111111111111, example names. The
"secrets" are fake strings used to prove that nothing but ids / names is kept or logged.
"""

import json
import logging
import subprocess
from pathlib import Path

import pytest

from iplens import terraform, tfrepo
from iplens.accounts import Account
from iplens.db import closing
from iplens.web import create_app

FAKE_SECRET = "example-not-a-real-secret-0000"
FAKE_KEY_ID = "AKIAEXAMPLE000000000"
ACCOUNT = "123456789012"
OTHER_ACCOUNT = "111111111111"

FILES = {
    # s3 backend, tfvars environments under envs/, workspace-per-env (terraform.workspace)
    "network/main.tf": """
terraform {
  # backend "local" {}  <- a comment, not the backend
  backend "s3" {
    bucket = "example-tfstate-bucket"
    key    = "network/terraform.tfstate"
    region = "us-east-1"
  }
}
provider "aws" {
  region = var.region
  assume_role { role_arn = var.role_arn }
}
locals { env = terraform.workspace } // workspace-per-environment
variable "region" {}
variable "db_password" { sensitive = true }
""",
    "network/envs/dev.tfvars": (
        f'region = "us-east-1"\naccount_id = "{ACCOUNT}"\ndb_password = "{FAKE_SECRET}"\n'
    ),
    "network/envs/prod.tfvars": (
        f'region = "eu-west-1"\nrole_arn = "arn:aws:iam::{OTHER_ACCOUNT}:role/example-deploy"\n'
    ),
    "network/backend/dev.tfbackend": 'key = "network/dev.tfstate"\n',
    "network/.terraform.lock.hcl": "# lock file\n",
    "network/subnets.tf": 'resource "aws_subnet" "app" { cidr_block = "10.0.1.0/24" }\n',
    # Terraform Cloud with tags: one workspace per tfvars environment
    "platform/main.tf": """
terraform {
  cloud {
    organization = "example-org"
    workspaces { tags = ["platform"] }
  }
}
provider "aws" { region = "us-east-1" }
""",
    "platform/dev.tfvars": f'aws_account_id = "{ACCOUNT}"\n',
    "platform/prod.tfvars": f'aws_account_id = "{OTHER_ACCOUNT}"\n',
    "platform/terraform.tfvars": 'tags_owner = "example-team"\n',
    # env sub-folders: apps/envs/<env> are environments of root "apps"
    "apps/envs/dev/main.tf": """
terraform {
  cloud {
    organization = "example-org"
    workspaces { name = "apps-dev" }
  }
}
""",
    "apps/envs/staging/main.tf": f"""
provider "aws" {{
  region              = "us-east-1"
  allowed_account_ids = ["{ACCOUNT}"]
}}
""",
    # local backend with CLI workspaces
    "legacy/main.tf": 'provider "aws" { region = "us-east-1" }\n',
    "legacy/terraform.tfstate.d/blue/terraform.tfstate": "{}",
    "legacy/terraform.tfstate.d/green/terraform.tfstate": "{}",
    # not roots: a module (even with a provider block), a hidden dir, a commented backend
    "modules/vpc/main.tf": 'provider "aws" { region = "us-east-1" }\n',
    ".terraform/modules/x/main.tf": 'terraform {\n  backend "s3" {}\n}\n',
    "scripts/notes.tf": '# terraform { backend "s3" {} }\nlocals { a = 1 }\n',
}


def _state(*resources):
    return {
        "format_version": "1.0",
        "values": {"root_module": {"resources": list(resources)}},
    }


def _subnet(name, sid):
    return {
        "address": f"aws_subnet.{name}",
        "mode": "managed",
        "type": "aws_subnet",
        "values": {"id": sid, "cidr_block": "10.0.1.0/24", "tags": {"secret": FAKE_SECRET}},
    }


@pytest.fixture
def repo(tmp_path) -> Path:
    root = tmp_path / "infra-repo"
    for rel, text in FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    local_state = {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "type": "aws_subnet",
                "name": "a",
                "instances": [{"attributes": {"id": "subnet-0000000c"}}],
            }
        ],
    }
    (root / "apps/envs/staging/terraform.tfstate").write_text(json.dumps(local_state))
    return root


def _tree(path: Path) -> dict[str, tuple[int, int]]:
    return {
        str(p.relative_to(path)): (p.stat().st_mtime_ns, p.stat().st_size)
        for p in sorted(path.rglob("*"))
    }


def _by_rel(roots):
    return {r.rel: r for r in roots}


def _env(root, name):
    return next(e for e in root.envs if e.env == name)


# -- discovery ------------------------------------------------------------------------------


def test_discovery_finds_roots_and_skips_modules_and_hidden_dirs(repo):
    roots = _by_rel(tfrepo.discover(repo))
    assert set(roots) == {"network", "platform", "apps/envs/dev", "apps/envs/staging", "legacy"}


def test_discovery_reads_backend_and_tfvars_envs(repo):
    net = _by_rel(tfrepo.discover(repo))["network"]
    assert net.backend == "s3"
    assert [e.env for e in net.envs] == ["dev", "prod"]
    dev, prod = _env(net, "dev"), _env(net, "prod")
    assert dev.kinds == {"tfvars", "workspace"}
    assert dev.var_file == "envs/dev.tfvars"
    assert dev.workspace == "dev"
    assert dev.backend_config == "backend/dev.tfbackend"
    assert (dev.account, dev.region) == (ACCOUNT, "us-east-1")
    assert (prod.account, prod.region) == (OTHER_ACCOUNT, "eu-west-1")
    assert prod.backend_config == ""


def test_discovery_terraform_cloud_workspaces(repo):
    roots = _by_rel(tfrepo.discover(repo))
    platform = roots["platform"]
    assert platform.backend == "cloud"
    assert {e.env: e.workspace for e in platform.envs} == {"dev": "dev", "prod": "prod"}
    assert _env(platform, "dev").account == ACCOUNT
    assert _env(platform, "prod").account == OTHER_ACCOUNT
    assert _env(platform, "dev").region == "us-east-1"  # from the provider block
    # a pinned workspace name needs no "workspace select"
    pinned = roots["apps/envs/dev"]
    assert (pinned.backend, pinned.label) == ("cloud", "apps")
    assert [(e.env, e.workspace, e.kinds) for e in pinned.envs] == [("dev", "", {"dir"})]


def test_discovery_env_folders_and_local_workspaces(repo):
    roots = _by_rel(tfrepo.discover(repo))
    staging = roots["apps/envs/staging"]
    assert (staging.label, staging.backend) == ("apps", "local")
    assert [(e.env, e.account, e.region) for e in staging.envs] == [
        ("staging", ACCOUNT, "us-east-1")
    ]
    legacy = roots["legacy"]
    assert {e.env: e.workspace for e in legacy.envs} == {"blue": "blue", "green": "green"}
    assert all(e.kinds == {"workspace"} for e in legacy.envs)


def test_discovery_is_pure_file_parsing(repo, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("discovery must not run any process")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    before = _tree(repo)
    roots = tfrepo.discover(repo)
    assert _tree(repo) == before  # the repository is untouched
    assert FAKE_SECRET not in repr(roots)  # tfvars values are never kept


def test_discovery_rejects_missing_dir(tmp_path):
    with pytest.raises(ValueError, match="not a directory"):
        tfrepo.discover(tmp_path / "missing")


def test_suggest_account_by_aws_id_then_name():
    accounts = [
        Account(id=1, display_name="root-a", aws_account_id=ACCOUNT, region="eu-west-1"),
        Account(id=2, display_name="root-b", aws_account_id=ACCOUNT, region="us-east-1"),
        Account(id=3, display_name="env-prod"),
    ]
    env = tfrepo.EnvInfo("dev", account=ACCOUNT, region="us-east-1")
    assert tfrepo.suggest_account(env, accounts) == 2
    assert tfrepo.suggest_account(tfrepo.EnvInfo("prod"), accounts) == 3
    assert tfrepo.suggest_account(tfrepo.EnvInfo("qa"), accounts) is None


# -- the allowlist --------------------------------------------------------------------------

TF = "/opt/example/bin/terraform"
INIT = [TF, "init", "-input=false", "-lockfile=readonly"]


@pytest.mark.parametrize(
    "argv",
    [
        INIT,
        [*INIT, "-backend-config=backend/dev.tfbackend"],
        [*INIT, "-backend-config=env.hcl"],
        [TF, "workspace", "select", "dev"],
        [TF, "workspace", "select", "example_ws-1.a"],
        [TF, "show", "-json"],
    ],
)
def test_allowlist_accepts_only_the_read_only_invocations(argv):
    assert tfrepo.check_allowlisted(argv, TF) == argv


@pytest.mark.parametrize(
    "argv",
    [
        [TF, "plan"],
        [TF, "plan", "-out=example.tfplan"],
        [TF, "apply"],
        [TF, "apply", "-auto-approve"],
        [TF, "import", "aws_subnet.app", "subnet-0000000a"],
        [TF, "destroy"],
        [TF, "destroy", "-auto-approve"],
        [TF, "refresh"],
        [TF, "taint", "aws_subnet.app"],
        [TF, "untaint", "aws_subnet.app"],
        [TF, "force-unlock", "0000"],
        [TF, "state", "rm", "aws_subnet.app"],
        [TF, "state", "push", "x.tfstate"],
        [TF, "state", "pull"],
        [TF, "console"],
        [TF, "output", "-json"],
        [TF, "get"],
        [TF, "init"],
        [TF, "init", "-input=false"],
        [TF, "init", "-upgrade"],
        [*INIT, "-upgrade"],
        [*INIT, "-reconfigure"],
        [*INIT, "-migrate-state"],
        [TF, "init", "-lockfile=readonly", "-input=false"],  # order is exact too
        [*INIT, "-backend-config=../outside.hcl"],
        [*INIT, "-backend-config=a/../../outside.hcl"],
        [*INIT, "-backend-config=/etc/example.hcl"],
        [*INIT, "-backend-config=bucket=example-bucket"],
        [*INIT, "-backend-config=-x.hcl"],
        [TF, "show"],
        [TF, "show", "-json", "example.tfplan"],
        [TF, "show", "-json", ";", "rm", "-rf", "/"],
        [TF, "show", "-json && rm -rf /"],
        [TF, "workspace", "new", "dev"],
        [TF, "workspace", "delete", "dev"],
        [TF, "workspace", "select", "-or-create", "dev"],
        [TF, "workspace", "select", "-dev"],
        [TF, "workspace", "select", "../dev"],
        [TF, "workspace", "select", "dev; rm -rf /"],
        [TF, "-chdir=/tmp", "show", "-json"],
        [TF],
        [],
        ["terraform", "show", "-json"],  # relative binary
        ["/bin/sh", "-c", "terraform show -json"],
        ["/opt/example/bin/tofu", "show", "-json"],
        [TF, "show", 1],
    ],
)
def test_allowlist_rejects_everything_else(argv):
    with pytest.raises(tfrepo.CommandNotAllowed):
        tfrepo.check_allowlisted(argv, TF)


def test_allowlist_rejects_shell_strings_and_other_binaries():
    with pytest.raises(tfrepo.CommandNotAllowed):
        tfrepo.check_allowlisted(f"{TF} show -json", TF)
    with pytest.raises(tfrepo.CommandNotAllowed):
        tfrepo.check_allowlisted(["/bin/rm", "show", "-json"], "/bin/rm")
    with pytest.raises(tfrepo.CommandNotAllowed):
        tfrepo.check_allowlisted([TF, "show", "-json"], "")


class FakeRunner:
    """Stands in for subprocess.run; records calls and answers per sub-command."""

    def __init__(self, show=None, fail=None, timeout=None, stderr=b""):
        self.calls = []
        self.show = _state() if show is None else show
        self.fail = fail
        self.timeout = timeout
        self.stderr = stderr

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        sub = argv[1]
        if sub == self.timeout:
            raise subprocess.TimeoutExpired(argv, kw["timeout"])
        if sub == self.fail:
            return subprocess.CompletedProcess(argv, 1, b"", self.stderr)
        out = json.dumps(self.show).encode() if sub == "show" else b""
        return subprocess.CompletedProcess(argv, 0, out, b"")

    @property
    def argvs(self):
        return [c[0][1:] for c in self.calls]


@pytest.mark.parametrize("sub", ["plan", "apply", "import", "destroy"])
def test_run_terraform_never_executes_a_rejected_command(sub, tmp_path):
    runner = FakeRunner()
    with pytest.raises(tfrepo.CommandNotAllowed):
        tfrepo.run_terraform(
            [TF, sub],
            terraform_bin=TF,
            cwd=tmp_path,
            env={"TF_DATA_DIR": str(tmp_path / "cache")},
            timeout=5,
            runner=runner,
        )
    assert runner.calls == []


def test_run_terraform_uses_argv_no_shell_timeout_and_tf_data_dir(tmp_path):
    runner = FakeRunner()
    with pytest.raises(tfrepo.CommandNotAllowed, match="TF_DATA_DIR"):
        tfrepo.run_terraform(
            [TF, "show", "-json"], terraform_bin=TF, cwd=tmp_path, env={}, timeout=5, runner=runner
        )
    assert runner.calls == []
    env = {"TF_DATA_DIR": str(tmp_path / "cache")}
    tfrepo.run_terraform(
        [TF, "show", "-json"], terraform_bin=TF, cwd=tmp_path, env=env, timeout=7, runner=runner
    )
    ((argv, kw),) = runner.calls
    assert argv == [TF, "show", "-json"]
    assert kw["shell"] is False and kw["timeout"] == 7 and kw["cwd"] == str(tmp_path)
    assert kw["env"]["TF_DATA_DIR"] == str(tmp_path / "cache")
    assert kw["stdin"] is subprocess.DEVNULL


def test_terraform_env_passes_only_the_mapped_credentials(tmp_path):
    base = {
        "PATH": "/usr/bin",
        "HOME": "/home/example",
        "AWS_ACCESS_KEY_ID": "AKIAEXAMPLEINHERITED",
        "AWS_PROFILE": "example-other",
        "TF_TOKEN_app_terraform_io": "example-token",
        "UNRELATED_SECRET": FAKE_SECRET,
    }
    acct = Account(
        auth_mode="keys",
        access_key_id=FAKE_KEY_ID,
        secret_access_key=FAKE_SECRET,
        region="us-east-1",
    )
    env = tfrepo.terraform_env(acct, tmp_path / "cache", base)
    assert env["AWS_ACCESS_KEY_ID"] == FAKE_KEY_ID
    assert env["AWS_SECRET_ACCESS_KEY"] == FAKE_SECRET
    assert "AWS_PROFILE" not in env and "UNRELATED_SECRET" not in env
    assert env["TF_TOKEN_app_terraform_io"] == "example-token"
    assert env["TF_DATA_DIR"] == str(tmp_path / "cache") and env["TF_INPUT"] == "0"
    profile = tfrepo.terraform_env(
        Account(auth_mode="profile", profile="example-profile"), tmp_path, base
    )
    assert profile["AWS_PROFILE"] == "example-profile"
    assert "AWS_ACCESS_KEY_ID" not in profile


# -- storage, mapping, sync ------------------------------------------------------------------


@pytest.fixture
def app(home):
    return create_app(home, testing=True, terraform_bin=TF, terraform_runner=FakeRunner())


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


def _keys_account(app, name="env-dev", aws_id=ACCOUNT):
    store = app.extensions["iplens"]["accounts"]
    acct_id = store.save(
        None,
        display_name=name,
        region="us-east-1",
        auth_mode="keys",
        access_key_id=FAKE_KEY_ID,
        secret_access_key=FAKE_SECRET,
    )
    with closing(_db(app)) as conn:
        conn.execute("UPDATE accounts SET aws_account_id=? WHERE id=?", (aws_id, acct_id))
    return acct_id


def _discovered(app, repo):
    with closing(_db(app)) as conn:
        repo_id = tfrepo.add_repo(conn, str(repo))
        tfrepo.save_discovery(
            conn, repo_id, tfrepo.discover(repo), app.extensions["iplens"]["accounts"].list()
        )
    return repo_id


def _envs(app, repo_id):
    with closing(_db(app)) as conn:
        return {(e["root_rel"], e["env"]): e for e in tfrepo.list_envs(conn, repo_id=repo_id)}


def test_mapping_is_saved_and_reloaded(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    envs = _envs(app, repo_id)
    assert len(envs) == 8
    dev = envs[("network", "dev")]
    # suggested from the guessed AWS account id, not yet confirmed
    assert (dev["account_ref"], dev["confirmed"]) == (acct, 0)
    assert envs[("network", "prod")]["account_ref"] is None
    with closing(_db(app)) as conn:
        synced = tfrepo.save_mapping(
            conn, repo_id, {dev["id"]: acct, envs[("platform", "prod")]["id"]: None, 99999: acct}
        )
    assert synced == 1
    reloaded = _envs(app, repo_id)
    assert (
        reloaded[("network", "dev")]["account_ref"],
        reloaded[("network", "dev")]["confirmed"],
    ) == (
        acct,
        1,
    )
    # a new scan keeps the confirmed mapping; removed envs are marked absent, not dropped
    (repo / "network/envs/prod.tfvars").unlink()
    _discovered(app, repo)
    again = _envs(app, repo_id)
    assert again[("network", "dev")]["confirmed"] == 1
    assert again[("network", "prod")]["present"] == 0
    with closing(_db(app)) as conn:
        dump = "\n".join(conn.iterdump())
    assert FAKE_SECRET not in dump and "example-tfstate-bucket" not in dump


def _confirm(app, repo_id, key, acct):
    env = _envs(app, repo_id)[key]
    with closing(_db(app)) as conn:
        tfrepo.save_mapping(conn, repo_id, {env["id"]: acct})
    return _envs(app, repo_id)[key]


def _sync(app, runner, **kw):
    paths = app.extensions["iplens"]["paths"]
    store = app.extensions["iplens"]["accounts"]
    return tfrepo.sync(
        paths.db_path,
        lambda ref: store.get(ref, with_secret=True),
        cache_dir=paths.tf_cache_dir,
        terraform_bin=TF,
        runner=runner,
        **kw,
    )


def test_sync_runs_only_allowlisted_commands_and_ingests_ids(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("network", "dev"), acct)
    before = _tree(repo)
    runner = FakeRunner(show=_state(_subnet("app", "subnet-0000000a")))
    (result,) = _sync(app, runner)
    assert result.status == tfrepo.OK and result.resources == 1
    assert runner.argvs == [
        ["init", "-input=false", "-lockfile=readonly", "-backend-config=backend/dev.tfbackend"],
        ["workspace", "select", "dev"],
        ["show", "-json"],
    ]
    cache = app.extensions["iplens"]["paths"].tf_cache_dir.resolve()
    for _argv, kw in runner.calls:
        assert kw["shell"] is False and kw["timeout"] > 0
        assert kw["cwd"] == str((repo / "network").resolve())
        assert Path(kw["env"]["TF_DATA_DIR"]).parent == cache
        assert kw["env"]["AWS_ACCESS_KEY_ID"] == FAKE_KEY_ID
    assert _tree(repo) == before  # the repository is untouched
    with closing(_db(app)) as conn:
        (root,) = [r for r in terraform.list_roots(conn) if r["origin"] == "repo"]
        index = terraform.load_index(conn)
        dump = "\n".join(conn.iterdump())
    assert root["resources"] == 1
    assert index[("subnet", "subnet-0000000a")][0]["address"] == "aws_subnet.app"
    assert FAKE_SECRET not in dump and "10.0.1.0/24" not in dump
    assert _envs(app, repo_id)[("network", "dev")]["status"] == tfrepo.OK


def test_sync_status_init_failed_without_leaking_credentials(app, repo, caplog):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("network", "dev"), acct)
    runner = FakeRunner(fail="init", stderr=f"Error: bad key {FAKE_KEY_ID} {FAKE_SECRET}".encode())
    with caplog.at_level(logging.INFO, logger="iplens"):
        (result,) = _sync(app, runner)
    assert result.status == tfrepo.INIT_FAILED
    assert runner.argvs == [
        ["init", "-input=false", "-lockfile=readonly", "-backend-config=backend/dev.tfbackend"]
    ]
    assert "init failed" in caplog.text
    assert FAKE_SECRET not in caplog.text and FAKE_KEY_ID not in caplog.text


def test_sync_status_no_state_and_timeout(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("platform", "dev"), acct)
    (result,) = _sync(app, FakeRunner(show={"format_version": "1.0"}))
    assert result.status == tfrepo.NO_STATE
    (result,) = _sync(app, FakeRunner(timeout="init"))
    assert (result.status, result.detail) == (tfrepo.INIT_FAILED, "timed out")


def test_sync_local_backend_reads_the_state_file_without_terraform(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("apps/envs/staging", "staging"), acct)
    runner = FakeRunner()
    (result,) = _sync(app, runner)
    assert (result.status, result.resources) == (tfrepo.OK, 1)
    assert runner.calls == []


def test_sync_refuses_a_cache_inside_the_repo(app, repo):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    row = _confirm(app, repo_id, ("network", "dev"), acct)
    runner = FakeRunner()
    with closing(_db(app)) as conn:
        result = tfrepo.sync_env(
            conn,
            row,
            app.extensions["iplens"]["accounts"].get(acct, with_secret=True),
            cache_dir=repo / "cache",
            terraform_bin=TF,
            runner=runner,
        )
    assert result.status == tfrepo.ERROR and runner.calls == []


def test_root_names_are_valid_and_unique():
    long_env = "e" * 60
    name = tfrepo.root_name_for("/srv/example/infra-repo", "network/envs/dev", long_env)
    assert terraform.validate_root_name(name) == name
    assert name != tfrepo.root_name_for("/srv/example/infra-repo", "network/envs/qa", long_env)


# -- web ------------------------------------------------------------------------------------


def test_web_add_confirm_sync_and_drift(app, client, repo, snapshot_builder):
    acct = _keys_account(app)
    resp = _post(client, "/settings/tfrepos", {"path": str(repo)})
    assert resp.status_code == 302 and "/settings/tfrepos/" in resp.location
    page = client.get(resp.location).data.decode()
    assert "network" in page and "envs/dev.tfvars" in page and ACCOUNT in page
    assert FAKE_SECRET not in page and "example-tfstate-bucket" not in page
    repo_id = int(resp.location.rstrip("/").rsplit("/", 1)[1])
    envs = _envs(app, repo_id)
    dev = envs[("network", "dev")]
    _post(client, f"/settings/tfrepos/{repo_id}", {f"account_{dev['id']}": str(acct)})
    assert _envs(app, repo_id)[("network", "dev")]["confirmed"] == 1
    assert "selected" in client.get(f"/settings/tfrepos/{repo_id}").data.decode()

    app.extensions["iplens"]["tf_runner"] = FakeRunner(
        show=_state(_subnet("app", "subnet-0000000a"), _subnet("gone", "subnet-0000000f"))
    )
    resp = _post(client, "/terraform/sync", {"next": "/terraform"})
    assert resp.status_code == 302
    (
        snapshot_builder(_db(app), account_ref=acct)
        .vpc("vpc-0example0000001", "10.0.0.0/16")
        .subnet("subnet-0000000a", "vpc-0example0000001", "10.0.1.0/24")
        .subnet("subnet-0000000b", "vpc-0example0000001", "10.0.2.0/24")
    )
    _post(client, "/accounts/active", {"account_id": str(acct)})
    page = client.get("/terraform").data.decode()
    assert "Terraform sync: 1 ok" in page
    # (a) in AWS, not in Terraform / (b) in Terraform, not in AWS
    assert "subnet-0000000b" in page and "vpc-0example0000001" in page
    assert "aws_subnet.gone" in page and "subnet-0000000f" in page
    assert FAKE_SECRET not in page
    settings = client.get("/settings").data.decode()
    assert "repo sync" in settings and str(repo) in settings


def test_web_drift_lists(app, repo, snapshot_builder):
    acct = _keys_account(app)
    repo_id = _discovered(app, repo)
    _confirm(app, repo_id, ("network", "dev"), acct)
    _sync(app, FakeRunner(show=_state(_subnet("app", "subnet-0000000a"))))
    snap = snapshot_builder(_db(app), account_ref=acct)
    snap.vpc("vpc-0example0000001", "10.0.0.0/16").subnet(
        "subnet-0000000a", "vpc-0example0000001", "10.0.1.0/24"
    )
    with closing(_db(app)) as conn:
        conn.execute("INSERT INTO vpcs VALUES(?, 'vpc-0default', '', '[]', 1)", (snap.id,))
        row = conn.execute("SELECT * FROM snapshots WHERE id=?", (snap.id,)).fetchone()
        d = tfrepo.drift(conn, acct, row)
    assert [r["resource_id"] for r in d.not_in_terraform] == ["vpc-0example0000001"]
    assert d.not_in_aws == []
    assert "security group" in d.skipped_kinds  # no security_groups inventory


def test_web_sync_rejects_bad_csrf_and_unknown_repo(client):
    assert client.post("/terraform/sync").status_code == 400
    assert client.get("/settings/tfrepos/999").status_code == 404
    resp = _post(client, "/settings/tfrepos", {"path": "relative/path"})
    assert resp.status_code == 302
    assert "absolute path" in client.get("/settings").data.decode()
