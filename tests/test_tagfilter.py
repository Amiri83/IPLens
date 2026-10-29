"""Visual page tag filters (iplens.tagfilter) and their browser mirror (static/tagfilter.js):
scope per resource type, OR within a filter / AND across filters on one type, untagged
resources, containers, discovered tags, named presets and their routes. The browser paths
are in tests/test_visual_browser.py. Placeholders only."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from iplens import queries, tagfilter, viewstate
from iplens.attribution import OWNER_LABELS
from iplens.db import closing, init_db
from iplens.tagfilter import (
    TagFilter,
    discovered_tags,
    hidden_containers,
    matches,
    parse_filters,
    resource_visible,
    type_counts,
)
from iplens.web import create_app

TAGFILTER_JS = Path(__file__).parent.parent / "iplens" / "static" / "tagfilter.js"
VPC = "vpc-0example0000001"


def _res(eni, type_, **tags):
    return {"eni_id": eni, "type": type_, "tags": tags}


EC2_PROD = _res("eni-0abc0001", "ec2", Env="prod", Team="team-a")
EC2_DEV = _res("eni-0abc0002", "ec2", env="dev", Team="team-b")
EC2_TEST = _res("eni-0abc0003", "ec2", ENV="test", Team="team-a")
EC2_UNTAGGED = _res("eni-0abc0004", "ec2", Name="test-server-a")
LAMBDA_DEV = _res("eni-0abc0005", "lambda", Env="dev")
LAMBDA_UNTAGGED = _res("eni-0abc0006", "lambda")
RESOURCES = [EC2_PROD, EC2_DEV, EC2_TEST, EC2_UNTAGGED, LAMBDA_DEV, LAMBDA_UNTAGGED]


def _f(type_="ec2", key="Env", values=(), untagged=False):
    return TagFilter(type_, key, tuple(values), untagged)


def _shown(filters):
    return [r["eni_id"] for r in RESOURCES if resource_visible(r, filters)]


# -- scope, OR / AND, untagged --------------------------------------------------------------


def test_no_filter_shows_everything():
    assert _shown([]) == [r["eni_id"] for r in RESOURCES]


def test_filter_only_hides_its_own_type():
    shown = _shown([_f(values=["prod"])])
    assert shown == ["eni-0abc0001", "eni-0abc0005", "eni-0abc0006"]  # every Lambda stays
    # A filter on a type that has no resources changes nothing.
    assert _shown([_f(type_="rds", values=["prod"])]) == _shown([])


def test_values_are_ored_within_a_filter():
    assert _shown([_f(values=["prod", "dev"])])[:2] == ["eni-0abc0001", "eni-0abc0002"]
    assert "eni-0abc0003" not in _shown([_f(values=["prod", "dev"])])


def test_filters_on_the_same_type_are_anded():
    env = _f(values=["prod", "test"])
    team = _f(key="Team", values=["team-a"])
    assert _shown([env])[:2] == ["eni-0abc0001", "eni-0abc0003"]
    assert _shown([env, _f(key="team", values=["team-b"])]) == ["eni-0abc0005", "eni-0abc0006"]
    assert _shown([env, team])[:2] == ["eni-0abc0001", "eni-0abc0003"]
    # Filters on other types do not take part in the AND.
    assert _shown([env, _f(type_="lambda", values=["dev"])]) == [
        "eni-0abc0001",
        "eni-0abc0003",
        "eni-0abc0005",
    ]


def test_keys_ignore_case_values_match_exactly():
    # Env / env / ENV are one key.
    assert matches(_f(key="ENV", values=["dev"]), EC2_DEV.get("tags"))
    assert matches(_f(key="env", values=["prod"]), EC2_PROD["tags"])
    assert not matches(_f(values=["Prod"]), EC2_PROD["tags"])
    assert not matches(_f(values=["prod "]), EC2_PROD["tags"])


def test_untagged_hidden_by_default_and_kept_on_request():
    assert TagFilter("ec2", "Env").include_untagged is False
    assert "eni-0abc0004" not in _shown([_f(values=["prod"])])
    assert "eni-0abc0004" in _shown([_f(values=["prod"], untagged=True)])
    # Only the untagged ones: no value, include_untagged.
    assert _shown([_f(untagged=True)])[:1] == ["eni-0abc0004"]
    assert "eni-0abc0001" not in _shown([_f(untagged=True)])
    # A tag with an empty value is tagged (with the value "").
    blank = _res("eni-0abc0007", "ec2", Env="")
    assert not resource_visible(blank, [_f(untagged=True)])
    assert resource_visible(blank, [_f(values=[""])])


# -- shared Lambda ENIs: every owner's values ------------------------------------------------

# One ENI shared by a dev function (first owner) and a uat function: ``tags`` (display) keeps
# the first owner's values, ``tag_values`` (filtering) every owner's.
LAMBDA_SHARED = {
    **_res("eni-0abc0008", "lambda", Env="dev", Team="team-a"),
    "tag_values": {"Env": ["dev", "uat"], "Team": ["team-a"]},
}


def test_shared_eni_matches_any_owner_value():
    uat = [_f(type_="lambda", values=["uat"])]
    assert resource_visible(LAMBDA_SHARED, uat)
    assert not resource_visible({k: v for k, v in LAMBDA_SHARED.items() if k != "tag_values"}, uat)
    assert resource_visible(LAMBDA_SHARED, [_f(type_="lambda", values=["dev"])])
    assert not resource_visible(LAMBDA_SHARED, [_f(type_="lambda", values=["prod"])])
    assert resource_visible(LAMBDA_SHARED, [_f(type_="lambda", key="team", values=["team-a"])])
    assert discovered_tags([LAMBDA_SHARED])["lambda"] == {"Env": ["dev", "uat"], "Team": ["team-a"]}


def test_visual_data_tag_values_of_a_shared_eni(home, snapshot_builder):
    b = snapshot_builder(home / "iplens.db")
    b.vpc(VPC, "192.0.2.0/24").subnet("subnet-a", VPC, "192.0.2.0/26")
    b.eni("eni-0abc0008", "subnet-a", ["192.0.2.18"], owner_type="lambda", owner_ref="fn-a")
    # Not shared: only the dev function.
    b.eni("eni-0abc0009", "subnet-a", ["192.0.2.19"], owner_type="lambda", owner_ref="fn-a")
    b.tag("lambda", "fn-a", "Env", "dev").tag("lambda", "fn-a", "Team", "team-a")
    b.tag("lambda", "fn-b", "Env", "uat")
    b.tag("eni", "eni-0abc0008", "Name", "test-server-a")
    with closing(home / "iplens.db") as c:
        c.execute(
            "UPDATE enis SET owner_names=? WHERE eni_id=?", ('["fn-a", "fn-b"]', "eni-0abc0008")
        )
        data = queries.visual_data(c, b.id, VPC, OWNER_LABELS)
    node, dev_only = sorted(data["vpc"]["subnets"][0]["items"], key=lambda n: n["eni_id"])
    assert dev_only["tag_values"] == {"Env": ["dev"], "Team": ["team-a"]}
    assert not resource_visible(dev_only, [_f(type_="lambda", values=["uat"])])
    assert node["tags"] == {"Env": "dev", "Name": "test-server-a", "Team": "team-a"}  # first owner
    assert node["tag_values"] == {
        "Env": ["dev", "uat"],
        "Name": ["test-server-a"],
        "Team": ["team-a"],
    }
    uat = [_f(type_="lambda", values=["uat"])]
    assert resource_visible(node, uat)
    assert not resource_visible({**node, "tag_values": None}, uat)  # first owner only: hidden
    assert not resource_visible(node, [_f(type_="lambda", values=["prod"])])


# -- containers and counts -------------------------------------------------------------------


SUBNETS = [
    {"subnet_id": "subnet-a", "resources": [EC2_PROD, LAMBDA_DEV]},
    {"subnet_id": "subnet-b", "resources": [EC2_DEV, EC2_UNTAGGED]},
    {"subnet_id": "subnet-c", "resources": []},
]


def test_containers_always_shown_by_default():
    flt = [_f(values=["nothing-matches"]), _f(type_="lambda", values=["nothing"])]
    gone = hidden_containers(SUBNETS, lambda r: resource_visible(r, flt), False)
    assert gone == {"subnets": [], "vpc": False}


def test_hide_empty_containers():
    flt = [_f(values=["prod"])]
    gone = hidden_containers(SUBNETS, lambda r: resource_visible(r, flt), True)
    assert gone == {"subnets": ["subnet-b", "subnet-c"], "vpc": False}
    nothing = [_f(values=["none"]), _f(type_="lambda", values=["none"])]
    gone = hidden_containers(SUBNETS, lambda r: resource_visible(r, nothing), True)
    assert gone == {"subnets": ["subnet-a", "subnet-b", "subnet-c"], "vpc": True}


def test_type_counts():
    flt = [_f(values=["prod", "dev"])]
    assert type_counts(RESOURCES, lambda r: resource_visible(r, flt)) == {
        "ec2": [2, 4],
        "lambda": [2, 2],
    }


def test_discovered_tags_per_type_merge_key_case():
    found = discovered_tags(RESOURCES)
    assert found == {
        "ec2": {
            "Env": ["dev", "prod", "test"],  # Env / env / ENV: spelled as first seen
            "Name": ["test-server-a"],
            "Team": ["team-a", "team-b"],
        },
        "lambda": {"Env": ["dev"]},
    }


# -- parsing ---------------------------------------------------------------------------------


def test_parse_filters_round_trip():
    raw = json.dumps(
        [
            {"resource_type": "ec2", "tag_key": " Env ", "values": ["prod", "dev", "prod"]},
            {"resource_type": "lambda", "tag_key": "Team", "include_untagged": True},
        ]
    )
    got = parse_filters(raw)
    assert got == [
        TagFilter("ec2", "Env", ("prod", "dev"), False),
        TagFilter("lambda", "Team", (), True),
    ]
    assert parse_filters([f.as_dict() for f in got]) == got
    assert parse_filters("") == [] and parse_filters(None) == []


@pytest.mark.parametrize(
    "raw, error",
    [
        ("nope", "JSON"),
        ('{"a": 1}', "list"),
        ("[1]", "object"),
        ('[{"resource_type": "ec2", "values": ["a"]}]', "tag_key"),
        ('[{"tag_key": "Env", "values": ["a"]}]', "resource_type"),
        ('[{"resource_type": "ec2", "tag_key": "Env"}]', "at least one value"),
        ('[{"resource_type": "ec2", "tag_key": "Env", "values": "a"}]', "list"),
        ('[{"resource_type": "ec2", "tag_key": "Env", "values": [1]}]', "string"),
        ('[{"resource_type": "ec2", "tag_key": "Env", "include_untagged": "yes"}]', "true or"),
        (json.dumps([{"resource_type": "ec2", "tag_key": "k" * 129, "values": ["a"]}]), "128"),
    ],
)
def test_parse_filters_rejects(raw, error):
    with pytest.raises(ValueError, match=error):
        parse_filters(raw)


def test_parse_filters_caps_the_count():
    one = {"resource_type": "ec2", "tag_key": "Env", "values": ["a"]}
    assert len(parse_filters([one] * tagfilter.MAX_FILTERS)) == tagfilter.MAX_FILTERS
    with pytest.raises(ValueError, match="at most"):
        parse_filters([one] * (tagfilter.MAX_FILTERS + 1))


# -- browser mirror --------------------------------------------------------------------------

_NODE_SCRIPT = r"""
const TF = require(process.argv[1]);
let input = "";
process.stdin.on("data", (c) => { input += c; });
process.stdin.on("end", () => {
  const p = JSON.parse(input);
  const out = p.cases.map((filters) => {
    const shown = (r) => TF.resourceVisible(r, filters);
    return {
      shown: p.resources.filter(shown).map((r) => r.eni_id),
      counts: TF.typeCounts(p.resources, shown),
      containers: [false, true].map((h) => TF.hiddenContainers(p.subnets, shown, h)),
    };
  });
  process.stdout.write(JSON.stringify({ out: out, found: TF.discoveredTags(p.resources) }));
});
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_js_mirror_matches_python():
    cases = [
        [],
        [_f(values=["prod"])],
        [_f(values=["prod", "dev"]), _f(key="TEAM", values=["team-a"])],
        [_f(values=["prod"], untagged=True), _f(type_="lambda", values=["dev"])],
        [_f(type_="lambda", untagged=True)],
        [_f(values=["none"]), _f(type_="lambda", values=["none"])],
        [_f(type_="lambda", values=["uat"])],  # only the shared ENI's second owner
        [_f(type_="lambda", key="team", values=["team-a"], untagged=True)],
    ]
    # With the shared Lambda ENI: tag_values ({key: [values]}) beside plain tags.
    resources = [*RESOURCES, LAMBDA_SHARED]
    payload = {
        "resources": resources,
        "subnets": SUBNETS,
        "cases": [[f.as_dict() for f in c] for c in cases],
    }
    result = subprocess.run(  # noqa: S603 - fixed argv, shipped file
        [shutil.which("node"), "-e", _NODE_SCRIPT, str(TAGFILTER_JS)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    js = json.loads(result.stdout)
    for filters, got in zip(cases, js["out"], strict=True):
        shown = lambda r, filters=filters: resource_visible(r, filters)  # noqa: E731
        assert got["shown"] == [r["eni_id"] for r in resources if shown(r)]
        assert got["counts"] == type_counts(resources, shown)
        assert got["containers"] == [hidden_containers(SUBNETS, shown, h) for h in (False, True)]
    assert "eni-0abc0008" in js["out"][6]["shown"]  # Env=uat keeps the shared ENI
    assert js["found"] == discovered_tags(resources)
    assert js["found"]["lambda"]["Env"] == ["dev", "uat"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_tagfilter_script_parses():
    result = subprocess.run(  # noqa: S603 - fixed argv, shipped file
        [shutil.which("node"), "--check", str(TAGFILTER_JS)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


# -- presets ---------------------------------------------------------------------------------


@pytest.fixture
def conn(tmp_path):
    db = tmp_path / "state.db"
    init_db(db)
    with closing(db) as c:
        c.executemany(
            "INSERT INTO accounts(region, auth_mode) VALUES('us-east-1', 'env')", [(), ()]
        )
        yield c


def test_presets_saved_loaded_deleted_per_account(conn):
    prod = [_f(values=["prod"]), _f(type_="lambda", key="Team", untagged=True)]
    viewstate.save_preset(conn, 1, "prod only", prod, hide_empty=True)
    viewstate.save_preset(conn, 1, "Dev", [_f(values=["dev"])])
    assert [p["name"] for p in viewstate.list_presets(conn, 1)] == ["Dev", "prod only"]
    assert viewstate.list_presets(conn, 2) == []
    got = viewstate.list_presets(conn, 1)[1]
    assert got == {"name": "prod only", "filters": [f.as_dict() for f in prod], "hide_empty": True}

    viewstate.save_preset(conn, 1, "prod only", [_f(values=["test"])])  # overwrites
    got = viewstate.list_presets(conn, 1)[1]
    assert got["filters"][0]["values"] == ["test"] and got["hide_empty"] is False

    assert viewstate.delete_preset(conn, 1, "Dev") is True
    assert viewstate.delete_preset(conn, 1, "Dev") is False
    assert viewstate.delete_preset(conn, 2, "prod only") is False  # other account
    assert [p["name"] for p in viewstate.list_presets(conn, 1)] == ["prod only"]


def test_preset_name_validation(conn):
    for bad in ("", "   ", "n" * (viewstate.MAX_PRESET_NAME + 1)):
        with pytest.raises(ValueError, match="preset name"):
            viewstate.save_preset(conn, 1, bad, [])


def test_unreadable_preset_is_skipped(conn):
    conn.execute(
        "INSERT INTO visual_filter_presets(account_ref, name, filters) VALUES(1, 'old', '{')"
    )
    viewstate.save_preset(conn, 1, "ok", [])
    assert [p["name"] for p in viewstate.list_presets(conn, 1)] == ["ok"]


# -- routes and page data --------------------------------------------------------------------


@pytest.fixture
def client(home):
    c = create_app(home, testing=True).test_client()
    c.get("/")
    return c


def _post(client, url, data):
    with client.session_transaction() as s:
        data = {**data, "csrf_token": s["csrf"]}
    return client.post(url, data=data)


def test_preset_routes(client, home, snapshot_builder):
    b = snapshot_builder(home / "iplens.db")
    b.vpc(VPC, "192.0.2.0/24").subnet("subnet-a", VPC, "192.0.2.0/26")
    b.eni("eni-0abc0001", "subnet-a", ["192.0.2.10"], name="test-server-a")
    filters = json.dumps([_f(values=["prod"]).as_dict()])
    resp = _post(client, "/visual/filter-presets", {"name": "prod", "filters": filters})
    assert resp.status_code == 200
    assert resp.get_json() == [
        {"name": "prod", "filters": json.loads(filters), "hide_empty": False}
    ]
    resp = _post(
        client, "/visual/filter-presets", {"name": "all", "filters": "[]", "hide_empty": "1"}
    )
    assert [p["name"] for p in resp.get_json()] == ["all", "prod"]
    assert resp.get_json()[0]["hide_empty"] is True

    page = client.get(f"/visual?vpc={VPC}").get_data(as_text=True)
    assert 'id="tag-filters"' in page and 'id="tf-hide-empty"' in page
    assert '"name": "prod"' in page  # presets embedded for the panel
    assert "tagfilter.js" in page

    assert _post(client, "/visual/filter-presets", {"name": "", "filters": "[]"}).status_code == 400
    bad = _post(client, "/visual/filter-presets", {"name": "x", "filters": '[{"tag_key": 1}]'})
    assert bad.status_code == 400
    assert client.post("/visual/filter-presets", data={"name": "x"}).status_code == 400  # csrf

    resp = _post(client, "/visual/filter-presets/delete", {"name": "prod"})
    assert [p["name"] for p in resp.get_json()] == ["all"]


def test_visual_data_lists_types_and_keeps_every_resource(home, snapshot_builder):
    """The data endpoint is unchanged by filters (they run in the browser): every resource
    is sent, with its type and tags, plus the type labels of the filter panel."""
    b = snapshot_builder(home / "iplens.db")
    b.vpc(VPC, "192.0.2.0/24").subnet("subnet-a", VPC, "192.0.2.0/26")
    b.eni("eni-0abc0001", "subnet-a", ["192.0.2.10"], name="test-server-a")
    b.eni("eni-0abc0002", "subnet-a", ["192.0.2.11"], owner_type="lambda", owner_ref="fn-a")
    b.tag("eni", "eni-0abc0001", "Env", "prod")
    with closing(home / "iplens.db") as c:
        data = queries.visual_data(c, b.id, VPC, OWNER_LABELS)
    assert data["type_labels"] == {"ec2": "EC2", "lambda": "Lambda"}
    items = data["vpc"]["subnets"][0]["items"]
    assert {(r["type"], r["eni_id"]) for r in items} == {
        ("ec2", "eni-0abc0001"),
        ("lambda", "eni-0abc0002"),
    }
    assert next(r for r in items if r["type"] == "ec2")["tags"] == {"Env": "prod"}
