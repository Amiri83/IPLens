"""Visual page view filters (iplens.tagfilter) and their browser mirror (static/tagfilter.js):
tag filters on every resource type, OR within a filter / AND across filters, untagged
resources, the name filter (comma-separated terms, AND'd with the tag filters), containers,
discovered tags, named presets and their routes. The browser paths are in
tests/test_visual_browser.py. Placeholders only."""

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
    name_matches,
    name_terms,
    parse_filters,
    parse_name_filter,
    resource_visible,
    type_counts,
)
from iplens.web import create_app

TAGFILTER_JS = Path(__file__).parent.parent / "iplens" / "static" / "tagfilter.js"
VPC = "vpc-0example0000001"


def _res(eni, type_, name, owners=(), **tags):
    return {"eni_id": eni, "type": type_, "name": name, "owners": list(owners), "tags": tags}


EC2_PROD = _res("eni-0abc0001", "ec2", "web-prod-a", Env="prod", Team="team-a")
EC2_DEV = _res("eni-0abc0002", "ec2", "web-dev-a", env="dev", Team="team-b")
EC2_TEST = _res("eni-0abc0003", "ec2", "web-test-a", ENV="test", Team="team-a")
EC2_UNTAGGED = _res("eni-0abc0004", "ec2", "test-server-a", Name="test-server-a")
LAMBDA_DEV = _res("eni-0abc0005", "lambda", "fn-b", ["fn-b"], Env="dev")
LAMBDA_UNTAGGED = _res("eni-0abc0006", "lambda", "fn-a", ["fn-a"])
RESOURCES = [EC2_PROD, EC2_DEV, EC2_TEST, EC2_UNTAGGED, LAMBDA_DEV, LAMBDA_UNTAGGED]


def _f(key="Env", values=(), untagged=False):
    return TagFilter(key, tuple(values), untagged)


def _shown(filters, name=""):
    return [r["eni_id"] for r in RESOURCES if resource_visible(r, filters, name)]


# -- every type, OR / AND, untagged ---------------------------------------------------------


def test_no_filter_shows_everything():
    assert _shown([]) == [r["eni_id"] for r in RESOURCES]


def test_a_filter_applies_to_every_resource_type():
    # Env=dev: the EC2 and the Lambda ENI; every other resource, of any type, is hidden.
    assert _shown([_f(values=["dev"])]) == ["eni-0abc0002", "eni-0abc0005"]
    assert _shown([_f(values=["prod"])]) == ["eni-0abc0001"]


def test_values_are_ored_within_a_filter():
    assert _shown([_f(values=["prod", "dev"])]) == ["eni-0abc0001", "eni-0abc0002", "eni-0abc0005"]


def test_filters_are_anded():
    env = _f(values=["prod", "test", "dev"])
    assert _shown([env, _f(key="Team", values=["team-a"])]) == ["eni-0abc0001", "eni-0abc0003"]
    assert _shown([env, _f(key="team", values=["team-b"])]) == ["eni-0abc0002"]
    # The Lambda ENI has no Team tag: hidden unless that filter includes untagged.
    assert _shown([env, _f(key="Team", values=["team-b"], untagged=True)]) == [
        "eni-0abc0002",
        "eni-0abc0005",
    ]


def test_keys_ignore_case_values_match_exactly():
    # Env / env / ENV are one key.
    assert matches(_f(key="ENV", values=["dev"]), EC2_DEV.get("tags"))
    assert matches(_f(key="env", values=["prod"]), EC2_PROD["tags"])
    assert not matches(_f(values=["Prod"]), EC2_PROD["tags"])
    assert not matches(_f(values=["prod "]), EC2_PROD["tags"])


def test_untagged_hidden_by_default_and_kept_on_request():
    assert TagFilter("Env").include_untagged is False
    assert "eni-0abc0004" not in _shown([_f(values=["prod"])])
    assert _shown([_f(values=["prod"], untagged=True)]) == [
        "eni-0abc0001",
        "eni-0abc0004",
        "eni-0abc0006",
    ]
    # Only the untagged ones (of every type): no value, include_untagged.
    assert _shown([_f(untagged=True)]) == ["eni-0abc0004", "eni-0abc0006"]
    # A tag with an empty value is tagged (with the value "").
    blank = _res("eni-0abc0007", "ec2", "test-server-b", Env="")
    assert not resource_visible(blank, [_f(untagged=True)])
    assert resource_visible(blank, [_f(values=[""])])


# -- name filter -----------------------------------------------------------------------------


def test_name_terms_split_on_commas_trimmed_lower_cased():
    assert name_terms(" Dev ,, NonProd ,") == ["dev", "nonprod"]
    assert name_terms("") == [] and name_terms(None) == [] and name_terms(" , ") == []


def test_name_filter_terms_are_ored_substrings_in_any_case():
    assert _shown([], "dev") == ["eni-0abc0002"]
    assert _shown([], "DEV, fn-a") == ["eni-0abc0002", "eni-0abc0006"]
    assert _shown([], "WEB-PROD") == ["eni-0abc0001"]
    assert _shown([], "nothing, matches") == []
    assert _shown([], " , ") == _shown([])  # no term: no filter


def test_name_filter_matches_owner_names_and_the_eni_id():
    assert _shown([], "0abc0004") == ["eni-0abc0004"]
    assert _shown([], "ENI-0ABC0003") == ["eni-0abc0003"]
    shared = _res("eni-0abc0008", "lambda", "fn-a +1 more", ["fn-a", "fn-nonprod"])
    # The second owner's name only appears in ``owners``.
    assert name_matches(shared, ["nonprod"])
    assert not name_matches({**shared, "owners": []}, ["nonprod"])


def test_name_filter_and_tag_filters_are_anded():
    assert _shown([_f(values=["dev"])], "web") == ["eni-0abc0002"]
    assert _shown([_f(values=["dev"])], "fn-, web-prod") == ["eni-0abc0005"]
    assert _shown([_f(values=["prod"])], "dev") == []


# -- shared Lambda ENIs: every owner's values ------------------------------------------------

# One ENI shared by a dev function (first owner) and a uat function: ``tags`` (display) keeps
# the first owner's values, ``tag_values`` (filtering) every owner's.
LAMBDA_SHARED = {
    **_res("eni-0abc0008", "lambda", "fn-a +1 more", ["fn-a", "fn-nonprod"], Env="dev"),
    "tag_values": {"Env": ["dev", "uat"], "Team": ["team-a"]},
}


def test_shared_eni_matches_any_owner_value():
    uat = [_f(values=["uat"])]
    assert resource_visible(LAMBDA_SHARED, uat)
    assert not resource_visible({k: v for k, v in LAMBDA_SHARED.items() if k != "tag_values"}, uat)
    assert resource_visible(LAMBDA_SHARED, [_f(values=["dev"])])
    assert not resource_visible(LAMBDA_SHARED, [_f(values=["prod"])])
    assert resource_visible(LAMBDA_SHARED, [_f(key="team", values=["team-a"])])
    assert discovered_tags([LAMBDA_SHARED]) == {"Env": ["dev", "uat"], "Team": ["team-a"]}


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
    assert not resource_visible(dev_only, [_f(values=["uat"])])
    assert node["tags"] == {"Env": "dev", "Name": "test-server-a", "Team": "team-a"}  # first owner
    assert node["tag_values"] == {
        "Env": ["dev", "uat"],
        "Name": ["test-server-a"],
        "Team": ["team-a"],
    }
    uat = [_f(values=["uat"])]
    assert resource_visible(node, uat)
    assert not resource_visible({**node, "tag_values": None}, uat)  # first owner only: hidden
    assert not resource_visible(node, [_f(values=["prod"])])
    # The name filter sees every owner of the shared ENI, not only the one in its name.
    assert node["name"] == "fn-a +1 more" and node["owners"] == ["fn-a", "fn-b"]
    assert resource_visible(node, [], "FN-B") and not resource_visible(dev_only, [], "fn-b")


# -- containers and counts -------------------------------------------------------------------


SUBNETS = [
    {"subnet_id": "subnet-a", "resources": [EC2_PROD, LAMBDA_DEV]},
    {"subnet_id": "subnet-b", "resources": [EC2_DEV, EC2_UNTAGGED]},
    {"subnet_id": "subnet-c", "resources": []},
]


def test_containers_always_shown_by_default():
    flt = [_f(values=["nothing-matches"])]
    gone = hidden_containers(SUBNETS, lambda r: resource_visible(r, flt, "none"), False)
    assert gone == {"subnets": [], "vpc": False}


def test_hide_empty_containers():
    flt = [_f(values=["prod"])]
    gone = hidden_containers(SUBNETS, lambda r: resource_visible(r, flt), True)
    assert gone == {"subnets": ["subnet-b", "subnet-c"], "vpc": False}
    gone = hidden_containers(SUBNETS, lambda r: resource_visible(r, [], "web-dev"), True)
    assert gone == {"subnets": ["subnet-a", "subnet-c"], "vpc": False}
    nothing = [_f(values=["none"])]
    gone = hidden_containers(SUBNETS, lambda r: resource_visible(r, nothing), True)
    assert gone == {"subnets": ["subnet-a", "subnet-b", "subnet-c"], "vpc": True}


def test_type_counts():
    flt = [_f(values=["prod", "dev"])]
    assert type_counts(RESOURCES, lambda r: resource_visible(r, flt)) == {
        "ec2": [2, 4],
        "lambda": [1, 2],
    }
    assert type_counts(RESOURCES, lambda r: resource_visible(r, [], "fn-")) == {
        "ec2": [0, 4],
        "lambda": [2, 2],
    }


def test_discovered_tags_over_every_type_merge_key_case():
    assert discovered_tags(RESOURCES) == {
        "Env": ["dev", "prod", "test"],  # Env / env / ENV: spelled as first seen
        "Name": ["test-server-a"],
        "Team": ["team-a", "team-b"],
    }


# -- parsing ---------------------------------------------------------------------------------


def test_parse_filters_round_trip():
    raw = json.dumps(
        [
            {"tag_key": " Env ", "values": ["prod", "dev", "prod"]},
            {"tag_key": "Team", "include_untagged": True},
        ]
    )
    got = parse_filters(raw)
    assert got == [TagFilter("Env", ("prod", "dev"), False), TagFilter("Team", (), True)]
    assert parse_filters([f.as_dict() for f in got]) == got
    assert got[0].as_dict() == {
        "tag_key": "Env",
        "values": ["prod", "dev"],
        "include_untagged": False,
    }
    assert parse_filters("") == [] and parse_filters(None) == []


def test_parse_filters_ignores_an_old_resource_type():
    old = [{"resource_type": "ec2", "tag_key": "Env", "values": ["dev"]}]
    assert parse_filters(json.dumps(old)) == [TagFilter("Env", ("dev",))]


@pytest.mark.parametrize(
    "raw, error",
    [
        ("nope", "JSON"),
        ('{"a": 1}', "list"),
        ("[1]", "object"),
        ('[{"values": ["a"]}]', "tag_key"),
        ('[{"tag_key": "Env"}]', "at least one value"),
        ('[{"tag_key": "Env", "values": "a"}]', "list"),
        ('[{"tag_key": "Env", "values": [1]}]', "string"),
        ('[{"tag_key": "Env", "include_untagged": "yes"}]', "true or"),
        (json.dumps([{"tag_key": "k" * 129, "values": ["a"]}]), "128"),
    ],
)
def test_parse_filters_rejects(raw, error):
    with pytest.raises(ValueError, match=error):
        parse_filters(raw)


def test_parse_filters_caps_the_count():
    one = {"tag_key": "Env", "values": ["a"]}
    assert len(parse_filters([one] * tagfilter.MAX_FILTERS)) == tagfilter.MAX_FILTERS
    with pytest.raises(ValueError, match="at most"):
        parse_filters([one] * (tagfilter.MAX_FILTERS + 1))


def test_parse_name_filter():
    assert parse_name_filter("  dev, nonprod ") == "dev, nonprod"
    assert parse_name_filter(None) == "" and parse_name_filter("") == ""
    with pytest.raises(ValueError, match="at most"):
        parse_name_filter("x" * (tagfilter.MAX_NAME_FILTER + 1))


# -- browser mirror --------------------------------------------------------------------------

_NODE_SCRIPT = r"""
const TF = require(process.argv[1]);
let input = "";
process.stdin.on("data", (c) => { input += c; });
process.stdin.on("end", () => {
  const p = JSON.parse(input);
  const out = p.cases.map(([filters, name]) => {
    const shown = (r) => TF.resourceVisible(r, filters, name);
    return {
      shown: p.resources.filter(shown).map((r) => r.eni_id),
      counts: TF.typeCounts(p.resources, shown),
      containers: [false, true].map((h) => TF.hiddenContainers(p.subnets, shown, h)),
      terms: TF.nameTerms(name),
    };
  });
  process.stdout.write(JSON.stringify({ out: out, found: TF.discoveredTags(p.resources) }));
});
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_js_mirror_matches_python():
    cases = [
        ([], ""),
        ([_f(values=["prod"])], ""),
        ([_f(values=["prod", "dev"]), _f(key="TEAM", values=["team-a"])], ""),
        ([_f(values=["prod"], untagged=True)], ""),
        ([_f(untagged=True)], ""),
        ([_f(values=["none"])], ""),
        ([_f(values=["uat"])], ""),  # only the shared ENI's second owner
        ([_f(key="team", values=["team-a"], untagged=True)], ""),
        ([], "dev, NONPROD"),  # the shared ENI's second owner name
        ([], " , "),
        ([], "0ABC0004,web-t"),
        ([_f(values=["dev"])], "fn-, web"),
        ([_f(values=["dev", "prod"])], "nothing"),
    ]
    # With the shared Lambda ENI: tag_values ({key: [values]}) beside plain tags.
    resources = [*RESOURCES, LAMBDA_SHARED]
    payload = {
        "resources": resources,
        "subnets": SUBNETS,
        "cases": [[[f.as_dict() for f in c], name] for c, name in cases],
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
    for (filters, name), got in zip(cases, js["out"], strict=True):
        shown = lambda r, filters=filters, name=name: resource_visible(r, filters, name)  # noqa: E731
        assert got["shown"] == [r["eni_id"] for r in resources if shown(r)]
        assert got["counts"] == type_counts(resources, shown)
        assert got["containers"] == [hidden_containers(SUBNETS, shown, h) for h in (False, True)]
        assert got["terms"] == name_terms(name)
    assert "eni-0abc0008" in js["out"][6]["shown"]  # Env=uat keeps the shared ENI
    assert js["out"][8]["shown"] == ["eni-0abc0002", "eni-0abc0008"]
    assert js["found"] == discovered_tags(resources)
    assert js["found"]["Env"] == ["dev", "prod", "test", "uat"]


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
    prod = [_f(values=["prod"]), _f(key="Team", untagged=True)]
    viewstate.save_preset(conn, 1, "prod only", prod, hide_empty=True, name_filter=" web, fn- ")
    viewstate.save_preset(conn, 1, "Dev", [_f(values=["dev"])])
    assert [p["name"] for p in viewstate.list_presets(conn, 1)] == ["Dev", "prod only"]
    assert viewstate.list_presets(conn, 2) == []
    got = viewstate.list_presets(conn, 1)[1]
    assert got == {
        "name": "prod only",
        "filters": [f.as_dict() for f in prod],
        "name_filter": "web, fn-",
        "hide_empty": True,
    }
    assert viewstate.list_presets(conn, 1)[0]["name_filter"] == ""

    viewstate.save_preset(conn, 1, "prod only", [_f(values=["test"])])  # overwrites
    got = viewstate.list_presets(conn, 1)[1]
    assert got["filters"][0]["values"] == ["test"] and got["hide_empty"] is False
    assert got["name_filter"] == ""

    assert viewstate.delete_preset(conn, 1, "Dev") is True
    assert viewstate.delete_preset(conn, 1, "Dev") is False
    assert viewstate.delete_preset(conn, 2, "prod only") is False  # other account
    assert [p["name"] for p in viewstate.list_presets(conn, 1)] == ["prod only"]


def test_old_preset_with_a_resource_type_loads_without_it(conn):
    old = [
        {"resource_type": "ec2", "tag_key": "Env", "values": ["prod"], "include_untagged": False}
    ]
    conn.execute(
        "INSERT INTO visual_filter_presets(account_ref, name, filters, hide_empty) "
        "VALUES(1, 'old', ?, 1)",
        (json.dumps(old),),
    )
    assert viewstate.list_presets(conn, 1) == [
        {
            "name": "old",
            "filters": [{"tag_key": "Env", "values": ["prod"], "include_untagged": False}],
            "name_filter": "",
            "hide_empty": True,
        }
    ]


def test_name_filter_column_added_to_an_existing_preset_table(tmp_path):
    db = tmp_path / "old.db"
    with closing(db) as c:
        c.execute(
            "CREATE TABLE visual_filter_presets (account_ref INTEGER NOT NULL, name TEXT NOT NULL, "
            "filters TEXT NOT NULL, hide_empty INTEGER NOT NULL DEFAULT 0, "
            "PRIMARY KEY (account_ref, name))"
        )
        c.execute(
            "INSERT INTO visual_filter_presets(account_ref, name, filters) VALUES(1, 'a', '[]')"
        )
    init_db(db)
    with closing(db) as c:
        assert viewstate.list_presets(c, 1)[0]["name_filter"] == ""


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
    resp = _post(
        client,
        "/visual/filter-presets",
        {"name": "prod", "filters": filters, "name_filter": "dev, nonprod"},
    )
    assert resp.status_code == 200
    assert resp.get_json() == [
        {
            "name": "prod",
            "filters": json.loads(filters),
            "name_filter": "dev, nonprod",
            "hide_empty": False,
        }
    ]
    resp = _post(
        client, "/visual/filter-presets", {"name": "all", "filters": "[]", "hide_empty": "1"}
    )
    assert [p["name"] for p in resp.get_json()] == ["all", "prod"]
    assert resp.get_json()[0]["hide_empty"] is True and resp.get_json()[0]["name_filter"] == ""

    page = client.get(f"/visual?vpc={VPC}").get_data(as_text=True)
    assert 'id="tag-filters"' in page and 'id="tf-hide-empty"' in page
    assert 'id="tf-name"' in page and 'id="tf-type"' not in page  # no resource type picker
    assert '"name": "prod"' in page  # presets embedded for the panel
    assert "tagfilter.js" in page

    assert _post(client, "/visual/filter-presets", {"name": "", "filters": "[]"}).status_code == 400
    bad = _post(client, "/visual/filter-presets", {"name": "x", "filters": '[{"tag_key": 1}]'})
    assert bad.status_code == 400
    long_name = {"name": "x", "filters": "[]", "name_filter": "x" * 513}
    assert _post(client, "/visual/filter-presets", long_name).status_code == 400
    assert client.post("/visual/filter-presets", data={"name": "x"}).status_code == 400  # csrf

    resp = _post(client, "/visual/filter-presets/delete", {"name": "prod"})
    assert [p["name"] for p in resp.get_json()] == ["all"]


def test_visual_data_lists_types_and_keeps_every_resource(home, snapshot_builder):
    """The data endpoint is unchanged by filters (they run in the browser): every resource
    is sent, with its type, name, owners and tags, plus the type labels of the counts."""
    b = snapshot_builder(home / "iplens.db")
    b.vpc(VPC, "192.0.2.0/24").subnet("subnet-a", VPC, "192.0.2.0/26")
    b.eni("eni-0abc0001", "subnet-a", ["192.0.2.10"], name="test-server-a")
    b.eni("eni-0abc0002", "subnet-a", ["192.0.2.11"], owner_type="lambda", owner_ref="fn-a")
    b.tag("eni", "eni-0abc0001", "Env", "prod")
    with closing(home / "iplens.db") as c:
        data = queries.visual_data(c, b.id, VPC, OWNER_LABELS)
    assert data["type_labels"] == {"ec2": "EC2", "lambda": "Lambda"}
    items = data["vpc"]["subnets"][0]["items"]
    assert {(r["type"], r["eni_id"], r["name"]) for r in items} == {
        ("ec2", "eni-0abc0001", "test-server-a"),
        ("lambda", "eni-0abc0002", "fn-a"),
    }
    assert next(r for r in items if r["type"] == "ec2")["tags"] == {"Env": "prod"}
    assert next(r for r in items if r["type"] == "lambda")["owners"] == ["fn-a"]
