"""``iplens check``: the pre-deploy IP fit check.

Plan parsing per resource type (tests/fixtures/fitcheck_plan.json), unresolved subnets,
updates and replacements, company rules, exit codes and output formats, the UI exports
(snapshot and rules for CI), and snapshot mode against live mode (moto). Placeholders
only: 192.0.2.N addresses, subnet-0000000a / i-0abc1234-style ids, example names."""

from __future__ import annotations

import json
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from iplens import aws as aws_mod
from iplens import checkcli, cli, fitcheck, fitlive
from iplens.collector import Collector
from iplens.db import closing
from iplens.fitcheck import (
    BELOW_MIN,
    FITS,
    SHORT,
    CheckError,
    Plan,
    Source,
    evaluate,
    inputs_from_dict,
    inputs_to_dict,
    parse_plan,
    plan_demand,
)
from iplens.headroom import Asg, EcsService, Inputs, LambdaFn, LoadBalancer, Subnet
from iplens.rules import Rule, export_yaml, save_rule
from iplens.web import create_app

REGION = "us-east-1"
SA, SB, SC = "subnet-0000000a", "subnet-0000000b", "subnet-0000000c"
VPC = "vpc-0000000a"
SG = "sg-0001"
PLAN_FILE = Path(__file__).parent / "fixtures" / "fitcheck_plan.json"
SOURCE = Source(kind="snapshot", label="test snapshot", account_ref=1)


def _inputs(sc_free: int = 10) -> Inputs:
    """Three subnets; an ASG with 1 of max 3 instances in SC (+2 headroom in SC); an
    existing Lambda ENI for (SA, sg-0001)."""
    return Inputs(
        subnets=[
            Subnet(SA, VPC, "us-east-1a", "192.0.2.0/26", "private-a", 50, 59, 9),
            Subnet(SB, VPC, "us-east-1b", "192.0.2.64/26", "private-b", 40, 59, 19),
            Subnet(SC, VPC, "us-east-1c", "192.0.2.128/27", "private-c", sc_free, 27, 27 - sc_free),
        ],
        asgs=[Asg("asg-existing", 1, 1, 3, (SC,), (("i-0abc1234", "us-east-1c"),))],
        instance_enis={"i-0abc1234": [SC]},
        lambda_combos={(SA, (SG,))},
    )


def _plan_doc() -> dict:
    return json.loads(PLAN_FILE.read_text())


def _plan(*changes: dict) -> Plan:
    return parse_plan({"resource_changes": list(changes)})


def _rc(rtype: str, name: str, actions, after=None, before=None, unknown=None) -> dict:
    return {
        "address": f"{rtype}.{name}",
        "mode": "managed",
        "type": rtype,
        "name": name,
        "change": {
            "actions": list(actions),
            "before": before,
            "after": after,
            "after_unknown": unknown or {},
        },
    }


def _by_address(demand) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for item in demand.items:
        out.setdefault(item.address, {})
        out[item.address][item.subnet_id] = out[item.address].get(item.subnet_id, 0) + item.ips
    return out


def _write_snapshot(path: Path, inputs: Inputs, account_ref: int | None = 1) -> Path:
    doc = {
        "format": fitcheck.SNAPSHOT_FORMAT,
        "version": fitcheck.SNAPSHOT_VERSION,
        "snapshot": {
            "id": 1,
            "taken_at": "2026-10-01T00:00:00+00:00",
            "region": REGION,
            "account_id": "123456789012",
            "account_ref": account_ref,
        },
        "inputs": inputs_to_dict(inputs),
    }
    path.write_text(json.dumps(doc))
    return path


# -- plan parsing per resource type --------------------------------------------------------


def test_plan_demand_per_resource_type():
    demand = plan_demand(parse_plan(_plan_doc()), _inputs())
    assert _by_address(demand) == {
        "aws_instance.web": {SA: 1},  # 1 ENI per instance
        "aws_network_interface.extra": {SB: 1},
        "aws_lb.app": {SA: 8, SB: 8},  # ALB: 8 per subnet
        "aws_lb.nlb": {SC: 1},  # NLB: 1 per subnet (subnet_mapping)
        "aws_lb.partial": {SC: 8},  # the known subnet counts, the unknown one is unresolved
        "aws_vpc_endpoint.ssm": {SA: 1, SB: 1},  # Interface: 1 per subnet; Gateway (s3): none
        "aws_nat_gateway.ngw": {SC: 1},
        "aws_ecs_service.api": {SA: 2, SB: 2, SC: 2},  # 3 tasks + 3 surge (maxPercent 200)
        "aws_ecs_service.worker": {SA: 1, SB: 1},  # desired 2 -> 4, maxPercent 100: no surge
        "aws_autoscaling_group.app": {SA: 3, SB: 3},  # max_size 4 -> 10 over 2 subnets
        "aws_lambda_function.fn_a": {SB: 1},  # (SA, sg-0001) already has an ENI
        "aws_db_instance.db": {SA: 1, SB: 1},  # Multi-AZ: 2, AWS picks the subnets
    }
    # Not counted: no-op, delete, data sources, Gateway endpoints, non-awsvpc ECS services,
    # and fn_b, whose combination fn_a already adds.
    counted = {i.address for i in demand.items}
    for address in (
        "aws_instance.unchanged",
        "aws_network_interface.old",
        "data.aws_subnet.lookup",
        "aws_vpc_endpoint.s3",
        "aws_ecs_service.bridge",
        "aws_lambda_function.fn_b",
    ):
        assert address not in counted
    assert demand.subnet_ids == [SA, SB, SC]


def test_each_plan_item_carries_its_assumption():
    demand = plan_demand(parse_plan(_plan_doc()), _inputs())
    texts = {(i.address, i.subnet_id): i.assumption for i in demand.items}
    assert texts[("aws_instance.web", SA)] == "1 ENI per instance: its primary network interface"
    assert texts[("aws_nat_gateway.ngw", SC)] == "1 IP for the NAT gateway's ENI"
    assert texts[("aws_lb.app", SA)] == "ALB: 8 IPs per ALB per subnet"
    assert texts[("aws_lb.nlb", SC)] == "NLB: 1 ENI per subnet"
    assert texts[("aws_vpc_endpoint.ssm", SA)] == "Interface endpoint: 1 ENI per subnet"
    assert "Hyperplane ENI" in texts[("aws_lambda_function.fn_a", SB)]
    assert "each must fit 1" in texts[("aws_db_instance.db", SA)]
    assert "was 2 here, net +3" in texts[("aws_autoscaling_group.app", SA)]
    surge = [
        i for i in demand.items if i.address == "aws_ecs_service.api" and "surge" in i.assumption
    ]
    assert len(surge) == 3 and "maxPercent 200" in surge[0].assumption
    assert all(i.assumption for i in demand.items)


def test_unresolved_subnets_are_listed_with_their_need():
    demand = plan_demand(parse_plan(_plan_doc()), _inputs())
    unresolved = {u.address: (u.reason, u.ips) for u in demand.unresolved}
    assert unresolved == {
        "aws_instance.pending": ("subnet_id is known after apply", 1),
        "aws_lb.partial": ("1 subnet known after apply", 8),
        "aws_ecs_service.new_net": ("network_configuration subnets are known after apply", 4),
        "aws_db_instance.lonely": (
            "DB subnet group db-group-elsewhere is not in the plan, so its subnets are unknown",
            1,
        ),
    }


def test_no_surge_leaves_out_the_planned_ecs_surge():
    demand = plan_demand(parse_plan(_plan_doc()), _inputs(), include_surge=False)
    assert _by_address(demand)["aws_ecs_service.api"] == {SA: 1, SB: 1, SC: 1}
    assert {u.address: u.ips for u in demand.unresolved}["aws_ecs_service.new_net"] == 2


def test_ecs_surge_follows_the_headroom_rule():
    base = {"name": "svc", "desired_count": 4, "network_configuration": [{"subnets": [SA]}]}
    cases = {
        "default": ({}, 4 + 4),  # maxPercent unset: the ECS default 200
        "150": ({"deployment_maximum_percent": 150}, 4 + 2),
        "blue/green": ({"deployment_controller": [{"type": "CODE_DEPLOY"}]}, 4),
    }
    for name, (extra, want) in cases.items():
        plan = _plan(_rc("aws_ecs_service", "svc", ["create"], {**base, **extra}))
        assert sum(i.ips for i in plan_demand(plan, _inputs()).items) == want, name


def test_updates_and_replacements_count_what_they_add():
    nic = {"subnet_id": SA}
    plan = _plan(
        # Destroy first, same subnet: the old IP is freed first.
        _rc("aws_network_interface", "swap", ["delete", "create"], nic, nic),
        # create_before_destroy: both exist for a while.
        _rc("aws_network_interface", "cbd", ["create", "delete"], nic, nic),
        # Moving to another subnet needs the IP there.
        _rc("aws_instance", "moved", ["delete", "create"], {"subnet_id": SB}, {"subnet_id": SA}),
        # An ASG update without a bigger max_size adds nothing.
        _rc(
            "aws_autoscaling_group",
            "tags",
            ["update"],
            {"max_size": 4, "vpc_zone_identifier": [SA]},
            {"max_size": 4, "vpc_zone_identifier": [SA]},
        ),
        # An ALB gaining a subnet reserves 8 there only.
        _rc(
            "aws_lb",
            "grow",
            ["update"],
            {"subnets": [SA, SB], "internal": True},
            {"subnets": [SA], "internal": True},
        ),
    )
    assert _by_address(plan_demand(plan, _inputs())) == {
        "aws_network_interface.cbd": {SA: 1},
        "aws_instance.moved": {SB: 1},
        "aws_lb.grow": {SB: 8},
    }


def test_db_instance_rules():
    groups = _rc("aws_db_subnet_group", "g", ["no-op"], {"name": "grp", "subnet_ids": [SA, SB]})
    single = _rc("aws_db_subnet_group", "one", ["create"], {"name": "one", "subnet_ids": [SC]})
    plan = _plan(
        groups,
        single,
        # Multi-AZ turned on: 1 more IP (the standby) somewhere in the group.
        _rc(
            "aws_db_instance",
            "toggle",
            ["update"],
            {"db_subnet_group_name": "grp", "multi_az": True},
            {"db_subnet_group_name": "grp", "multi_az": False},
        ),
        # A pinned AZ narrows the candidates to its subnet.
        _rc(
            "aws_db_instance",
            "pinned",
            ["create"],
            {"db_subnet_group_name": "grp", "availability_zone": "us-east-1b"},
        ),
        _rc("aws_db_instance", "solo", ["create"], {"db_subnet_group_name": "one"}),
        # Destroy-first replacement into another group: counted in full there.
        _rc(
            "aws_db_instance",
            "moved",
            ["delete", "create"],
            {"db_subnet_group_name": "one"},
            {"db_subnet_group_name": "grp"},
        ),
        # ...and within the same group: the old IP is freed first.
        _rc(
            "aws_db_instance",
            "rebuilt",
            ["delete", "create"],
            {"db_subnet_group_name": "grp"},
            {"db_subnet_group_name": "grp"},
        ),
        _rc("aws_db_instance", "same", ["update"], {"db_subnet_group_name": "grp"}, {"x": 1}),
    )
    demand = plan_demand(plan, _inputs())
    assert _by_address(demand) == {
        "aws_db_instance.toggle": {SA: 1, SB: 1},
        "aws_db_instance.pinned": {SB: 1},
        "aws_db_instance.solo": {SC: 1},
        "aws_db_instance.moved": {SC: 1},
    }
    toggle = next(i for i in demand.items if i.address == "aws_db_instance.toggle")
    assert toggle.assumption.startswith("Multi-AZ turned on: 1 IP for the standby")


def test_db_subnet_group_from_prior_state_and_unknown_group():
    doc = {
        "prior_state": {
            "values": {
                "root_module": {
                    "child_modules": [
                        {
                            "resources": [
                                {
                                    "type": "aws_db_subnet_group",
                                    "values": {"name": "old-grp", "subnet_ids": [SC]},
                                }
                            ]
                        }
                    ]
                }
            }
        },
        "resource_changes": [
            _rc("aws_db_instance", "a", ["create"], {"db_subnet_group_name": "old-grp"}),
            _rc(
                "aws_db_instance",
                "b",
                ["create"],
                {},
                unknown={"db_subnet_group_name": True},
            ),
        ],
    }
    demand = plan_demand(parse_plan(doc), _inputs())
    assert _by_address(demand) == {"aws_db_instance.a": {SC: 1}}
    assert [u.reason for u in demand.unresolved] == ["db_subnet_group_name is known after apply"]


def test_lambda_combinations():
    def fn(name, subnets, sgs, unknown=None, actions=("create",), before=None):
        cfg = {"subnet_ids": subnets, "security_group_ids": sgs}
        return _rc("aws_lambda_function", name, actions, {"vpc_config": [cfg]}, before, unknown)

    plan = _plan(
        fn("existing", [SA], [SG]),  # combination has an ENI already
        fn("new_sg", [SA], ["sg-0002"]),
        fn("same_new_sg", [SA], ["sg-0002"]),  # shares new_sg's new ENI
        # A security group created by the plan: always a new combination.
        fn("unknown_sg", [SB], [], unknown={"vpc_config": [{"security_group_ids": True}]}),
        # An update adding a subnet: only the new combination counts.
        fn(
            "grow",
            [SB, SC],
            ["sg-0003"],
            actions=("update",),
            before={"vpc_config": [{"subnet_ids": [SB], "security_group_ids": ["sg-0003"]}]},
        ),
        fn("nowhere", [], [], unknown={"vpc_config": [{"subnet_ids": True}]}),
    )
    demand = plan_demand(plan, _inputs())
    assert _by_address(demand) == {
        "aws_lambda_function.new_sg": {SA: 1},
        "aws_lambda_function.unknown_sg": {SB: 1},
        "aws_lambda_function.grow": {SC: 1},
    }
    assert [u.address for u in demand.unresolved] == ["aws_lambda_function.nowhere"]


def test_strings_walks_nested_blocks_and_counts_unknowns():
    value = {"blocks": [{"ids": ["a", None]}, {"ids": ["b", "a"]}]}
    unknown = {"blocks": [{"ids": [False, True]}, {}]}
    assert fitcheck._strings(value, unknown, "blocks", "ids") == (["a", "b"], 1)
    assert fitcheck._strings({}, {"blocks": True}, "blocks", "ids") == ([], 1)
    assert fitcheck._strings({"blocks": []}, {}, "blocks", "ids") == ([], 0)


def test_not_a_plan_is_an_error():
    with pytest.raises(CheckError, match="not a Terraform plan"):
        parse_plan({"values": {"root_module": {}}})  # `terraform show -json` of a state


# -- evaluation -----------------------------------------------------------------------------


def test_result_is_free_minus_headroom_minus_plan():
    plan = parse_plan(_plan_doc())
    result = evaluate(_inputs(), plan_demand(plan, _inputs()), SOURCE, plan=plan)
    rows = {f.subnet.subnet_id: f for f in result.subnets}
    assert (rows[SA].free, rows[SA].existing_demand, rows[SA].plan_demand, rows[SA].left) == (
        50,
        0,
        17,
        33,
    )
    assert (rows[SB].plan_demand, rows[SB].left) == (18, 22)
    # SC: 10 free - 2 (ASG asg-existing at max) - 12 planned.
    assert (rows[SC].existing_demand, rows[SC].plan_demand, rows[SC].left) == (2, 12, -4)
    assert rows[SC].status == SHORT and result.subnets[0] is rows[SC]  # failing first
    assert not result.ok and result.exit_code == 1
    assert result.summary.startswith("DOES NOT FIT: 1 subnet short of IPs")
    assert "(4 unresolved, not counted)" in result.summary


def test_min_free_pct_fails_a_subnet_below_it():
    plan = parse_plan(_plan_doc())
    inputs = _inputs(sc_free=30)  # SC: 30 - 2 - 12 = 16 left of 27 usable (59%)
    ok = evaluate(inputs, plan_demand(plan, inputs), SOURCE, plan=plan)
    assert ok.ok and ok.exit_code == 0 and {f.status for f in ok.subnets} == {FITS}
    strict = evaluate(inputs, plan_demand(plan, inputs), SOURCE, plan=plan, min_free_pct=40)
    # SB: 22 / 59 = 37.3% < 40%.
    assert [f.subnet.subnet_id for f in strict.failing] == [SB]
    assert strict.failing[0].status == BELOW_MIN and strict.exit_code == 1


def test_unknown_subnet_is_an_error():
    plan = _plan(_rc("aws_instance", "x", ["create"], {"subnet_id": "subnet-0000000f"}))
    with pytest.raises(CheckError, match="subnet-0000000f"):
        evaluate(_inputs(), plan_demand(plan, _inputs()), SOURCE, plan=plan)


# -- company rules --------------------------------------------------------------------------


def _rules_file(tmp_path: Path, *rules: Rule) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(export_yaml(rules))
    return path


def _check_rules(*rules: Rule, plan: Plan | None = None, inputs=None, account_ref=1):
    inputs = inputs or _inputs(sc_free=30)
    plan = plan or parse_plan(_plan_doc())
    source = Source(kind="snapshot", label="test", account_ref=account_ref)
    return evaluate(inputs, plan_demand(plan, inputs), source, plan=plan, rules=rules)


def test_rules_min_free_and_reserved_subnet():
    result = _check_rules(
        Rule("keep-50", "min_free_pct", {"percent": 50, "subnet_ids": [SA, SB]}),
        Rule("reserved-c", "subnet_reserved", {"subnet_ids": [SC]}),
        Rule("off", "subnet_reserved", {"subnet_ids": [SA]}, enabled=False),
    )
    # SA keeps 33 / 59 = 55.9% free; SB only 22 / 59.
    assert [v.text for v in result.violations] == [
        f"keep-50 (min_free_pct): {SB} would have 37.3% free at max scale after the change (< 50%)",
        "reserved-c (subnet_reserved): places 12 IPs in reserved subnet "
        f"{SC} (aws_ecs_service.api, aws_lb.nlb, aws_lb.partial, aws_nat_gateway.ngw)",
    ]
    assert result.exit_code == 1 and "2 rule violations" in result.summary


def test_rules_on_plan_resources():
    plan = _plan(
        _rc(
            "aws_lb", "public", ["create"], {"name": "alb-pub", "internal": False, "subnets": [SA]}
        ),
        _rc(
            "aws_lb", "other", ["create"], {"name": "alb-other", "internal": False, "subnets": [SA]}
        ),
        _rc("aws_lambda_function", "flat", ["create"], {"function_name": "fn-flat"}),
        _rc(
            "aws_network_interface",
            "gone",
            ["delete"],
            None,
            {"id": "eni-0abc1234", "description": "bucket-a gateway", "subnet_id": SA},
        ),
        _rc("aws_network_interface", "keep", ["delete"], None, {"id": "eni-0abc5678"}),
    )
    result = _check_rules(
        Rule("internal", "internal_only", {"scope": "load_balancer", "lb_names": ["alb-pub"]}),
        Rule("vpc-lambda", "lambda_vpc_required", {}),
        Rule("protect", "protected_eni", {"pattern": "bucket-a"}),
        Rule("no-scale-down", "ecs_scale_down", {"mode": "deny", "pattern": ""}),
        plan=plan,
    )
    assert [v.text for v in result.violations] == [
        "internal (internal_only): aws_lb.public would be internet-facing",
        "vpc-lambda (lambda_vpc_required): aws_lambda_function.flat is not VPC-attached",
        "protect (protected_eni): aws_network_interface.gone (eni-0abc1234) would be removed",
    ]
    assert any("no-scale-down" in n and "only applies to suggestions" in n for n in result.notes)


def test_account_scoped_rules():
    rule = Rule("reserved-c", "subnet_reserved", {"subnet_ids": [SC]}, account_ref=7)
    assert _check_rules(rule, account_ref=7).violations  # the snapshot's account
    assert not _check_rules(rule, account_ref=1).violations  # another account
    live = _check_rules(rule, account_ref=None)
    assert not live.violations
    assert any("limited to IPLens account 7" in n for n in live.notes)


# -- snapshot for CI ------------------------------------------------------------------------


def test_snapshot_inputs_round_trip():
    inputs = Inputs(
        subnets=[Subnet(SA, VPC, "us-east-1a", "192.0.2.0/26", "a", 50, 59, 9)],
        asgs=[Asg("asg-a", 1, 2, 6, (SA, SB), (("i-0abc1234", "us-east-1a"),))],
        ecs=[EcsService("cluster-a", "api", 2, 2, (SA,), 150, "ECS")],
        ecs_max={("cluster-a", "api"): 8},
        lbs=[LoadBalancer("alb-a", "application", None)],
        lambdas=[LambdaFn("fn-a", (SA,), (SG,))],
        instance_enis={"i-0abc1234": [SA]},
        task_subnets={("cluster-a", "api"): {SA: 2}},
        lb_eni_subnets={"alb-a": {SA}},
        lambda_combos={(SA, (SG,))},
        missing=frozenset({"lambda:ListFunctions"}),
    )
    data = json.loads(json.dumps(inputs_to_dict(inputs)))
    assert inputs_from_dict(data) == inputs
    with pytest.raises(ValueError, match="malformed"):
        inputs_from_dict({"subnets": [{"vpc_id": VPC}]})


def test_load_snapshot_checks_the_format(tmp_path):
    path = _write_snapshot(tmp_path / "snap.json", _inputs())
    inputs, source = fitcheck.load_snapshot(path)
    assert inputs == _inputs() and source.account_ref == 1
    assert (
        source.label
        == "snapshot snap.json taken 2026-10-01T00:00:00+00:00 (123456789012, us-east-1)"
    )
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"format": "something-else"}))
    with pytest.raises(CheckError, match="not an IPLens snapshot"):
        fitcheck.load_snapshot(bad)
    bad.write_text(json.dumps({"format": fitcheck.SNAPSHOT_FORMAT, "version": 99}))
    with pytest.raises(CheckError, match="version 99"):
        fitcheck.load_snapshot(bad)


# -- the command: exit codes and output -----------------------------------------------------


@pytest.fixture
def files(tmp_path):
    return {
        "plan": str(PLAN_FILE),
        "short": str(_write_snapshot(tmp_path / "short.json", _inputs())),
        "fits": str(_write_snapshot(tmp_path / "fits.json", _inputs(sc_free=30))),
        "dir": tmp_path,
    }


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    code = checkcli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_exit_0_when_the_plan_fits(files, capsys):
    code, out, _ = _run(capsys, "--plan", files["plan"], "--snapshot", files["fits"])
    assert code == 0
    assert "Result: FITS: 3 subnets checked (4 unresolved, not counted)" in out
    assert "Unresolved (known after apply, not counted):" in out
    assert "aws_instance.pending: subnet_id is known after apply (needs 1 IP, not counted)" in out
    assert "  plan      aws_instance.web: +1 (1 ENI per instance" in out
    assert "  headroom  ASG asg-existing: +2" in out


def test_exit_1_when_a_subnet_is_short_or_below_min(files, capsys):
    code, out, _ = _run(capsys, "--plan", files["plan"], "--snapshot", files["short"])
    assert code == 1 and "Result: DOES NOT FIT: 1 subnet short of IPs" in out
    code, out, _ = _run(
        capsys, "--plan", files["plan"], "--snapshot", files["fits"], "--min-free-pct", "40"
    )
    assert code == 1 and "1 subnet below 40% free" in out


def test_exit_1_on_a_rule_violation(files, capsys):
    rules = _rules_file(files["dir"], Rule("reserved-c", "subnet_reserved", {"subnet_ids": [SC]}))
    code, out, _ = _run(
        capsys, "--plan", files["plan"], "--snapshot", files["fits"], "--rules", str(rules)
    )
    assert code == 1 and "Rule violations:" in out and "reserved-c (subnet_reserved)" in out


def test_only_unresolved_demand_warns_but_passes(files, capsys):
    doc = _plan_doc()
    doc["resource_changes"] = [
        rc for rc in doc["resource_changes"] if rc["address"] == "aws_instance.pending"
    ]
    plan = files["dir"] / "pending.json"
    plan.write_text(json.dumps(doc))
    code, out, _ = _run(
        capsys, "--plan", str(plan), "--snapshot", files["short"], "--format", "json"
    )
    data = json.loads(out)
    assert code == 0 and data["result"] == "fits" and data["subnets"] == []
    assert data["unresolved"] == [
        {
            "address": "aws_instance.pending",
            "type": "aws_instance",
            "reason": "subnet_id is known after apply",
            "ips": 1,
        }
    ]


def test_subnet_need_mode(files, capsys):
    code, out, _ = _run(capsys, "--subnet", SB, "--need", "40", "--snapshot", files["short"])
    assert code == 0 and "Result: FITS: 1 subnet checked" in out
    code, out, _ = _run(capsys, "--subnet", SC, "--need", "9", "--snapshot", files["short"])
    # 10 free - 2 headroom - 9 = -1.
    assert code == 1 and "--need: +9 (9 more IPs requested)" in out
    rules = _rules_file(files["dir"], Rule("reserved-b", "subnet_reserved", {"subnet_ids": [SB]}))
    code, _, _ = _run(
        capsys, "--subnet", SB, "--need", "1", "--snapshot", files["short"], "--rules", str(rules)
    )
    assert code == 1


@pytest.mark.parametrize(
    "argv, message",
    [
        (["--plan", "missing.json", "--snapshot", "SNAP"], "cannot read plan file"),
        (["--plan", "BADJSON", "--snapshot", "SNAP"], "invalid JSON"),
        (["--plan", "SNAP", "--snapshot", "SNAP"], "not a Terraform plan"),
        (["--plan", "PLAN", "--snapshot", "PLAN"], "not an IPLens snapshot"),
        (["--subnet", "subnet-0000000f", "--need", "1", "--snapshot", "SNAP"], "not found"),
        (["--plan", "PLAN", "--snapshot", "SNAP", "--rules", "BADRULES"], "unknown rule kind"),
    ],
)
def test_exit_2_on_errors(files, capsys, argv, message):
    (files["dir"] / "bad.json").write_text("{nope")
    (files["dir"] / "bad-rules.yaml").write_text("rules:\n  - {name: x, kind: nope}\n")
    subst = {
        "SNAP": files["short"],
        "PLAN": files["plan"],
        "BADJSON": str(files["dir"] / "bad.json"),
        "BADRULES": str(files["dir"] / "bad-rules.yaml"),
    }
    code, out, err = _run(capsys, *[subst.get(a, a) for a in argv])
    assert code == 2 and message in err and out == ""


def test_exit_2_json_error_document(files, capsys):
    code, out, _ = _run(
        capsys, "--subnet", "subnet-0000000f", "--need", "1", "--snapshot", files["short"],
        "--format", "json",
    )  # fmt: skip
    assert code == 2 and json.loads(out)["result"] == "error"


@pytest.mark.parametrize(
    "argv",
    [
        [],  # neither --plan nor --subnet
        ["--subnet", SA],  # no --need
        ["--plan", "p.json", "--need", "3"],  # --need without --subnet
        ["--plan", "p.json", "--subnet", SA, "--need", "1"],  # both
        ["--subnet", SA, "--need", "-1"],
        ["--plan", "p.json", "--min-free-pct", "101"],
        ["--plan", "p.json", "--format", "xml"],
    ],
)
def test_bad_arguments_exit_2(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        checkcli.main(argv)
    assert exc.value.code == 2


def test_iplens_check_subcommand_dispatch(files, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--plan", files["plan"], "--snapshot", files["fits"]])
    assert exc.value.code == 0
    assert "IPLens IP fit check of the plan" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--plan", files["plan"], "--snapshot", files["short"]])
    assert exc.value.code == 1


def test_json_output(files, capsys):
    code, out, _ = _run(
        capsys, "--plan", files["plan"], "--snapshot", files["short"], "--format", "json"
    )
    data = json.loads(out)
    assert code == 1 and data["exit_code"] == 1 and data["result"] == "does-not-fit"
    sc = data["subnets"][0]
    assert (sc["subnet_id"], sc["free"], sc["headroom_demand"], sc["plan_demand"], sc["left"]) == (
        SC,
        10,
        2,
        12,
        -4,
    )
    assert sc["status"] == "short" and sc["headroom"][0]["kind"] == "asg"
    assert {p["address"] for p in sc["plan"]} == {
        "aws_ecs_service.api",
        "aws_lb.nlb",
        "aws_lb.partial",
        "aws_nat_gateway.ngw",
    }
    assert data["source"]["kind"] == "snapshot" and len(data["unresolved"]) == 4


def test_markdown_output_for_pr_comments(files, capsys):
    code, out, _ = _run(
        capsys, "--plan", files["plan"], "--snapshot", files["short"], "--format", "markdown"
    )
    assert code == 1
    assert out.startswith("### ❌ IPLens IP fit check: DOES NOT FIT")
    assert "| Subnet | Name | AZ | CIDR | Free | Headroom | Plan | Left | Left % | Result |" in out
    row = f"| `{SC}` | private-c | us-east-1c | 192.0.2.128/27 | 10 | 2 | 12 | -4 | -14.8% |"
    assert f"{row} **SHORT** |" in out
    assert "**Unresolved** (known after apply, not counted)" in out
    assert "<details><summary>Demand per subnet</summary>" in out
    code, out, _ = _run(
        capsys, "--plan", files["plan"], "--snapshot", files["fits"], "--format", "markdown"
    )
    assert code == 0 and out.startswith("### ✅ IPLens IP fit check: FITS")


def test_markdown_escapes_table_breaking_text():
    assert checkcli._md("a|b <script>") == "a\\|b &lt;script&gt;"


# -- UI exports -----------------------------------------------------------------------------


@pytest.fixture
def app(home):
    return create_app(home, testing=True)


def _db(app) -> Path:
    return app.extensions["iplens"]["paths"].db_path


def test_export_snapshot_for_ci_round_trips_into_the_check(
    app, snapshot_builder, ips, tmp_path, capsys
):
    client = app.test_client()
    assert client.get("/headroom/export-ci.json").status_code == 404  # no snapshot yet
    b = snapshot_builder(_db(app))
    b.vpc(VPC, "192.0.2.0/24")
    b.subnet(SA, VPC, "192.0.2.0/26", name="private-a")
    b.eni("eni-0abc1234", SA, ips("192.0.2.0", 4, 10), owner_ref="i-0abc1234")
    page = client.get("/headroom").get_data(as_text=True)
    assert 'href="/headroom/export-ci.json"' in page and "Export snapshot for CI" in page
    resp = client.get("/headroom/export-ci.json")
    assert resp.status_code == 200
    assert "attachment; filename=iplens-ci-snapshot.json" in resp.headers["Content-Disposition"]
    doc = resp.get_json()
    assert doc["format"] == fitcheck.SNAPSHOT_FORMAT and doc["snapshot"]["id"] == b.id
    assert doc["snapshot"]["account_ref"] == b.account_ref
    assert doc["inputs"]["subnets"][0]["free"] == 59 - 10
    assert "secret" not in resp.get_data(as_text=True).lower()
    snap = tmp_path / "snap.json"
    snap.write_bytes(resp.get_data())
    code, out, _ = _run(capsys, "--subnet", SA, "--need", "49", "--snapshot", str(snap))
    assert code == 0
    code, out, _ = _run(capsys, "--subnet", SA, "--need", "50", "--snapshot", str(snap))
    assert code == 1


def test_export_rules_for_ci_keeps_this_accounts_rules(app, tmp_path):
    with closing(_db(app)) as conn:
        active = conn.execute("SELECT MIN(id) FROM accounts").fetchone()[0]
        other = conn.execute(
            "INSERT INTO accounts(display_name, region, auth_mode) VALUES('b', 'us-east-1', 'env')"
        ).lastrowid
        save_rule(conn, Rule("global", "subnet_reserved", {"subnet_ids": [SA]}))
        save_rule(conn, Rule("mine", "min_free_pct", {"percent": 10}, account_ref=active))
        save_rule(conn, Rule("theirs", "min_free_pct", {"percent": 90}, account_ref=other))
    client = app.test_client()
    assert 'href="/rules/export-ci.yaml"' in client.get("/rules").get_data(as_text=True)
    resp = client.get("/rules/export-ci.yaml")
    assert "iplens-ci-rules.yaml" in resp.headers["Content-Disposition"]
    path = tmp_path / "rules.yaml"
    path.write_bytes(resp.get_data())
    rules = fitcheck.load_rules(path)
    assert [(r.name, r.account_ref) for r in rules] == [("global", None), ("mine", None)]


# -- live mode (moto) vs snapshot mode ------------------------------------------------------


@pytest.fixture
def aws_env():
    """Two subnets in 192.0.2.0/24, an ASG over both (max 6), an awsvpc ECS service
    (desired 2, auto scaling max 4), a Lambda ENI for (subnet a, sg) and an ALB ENI in
    subnet b."""
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc_id = ec2.create_vpc(CidrBlock="192.0.2.0/24")["Vpc"]["VpcId"]
        sa = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="192.0.2.0/26", AvailabilityZone="us-east-1a"
        )["Subnet"]["SubnetId"]
        sb = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="192.0.2.64/26", AvailabilityZone="us-east-1b"
        )["Subnet"]["SubnetId"]
        sg = ec2.create_security_group(GroupName="sg-a", Description="example", VpcId=vpc_id)[
            "GroupId"
        ]
        image_id = ec2.describe_images()["Images"][0]["ImageId"]
        ec2.create_launch_template(
            LaunchTemplateName="lt-a",
            LaunchTemplateData={"ImageId": image_id, "InstanceType": "t3.micro"},
        )
        boto3.client("autoscaling", region_name=REGION).create_auto_scaling_group(
            AutoScalingGroupName="asg-a",
            MinSize=1,
            MaxSize=6,
            DesiredCapacity=2,
            LaunchTemplate={"LaunchTemplateName": "lt-a"},
            VPCZoneIdentifier=f"{sa},{sb}",
        )
        ecs = boto3.client("ecs", region_name=REGION)
        ecs.create_cluster(clusterName="cluster-a")
        ecs.register_task_definition(
            family="td-a",
            networkMode="awsvpc",
            containerDefinitions=[{"name": "app", "image": "example", "memory": 128}],
        )
        ecs.create_service(
            cluster="cluster-a",
            serviceName="api",
            taskDefinition="td-a",
            desiredCount=2,
            networkConfiguration={
                "awsvpcConfiguration": {"subnets": [sa, sb], "securityGroups": [sg]}
            },
        )
        boto3.client("application-autoscaling", region_name=REGION).register_scalable_target(
            ServiceNamespace="ecs",
            ResourceId="service/cluster-a/api",
            ScalableDimension="ecs:service:DesiredCount",
            MinCapacity=1,
            MaxCapacity=4,
        )
        ec2.create_network_interface(
            SubnetId=sa, Groups=[sg], Description="AWS Lambda VPC ENI-fn-a-0abc1234"
        )
        yield {"a": sa, "b": sb, "sg": sg, "ec2": ec2}


def _live_plan(tmp_path: Path, env: dict) -> Path:
    doc = {
        "resource_changes": [
            _rc("aws_instance", "web", ["create"], {"subnet_id": env["a"]}),
            _rc(
                "aws_lambda_function",
                "fn",
                ["create"],
                {
                    "vpc_config": [
                        {"subnet_ids": [env["a"], env["b"]], "security_group_ids": [env["sg"]]}
                    ]
                },
            ),
        ]
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(doc))
    return path


def _subnet_rows(out: str) -> dict:
    return {
        s["subnet_id"]: (s["free"], s["headroom_demand"], s["plan_demand"], s["left"])
        for s in json.loads(out)["subnets"]
    }


def test_live_mode_matches_snapshot_mode(aws_env, app, tmp_path, capsys, monkeypatch):
    sa, sb = aws_env["a"], aws_env["b"]
    plan = _live_plan(tmp_path, aws_env)
    # Snapshot mode: Refresh into IPLens, export the snapshot for CI, check against it.
    with closing(_db(app)) as conn:
        ref = conn.execute("SELECT MIN(id) FROM accounts").fetchone()[0]
    gw = aws_mod.AwsGateway(boto3.session.Session(region_name=REGION))
    Collector(gw, _db(app), account_ref=ref).run()
    snap = tmp_path / "snap.json"
    snap.write_bytes(app.test_client().get("/headroom/export-ci.json").get_data())
    code, out, _ = _run(capsys, "--plan", str(plan), "--snapshot", str(snap), "--format", "json")
    from_snapshot = _subnet_rows(out)
    # Live mode: the same environment straight from (mocked) AWS.
    code_live, out_live, _ = _run(
        capsys, "--plan", str(plan), "--region", REGION, "--format", "json"
    )
    live = _subnet_rows(out_live)
    assert code == code_live == 0
    assert live == from_snapshot
    # ASG: 6 - 2 = 4 more, 2 per subnet; ECS: the scalable target's max 4, running 0 -> 2
    # per subnet, surge 4 -> 2 per subnet; plan: the instance in a, the Lambda only in b
    # (a has an ENI).
    assert live[sa][1:3] == (2 + 2 + 2, 1) and live[sb][1:3] == (2 + 2 + 2, 1)
    data = json.loads(out_live)
    assert not any("DescribeScalableTargets" in n for n in data["notes"])
    ecs = [h for s in data["subnets"] for h in s["headroom"] if h["kind"] == "ecs"]
    assert ecs and all("max 4" in h["assumption"] for h in ecs)


def test_live_mode_without_application_autoscaling_counts_to_desired(
    aws_env, tmp_path, capsys, monkeypatch
):
    real_client = aws_mod.AwsGateway.client

    def no_scaling(self, service, **kw):
        if service == "application-autoscaling":
            raise fitlive.ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "no"}},
                "DescribeScalableTargets",
            )
        return real_client(self, service, **kw)

    monkeypatch.setattr(aws_mod.AwsGateway, "client", no_scaling)
    code, out, _ = _run(
        capsys, "--subnet", aws_env["a"], "--need", "1", "--region", REGION, "--format", "json"
    )
    assert code == 0
    data = json.loads(out)
    ecs = [h for h in data["subnets"][0]["headroom"] if h["kind"] == "ecs"]
    assert ecs[0]["ips"] == 1 and "scaling unknown, max = desired 2" in ecs[0]["assumption"]
    assert (
        "application-autoscaling:DescribeScalableTargets failed (AccessDeniedException)."
        in (data["notes"])
    )
    assert any("DescribeScalableTargets was skipped in the live check" in n for n in data["notes"])


def test_live_mode_only_reads_the_involved_subnets(aws_env, tmp_path, capsys, monkeypatch):
    calls: list[tuple[str, str, dict]] = []
    real_guard = aws_mod._guard_read_only

    def recording_guard(model=None, params=None, **kw):
        calls.append((model.service_model.service_name, model.name, params or {}))
        real_guard(model=model, params=params, **kw)

    monkeypatch.setattr(aws_mod, "_guard_read_only", recording_guard)
    timeouts: list[float] = []
    real_timeouts = fitlive.call_timeouts
    monkeypatch.setattr(fitlive, "call_timeouts", lambda t: timeouts.append(t) or real_timeouts(t))
    code, out, _ = _run(
        capsys, "--subnet", aws_env["b"], "--need", "3", "--region", REGION, "--timeout", "20"
    )
    assert code == 0
    assert {(svc, op) for svc, op, _ in calls} <= {
        ("ec2", "DescribeSubnets"),
        ("ec2", "DescribeNetworkInterfaces"),
        ("autoscaling", "DescribeAutoScalingGroups"),
        ("ecs", "ListClusters"),
        ("ecs", "ListServices"),
        ("ecs", "DescribeServices"),
        ("application-autoscaling", "DescribeScalableTargets"),
    }
    # The EC2 calls are filtered to the one subnet (the serialized query of the request).
    ec2_bodies = [p["body"] for svc, _op, p in calls if svc == "ec2"]
    assert len(ec2_bodies) == 2
    for body in ec2_bodies:
        filters = {k: v for k, v in body.items() if k.startswith("Filter.")}
        assert filters == {"Filter.1.Name": "subnet-id", "Filter.1.Value.1": aws_env["b"]}
    # The scalable targets are those of the services found in the subnet.
    scaling = [p["body"] for svc, _op, p in calls if svc == "application-autoscaling"]
    assert len(scaling) == 1
    assert json.loads(scaling[0])["ResourceIds"] == ["service/cluster-a/api"]
    # The Refresh timeouts: the required resources get at least 120s, the others --timeout.
    assert timeouts == [120, 20, 20, 20]


def test_live_mode_alb_and_skipped_sources(aws_env, tmp_path, capsys, monkeypatch):
    aws_env["ec2"].create_network_interface(
        SubnetId=aws_env["b"], Description="ELB app/alb-a/0abc1234"
    )
    real_client = aws_mod.AwsGateway.client

    def no_ecs(self, service, **kw):
        if service == "ecs":
            raise fitlive.ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "ListClusters"
            )
        return real_client(self, service, **kw)

    monkeypatch.setattr(aws_mod.AwsGateway, "client", no_ecs)
    code, out, _ = _run(
        capsys, "--subnet", aws_env["b"], "--need", "1", "--region", REGION, "--format", "json"
    )
    data = json.loads(out)
    kinds = {h["kind"]: h for h in data["subnets"][0]["headroom"]}
    assert kinds["alb"]["name"] == "alb-a" and kinds["alb"]["ips"] == 8
    assert "ecs" not in kinds
    assert "ECS services could not be read (AccessDeniedException)." in data["notes"]
    assert any("ECS services and tasks was skipped in the live check" in n for n in data["notes"])


def test_live_mode_errors_exit_2(aws_env, capsys, monkeypatch):
    code, _, err = _run(capsys, "--subnet", "subnet-0000000f", "--need", "1", "--region", REGION)
    assert code == 2 and "not found in the live check: subnet-0000000f" in err
    monkeypatch.delenv("AWS_DEFAULT_REGION")
    monkeypatch.delenv("AWS_REGION", raising=False)
    code, _, err = _run(capsys, "--subnet", aws_env["a"], "--need", "1")
    assert code == 2 and "no AWS region" in err


def test_live_mode_without_demand_makes_no_aws_call(capsys, monkeypatch, tmp_path):
    def boom(*_a, **_k):
        raise AssertionError("no AWS call expected")

    monkeypatch.setattr(fitlive, "gateway", boom)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"resource_changes": []}))
    code, out, _ = _run(capsys, "--plan", str(plan))
    assert code == 0 and "No IP demand in known subnets." in out
