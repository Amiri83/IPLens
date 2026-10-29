"""Effective access: which connections the security groups and IAM actually allow.

The Visual page draws a connection only when both checks allow it; the others are
*blocked* (drawn dashed red under "Show blocked", with the reason).

Network (pure analysis of the snapshot's security group rules, no AWS call): a flow
A -> B on a protocol / port range needs

- an **egress** rule of one of A's security groups (all of them, as a union) naming one of
  B's groups or a CIDR containing one of B's private IPs, and
- an **ingress** rule of one of B's groups naming one of A's groups or a CIDR containing
  one of A's IPs,

with at least one port allowed by both. An ENI without security groups is not filtered on
its side. A side whose groups' rules are not in the snapshot (DescribeSecurityGroups
skipped, or egress CIDR rules of a snapshot from before 1.6.0) is "not checked" and does
not block.

Identity (IAM): the Extended crawl simulates, per compute principal (a Lambda function's
execution role, an ECS service's task role; its task execution role for ECR image pulls),
the actions a connection needs with ``iam:SimulatePrincipalPolicy`` and caches the
decisions in the snapshot (``iam_sims``; a retry of skipped resources keeps them). The
resource policy of an SQS queue / SNS topic is evaluated by the crawl as well, the VPC
endpoint policy (collected with the endpoint) when the Visual page is built. A
connection without simulation data (no crawl yet, a principal without a role) is "not
checked" and does not block.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

PORT_MAX = 65535
ALL = "all"
_PROTOCOLS = {"-1": ALL, "6": "tcp", "17": "udp", "1": "icmp"}

ALLOWED = "allowed"
EXPLICIT_DENY = "explicitDeny"
IMPLICIT_DENY = "implicitDeny"

# Interface endpoint service name suffix -> the action pulling an image through it needs.
ECR_ACTIONS = {".ecr.api": "ecr:GetAuthorizationToken", ".ecr.dkr": "ecr:BatchGetImage"}
# Extended view connections checked against IAM: target service -> action of the source.
SEND_ACTIONS = {"sqs": "sqs:SendMessage", "sns": "sns:Publish"}
# An SQS event source mapping (queue -> function): the function's role receives.
RECEIVE_ACTION = "sqs:ReceiveMessage"
COMPUTE = ("lambda", "ecs")
# Reasons listed per side of a network verdict.
MAX_REASONS = 3


# -- ports --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Ports:
    """A protocol and port range; ``proto`` "all" is any protocol."""

    proto: str
    lo: int = 0
    hi: int = PORT_MAX

    def __str__(self) -> str:
        if self.proto == ALL:
            return ALL
        if (self.lo, self.hi) == (0, PORT_MAX):
            return self.proto
        return (
            f"{self.proto}/{self.lo}" if self.lo == self.hi else f"{self.proto}/{self.lo}-{self.hi}"
        )


def norm_proto(protocol: Any) -> str:
    proto = str(protocol).lower()
    return _PROTOCOLS.get(proto, proto)


def rule_ports(protocol: Any, from_port: int | None, to_port: int | None) -> Ports:
    """The ports of a rule row (``from_port`` None or -1: every port)."""
    proto = norm_proto(protocol)
    if proto == ALL or from_port is None or from_port == -1:
        return Ports(proto)
    return Ports(proto, int(from_port), int(from_port if to_port is None else to_port))


def parse_ports(text: str) -> Ports:
    """An ``sg_refs.ports`` string: "all", "tcp", "tcp/443", "tcp/8000-8100"."""
    proto, _, span = text.partition("/")
    if not span:
        return rule_ports(proto, None, None)
    lo, _, hi = span.partition("-")
    return rule_ports(proto, int(lo), int(hi or lo))


def meet(a: Ports, b: Ports) -> Ports | None:
    """What both ``a`` and ``b`` allow; None if nothing."""
    if a.proto == ALL:
        proto = b.proto
    elif b.proto in (ALL, a.proto):
        proto = a.proto
    else:
        return None
    lo, hi = max(a.lo, b.lo), min(a.hi, b.hi)
    return Ports(proto, lo, hi) if lo <= hi else None


# -- network check ------------------------------------------------------------------------


class Peer(Protocol):
    """An ENI as the network check sees it (``iplens.visual._Node``)."""

    name: str
    sgs: tuple[str, ...]
    ips: tuple[str, ...]


@dataclass(frozen=True)
class _Rule:
    group: str
    ports: Ports
    peer_group: str = ""
    cidr: Any = None  # ipaddress.IPv4Network

    def matches(self, peer: Peer) -> bool:
        if self.peer_group:
            return self.peer_group in peer.sgs
        return any(_in(ip, self.cidr) for ip in peer.ips)


def _in(ip: str, net: Any) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


@dataclass
class Verdict:
    """``allowed`` False: blocked. ``checked`` False: nothing to check it against."""

    allowed: bool
    lines: list[str] = field(default_factory=list)
    checked: bool = True


class SgRules:
    """The security group rules of one snapshot, by direction and group."""

    def __init__(self, conn: sqlite3.Connection, snap_id: int, names: dict[str, str] | None):
        self.names = names or {}
        self.rules: dict[tuple[str, str], list[_Rule]] = {}
        # Groups whose rules are in the snapshot: {group: egress CIDR rules collected}.
        self.known: dict[str, bool] = {
            r["group_id"]: bool(r["egress_collected"])
            for r in conn.execute(
                "SELECT group_id, egress_collected FROM security_groups WHERE snapshot_id=?",
                (snap_id,),
            )
        }
        for r in conn.execute(
            "SELECT group_id, direction, ref_group_id, ports FROM sg_refs WHERE snapshot_id=? "
            "ORDER BY group_id, direction, ref_group_id, ports",
            (snap_id,),
        ):
            self._add(
                r["direction"],
                _Rule(r["group_id"], parse_ports(r["ports"]), peer_group=r["ref_group_id"]),
            )
        for direction, table in (("ingress", "sg_cidr_rules"), ("egress", "sg_egress_cidr_rules")):
            for r in conn.execute(
                f"SELECT group_id, cidr, ip_protocol, from_port, to_port FROM {table} "  # noqa: S608
                "WHERE snapshot_id=? ORDER BY group_id, cidr, ip_protocol, from_port, to_port",
                (snap_id,),
            ):
                try:
                    net = ipaddress.ip_network(r["cidr"], strict=False)
                except ValueError:
                    continue
                ports = rule_ports(r["ip_protocol"], r["from_port"], r["to_port"])
                self._add(direction, _Rule(r["group_id"], ports, cidr=net))

    def _add(self, direction: str, rule: _Rule) -> None:
        self.rules.setdefault((direction, rule.group), []).append(rule)

    def _knows(self, direction: str, group: str) -> bool:
        return group in self.known and (direction == "ingress" or self.known[group])

    def label(self, group: str) -> str:
        name = self.names.get(group)
        return f"{group} ({name})" if name and name != group else group

    def _side(
        self, direction: str, holder: Peer, peer: Peer, flow: Ports
    ) -> tuple[list[Ports] | None, list[str]]:
        """What ``holder``'s groups allow towards (egress) / from (ingress) ``peer``:
        the allowed port ranges (None: not filtered or not checked) and why."""
        word = "to" if direction == "egress" else "from"
        if not holder.sgs:
            return None, [f"{direction} of {holder.name}: no security groups (not filtered)"]
        found: list[tuple[_Rule, Ports]] = []
        for group in holder.sgs:
            for rule in self.rules.get((direction, group), []):
                both = meet(flow, rule.ports)
                if both is not None and rule.matches(peer):
                    found.append((rule, both))
        if found:
            reasons = [
                f"{direction}: {self.label(rule.group)} on {holder.name} allows {rule.ports} "
                f"{word} {rule.peer_group or rule.cidr} ({peer.name})"
                for rule, _ in found[:MAX_REASONS]
            ]
            return [both for _, both in found], reasons
        unknown = [g for g in holder.sgs if not self._knows(direction, g)]
        if unknown:
            what = "egress CIDR rules" if direction == "egress" else "rules"
            return None, [
                f"{direction} of {holder.name} not checked: the {what} of "
                f"{', '.join(unknown)} are not in this snapshot"
            ]
        groups = ", ".join(self.label(g) for g in holder.sgs)
        addr = f" ({', '.join(peer.ips[:2])})" if peer.ips else ""
        return [], [
            f"blocked by {direction}: no rule of {groups} on {holder.name} allows {flow} "
            f"{word} {peer.name}{addr}"
        ]

    def check(self, source: Peer, target: Peer, flow: Ports) -> Verdict:
        """May ``source`` open ``flow`` to ``target``? Both sides, union of their groups."""
        out, out_why = self._side("egress", source, target, flow)
        into, in_why = self._side("ingress", target, source, flow)
        if out == [] or into == []:
            return Verdict(
                False, [*(out_why if out == [] else []), *(in_why if into == [] else [])]
            )
        common = [
            p
            for p in (meet(a, b) for a in (out or [flow]) for b in (into or [flow]))
            if p is not None
        ]
        if not common:
            allowed_out = ", ".join(sorted({str(p) for p in out or [flow]}))
            allowed_in = ", ".join(sorted({str(p) for p in into or [flow]}))
            return Verdict(
                False,
                [
                    f"blocked: egress of {source.name} allows {allowed_out}, ingress of "
                    f"{target.name} allows {allowed_in}: no port in common"
                ],
            )
        return Verdict(True, [*out_why, *in_why], checked=out is not None or into is not None)


# -- resource / endpoint policies (evaluated locally, never stored) -------------------------


def _pattern(text: str, ignore_case: bool) -> re.Pattern[str]:
    body = re.escape(text).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(f"^{body}$", re.IGNORECASE if ignore_case else 0)


def _any_match(patterns: Any, value: str, ignore_case: bool = False) -> bool:
    values = patterns if isinstance(patterns, list) else [patterns]
    return any(isinstance(p, str) and _pattern(p, ignore_case).match(value) for p in values)


def _principal_matches(principal: Any, arn: str) -> bool:
    if principal is None or principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    aws = principal.get("AWS")
    values = aws if isinstance(aws, list) else [aws]
    account = arn.split(":")[4] if arn.count(":") >= 5 else ""
    return any(
        v == "*" or v == arn or (account and v in (account, f"arn:aws:iam::{account}:root"))
        for v in values
        if isinstance(v, str)
    )


def policy_decision(doc: Any, principal: str, action: str, resource: str) -> tuple[str, str]:
    """``(decision, statement)`` of a resource or VPC endpoint policy for ``principal``
    doing ``action`` on ``resource``: an explicit Deny wins, else an Allow is needed.
    Conditions are not evaluated: a conditional Allow counts, a conditional Deny does not
    block (noted in ``statement``)."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return ALLOWED, "policy not readable (not checked)"
    statements = doc.get("Statement") if isinstance(doc, dict) else None
    if isinstance(statements, dict):
        statements = [statements]
    allow = ""
    for i, st in enumerate(statements or []):
        if not isinstance(st, dict):
            continue
        sid = st.get("Sid") or f"statement {i + 1}"
        if "NotPrincipal" in st or not _principal_matches(st.get("Principal"), principal):
            continue
        if "Action" in st and not _any_match(st["Action"], action, ignore_case=True):
            continue
        if "NotAction" in st and _any_match(st["NotAction"], action, ignore_case=True):
            continue
        if "Resource" in st and not _any_match(st["Resource"], resource):
            continue
        if "NotResource" in st and _any_match(st["NotResource"], resource):
            continue
        conditional = " (conditions not evaluated)" if st.get("Condition") else ""
        if st.get("Effect") == "Deny":
            if not conditional:
                return EXPLICIT_DENY, sid
        elif st.get("Effect") == "Allow" and not allow:
            allow = sid + conditional
    return (ALLOWED, allow) if allow else (IMPLICIT_DENY, "no statement allows it")


# -- identity check -----------------------------------------------------------------------


def ecr_action(service_name: str | None) -> str | None:
    """The action an image pull needs through an ECR interface endpoint, else None."""
    for suffix, action in ECR_ACTIONS.items():
        if (service_name or "").endswith(suffix):
            return action
    return None


def ext_request(source: str, target: str) -> tuple[str, str, str] | None:
    """``(principal holder, action, resource node)`` an Extended view connection between
    two crawled nodes needs (``lambda:fn-a`` -> ``sqs:sqs-a``: fn-a sends), else None."""
    s, t = source.partition(":")[0], target.partition(":")[0]
    if s == "sqs" and t == "lambda":
        return target, RECEIVE_ACTION, source
    if s in COMPUTE and t in SEND_ACTIONS:
        return source, SEND_ACTIONS[t], target
    return None


def purposes(holder: str, action: str) -> tuple[str, ...]:
    """The roles of ``holder`` to simulate ``action`` for, in order of preference."""
    if holder.startswith("lambda:"):
        return ("lambda",)
    # ECS pulls images with the task execution role; the application uses the task role.
    return ("execution", "task") if action.startswith("ecr:") else ("task",)


def role_name(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def _short(resource: str) -> str:
    return "*" if resource == "*" else re.split(r"[:/]", resource)[-1]


class IamIndex:
    """The cached simulations and endpoint policies of one snapshot."""

    def __init__(self, conn: sqlite3.Connection, snap_id: int):
        self.roles = {
            (r["holder"], r["purpose"]): r["role_arn"]
            for r in conn.execute(
                "SELECT holder, purpose, role_arn FROM iam_principals WHERE snapshot_id=?",
                (snap_id,),
            )
        }
        self.sims = {
            (r["role_arn"], r["action"], r["resource"]): r
            for r in conn.execute("SELECT * FROM iam_sims WHERE snapshot_id=?", (snap_id,))
        }
        self.endpoints = {
            r["endpoint_id"]: (r["service_name"] or "", r["policy"])
            for r in conn.execute(
                "SELECT endpoint_id, service_name, policy FROM endpoints WHERE snapshot_id=?",
                (snap_id,),
            )
        }

    def role(self, holder: str, action: str) -> str | None:
        return next(
            (
                self.roles[(holder, p)]
                for p in purposes(holder, action)
                if (holder, p) in self.roles
            ),
            None,
        )

    def check(self, holder: str, action: str, resource: str, endpoint: str = "") -> Verdict | None:
        """Is ``holder`` allowed ``action`` on ``resource`` (through VPC endpoint
        ``endpoint``)? None when not simulated."""
        role = self.role(holder, action)
        sim = self.sims.get((role, action, resource)) if role else None
        if sim is None:
            return None
        who = f"role {role_name(role or '')} of {holder.partition(':')[2]}"
        what = f"{action} on {_short(resource)}"
        if sim["decision"] == EXPLICIT_DENY:
            return Verdict(
                False, [f"IAM: blocked: {who}: {what} explicitly denied by {sim['detail']}"]
            )
        if sim["resource_decision"] == EXPLICIT_DENY:
            return Verdict(
                False,
                [
                    f"IAM: blocked: the resource policy of {_short(resource)} denies {who} "
                    f"{action} ({sim['resource_detail']})"
                ],
            )
        if sim["decision"] == ALLOWED:
            lines = [f"IAM: {who} allows {what} ({sim['detail']})"]
        elif sim["resource_decision"] == ALLOWED:
            lines = [
                f"IAM: the resource policy of {_short(resource)} allows {who} {action} "
                f"({sim['resource_detail']})"
            ]
        else:
            return Verdict(False, [f"IAM: blocked: no policy of {who} allows {what}"])
        _service, policy = self.endpoints.get(endpoint, ("", None))
        if policy:
            decision, statement = policy_decision(policy, role or "", action, resource)
            if decision != ALLOWED:
                return Verdict(
                    False,
                    [*lines, f"IAM: blocked by the endpoint policy of {endpoint} ({statement})"],
                )
            lines.append(f"IAM: the endpoint policy of {endpoint} allows it ({statement})")
        return Verdict(True, lines)

    def check_any(
        self, holders: Iterable[str], action: str, resource: str, endpoint: str = ""
    ) -> Verdict | None:
        """:meth:`check` for several principals sharing one ENI: allowed if one is."""
        verdicts = [v for h in holders if (v := self.check(h, action, resource, endpoint))]
        if not verdicts:
            return None
        allowed = [v for v in verdicts if v.allowed]
        return Verdict(bool(allowed), [ln for v in (allowed or verdicts) for ln in v.lines])


# -- simulation (Extended crawl) ----------------------------------------------------------


@dataclass(frozen=True, order=True)
class SimRequest:
    role_arn: str
    action: str
    resource: str  # ARN, or "*"


def _sim_detail(result: dict[str, Any]) -> str:
    ids = sorted(
        {m.get("SourcePolicyId", "") for m in result.get("MatchedStatements") or []} - {""}
    )
    detail = ", ".join(ids) if ids else "no matching statement"
    boundary = result.get("PermissionsBoundaryDecisionDetail") or {}
    if boundary.get("AllowedByPermissionsBoundary") is False:
        detail += "; not allowed by the permissions boundary"
    orgs = result.get("OrganizationsDecisionDetail") or {}
    if orgs.get("AllowedByOrganizations") is False:
        detail += "; not allowed by an SCP"
    return detail[:400]


def simulate(
    iam: Any, requests: Iterable[SimRequest], cached: set[SimRequest]
) -> Iterator[tuple[SimRequest, str, str]]:
    """``(request, decision, detail)`` from ``iam:SimulatePrincipalPolicy``, one call per
    role and resource (its actions batched); ``cached`` requests are skipped."""
    todo: dict[tuple[str, str], list[str]] = {}
    for req in requests:
        if req not in cached:
            actions = todo.setdefault((req.role_arn, req.resource), [])
            if req.action not in actions:
                actions.append(req.action)
    for (role, resource), actions in sorted(todo.items()):
        pages = iam.get_paginator("simulate_principal_policy").paginate(
            PolicySourceArn=role, ActionNames=actions, ResourceArns=[resource]
        )
        for page in pages:
            for result in page.get("EvaluationResults", []):
                action = result.get("EvalActionName", "")
                if action in actions:
                    yield (
                        SimRequest(role, action, resource),
                        result.get("EvalDecision", IMPLICIT_DENY),
                        _sim_detail(result),
                    )
