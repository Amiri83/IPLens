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

Full path (1.6.1), from data the Extended crawl caches per snapshot:

- **NACL**: the network ACLs of both subnets, stateless and in rule number order (first
  match wins, the default rule ``*`` denies), in both directions: the request (outbound of
  A's subnet, inbound of B's) and its return traffic on the ephemeral ports 1024-65535
  (outbound of B's subnet, inbound of A's). Traffic inside one subnet is not filtered.
- **route**: A's subnet's route table (explicit, else the VPC's main table) needs a route to
  B: longest prefix match (local, NAT / internet gateway, transit gateway, peering, ...), a
  blackhole route refuses. To a regional service (SQS, SNS): an interface VPC endpoint of
  the service in the VPC, else a default route (an internet gateway only for an ENI with a
  public IP).
- **KMS**: for an encrypted SQS queue / SNS topic / ECR repository, ``kms:GenerateDataKey``
  / ``kms:Decrypt`` on its key, simulated for the role, and the key policy when readable
  (a statement naming the account root delegates to IAM).
- **SCP**: the service control policies from the organization root down to the account
  (every level must allow, none deny) when Organizations is readable; otherwise the
  connection is marked "SCP not evaluated" and not blocked.

A blocked connection's reasons start with the layer(s) that blocked it
(:func:`reasons`): SG, NACL, route, IAM, endpoint policy, resource policy, KMS or SCP.

Conditions (1.6.2): endpoint, resource, key policies and SCPs evaluate ``aws:SourceVpce``,
``aws:SourceVpc``, ``aws:PrincipalArn``, ``aws:PrincipalAccount`` and ``aws:PrincipalOrgID``
with String / Arn Equals / Like, their Not variants and IfExists (:func:`condition_result`);
the simulation gets them as ``ContextEntries``. Any other key or operator makes the
decision :data:`CONDITIONAL`. A connection has one of three :func:`state` values:
``allowed`` (every layer checked and passing), ``unverified`` (a layer not checked, or
conditional: ``Verdict.unverified`` names them) or ``blocked``.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

PORT_MAX = 65535
ALL = "all"
_PROTOCOLS = {"-1": ALL, "6": "tcp", "17": "udp", "1": "icmp"}

ALLOWED = "allowed"
EXPLICIT_DENY = "explicitDeny"
IMPLICIT_DENY = "implicitDeny"
# A policy whose outcome depends on a condition key or operator not evaluated locally.
CONDITIONAL = "conditional"

# Interface endpoint service name suffix -> the action pulling an image through it needs.
ECR_ACTIONS = {".ecr.api": "ecr:GetAuthorizationToken", ".ecr.dkr": "ecr:BatchGetImage"}
# Extended view connections checked against IAM: target service -> action of the source.
SEND_ACTIONS = {"sqs": "sqs:SendMessage", "sns": "sns:Publish"}
# An SQS event source mapping (queue -> function): the function's role receives.
RECEIVE_ACTION = "sqs:ReceiveMessage"
COMPUTE = ("lambda", "ecs")
# Reasons listed per side of a network verdict.
MAX_REASONS = 3
# Return traffic of a TCP / UDP flow reaches the client on one of these ports.
EPHEMERAL = (1024, PORT_MAX)
# The KMS actions a connection to an encrypted target needs, by the connection's action.
KMS_ACTIONS = {
    "sqs:SendMessage": ("kms:GenerateDataKey", "kms:Decrypt"),
    "sns:Publish": ("kms:GenerateDataKey", "kms:Decrypt"),
    "sqs:ReceiveMessage": ("kms:Decrypt",),
    "ecr:BatchGetImage": ("kms:Decrypt",),
}
# Key policy verdict: allowed through a statement naming the account root, so IAM decides.
DELEGATED = "delegated"

# The layers of the path, as a blocked connection's reason names them.
SG, NACL, ROUTE, IAM = "SG", "NACL", "route", "IAM"
ENDPOINT_POLICY, RESOURCE_POLICY, KMS, SCP = "endpoint policy", "resource policy", "KMS", "SCP"
BLOCKED_AT = "Blocked at layer: "
UNVERIFIED_AT = "Unverified: "
# The state of a connection (edge["state"]).
VERIFIED, UNVERIFIED, BLOCKED = "allowed", "unverified", "blocked"

# Condition keys evaluated locally, as the request context names them.
CONTEXT_KEYS = (
    "aws:SourceVpce",
    "aws:SourceVpc",
    "aws:PrincipalArn",
    "aws:PrincipalAccount",
    "aws:PrincipalOrgID",
)
# Condition operators evaluated locally (lower case, without IfExists): (match, negated).
_OPERATORS = {
    "stringequals": ("string", False),
    "stringnotequals": ("string", True),
    "stringlike": ("like", False),
    "stringnotlike": ("like", True),
    "arnequals": ("arn", False),
    "arnnotequals": ("arn", True),
    "arnlike": ("arn", False),
    "arnnotlike": ("arn", True),
}
# A request context: condition key (lower case) -> value, None when the key is known to be
# absent from the request; a key not in the mapping is unknown.
Context = Mapping[str, str | None]


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
    """``allowed`` False: blocked (by ``layers``). ``checked`` False: nothing to check it
    against. ``unverified``: the layers not checked or conditional ("NACL not checked",
    "endpoint policy conditional")."""

    allowed: bool
    lines: list[str] = field(default_factory=list)
    checked: bool = True
    layers: list[str] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)


def not_checked(layer: str, line: str) -> Verdict:
    """A layer without data to check it against: not blocking, but unverified."""
    return Verdict(True, [line], checked=False, unverified=[f"{layer} not checked"])


def combine(verdicts: Iterable[Verdict | None]) -> Verdict:
    """All layers of one path: allowed only if every checked layer allows it."""
    found = [v for v in verdicts if v is not None]
    layers = [layer for v in found if not v.allowed for layer in v.layers]
    return Verdict(
        all(v.allowed for v in found),
        [ln for v in found for ln in v.lines],
        checked=any(v.checked for v in found),
        layers=list(dict.fromkeys(layers)),
        unverified=list(dict.fromkeys(x for v in found for x in v.unverified)),
    )


def preferred(verdicts: list[Verdict]) -> list[Verdict]:
    """Of alternative verdicts (flows, principals): the fully verified allowed ones, else the
    allowed ones, else all of them."""
    allowed = [v for v in verdicts if v.allowed]
    return [v for v in allowed if not v.unverified] or allowed or verdicts


def state(verdict: Verdict) -> str:
    if not verdict.allowed:
        return BLOCKED
    return UNVERIFIED if verdict.unverified else VERIFIED


def headline(layers: Iterable[str]) -> str:
    return BLOCKED_AT + ", ".join(dict.fromkeys(layers))


def unverified_headline(items: Iterable[str]) -> str:
    return UNVERIFIED_AT + ", ".join(dict.fromkeys(items))


def reasons(verdict: Verdict) -> list[str]:
    """The lines of a verdict, led by the blocking layer(s) when it is blocked, by the
    layers not checked / conditional when it is unverified."""
    if not verdict.allowed:
        return [headline(verdict.layers), *verdict.lines]
    if verdict.unverified:
        return [unverified_headline(verdict.unverified), *verdict.lines]
    return list(verdict.lines)


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
            return [flow], [f"{direction} of {holder.name}: no security groups (not filtered)"]
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
                False,
                [*(out_why if out == [] else []), *(in_why if into == [] else [])],
                layers=[SG],
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
                layers=[SG],
            )
        return Verdict(
            True,
            [*out_why, *in_why],
            checked=out is not None or into is not None,
            unverified=[f"{SG} not checked"] if out is None or into is None else [],
        )


# -- network ACLs -------------------------------------------------------------------------

Spans = list[tuple[int, int]]


def _cut(spans: Spans, lo: int, hi: int) -> tuple[Spans, Spans]:
    """``(the parts of spans inside [lo, hi], the rest)``."""
    inside: Spans = []
    rest: Spans = []
    for a, b in spans:
        if b < lo or a > hi:
            rest.append((a, b))
            continue
        inside.append((max(a, lo), min(b, hi)))
        if a < lo:
            rest.append((a, lo - 1))
        if b > hi:
            rest.append((hi + 1, b))
    return inside, rest


def _intersect(xs: Spans, ys: Spans) -> Spans:
    return sorted((max(a, c), min(b, d)) for a, b in xs for c, d in ys if max(a, c) <= min(b, d))


def _fmt(proto: str, spans: Spans) -> str:
    return ", ".join(str(Ports(proto, lo, hi)) for lo, hi in sorted(spans))


def _addr(peer: Peer) -> str:
    return f" ({', '.join(peer.ips[:2])})" if peer.ips else ""


@dataclass(frozen=True)
class _AclEntry:
    number: int
    ports: Ports
    net: Any  # ipaddress.IPv4Network
    allow: bool


class Nacls:
    """The network ACL of each subnet of one snapshot (stored by the Extended crawl)."""

    def __init__(self, conn: sqlite3.Connection, snap_id: int):
        self.of_subnet = {
            r["subnet_id"]: r["nacl_id"]
            for r in conn.execute(
                "SELECT subnet_id, nacl_id FROM nacl_subnets WHERE snapshot_id=?", (snap_id,)
            )
        }
        self.entries: dict[tuple[str, bool], list[_AclEntry]] = {}
        for r in conn.execute(
            "SELECT * FROM nacl_entries WHERE snapshot_id=? ORDER BY nacl_id, egress, rule_number",
            (snap_id,),
        ):
            try:
                net = ipaddress.ip_network(r["cidr"], strict=False)
            except ValueError:
                continue
            self.entries.setdefault((r["nacl_id"], bool(r["egress"])), []).append(
                _AclEntry(
                    r["rule_number"],
                    rule_ports(r["protocol"], r["from_port"], r["to_port"]),
                    net,
                    r["action"] == "allow",
                )
            )

    def _hop(
        self, nacl: str, egress: bool, peer: Peer, proto: str, spans: Spans
    ) -> tuple[Spans, list[tuple[_AclEntry, Spans]]]:
        """Stateless evaluation in rule number order (the first matching rule decides each
        port): the allowed port spans and the rules that decided."""
        allowed: Spans = []
        decided: list[tuple[_AclEntry, Spans]] = []
        rest = list(spans)
        for e in self.entries.get((nacl, egress), []):
            if not rest:
                break
            if e.ports.proto not in (ALL, proto) or not any(_in(ip, e.net) for ip in peer.ips):
                continue
            inside, rest = _cut(rest, e.ports.lo, e.ports.hi)
            if inside:
                decided.append((e, inside))
                if e.allow:
                    allowed += inside
        return allowed, decided

    def check(
        self, source: Peer, src_subnet: str, target: Peer, dst_subnet: str, flow: Ports
    ) -> Verdict | None:
        """May ``flow`` pass the NACLs from ``source`` to ``target`` and its return traffic
        come back? None when a subnet's ACL is not in the snapshot."""
        if src_subnet and src_subnet == dst_subnet:
            return Verdict(True, [f"NACL: same subnet {src_subnet} (not filtered)"])
        a, b = self.of_subnet.get(src_subnet), self.of_subnet.get(dst_subnet)
        if not a or not b:
            return None
        failure: list[str] = []
        for proto in [flow.proto] if flow.proto != ALL else ["tcp", "udp", "icmp"]:
            request = [(flow.lo, flow.hi)]
            back = [(0, PORT_MAX)] if proto == "icmp" else [EPHEMERAL]
            hops = (
                (a, src_subnet, True, target, request, ""),
                (b, dst_subnet, False, source, request, ""),
                (b, dst_subnet, True, source, back, "return traffic: "),
                (a, src_subnet, False, target, back, "return traffic: "),
            )
            why: list[str] = []
            for nacl, subnet, egress, peer, spans, what in hops:
                allowed, decided = self._hop(nacl, egress, peer, proto, spans)
                if what:
                    back = _intersect(back, allowed)
                else:
                    request = _intersect(request, allowed)
                if not allowed:
                    denies = [
                        f"rule {e.number} denies {_fmt(proto, s)}"
                        for e, s in decided
                        if not e.allow
                    ]
                    word = "to" if egress else "from"
                    why.append(
                        f"NACL: blocked: {what}{'outbound' if egress else 'inbound'} of {nacl} "
                        f"({subnet}): "
                        + ("; ".join(denies[:MAX_REASONS]) or "no rule allows it (rule * denies)")
                        + f" – {_fmt(proto, spans)} {word} {peer.name}{_addr(peer)}"
                    )
                    break
            if not why and not request:
                why.append(f"NACL: blocked: {a} and {b} allow no {proto} port in common")
            if not why and not back:
                why.append(
                    f"NACL: blocked: return traffic: {b} and {a} allow no ephemeral port in common"
                )
            if why:
                failure = failure or why
                continue
            line = (
                f"NACL: {a} ({src_subnet}) outbound and {b} ({dst_subnet}) inbound allow "
                f"{_fmt(proto, request)}; return traffic allowed on {_fmt(proto, back)}"
            )
            if proto != "icmp" and back != [EPHEMERAL]:
                line += " (not all ephemeral ports 1024-65535)"
            return Verdict(True, [line])
        return Verdict(False, failure, layers=[NACL])


# -- routes -------------------------------------------------------------------------------

ROUTE_KINDS = {
    "local": "local",
    "igw-": "internet gateway",
    "nat-": "NAT gateway",
    "tgw-": "transit gateway",
    "pcx-": "VPC peering",
    "vpce-": "VPC endpoint",
    "vgw-": "virtual private gateway",
    "eni-": "network interface",
    "i-": "instance",
}


def route_kind(target: str) -> str:
    return next((k for p, k in ROUTE_KINDS.items() if target.startswith(p)), "other")


@dataclass(frozen=True)
class _Route:
    destination: str
    net: Any  # ipaddress.IPv4Network, None for a prefix list
    target: str
    state: str

    def __str__(self) -> str:
        return f"{self.destination} → {self.target} ({route_kind(self.target)})"


class Routes:
    """The route tables of one snapshot's subnets (stored by the Extended crawl) and the
    interface VPC endpoints (from the Refresh)."""

    def __init__(self, conn: sqlite3.Connection, snap_id: int):
        self.table: dict[str, str] = {}  # subnet -> explicitly associated route table
        self.main: dict[str, str] = {}  # VPC -> main route table
        for r in conn.execute(
            "SELECT route_table_id, vpc_id, subnet_id FROM route_subnets WHERE snapshot_id=?",
            (snap_id,),
        ):
            if r["subnet_id"]:
                self.table[r["subnet_id"]] = r["route_table_id"]
            else:
                self.main[r["vpc_id"]] = r["route_table_id"]
        self.routes: dict[str, list[_Route]] = {}
        for r in conn.execute(
            "SELECT * FROM route_entries WHERE snapshot_id=? ORDER BY route_table_id, destination",
            (snap_id,),
        ):
            try:
                net = ipaddress.ip_network(r["destination"], strict=False)
            except ValueError:
                net = None
            self.routes.setdefault(r["route_table_id"], []).append(
                _Route(r["destination"], net, r["target"], r["state"])
            )
        self.vpc_of = {
            r[0]: r[1]
            for r in conn.execute(
                "SELECT subnet_id, vpc_id FROM subnets WHERE snapshot_id=?", (snap_id,)
            )
        }
        self.endpoints: dict[str, list[tuple[str, str, list[str]]]] = {}
        for r in conn.execute(
            "SELECT endpoint_id, vpc_id, service_name, eni_ids FROM endpoints "
            "WHERE snapshot_id=? AND endpoint_type='Interface' ORDER BY endpoint_id",
            (snap_id,),
        ):
            self.endpoints.setdefault(r["vpc_id"], []).append(
                (r["endpoint_id"], r["service_name"] or "", json.loads(r["eni_ids"] or "[]"))
            )

    def table_of(self, subnet: str) -> str | None:
        """The subnet's route table, None when not in the snapshot."""
        rtb = self.table.get(subnet) or self.main.get(self.vpc_of.get(subnet, ""))
        return rtb if rtb in self.routes else None

    def _best(self, rtb: str, ip: str) -> _Route | None:
        return max(
            (r for r in self.routes[rtb] if r.net is not None and _in(ip, r.net)),
            key=lambda r: r.net.prefixlen,
            default=None,
        )

    def to_ip(self, subnet: str, target: Peer) -> Verdict | None:
        """A route from ``subnet`` to ``target`` (its first IP); None when not checked."""
        rtb = self.table_of(subnet)
        if rtb is None or not target.ips:
            return None
        ip = target.ips[0]
        best = self._best(rtb, ip)
        if best is None:
            return Verdict(
                False,
                [f"route: blocked: no route in {rtb} of {subnet} to {target.name} ({ip})"],
                layers=[ROUTE],
            )
        if best.state == "blackhole":
            return Verdict(
                False,
                [f"route: blocked: {best} in {rtb} of {subnet} is a blackhole"],
                layers=[ROUTE],
            )
        return Verdict(True, [f"route: {subnet} to {target.name} ({ip}) via {best} in {rtb}"])

    def endpoint(self, subnet: str, service: str) -> tuple[str, list[str]] | None:
        """``(endpoint id, ENI ids)`` of an interface endpoint of ``service`` ("sqs") in the
        subnet's VPC."""
        suffix = "." + service
        return next(
            (
                (ep, enis)
                for ep, name, enis in self.endpoints.get(self.vpc_of.get(subnet, ""), [])
                if name.endswith(suffix)
            ),
            None,
        )

    def to_service(self, subnet: str, service: str, name: str, public_ip: bool) -> Verdict | None:
        """A path from ``subnet`` to a regional AWS service: an interface endpoint in the
        VPC, else a default route. None when not checked."""
        rtb = self.table_of(subnet)
        if rtb is None:
            return None
        ep = self.endpoint(subnet, service)
        if ep is not None:
            return Verdict(
                True, [f"route: {subnet} to {service} through VPC endpoint {ep[0]} (local)"]
            )
        default = max(
            (r for r in self.routes[rtb] if r.net is not None and r.net.prefixlen == 0),
            key=lambda r: r.state != "blackhole",
            default=None,
        )
        why = ""
        if default is None:
            why = f"no VPC endpoint for {service} and no default route in {rtb} of {subnet}"
        elif default.state == "blackhole":
            why = f"{default} in {rtb} of {subnet} is a blackhole"
        elif default.target.startswith("igw-") and not public_ip:
            why = (
                f"{default} in {rtb} of {subnet}: {name} has no public IP (needs a NAT "
                f"gateway or a VPC endpoint for {service})"
            )
        elif default.target.startswith("pcx-"):
            why = f"{default} in {rtb} of {subnet}: VPC peering does not reach {service}"
        if why:
            return Verdict(False, [f"route: blocked: {why}"], layers=[ROUTE])
        note = " (beyond the transit gateway not evaluated)" if "tgw-" in default.target else ""
        return Verdict(True, [f"route: {subnet} to {service} via {default} in {rtb}{note}"])


@dataclass(frozen=True)
class _Eni:
    name: str
    sgs: tuple[str, ...]
    ips: tuple[str, ...]
    subnet: str
    public: bool


class PathCheck:
    """The network layers of a flow between two ENIs (SG, NACL, route), and of a VPC
    ENI's path to a regional AWS service (route, and the NACLs to its VPC endpoint)."""

    def __init__(self, conn: sqlite3.Connection, snap_id: int, names: dict[str, str] | None):
        self.sgs = SgRules(conn, snap_id, names)
        self.nacls = Nacls(conn, snap_id)
        self.routes = Routes(conn, snap_id)
        self._conn, self._snap_id = conn, snap_id
        self._enis: dict[str, _Eni] | None = None

    def check(
        self, source: Peer, src_subnet: str, target: Peer, dst_subnet: str, flow: Ports
    ) -> Verdict:
        nacl = self.nacls.check(source, src_subnet, target, dst_subnet, flow)
        route = self.routes.to_ip(src_subnet, target)
        verdict = combine([self.sgs.check(source, target, flow), nacl, route])
        missing = [what for what, v in ((NACL, nacl), (ROUTE, route)) if v is None]
        if missing:
            verdict.lines.append(f"{' and '.join(missing)} not checked (run the Extended crawl)")
            verdict.unverified += [f"{what} not checked" for what in missing]
        return verdict

    def eni(self, eni_id: str) -> _Eni | None:
        if self._enis is None:
            self._enis = {}
            rows = self._conn.execute(
                "SELECT e.eni_id, e.subnet_id, e.security_groups, i.ip, i.public_ip FROM enis e "
                "LEFT JOIN ips i ON i.snapshot_id=e.snapshot_id AND i.eni_id=e.eni_id "
                "WHERE e.snapshot_id=? ORDER BY e.eni_id, i.is_primary DESC, i.ip",
                (self._snap_id,),
            )
            for r in rows:
                old = self._enis.get(r["eni_id"])
                ips = (*(old.ips if old else ()), *((r["ip"],) if r["ip"] else ()))
                self._enis[r["eni_id"]] = _Eni(
                    r["eni_id"],
                    tuple(json.loads(r["security_groups"] or "[]")),
                    ips,
                    r["subnet_id"] or "",
                    bool(r["public_ip"]) or bool(old and old.public),
                )
        return self._enis.get(eni_id)

    def to_service(self, eni_id: str, service: str) -> Verdict | None:
        """VPC ENI -> a regional service: a route (endpoint or default route) and, through
        an interface endpoint, the NACLs on tcp/443 to one of its ENIs. None: not checked."""
        src = self.eni(eni_id)
        if src is None:
            return None
        route = self.routes.to_service(src.subnet, service, src.name, src.public)
        ep = self.routes.endpoint(src.subnet, service) if route is not None else None
        if ep is None:
            return route
        https = Ports("tcp", 443, 443)
        nacls = [
            v
            for e in ep[1]
            if (dst := self.eni(e)) is not None
            and (v := self.nacls.check(src, src.subnet, dst, dst.subnet, https)) is not None
        ]
        if not nacls:
            return combine([route, not_checked(NACL, f"NACL to {ep[0]} not checked")])
        return combine([route, preferred(nacls)[0]])


# -- resource / endpoint policies (evaluated locally, never stored) -------------------------


def _pattern(text: str, ignore_case: bool) -> re.Pattern[str]:
    body = re.escape(text).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(f"^{body}$", re.IGNORECASE if ignore_case else 0)


def _any_match(patterns: Any, value: str, ignore_case: bool = False) -> bool:
    values = patterns if isinstance(patterns, list) else [patterns]
    return any(isinstance(p, str) and _pattern(p, ignore_case).match(value) for p in values)


def account_of(arn: str) -> str:
    return arn.split(":")[4] if arn.count(":") >= 5 else ""


def _arn_match(pattern: str, arn: str) -> bool:
    """ArnEquals / ArnLike: each of the six colon-separated parts matched on its own, with
    ``*`` / ``?`` wildcards."""
    want, have = pattern.split(":", 5), arn.split(":", 5)
    return len(want) == len(have) == 6 and all(
        _pattern(w, False).match(h) for w, h in zip(want, have, strict=True)
    )


def _value_match(kind: str, pattern: Any, value: str) -> bool:
    if not isinstance(pattern, str):
        return False
    if kind == "string":
        return pattern == value
    if kind == "like":
        return bool(_pattern(pattern, False).match(value))
    return _arn_match(pattern, value)


def principal_context(role: str, org_id: str = "") -> dict[str, str | None]:
    """The principal keys of a request made by ``role`` (its organization when known)."""
    ctx: dict[str, str | None] = {
        "aws:principalarn": role,
        "aws:principalaccount": account_of(role),
    }
    if org_id:
        ctx["aws:principalorgid"] = org_id
    return ctx


def network_context(endpoint: str | None, vpc: str | None) -> dict[str, str | None]:
    """The network keys of a request whose path is known: through VPC endpoint ``endpoint``
    of ``vpc``, or (``endpoint`` None) not through an endpoint: both keys absent."""
    return {"aws:sourcevpce": endpoint, "aws:sourcevpc": vpc if endpoint else None}


def condition_result(block: Any, context: Context) -> tuple[bool | None, list[str]]:
    """A statement's ``Condition`` (every operator and key must hold): True / False, or
    None with the operators / keys not evaluated locally (an unknown operator or key, or a
    key whose value the context does not know)."""
    if not isinstance(block, dict):
        return None, ["Condition"]
    unknown: list[str] = []
    for operator, tests in block.items():
        name = str(operator).lower()
        if_exists = name.endswith("ifexists")
        kind, negated = _OPERATORS.get(name.removesuffix("ifexists"), ("", False))
        if not kind or not isinstance(tests, dict):
            unknown.append(str(operator))
            continue
        for key, patterns in tests.items():
            if str(key).lower() not in context:
                unknown.append(str(key))
                continue
            value = context[str(key).lower()]
            if value is None:  # absent: only a negated operator or IfExists holds
                holds = if_exists or negated
            else:
                values = patterns if isinstance(patterns, list) else [patterns]
                found = any(_value_match(kind, p, value) for p in values)
                holds = not found if negated else found
            if not holds:
                return False, []
    return (None, unknown) if unknown else (True, [])


def _principal_matches(principal: Any, arn: str, account_root: bool = True) -> bool:
    if principal is None or principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    aws = principal.get("AWS")
    values = aws if isinstance(aws, list) else [aws]
    account = account_of(arn) if account_root else ""
    return any(
        v == "*" or v == arn or (account and v in (account, f"arn:aws:iam::{account}:root"))
        for v in values
        if isinstance(v, str)
    )


def policy_decision(
    doc: Any,
    principal: str,
    action: str,
    resource: str,
    account_root: bool = True,
    context: Context | None = None,
) -> tuple[str, str]:
    """``(decision, statement)`` of a resource or VPC endpoint policy for ``principal``
    doing ``action`` on ``resource``: an explicit Deny wins, else an Allow is needed.
    Conditions are evaluated against ``context`` (:func:`condition_result`); one that
    cannot be makes the decision :data:`CONDITIONAL` when its statement could change it.
    ``account_root`` False: a statement naming the principal's account does not match it."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return CONDITIONAL, "policy not readable (not checked)"
    statements = doc.get("Statement") if isinstance(doc, dict) else None
    if isinstance(statements, dict):
        statements = [statements]
    allow, maybe_allow, maybe_deny = "", "", ""
    for i, st in enumerate(statements or []):
        if not isinstance(st, dict):
            continue
        sid = st.get("Sid") or f"statement {i + 1}"
        if "NotPrincipal" in st or not _principal_matches(
            st.get("Principal"), principal, account_root
        ):
            continue
        if "Action" in st and not _any_match(st["Action"], action, ignore_case=True):
            continue
        if "NotAction" in st and _any_match(st["NotAction"], action, ignore_case=True):
            continue
        if "Resource" in st and not _any_match(st["Resource"], resource):
            continue
        if "NotResource" in st and _any_match(st["NotResource"], resource):
            continue
        holds, unknown = (
            condition_result(st["Condition"], context or {}) if "Condition" in st else (True, [])
        )
        if holds is False:
            continue
        what = sid if holds else f"{sid}: condition {', '.join(unknown)} not evaluated"
        if st.get("Effect") == "Deny":
            if holds:
                return EXPLICIT_DENY, sid
            maybe_deny = maybe_deny or what
        elif st.get("Effect") == "Allow":
            if holds:
                allow = allow or (sid + " (condition met)" if "Condition" in st else sid)
            else:
                maybe_allow = maybe_allow or what
    if not allow and not maybe_allow:
        return IMPLICIT_DENY, "no statement allows it"
    if maybe_deny or not allow:
        return CONDITIONAL, maybe_deny or maybe_allow
    return ALLOWED, allow


def key_policy_decision(
    doc: Any, role: str, action: str, key: str, context: Context | None = None
) -> tuple[str, str]:
    """A KMS key policy for ``role`` doing ``action``: an explicit Deny wins; a statement
    naming the role (or ``*``) allows it, one naming only the account root is
    :data:`DELEGATED` (the role's IAM policies must allow it too)."""
    decision, statement = policy_decision(doc, role, action, key, context=context)
    if decision != ALLOWED:
        return decision, statement
    direct, direct_statement = policy_decision(
        doc, role, action, key, account_root=False, context=context
    )
    return (ALLOWED, direct_statement) if direct == ALLOWED else (DELEGATED, statement)


def scp_decision(
    levels: Iterable[tuple[str, Iterable[tuple[str, Any]]]],
    action: str,
    resource: str,
    context: Context | None = None,
) -> tuple[str, str]:
    """``(decision, detail)`` of the SCPs on the way from the organization root down to an
    account (``levels``: ``(target id, [(policy name, document), ...])``): every level
    needs an SCP allowing ``action``, and no SCP may deny it. An SCP whose conditions are
    not evaluated makes it :data:`CONDITIONAL` (unless another one denies it)."""
    allowed_by: list[str] = []
    conditional = ""
    for target, policies in levels:
        allow, maybe = "", ""
        for name, doc in policies:
            decision, statement = policy_decision(doc, "", action, resource, context=context)
            if decision == EXPLICIT_DENY:
                return EXPLICIT_DENY, f"SCP {name} ({statement}) attached to {target} denies it"
            if decision == ALLOWED and not allow:
                allow = name
            if decision == CONDITIONAL and not maybe:
                maybe = f"SCP {name} ({statement}) attached to {target}"
        if not allow and not maybe:
            return IMPLICIT_DENY, f"no SCP attached to {target} allows it"
        conditional = conditional or maybe
        if allow:
            allowed_by.append(f"{allow} on {target}")
    if conditional:
        return CONDITIONAL, f"conditional: {conditional}"[:400]
    return ALLOWED, ("allowed by " + ", ".join(allowed_by))[:400]


# -- identity check -----------------------------------------------------------------------


def ecr_action(service_name: str | None) -> str | None:
    """The action an image pull needs through an ECR interface endpoint, else None."""
    for suffix, action in ECR_ACTIONS.items():
        if (service_name or "").endswith(suffix):
            return action
    return None


def endpoint_suffix(action: str) -> str:
    """The interface endpoint service name suffix a request for ``action`` goes through:
    ".sqs", ".kms", ".ecr.api" / ".ecr.dkr" for an image pull."""
    ecr = next((s for s, a in ECR_ACTIONS.items() if a == action), None)
    return ecr or "." + action.partition(":")[0]


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
        self.endpoints: dict[str, tuple[str, str | None]] = {}
        self.endpoint_vpcs: dict[str, str] = {}
        for r in conn.execute(
            "SELECT endpoint_id, vpc_id, service_name, policy FROM endpoints WHERE snapshot_id=?",
            (snap_id,),
        ):
            self.endpoints[r["endpoint_id"]] = (r["service_name"] or "", r["policy"])
            self.endpoint_vpcs[r["endpoint_id"]] = r["vpc_id"]
        row = conn.execute(
            "SELECT org_id FROM iam_context WHERE snapshot_id=?", (snap_id,)
        ).fetchone()
        self.org_id = row["org_id"] if row else ""
        # Encrypted targets: resource ARN -> keys; ECS service -> (ECR repository, key).
        self.keys: dict[str, list[str]] = {}
        self.pulled: dict[str, list[tuple[str, str]]] = {}
        for r in conn.execute(
            "SELECT resource, holder, key_arn FROM kms_targets WHERE snapshot_id=? "
            "ORDER BY resource, holder",
            (snap_id,),
        ):
            if r["holder"]:
                self.pulled.setdefault(r["holder"], []).append((r["resource"], r["key_arn"]))
            else:
                self.keys.setdefault(r["resource"], []).append(r["key_arn"])
        self.kms = {
            (r["role_arn"], r["key_arn"], r["action"]): r
            for r in conn.execute("SELECT * FROM kms_sims WHERE snapshot_id=?", (snap_id,))
        }
        self.scps = {
            (r["account"], r["action"], r["resource"]): r
            for r in conn.execute("SELECT * FROM scp_checks WHERE snapshot_id=?", (snap_id,))
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
        role = role or ""
        who = f"role {role_name(role)} of {holder.partition(':')[2]}"
        what = f"{action} on {_short(resource)}"
        # The simulation reports an SCP that refuses the action (OrganizationsDecisionDetail).
        iam_layer = SCP if "not allowed by an SCP" in sim["detail"] else IAM
        if sim["decision"] == EXPLICIT_DENY:
            return Verdict(
                False,
                [f"IAM: blocked: {who}: {what} explicitly denied by {sim['detail']}"],
                layers=[iam_layer],
            )
        if sim["resource_decision"] == EXPLICIT_DENY:
            return Verdict(
                False,
                [
                    f"IAM: blocked: the resource policy of {_short(resource)} denies {who} "
                    f"{action} ({sim['resource_detail']})"
                ],
                layers=[RESOURCE_POLICY],
            )
        decisions = (sim["decision"], sim["resource_decision"])
        if sim["decision"] == ALLOWED:
            lines = [f"IAM: {who} allows {what} ({sim['detail']})"]
        elif sim["resource_decision"] == ALLOWED:
            lines = [
                f"IAM: the resource policy of {_short(resource)} allows {who} {action} "
                f"({sim['resource_detail']})"
            ]
        elif CONDITIONAL not in decisions:
            return Verdict(
                False, [f"IAM: blocked: no policy of {who} allows {what}"], layers=[iam_layer]
            )
        else:
            lines = []
        pending = []
        if sim["decision"] == CONDITIONAL:
            lines.append(f"IAM: {who}: {what} conditional ({sim['detail']})")
            pending.append(f"{iam_layer} conditional")
        if sim["resource_decision"] == CONDITIONAL:
            lines.append(
                f"IAM: the resource policy of {_short(resource)} is conditional for {who} "
                f"{action} ({sim['resource_detail']})"
            )
            pending.append(f"{RESOURCE_POLICY} conditional")
        _service, policy = self.endpoints.get(endpoint, ("", None))
        if policy:
            context = {
                **principal_context(role, self.org_id),
                **network_context(endpoint, self.endpoint_vpcs.get(endpoint)),
            }
            decision, statement = policy_decision(policy, role, action, resource, context=context)
            if decision == CONDITIONAL:
                lines.append(f"IAM: the endpoint policy of {endpoint} is conditional ({statement})")
                pending.append(f"{ENDPOINT_POLICY} conditional")
            elif decision != ALLOWED:
                return Verdict(
                    False,
                    [*lines, f"IAM: blocked by the endpoint policy of {endpoint} ({statement})"],
                    layers=[ENDPOINT_POLICY],
                )
            else:
                lines.append(f"IAM: the endpoint policy of {endpoint} allows it ({statement})")
        keys = self._keys(holder, action, resource)
        kms = [self._kms(role, key, a) for key in keys for a in KMS_ACTIONS.get(action, ())]
        actions = [(action, resource)] + [
            (a, key) for key in keys for a in KMS_ACTIONS.get(action, ())
        ]
        return combine([Verdict(True, lines, unverified=pending), *kms, self._scp(role, actions)])

    def _keys(self, holder: str, action: str, resource: str) -> list[str]:
        """The KMS keys of the encrypted target(s) of a connection."""
        if action == "ecr:BatchGetImage":
            return sorted({key for _repo, key in self.pulled.get(holder, [])})
        return self.keys.get(resource, [])

    def _kms(self, role: str, key: str, action: str) -> Verdict:
        """``action`` on ``key``: the simulated IAM decision and the key policy."""
        row = self.kms.get((role, key, action))
        who, short = f"role {role_name(role)}", _short(key)
        if row is None:
            return not_checked(KMS, f"KMS: {action} on key {short} not checked")
        if row["decision"] == EXPLICIT_DENY:
            line = (
                f"KMS: blocked: {who}: {action} on key {short} explicitly denied by {row['detail']}"
            )
        elif row["policy_decision"] == EXPLICIT_DENY:
            line = (
                f"KMS: blocked: the key policy of {short} denies {who} {action} "
                f"({row['policy_detail']})"
            )
        elif row["policy_decision"] == IMPLICIT_DENY:
            line = (
                f"KMS: blocked: the key policy of {short} allows {action} to neither {who} "
                "nor its account"
            )
        elif CONDITIONAL in (row["decision"], row["policy_decision"]):
            return Verdict(
                True,
                [
                    f"KMS: {action} on key {short} for {who} is conditional ({row['detail']}; "
                    f"key policy: {row['policy_detail'] or 'not readable'})"
                ],
                unverified=[f"{KMS} conditional"],
            )
        elif row["policy_decision"] == ALLOWED:
            return Verdict(
                True,
                [f"KMS: the key policy of {short} allows {who} {action} ({row['policy_detail']})"],
            )
        elif row["decision"] == ALLOWED:
            delegated = row["policy_decision"] == DELEGATED
            policy = (
                f"the key policy delegates to IAM ({row['policy_detail']})"
                if delegated
                else "key policy not readable"
            )
            return Verdict(
                True,
                [f"KMS: {who} allows {action} on key {short} ({row['detail']}; {policy})"],
                unverified=[] if delegated else [f"{KMS} key policy not checked"],
            )
        else:
            line = f"KMS: blocked: no policy of {who} allows {action} on key {short}"
        return Verdict(False, [line], layers=[KMS])

    def _scp(self, role: str, actions: list[tuple[str, str]]) -> Verdict:
        """The service control policies of ``role``'s account for every ``(action,
        resource)``; not evaluated (not blocking) without Organizations data."""
        account = account_of(role)
        rows = [self.scps.get((account, a, r)) for a, r in actions]
        denied = [
            (a, row)
            for (a, _), row in zip(actions, rows, strict=True)
            if row is not None and row["decision"] not in (ALLOWED, CONDITIONAL)
        ]
        if denied:
            action, row = denied[0]
            return Verdict(
                False,
                [f"SCP: blocked: {action} for account {account}: {row['detail']}"],
                layers=[SCP],
            )
        if not rows or any(row is None for row in rows):
            return not_checked(
                SCP, "SCP not evaluated (no Organizations read access in the Extended crawl)"
            )
        maybe = [
            (a, row)
            for (a, _), row in zip(actions, rows, strict=True)
            if row["decision"] == CONDITIONAL
        ]
        if maybe:
            action, row = maybe[0]
            return Verdict(
                True,
                [f"SCP: {action} for account {account}: {row['detail']}"],
                unverified=[f"{SCP} conditional"],
            )
        return Verdict(True, [f"SCP: account {account}: {rows[0]['detail']}"])

    def check_any(
        self, holders: Iterable[str], action: str, resource: str, endpoint: str = ""
    ) -> Verdict | None:
        """:meth:`check` for several principals sharing one ENI: allowed if one is."""
        verdicts = [v for h in holders if (v := self.check(h, action, resource, endpoint))]
        if not verdicts:
            return None
        return combine(preferred(verdicts))


def iam_crawled(conn: sqlite3.Connection, snap_id: int) -> bool:
    """Has the snapshot been through an Extended crawl (or kept its IAM data in a Retry)?"""
    return any(
        conn.execute(
            f"SELECT 1 FROM {table} WHERE snapshot_id=? LIMIT 1",  # noqa: S608 - constants
            (snap_id,),
        ).fetchone()
        for table in ("ext_crawls", "iam_principals")
    )


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


def context_entries(context: Context) -> list[dict[str, Any]]:
    """``ContextEntries`` of ``iam:SimulatePrincipalPolicy`` for the known keys of
    ``context`` (an absent key is simply not passed)."""
    names = {k.lower(): k for k in CONTEXT_KEYS}
    return [
        {"ContextKeyName": names.get(k, k), "ContextKeyValues": [v], "ContextKeyType": "string"}
        for k, v in sorted(context.items())
        if v is not None
    ]


def _missing_keys(result: dict[str, Any]) -> set[str]:
    found = set(result.get("MissingContextValues") or [])
    for r in result.get("ResourceSpecificResults") or []:
        found.update(r.get("MissingContextValues") or [])
    return found


def simulate(
    iam: Any,
    requests: Iterable[SimRequest],
    cached: set[SimRequest],
    contexts: Callable[[SimRequest], Context] | None = None,
) -> Iterator[tuple[SimRequest, str, str]]:
    """``(request, decision, detail)`` from ``iam:SimulatePrincipalPolicy``, one call per
    role, resource and request context (its actions batched); ``cached`` requests are
    skipped. A decision depending on a context key the simulation was not given (and not
    known to be absent) is :data:`CONDITIONAL`, unless an explicit deny."""
    todo: dict[tuple[str, str, tuple[tuple[str, str | None], ...]], list[str]] = {}
    for req in requests:
        if req not in cached:
            ctx = tuple(sorted((contexts(req) if contexts else {}).items()))
            actions = todo.setdefault((req.role_arn, req.resource, ctx), [])
            if req.action not in actions:
                actions.append(req.action)
    order = sorted(todo, key=lambda k: (k[0], k[1], str(k[2])))
    for (role, resource, ctx), actions in ((k, todo[k]) for k in order):
        entries = context_entries(dict(ctx))
        pages = iam.get_paginator("simulate_principal_policy").paginate(
            PolicySourceArn=role,
            ActionNames=actions,
            ResourceArns=[resource],
            **({"ContextEntries": entries} if entries else {}),
        )
        known = {k for k, _ in ctx}
        for page in pages:
            for result in page.get("EvaluationResults", []):
                action = result.get("EvalActionName", "")
                if action not in actions:
                    continue
                decision, detail = result.get("EvalDecision", IMPLICIT_DENY), _sim_detail(result)
                unknown = sorted(k for k in _missing_keys(result) if k.lower() not in known)
                if unknown and decision != EXPLICIT_DENY:
                    decision = CONDITIONAL
                    detail = f"{detail}; condition {', '.join(unknown)} not evaluated"[:400]
                yield SimRequest(role, action, resource), decision, detail
