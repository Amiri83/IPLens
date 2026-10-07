"""IP-optimization suggestions derived from a snapshot, filtered through rules."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from .queries import SubnetStats, VpcNode, subnet_stats, vpc_tree
from .rules import Rule

# Services that support (free, IP-less) gateway endpoints.
GATEWAY_CAPABLE = (".s3", ".dynamodb")

AZ_IMBALANCE_RATIO = 2.0
AZ_IMBALANCE_MIN_DELTA = 16
VPC_SPACE_ALLOCATED_PCT = 90.0
VPC_CONSUMED_PCT = 70.0

KIND_LABELS = {
    "detached_eni": "Detached ENI",
    "lambda_sg_combo": "Lambda SG combos",
    "lambda_subnet_spread": "Lambda subnet spread",
    "lambda_detach_vpc": "Lambda outside VPC",
    "duplicate_endpoint": "Duplicate endpoint",
    "gateway_endpoint": "Gateway endpoint",
    "endpoint_via_nat": "Endpoints via NAT",
    "az_imbalance": "AZ imbalance",
    "secondary_cidr": "Secondary CIDR",
}


@dataclass
class Context:
    subnets: dict[str, SubnetStats]
    enis: dict[str, dict[str, Any]]
    eni_ip_count: dict[str, int]
    vpcs: list[VpcNode]
    lambdas: list[dict[str, Any]]
    endpoints: list[dict[str, Any]]
    load_balancers: list[dict[str, Any]]


@dataclass
class Suggestion:
    key: str
    kind: str
    title: str
    detail: str
    vpc_id: str
    ips_saved: int = 0
    impact: str = ""
    subnet_ids: list[str] = field(default_factory=list)
    target_subnets: dict[str, int] = field(default_factory=dict)
    eni_ids: list[str] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    blocked_by: list[tuple[str, str]] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.blocked_by)

    @property
    def kind_label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)


def build_context(conn: sqlite3.Connection, snap_id: int) -> Context:
    enis = {}
    for r in conn.execute("SELECT * FROM enis WHERE snapshot_id=?", (snap_id,)):
        d = dict(r)
        d["security_groups"] = json.loads(d.get("security_groups") or "[]")
        enis[d["eni_id"]] = d
    counts = {
        r["eni_id"]: r["n"]
        for r in conn.execute(
            "SELECT eni_id, COUNT(*) AS n FROM ips WHERE snapshot_id=? GROUP BY eni_id",
            (snap_id,),
        )
    }

    def rows(table: str, *json_cols: str) -> list[dict[str, Any]]:
        out = []
        for r in conn.execute(
            f"SELECT * FROM {table} WHERE snapshot_id=?", (snap_id,)  # noqa: S608 - fixed names
        ):
            d = dict(r)
            for c in json_cols:
                d[c] = json.loads(d.get(c) or "[]")
            out.append(d)
        return out

    return Context(
        subnets={s.subnet_id: s for s in subnet_stats(conn, snap_id)},
        enis=enis,
        eni_ip_count=counts,
        vpcs=vpc_tree(conn, snap_id),
        lambdas=rows("lambdas", "subnet_ids", "security_groups"),
        endpoints=rows("endpoints", "subnet_ids", "eni_ids"),
        load_balancers=rows("load_balancers"),
    )


# -- generators ---------------------------------------------------------------

def _detached_enis(ctx: Context) -> list[Suggestion]:
    out = []
    for eni in ctx.enis.values():
        if eni["status"] != "available" or eni["requester_managed"]:
            continue
        n = ctx.eni_ip_count.get(eni["eni_id"], 0)
        label = eni.get("name") or eni.get("description") or "no description"
        out.append(Suggestion(
            key=f"detached:{eni['eni_id']}",
            kind="detached_eni",
            title=f"Delete detached ENI {eni['eni_id']}",
            detail=f"ENI '{label}' in {eni['subnet_id']} is not attached to anything "
                   f"but holds {n} private IP(s).",
            vpc_id=eni["vpc_id"] or "",
            ips_saved=n,
            subnet_ids=[eni["subnet_id"]] if eni["subnet_id"] else [],
            eni_ids=[eni["eni_id"]],
        ))
    return out


def _sg_key(eni: dict[str, Any]) -> tuple[str, ...]:
    return tuple(sorted(eni["security_groups"]))


def _lambda(ctx: Context) -> list[Suggestion]:
    out: list[Suggestion] = []
    by_vpc: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for eni in ctx.enis.values():
        if eni["owner_type"] == "lambda" and eni["vpc_id"]:
            by_vpc[eni["vpc_id"]].append(eni)

    for vpc_id, enis in sorted(by_vpc.items()):
        by_subnet: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in enis:
            by_subnet[e["subnet_id"]].append(e)

        # 1) several SG sets in the same subnet -> one ENI per (subnet, SG set)
        saved, touched, eni_ids = 0, [], []
        for subnet_id, sub_enis in sorted(by_subnet.items()):
            combos = Counter(_sg_key(e) for e in sub_enis)
            if len(combos) > 1:
                dominant = combos.most_common(1)[0][0]
                saved += len(combos) - 1
                touched.append(subnet_id)
                eni_ids += [e["eni_id"] for e in sub_enis if _sg_key(e) != dominant]
        if saved:
            out.append(Suggestion(
                key=f"lambda-sg:{vpc_id}",
                kind="lambda_sg_combo",
                title=f"Standardise Lambda security groups in {vpc_id}",
                detail="Lambda creates one ENI per unique subnet + security-group combination. "
                       f"{len(touched)} subnet(s) host several SG combinations; sharing one SG "
                       "set per subnet removes the extra ENIs.",
                vpc_id=vpc_id, ips_saved=saved, subnet_ids=touched, eni_ids=eni_ids,
            ))

        # 2) Lambda spread across several subnets in the same AZ
        by_az: dict[str, list[str]] = defaultdict(list)
        for subnet_id in by_subnet:
            st = ctx.subnets.get(subnet_id)
            if st:
                by_az[st.az].append(subnet_id)
        for az, subnet_ids in sorted(by_az.items()):
            if len(subnet_ids) < 2:
                continue
            target = max(subnet_ids, key=lambda s: (ctx.subnets[s].free, s))
            target_sets = {_sg_key(e) for e in by_subnet[target]}
            moved, saved_here, src_enis = 0, 0, []
            for sid in sorted(set(subnet_ids) - {target}):
                for e in by_subnet[sid]:
                    src_enis.append(e["eni_id"])
                    if _sg_key(e) in target_sets:
                        saved_here += ctx.eni_ip_count.get(e["eni_id"], 1)
                    else:
                        target_sets.add(_sg_key(e))
                        moved += 1
            if saved_here:
                out.append(Suggestion(
                    key=f"lambda-spread:{vpc_id}:{az}",
                    kind="lambda_subnet_spread",
                    title=f"Use a single Lambda subnet in {az} ({vpc_id})",
                    detail=f"Lambda ENIs are spread over {len(subnet_ids)} subnets in {az}. "
                           f"Pointing functions at {target} only removes duplicate ENIs.",
                    vpc_id=vpc_id, ips_saved=saved_here,
                    subnet_ids=sorted(set(subnet_ids) - {target}),
                    target_subnets={target: moved} if moved else {target: 0},
                    eni_ids=src_enis,
                ))

        # 3) the radical option: run functions outside the VPC
        total = sum(ctx.eni_ip_count.get(e["eni_id"], 1) for e in enis)
        out.append(Suggestion(
            key=f"lambda-novpc:{vpc_id}",
            kind="lambda_detach_vpc",
            title=f"Run Lambdas that need no private access outside {vpc_id}",
            detail="Functions that only call public AWS APIs do not need a VPC attachment; "
                   "detaching them frees their Hyperplane ENIs.",
            vpc_id=vpc_id, ips_saved=total, subnet_ids=sorted(by_subnet),
            eni_ids=[e["eni_id"] for e in enis], flags={"lambda_detach_vpc"},
        ))
    return out


def _endpoint_ip_count(ctx: Context, ep: dict[str, Any]) -> int:
    return sum(ctx.eni_ip_count.get(e, 1) for e in ep["eni_ids"])


def _endpoints(ctx: Context) -> list[Suggestion]:
    out: list[Suggestion] = []
    interface = [e for e in ctx.endpoints if (e["endpoint_type"] or "").lower() == "interface"]
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for ep in interface:
        groups[(ep["vpc_id"], ep["service_name"])].append(ep)

    for (vpc_id, service), eps in sorted(groups.items()):
        if len(eps) > 1:
            keep = max(eps, key=lambda e: (len(e["subnet_ids"]), e["endpoint_id"]))
            extra = [e for e in eps if e is not keep]
            out.append(Suggestion(
                key=f"dup-endpoint:{vpc_id}:{service}",
                kind="duplicate_endpoint",
                title=f"Remove duplicate {service} endpoints in {vpc_id}",
                detail=f"{len(eps)} interface endpoints serve {service}; keep "
                       f"{keep['endpoint_id']} and remove "
                       f"{', '.join(e['endpoint_id'] for e in extra)}.",
                vpc_id=vpc_id,
                ips_saved=sum(_endpoint_ip_count(ctx, e) for e in extra),
                subnet_ids=sorted({s for e in extra for s in e["subnet_ids"]}),
                eni_ids=[i for e in extra for i in e["eni_ids"]],
            ))
        if service.endswith(GATEWAY_CAPABLE):
            out.append(Suggestion(
                key=f"gw-endpoint:{vpc_id}:{service}",
                kind="gateway_endpoint",
                title=f"Use a gateway endpoint for {service} in {vpc_id}",
                detail="S3 and DynamoDB support gateway endpoints, which are free, stay "
                       "private and consume no subnet IPs.",
                vpc_id=vpc_id,
                ips_saved=sum(_endpoint_ip_count(ctx, e) for e in eps),
                subnet_ids=sorted({s for e in eps for s in e["subnet_ids"]}),
                eni_ids=[i for e in eps for i in e["eni_ids"]],
            ))

    nat_vpcs = {e["vpc_id"] for e in ctx.enis.values() if e["owner_type"] == "nat"}
    by_vpc: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ep in interface:
        by_vpc[ep["vpc_id"]].append(ep)
    for vpc_id, eps in sorted(by_vpc.items()):
        if vpc_id not in nat_vpcs:
            continue
        out.append(Suggestion(
            key=f"endpoint-nat:{vpc_id}",
            kind="endpoint_via_nat",
            title=f"Reach AWS services through the NAT gateway in {vpc_id}",
            detail=f"Removing {len(eps)} interface endpoint(s) frees their ENIs, but traffic "
                   "would leave the VPC over public service endpoints.",
            vpc_id=vpc_id,
            ips_saved=sum(_endpoint_ip_count(ctx, e) for e in eps),
            subnet_ids=sorted({s for e in eps for s in e["subnet_ids"]}),
            eni_ids=[i for e in eps for i in e["eni_ids"]],
            flags={"public_path:vpc_endpoint"},
        ))
    return out


def _az_imbalance(ctx: Context) -> list[Suggestion]:
    out = []
    for vpc in ctx.vpcs:
        per_az: dict[str, int] = defaultdict(int)
        for s in vpc.subnets:
            per_az[s.az] += s.consumed
        if len(per_az) < 2:
            continue
        azs = sorted(per_az)
        hot = max(azs, key=per_az.__getitem__)
        cold = min(azs, key=per_az.__getitem__)
        delta = per_az[hot] - per_az[cold]
        if delta < AZ_IMBALANCE_MIN_DELTA or per_az[hot] < AZ_IMBALANCE_RATIO * per_az[cold]:
            continue
        candidates = [s for s in vpc.subnets if s.az == cold]
        target = max(candidates, key=lambda s: (s.free, s.subnet_id))
        shift = delta // 2
        out.append(Suggestion(
            key=f"az:{vpc.vpc_id}",
            kind="az_imbalance",
            title=f"Rebalance IP usage across AZs in {vpc.vpc_id}",
            detail=f"{hot} uses {per_az[hot]} IPs vs {per_az[cold]} in {cold}. Shifting "
                   f"~{shift} IPs of workload to {target.subnet_id} evens out exhaustion risk.",
            vpc_id=vpc.vpc_id,
            impact=f"~{shift} IPs headroom in {hot}",
            target_subnets={target.subnet_id: shift},
        ))
    return out


def _secondary_cidr(ctx: Context) -> list[Suggestion]:
    out = []
    for vpc in ctx.vpcs:
        usable = sum(s.usable for s in vpc.subnets)
        consumed = sum(s.consumed for s in vpc.subnets)
        if not usable:
            continue
        consumed_pct = 100.0 * consumed / usable
        if vpc.allocated_pct < VPC_SPACE_ALLOCATED_PCT or consumed_pct < VPC_CONSUMED_PCT:
            continue
        out.append(Suggestion(
            key=f"cidr:{vpc.vpc_id}",
            kind="secondary_cidr",
            title=f"Add a secondary CIDR to {vpc.vpc_id}",
            detail=f"{vpc.allocated_pct:.0f}% of the VPC range is carved into subnets and "
                   f"{consumed_pct:.0f}% of subnet IPs are in use. A secondary CIDR (for example "
                   "from 100.64.0.0/10 for non-routable workloads) adds room for new subnets.",
            vpc_id=vpc.vpc_id,
            impact="adds capacity",
        ))
    return out


GENERATORS = (_detached_enis, _lambda, _endpoints, _az_imbalance, _secondary_cidr)


def generate(ctx: Context, rules: list[Rule]) -> list[Suggestion]:
    suggestions: list[Suggestion] = []
    for gen in GENERATORS:
        suggestions.extend(gen(ctx))
    for s in suggestions:
        for rule in rules:
            reason = rule.blocks(s, ctx)
            if reason:
                s.blocked_by.append((rule.name, reason))
    suggestions.sort(key=lambda s: (s.blocked, -s.ips_saved, s.kind, s.key))
    return suggestions


def totals(suggestions: list[Suggestion]) -> dict[str, int]:
    return {
        "allowed": sum(s.ips_saved for s in suggestions if not s.blocked),
        "blocked": sum(s.ips_saved for s in suggestions if s.blocked),
    }
