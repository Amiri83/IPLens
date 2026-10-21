"""Owner names of managed-service ENIs: RDS / Aurora, Redshift, ElastiCache, OpenSearch, MSK.

AWS creates these interfaces in the account's subnets, and the ENI itself only says
which service it belongs to (requester ``amazon-rds``, description ``RDSNetworkInterface``,
...). The optional collectors (see :class:`iplens.collector.Collector`) list the
clusters / domains as :class:`ManagedResource` rows, and :class:`ManagedIndex` maps an
ENI to the one it belongs to, so its owner name reads e.g. "Aurora cluster db-a"
instead of the generic "RDS".

Only ENIs that today's attribution (:func:`iplens.attribution.attribute_eni`) already
gives to the service are considered: owner type ``rds`` / ``elasticache`` /
``opensearch``, and for Redshift and MSK (no owner type of their own) ``other`` ENIs
not identified as something else. Signals, most reliable first; the first one with a
candidate decides, and candidates with different names there leave the ENI unmatched:

1. the ENI id or one of its private IPs (Redshift cluster nodes and managed endpoints),
2. the reference the ENI description names (ElastiCache cache cluster id, OpenSearch
   domain name),
3. the subnet and exactly the resource's security groups,
4. exactly the resource's security groups, for resources whose subnets are unknown (a
   subnet group is only a name: Aurora / RDS clusters, Redshift, ElastiCache).

An ENI whose description names a resource is never matched by 3. / 4. to a resource of
the same service that has another name. Redshift and MSK ENIs also need to be
requester-managed or carry the service in their description for 3. / 4.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .attribution import Attribution

# Snapshot table of each service's resources (one per Retry merge entry, see
# iplens.collector._MERGED), all with the columns of db.MANAGED_TABLE.
TABLES = {
    "rds": "rds_resources",
    "redshift": "redshift_clusters",
    "elasticache": "elasticache_resources",
    "opensearch": "opensearch_domains",
    "msk": "msk_clusters",
}

# ENI owner types (iplens.attribution) each service's ENIs carry.
_OWNER_TYPES = {
    "rds": "rds",
    "redshift": "other",
    "elasticache": "elasticache",
    "opensearch": "opensearch",
    "msk": "other",
}
# Redshift / MSK ("other" ENIs): matching by network needs one of these signs.
_DESC_HINTS = {
    "redshift": re.compile(r"redshift", re.IGNORECASE),
    "msk": re.compile(r"\b(?:kafka|msk)\b", re.IGNORECASE),
}


@dataclass(frozen=True)
class ManagedResource:
    service: str  # a key of TABLES
    kind: str  # instance | cluster | cache_cluster | domain | serverless
    resource_id: str
    name: str  # owner name of its ENIs, e.g. "Aurora cluster db-a"
    ref: str = ""  # owner_ref of its ENIs (cluster / instance id, domain name)
    vpc_id: str = ""
    subnet_ids: tuple[str, ...] = ()  # empty: unknown
    security_groups: tuple[str, ...] = ()
    eni_ids: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    refs: tuple[str, ...] = ()  # references ENI descriptions name


@dataclass(frozen=True)
class Match:
    name: str
    ref: str  # "" when the matching resources disagree (the ENI keeps its own)


def _ids(items: Iterable[dict], key: str) -> tuple[str, ...]:
    return tuple(sorted({str(i[key]) for i in items or [] if i.get(key)}))


def _sorted(values: Iterable[str | None]) -> tuple[str, ...]:
    return tuple(sorted({v for v in values if v}))


# -- API responses -> resources ------------------------------------------------------


def _rds_name(engine: str, identifier: str, *, cluster: bool) -> str:
    engine = (engine or "").lower()
    if engine.startswith("aurora"):
        return f"Aurora cluster {identifier}"
    if engine.startswith("docdb"):
        return f"DocumentDB cluster {identifier}"
    if engine.startswith("neptune"):
        return f"Neptune cluster {identifier}"
    return f"RDS {'cluster' if cluster else 'instance'} {identifier}"


def rds_resources(instances: Iterable[dict], clusters: Iterable[dict]) -> list[ManagedResource]:
    """``rds:DescribeDBInstances`` / ``rds:DescribeDBClusters`` items. A cluster member is
    named after its cluster ("Aurora cluster <id>"); a cluster is matched by its security
    groups alone (its subnet group is only a name), its instances by subnet as well."""
    clusters = list(clusters)
    engines = {c.get("DBClusterIdentifier"): c.get("Engine") or "" for c in clusters}
    out = []
    for c in clusters:
        cid = c.get("DBClusterIdentifier")
        if not cid:
            continue
        out.append(
            ManagedResource(
                "rds",
                "cluster",
                cid,
                _rds_name(c.get("Engine") or "", cid, cluster=True),
                cid,
                security_groups=_ids(c.get("VpcSecurityGroups"), "VpcSecurityGroupId"),
            )
        )
    for db in instances:
        iid = db.get("DBInstanceIdentifier")
        if not iid:
            continue
        cid = db.get("DBClusterIdentifier") or ""
        engine = db.get("Engine") or engines.get(cid, "")
        group = db.get("DBSubnetGroup") or {}
        out.append(
            ManagedResource(
                "rds",
                "instance",
                iid,
                _rds_name(engine, cid or iid, cluster=bool(cid)),
                cid or iid,
                vpc_id=group.get("VpcId") or "",
                subnet_ids=_ids(group.get("Subnets"), "SubnetIdentifier"),
                security_groups=_ids(db.get("VpcSecurityGroups"), "VpcSecurityGroupId"),
            )
        )
    return out


def redshift_resources(clusters: Iterable[dict]) -> list[ManagedResource]:
    """``redshift:DescribeClusters`` items: matched by node / endpoint IP and ENI id."""
    out = []
    for c in clusters:
        cid = c.get("ClusterIdentifier")
        if not cid:
            continue
        nics = [n for ep in c.get("VpcEndpoints") or [] for n in ep.get("NetworkInterfaces") or []]
        out.append(
            ManagedResource(
                "redshift",
                "cluster",
                cid,
                f"Redshift cluster {cid}",
                cid,
                vpc_id=c.get("VpcId") or "",
                security_groups=_ids(c.get("VpcSecurityGroups"), "VpcSecurityGroupId"),
                eni_ids=_ids(nics, "NetworkInterfaceId"),
                ips=_sorted(
                    [n.get("PrivateIPAddress") for n in c.get("ClusterNodes") or []]
                    + [n.get("PrivateIpAddress") for n in nics]
                ),
            )
        )
    return out


def elasticache_resources(
    cache_clusters: Iterable[dict], replication_groups: Iterable[dict]
) -> list[ManagedResource]:
    """``elasticache:DescribeCacheClusters`` / ``DescribeReplicationGroups`` items. ENI
    descriptions name the cache cluster ("ElastiCache <cache cluster id>"); a member of a
    replication group is named after the group."""
    groups = list(replication_groups)
    group_of = {m: g["ReplicationGroupId"] for g in groups for m in g.get("MemberClusters") or []}
    out = []
    seen = set()
    for cc in cache_clusters:
        ccid = cc.get("CacheClusterId")
        if not ccid:
            continue
        seen.add(ccid)
        group = cc.get("ReplicationGroupId") or group_of.get(ccid, "")
        engine = cc.get("Engine") or ""
        name = (
            f"ElastiCache replication group {group}"
            if group
            else " ".join(p for p in ("ElastiCache", engine, "cluster", ccid) if p)
        )
        out.append(
            ManagedResource(
                "elasticache",
                "cache_cluster",
                ccid,
                name,
                ccid,
                security_groups=_ids(cc.get("SecurityGroups"), "SecurityGroupId"),
                refs=(ccid,),
            )
        )
    # Without elasticache:DescribeCacheClusters: the members a replication group lists.
    for g in groups:
        for member in g.get("MemberClusters") or []:
            if member not in seen:
                seen.add(member)
                name = f"ElastiCache replication group {g['ReplicationGroupId']}"
                out.append(
                    ManagedResource(
                        "elasticache", "cache_cluster", member, name, member, refs=(member,)
                    )
                )
    return out


def opensearch_resources(domains: Iterable[dict]) -> list[ManagedResource]:
    """``es:DescribeDomains`` items with VPC access (public domains have no ENIs)."""
    out = []
    for d in domains:
        name = d.get("DomainName")
        vpc = d.get("VPCOptions") or {}
        if not name or not vpc.get("SubnetIds"):
            continue
        out.append(
            ManagedResource(
                "opensearch",
                "domain",
                name,
                f"OpenSearch domain {name}",
                name,
                vpc_id=vpc.get("VPCId") or "",
                subnet_ids=_sorted(vpc.get("SubnetIds") or []),
                security_groups=_sorted(vpc.get("SecurityGroupIds") or []),
                refs=(name,),
            )
        )
    return out


def msk_resources(clusters: Iterable[dict]) -> list[ManagedResource]:
    """``kafka:ListClustersV2`` items: brokers' client subnets and security groups
    (serverless: the union of the cluster's VPC configs)."""
    out = []
    for c in clusters:
        name = c.get("ClusterName")
        if not name:
            continue
        if c.get("ClusterType") == "SERVERLESS":
            configs = (c.get("Serverless") or {}).get("VpcConfigs") or []
            subnets = [s for cfg in configs for s in cfg.get("SubnetIds") or []]
            groups = [g for cfg in configs for g in cfg.get("SecurityGroupIds") or []]
            kind, label = "serverless", f"MSK Serverless cluster {name}"
        else:
            nodes = (c.get("Provisioned") or {}).get("BrokerNodeGroupInfo") or {}
            subnets, groups = nodes.get("ClientSubnets") or [], nodes.get("SecurityGroups") or []
            kind, label = "cluster", f"MSK cluster {name}"
        if subnets:
            out.append(
                ManagedResource(
                    "msk",
                    kind,
                    name,
                    label,
                    name,
                    subnet_ids=_sorted(subnets),
                    security_groups=_sorted(groups),
                )
            )
    return out


# -- snapshot rows ---------------------------------------------------------------------

_COLUMNS = "kind, resource_id, name, ref, vpc_id, subnet_ids, security_groups, eni_ids, ips, refs"
_LISTS = ("subnet_ids", "security_groups", "eni_ids", "ips", "refs")


def write(conn: sqlite3.Connection, snap_id: int, resources: Iterable[ManagedResource]) -> None:
    """One snapshot's rows of each resource's service table (:data:`TABLES`)."""
    for r in resources:
        conn.execute(
            f"INSERT OR IGNORE INTO {TABLES[r.service]}(snapshot_id, {_COLUMNS}) "  # noqa: S608
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                snap_id,
                r.kind,
                r.resource_id,
                r.name,
                r.ref,
                r.vpc_id,
                *(json.dumps(list(getattr(r, col))) for col in _LISTS),
            ),
        )


def load(conn: sqlite3.Connection, snap_id: int, service: str) -> list[ManagedResource]:
    """The resources of ``service`` stored with snapshot ``snap_id``."""
    rows = conn.execute(
        f"SELECT {_COLUMNS} FROM {TABLES[service]} WHERE snapshot_id=? "  # noqa: S608
        "ORDER BY kind, resource_id",
        (snap_id,),
    )
    return [
        ManagedResource(
            service,
            r["kind"],
            r["resource_id"],
            r["name"],
            r["ref"] or "",
            r["vpc_id"] or "",
            *(tuple(json.loads(r[col] or "[]")) for col in _LISTS),
        )
        for r in rows
    ]


# -- ENI matching ----------------------------------------------------------------------


class ManagedIndex:
    """The collected managed-service resources, indexed for :meth:`match`."""

    def __init__(self, resources: Iterable[ManagedResource]):
        self._by_type: dict[str, list[ManagedResource]] = {}
        self._by_eni: dict[str, list[ManagedResource]] = {}
        self._by_ip: dict[str, list[ManagedResource]] = {}
        self._by_ref: dict[str, list[ManagedResource]] = {}
        self._by_sgs: dict[frozenset[str], list[ManagedResource]] = {}
        for r in resources:
            self._by_type.setdefault(_OWNER_TYPES[r.service], []).append(r)
            for eni_id in r.eni_ids:
                self._by_eni.setdefault(eni_id, []).append(r)
            for ip in r.ips:
                self._by_ip.setdefault(ip, []).append(r)
            for ref in r.refs:
                self._by_ref.setdefault(ref, []).append(r)
            if r.security_groups:
                self._by_sgs.setdefault(frozenset(r.security_groups), []).append(r)

    def __bool__(self) -> bool:
        return bool(self._by_type)

    def match(self, eni: dict, attr: Attribution, ips: Sequence[str] = ()) -> Match | None:
        """The resource a raw ``describe_network_interfaces`` item belongs to (``attr``:
        its attribution, ``ips``: its private IPs), or None (see the module docstring)."""
        otype = attr.owner_type
        if otype not in self._by_type or (otype == "other" and attr.owner_ref):
            return None

        def eligible(found: Iterable[ManagedResource]) -> list[ManagedResource]:
            return [r for r in found if _OWNER_TYPES[r.service] == otype]

        vpc = eni.get("VpcId") or ""
        exact = eligible(self._by_eni.get(eni.get("NetworkInterfaceId") or "", []))
        exact += [
            r
            for ip in ips
            for r in eligible(self._by_ip.get(ip, []))
            if not r.vpc_id or r.vpc_id == vpc
        ]
        if exact:
            return _decide(exact)
        if attr.owner_ref:
            named = eligible(self._by_ref.get(attr.owner_ref, []))
            if named:
                return _decide(named)
        sgs = frozenset(g["GroupId"] for g in eni.get("Groups") or [] if g.get("GroupId"))
        network = [
            r
            for r in eligible(self._by_sgs.get(sgs, []))
            if not (attr.owner_ref and r.refs)
            and (not r.vpc_id or r.vpc_id == vpc)
            and _hinted(r.service, eni)
        ]
        subnet = eni.get("SubnetId") or ""
        in_subnet = [r for r in network if subnet in r.subnet_ids]
        if in_subnet:
            return _decide(in_subnet)
        anywhere = [r for r in network if not r.subnet_ids]
        return _decide(anywhere) if anywhere else None


def _hinted(service: str, eni: dict) -> bool:
    hint = _DESC_HINTS.get(service)
    if hint is None:
        return True
    return bool(eni.get("RequesterManaged")) or bool(hint.search(eni.get("Description") or ""))


def _decide(candidates: list[ManagedResource]) -> Match | None:
    names = {r.name for r in candidates}
    if len(names) != 1:
        return None
    refs = {r.ref for r in candidates}
    return Match(names.pop(), refs.pop() if len(refs) == 1 else "")
