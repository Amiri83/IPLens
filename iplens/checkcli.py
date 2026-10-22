"""``iplens check``: the pre-deploy IP fit check for CI (see :mod:`iplens.fitcheck`).

Exit codes: 0 = fits, 1 = does not fit or breaks a rule, 2 = error (bad arguments,
unreadable file, unknown subnet, AWS error). Read-only: a snapshot file needs no AWS
access at all; live mode makes only the Describe / List calls of :mod:`iplens.fitlive`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from typing import Any

from . import __version__, fitcheck
from .fitcheck import EXIT_ERROR, CheckError, CheckResult, SubnetFit
from .settings import DEFAULT_RESOURCE_TIMEOUT, MAX_RESOURCE_TIMEOUT, MIN_RESOURCE_TIMEOUT

FORMATS = ("text", "json", "markdown")


def _need(value: str) -> int:
    n = int(value)
    if n < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return n


def _pct(value: str) -> float:
    pct = float(value)
    if not 0 <= pct <= 100:
        raise argparse.ArgumentTypeError("must be between 0 and 100")
    return pct


def _timeout(value: str) -> int:
    seconds = int(value)
    if not MIN_RESOURCE_TIMEOUT <= seconds <= MAX_RESOURCE_TIMEOUT:
        raise argparse.ArgumentTypeError(
            f"must be {MIN_RESOURCE_TIMEOUT}-{MAX_RESOURCE_TIMEOUT} seconds"
        )
    return seconds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iplens check",
        description="Pre-deploy IP fit check: free IPs - existing headroom demand - plan "
        "demand, per subnet. Exit 0 = fits, 1 = does not fit / breaks a rule, 2 = error.",
    )
    what = parser.add_mutually_exclusive_group(required=True)
    what.add_argument("--plan", metavar="FILE", help="`terraform show -json` output of a plan")
    what.add_argument("--subnet", metavar="ID", help="check one subnet (with --need)")
    parser.add_argument("--need", type=_need, metavar="N", help="IPs to fit in --subnet")
    parser.add_argument(
        "--snapshot",
        metavar="FILE",
        help="IPLens 'snapshot for CI' export (Headroom page); default: live AWS",
    )
    parser.add_argument("--profile", help="AWS profile (live mode; default: env / default chain)")
    parser.add_argument("--region", help="AWS region (live mode)")
    parser.add_argument(
        "--timeout",
        type=_timeout,
        default=DEFAULT_RESOURCE_TIMEOUT,
        metavar="SECONDS",
        help=f"per-resource AWS timeout in live mode (default {DEFAULT_RESOURCE_TIMEOUT}; "
        "subnets and ENIs get at least the Refresh's required-resource timeout)",
    )
    parser.add_argument(
        "--min-free-pct",
        type=_pct,
        default=0.0,
        metavar="PCT",
        help="fail when less than PCT%% of a subnet's usable IPs would be left (default 0)",
    )
    parser.add_argument(
        "--rules", metavar="FILE", help="company rules export (Rules page, YAML) to enforce"
    )
    parser.add_argument(
        "--no-surge",
        action="store_true",
        help="leave out the ECS rolling-deployment surge (existing and planned services)",
    )
    parser.add_argument("--format", choices=FORMATS, default="text", help="output (default text)")
    parser.add_argument("--version", action="version", version=f"iplens {__version__}")
    return parser


def run(args: argparse.Namespace) -> CheckResult:
    include_surge = not args.no_surge
    rules = fitcheck.load_rules(args.rules) if args.rules else []
    plan = fitcheck.load_plan(args.plan) if args.plan else None
    if args.snapshot:
        inputs, source = fitcheck.load_snapshot(args.snapshot)
        notes: list[str] = []
    else:
        from . import fitlive

        # The subnets the plan names (a first pass without subnet data).
        empty = fitcheck.Inputs(subnets=[])
        ids = fitcheck.plan_demand(plan, empty, include_surge).subnet_ids if plan else [args.subnet]
        if ids:
            gw = fitlive.gateway(args.profile, args.region)
            inputs, source, notes = fitlive.load(gw, ids, args.timeout)
        else:  # nothing to place: no AWS call needed
            inputs, notes = empty, []
            source = fitcheck.Source(kind="live", label="live AWS (no subnet to read)")
    if plan is not None:
        demand = fitcheck.plan_demand(plan, inputs, include_surge)
    else:
        demand = fitcheck.need_demand(args.subnet, args.need)
    result = fitcheck.evaluate(
        inputs,
        demand,
        source,
        mode="plan" if plan is not None else "need",
        plan=plan,
        min_free_pct=args.min_free_pct,
        rules=rules,
        include_surge=include_surge,
    )
    result.notes += notes
    return result


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)  # exits 2 on bad arguments
    if args.subnet and args.need is None:
        parser.error("--subnet needs --need N")
    if args.need is not None and not args.subnet:
        parser.error("--need goes with --subnet")
    try:
        result = run(args)
    except CheckError as exc:
        _error(args.format, str(exc))
        return EXIT_ERROR
    print(RENDERERS[args.format](result))
    return result.exit_code


def _error(fmt: str, message: str) -> None:
    if fmt == "json":
        print(json.dumps({"result": "error", "exit_code": EXIT_ERROR, "error": message}, indent=2))
    elif fmt == "markdown":
        print(f"### IPLens IP fit check: error\n\n{_md(message)}")
    print(f"iplens check: error: {message}", file=sys.stderr)


# -- output ---------------------------------------------------------------------------------


def _row(f: SubnetFit) -> list[str]:
    return [
        f.subnet.subnet_id,
        f.subnet.name,
        f.subnet.az,
        f.subnet.cidr,
        str(f.free),
        str(f.existing_demand),
        str(f.plan_demand),
        str(f.left),
        f"{f.left_pct:.1f}%",
        f.status_label,
    ]


HEADERS = ["Subnet", "Name", "AZ", "CIDR", "Free", "Headroom", "Plan", "Left", "Left %", "Result"]
_RIGHT = {4, 5, 6, 7, 8}  # numeric columns


def _what(r: CheckResult) -> str:
    return "the plan" if r.mode == "plan" else "the request"


def render_text(r: CheckResult) -> str:
    lines = [f"IPLens IP fit check of {_what(r)} against {r.source.label}"]
    settings = [f"min free {r.min_free_pct:g}%"] if r.min_free_pct else []
    settings.append("deploy surge " + ("included" if r.include_surge else "left out"))
    lines.append(f"({', '.join(settings)}; Left = Free - Headroom - Plan)")
    lines.append("")
    if r.subnets:
        rows = [HEADERS] + [_row(f) for f in r.subnets]
        widths = [max(len(row[i]) for row in rows) for i in range(len(HEADERS))]
        for row in rows:
            cells = [
                c.rjust(widths[i]) if i in _RIGHT else c.ljust(widths[i]) for i, c in enumerate(row)
            ]
            lines.append("  ".join(cells).rstrip())
    else:
        lines.append("No IP demand in known subnets.")
    for f in r.subnets:
        lines.append("")
        lines.append(f"{f.subnet.subnet_id}:")
        for item in f.plan:
            lines.append(f"  plan      {item.text}")
        for c in f.existing:
            lines.append(f"  headroom  {c.text}")
    sections = [
        ("Unresolved (known after apply, not counted)", [u.text for u in r.unresolved]),
        ("Rule violations", [v.text for v in r.violations]),
        ("Notes", r.notes),
    ]
    for title, items in sections:
        if items:
            lines += ["", f"{title}:"] + [f"  - {i}" for i in items]
    lines += ["", f"Result: {r.summary}"]
    return "\n".join(lines)


def _md(text: Any) -> str:
    """Table-safe Markdown text (no raw HTML, no pipe breaking a table row)."""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
    )


def render_markdown(r: CheckResult) -> str:
    icon = "✅" if r.ok else "❌"
    lines = [
        f"### {icon} IPLens IP fit check: {_md(r.summary)}",
        "",
        f"Checked {_what(r)} against {_md(r.source.label)}; Left = Free − Headroom (existing "
        f"demand at max scale) − Plan."
        + (f" Minimum free: {r.min_free_pct:g}%." if r.min_free_pct else "")
        + ("" if r.include_surge else " ECS deploy surge left out."),
        "",
    ]
    if r.subnets:
        lines.append("| " + " | ".join(HEADERS) + " |")
        lines.append(
            "|" + "|".join("---:" if i in _RIGHT else "---" for i in range(len(HEADERS))) + "|"
        )
        for f in r.subnets:
            cells = [_md(c) for c in _row(f)]
            cells[0] = f"`{cells[0]}`"
            cells[-1] = f"**{cells[-1]}**" if f.status != fitcheck.FITS else cells[-1]
            lines.append("| " + " | ".join(cells) + " |")
    else:
        lines.append("No IP demand in known subnets.")
    if r.violations:
        lines += ["", "**Rule violations**", ""] + [f"- {_md(v.text)}" for v in r.violations]
    if r.unresolved:
        lines += ["", "**Unresolved** (known after apply, not counted)", ""]
        lines += [f"- {_md(u.text)}" for u in r.unresolved]
    if r.subnets:
        lines += ["", "<details><summary>Demand per subnet</summary>", ""]
        for f in r.subnets:
            lines.append(f"- `{_md(f.subnet.subnet_id)}`")
            lines += [f"  - plan: {_md(i.text)}" for i in f.plan]
            lines += [f"  - headroom: {_md(c.text)}" for c in f.existing]
        lines += ["", "</details>"]
    if r.notes:
        lines += ["", "**Notes**", ""] + [f"- {_md(n)}" for n in r.notes]
    return "\n".join(lines)


def to_dict(r: CheckResult) -> dict[str, Any]:
    return {
        "result": "fits" if r.ok else "does-not-fit",
        "exit_code": r.exit_code,
        "summary": r.summary,
        "mode": r.mode,
        "source": {"kind": r.source.kind, "label": r.source.label, "taken_at": r.source.taken_at},
        "min_free_pct": r.min_free_pct,
        "include_surge": r.include_surge,
        "subnets": [
            {
                "subnet_id": f.subnet.subnet_id,
                "name": f.subnet.name,
                "vpc_id": f.subnet.vpc_id,
                "az": f.subnet.az,
                "cidr": f.subnet.cidr,
                "usable": f.subnet.usable,
                "free": f.free,
                "headroom_demand": f.existing_demand,
                "plan_demand": f.plan_demand,
                "left": f.left,
                "left_pct": round(f.left_pct, 2),
                "status": f.status,
                "plan": [
                    {"address": i.address, "type": i.type, "ips": i.ips, "assumption": i.assumption}
                    for i in f.plan
                ],
                "headroom": [
                    {"kind": c.kind, "name": c.name, "ips": c.ips, "assumption": c.assumption}
                    for c in f.existing
                ],
            }
            for f in r.subnets
        ],
        "unresolved": [
            {"address": u.address, "type": u.type, "reason": u.reason, "ips": u.ips}
            for u in r.unresolved
        ],
        "violations": [
            {"rule": v.rule, "kind": v.kind, "message": v.message} for v in r.violations
        ],
        "notes": list(r.notes),
    }


def render_json(r: CheckResult) -> str:
    return json.dumps(to_dict(r), indent=2)


RENDERERS: dict[str, Callable[[CheckResult], str]] = {
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
}
