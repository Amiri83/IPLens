"""Flask application: settings, collection, views, rules, suggestions, logs."""

from __future__ import annotations

import logging
import os
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup

from . import diagram, queries, viewstate
from . import rules as rules_mod
from . import scope as scope_mod
from . import suggestions as sugg_mod
from .accounts import (
    AUTH_MODE_LABELS,
    AUTH_MODES,
    EXPIRED_MESSAGE,
    Account,
    AccountStore,
    CredentialError,
    MemoryVault,
    discover_profiles,
)
from .attribution import OWNER_LABELS, OWNER_TYPES
from .aws import AwsGateway, check_connection, is_credential_failure
from .collector import Collector
from .config import AppPaths, default_paths
from .crypto import SecretBox
from .db import closing, connect, init_db
from .export import XLSX_MIMETYPE, ips_to_xlsx
from .logging_setup import LEVELS, configure_logging, read_log
from .queries import LB_ICONS, TYPE_ICONS
from .settings import MAX_DISPLAY_NAME, REGIONS, Settings, SettingsStore
from .visual import (
    DEFAULT_EDGE_TYPES,
    EDGE_TYPE_LABELS,
    EDGE_TYPES,
    SHORT_NAME_MAX,
    parse_edge_types,
)

log = logging.getLogger(__name__)

GatewayFactory = Callable[[Account], AwsGateway]
# Typed on the Discovery page to confirm deleting snapshots.
DELETE_CONFIRMATION = "DELETE"
HISTORY_ROWS = 50
OUT_OF_SCOPE = "This resource is outside the active scope."
# DNS-rebinding protection: only these Host header names are served.
ALLOWED_HOSTS = ("127.0.0.1", "localhost")


def host_allowed(host: str, port: int | None) -> bool:
    """True if ``host`` (a raw Host header) names this local server.

    With a known ``port`` the header must carry exactly that port (a bare name
    is only valid for port 80). With ``port=None`` any numeric port is accepted.
    """
    name, sep, host_port = host.strip().lower().partition(":")
    if name not in ALLOWED_HOSTS:
        return False
    if port is None:
        return not sep or host_port.isdigit()
    return host_port == str(port) if sep else port == 80


def account_label(account_id: str | None, alias: str | None, display_name: str = "") -> str:
    """``"<name> (<account id>)"``; the configured display name beats the IAM alias,
    and without either only the account id is shown."""
    name = display_name or alias or ""
    if name and account_id:
        return f"{name} ({account_id})"
    return name or account_id or "unknown account"


def snapshot_label(snap: Any) -> str:
    """Label from the snapshot's own frozen name / AWS account id / alias.

    Never the account record's current name: a renamed or re-pointed account must
    not relabel what was captured earlier.
    """
    keys = snap.keys() if hasattr(snap, "keys") else snap
    name = snap["account_name"] if "account_name" in keys else ""
    return account_label(snap["account_id"], snap["account_alias"], name or "")


def utc_iso(value: Any) -> str | None:
    """Normalise a stored timestamp to ``YYYY-MM-DDTHH:MM:SSZ``.

    Snapshot times are stored timezone-aware (UTC); naive values (log file lines)
    are in the server's local time. Returns None for empty/unparseable input.
    """
    if not value:
        return None
    try:
        ts = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.astimezone()
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_time(value: Any) -> Markup | str:
    """``<time>`` element that static/localtime.js re-renders in the browser's time zone.

    The UTC text is only the no-JavaScript fallback; the ISO value stays in the tooltip.
    """
    iso = utc_iso(value)
    if iso is None:
        return value or ""
    fallback = iso.replace("T", " ").removesuffix("Z") + " UTC"
    return Markup('<time class="localtime" datetime="{0}" title="{0}">{1}</time>').format(
        iso, fallback
    )


def _flask_secret(paths: AppPaths) -> bytes:
    p = paths.flask_secret_path
    if p.exists():
        return p.read_bytes()
    key = secrets.token_bytes(32)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def create_app(
    home: str | os.PathLike[str] | None = None,
    *,
    gateway_factory: GatewayFactory | None = None,
    testing: bool = False,
    port: int | None = None,
) -> Flask:
    """Build the app. ``port`` is the port the server listens on; when given,
    the Host header must be ``127.0.0.1:<port>`` or ``localhost:<port>``."""
    paths = default_paths(home).ensure()
    init_db(paths.db_path)
    box = SecretBox.from_path(paths.key_path)
    store = SettingsStore(paths.db_path)
    # Memory-only credentials live in this process for the lifetime of the app.
    account_store = AccountStore(paths.db_path, box, MemoryVault())

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=_flask_secret(paths),
        TESTING=testing,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_HTTPONLY=True,
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )
    app.extensions["iplens"] = {
        "paths": paths,
        "store": store,
        "accounts": account_store,
        "gateway_factory": gateway_factory or AwsGateway.from_account,
        "port": port,
    }
    apply_log_dir(app, store.load())
    log.info("IPLens started (data dir %s)", paths.home)

    _register(app)
    return app


def _ext() -> dict[str, Any]:
    return current_app.extensions["iplens"]


def _paths() -> AppPaths:
    return _ext()["paths"]


def _store() -> SettingsStore:
    return _ext()["store"]


def _accounts() -> AccountStore:
    return _ext()["accounts"]


def log_dir_for(paths: AppPaths, settings: Settings) -> Path:
    return Path(settings.log_dir).expanduser() if settings.log_dir else paths.default_log_dir


def apply_log_dir(app: Flask, settings: Settings) -> Path:
    paths: AppPaths = app.extensions["iplens"]["paths"]
    log_dir = log_dir_for(paths, settings)
    configure_logging(log_dir)
    app.extensions["iplens"]["log_dir"] = log_dir
    return log_dir


def _db():
    if "db" not in g:
        g.db = connect(_paths().db_path)
    return g.db


def _active() -> Account | None:
    """The active account; falls back to (and persists) the first one if unset or gone."""
    if "active_account" not in g:
        store = _accounts()
        acct = store.get(_store().active_account_id())
        if acct is None:
            acct = next(iter(store.list()), None)
            _store().set_active_account_id(acct.id if acct else None)
        g.active_account = acct
    return g.active_account


def _active_ref() -> int | None:
    acct = _active()
    return acct.id if acct else None


def _snapshot_or_none():
    """Latest successful snapshot of the active account (None without an account)."""
    ref = _active_ref()
    return queries.latest_snapshot(_db(), ref) if ref is not None else None


def _scope_config() -> scope_mod.Scope:
    """The active account's saved scope."""
    if "scope_config" not in g:
        g.scope_config = scope_mod.load(_db(), _active_ref())
    return g.scope_config


def _scope() -> scope_mod.ResolvedScope:
    """The active account's scope applied to its latest snapshot."""
    if "scope" not in g:
        snap = _snapshot_or_none()
        g.scope = (
            scope_mod.resolve(_db(), snap["id"], _scope_config()) if snap else scope_mod.UNSCOPED
        )
    return g.scope


def _in_scope_or_404(subnet_id: str | None) -> None:
    if not _scope().subnet_ok(subnet_id):
        abort(404, OUT_OF_SCOPE)


def account_choice_label(acct: Account, snap: Any = None) -> str:
    """Selector label: the display name, else the alias / AWS account id seen last."""
    if acct.display_name:
        return acct.display_name
    if snap is not None and (snap["account_alias"] or snap["account_id"]):
        return account_label(snap["account_id"], snap["account_alias"])
    if acct.aws_account_id:
        return acct.aws_account_id
    return f"Account {acct.id}"


def _account_choices() -> list[dict[str, Any]]:
    if "account_choices" not in g:
        g.account_choices = [
            {
                "id": acct.id,
                "label": account_choice_label(acct, queries.latest_snapshot(_db(), acct.id)),
                "account": acct.public_dict(),
            }
            for acct in _accounts().list()
        ]
    return g.account_choices


def _safe_next(target: str | None) -> str:
    """Only same-site paths ("/..."), never "//host", a scheme or a backslash trick."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("overview")


def _credential_flash(prefix: str, message: str, account_id: int) -> None:
    edit = url_for("account_edit", account_id=account_id)
    flash(
        Markup('{0}: {1} — <a href="{2}">edit account</a>').format(prefix, message, edit),
        "error",
    )


def _identity_flash(message: str, account_id: int) -> None:
    edit = url_for("account_edit", account_id=account_id)
    flash(
        Markup('Warning: {0} — check the <a href="{1}">account settings</a>.').format(
            message, edit
        ),
        "warn",
    )


def _register(app: Flask) -> None:
    @app.teardown_appcontext
    def _close_db(_exc: BaseException | None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # Registered first so it runs before anything else touches the request.
    @app.before_request
    def _trusted_host() -> None:
        # Raw header: werkzeug's request.host drops default ports.
        host = request.headers.get("Host", "")
        if not host_allowed(host, _ext()["port"]):
            log.warning(
                "rejected request %s with untrusted Host header %r", request.path, host[:100]
            )
            abort(400, "invalid Host header")

    @app.before_request
    def _csrf() -> None:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            if not secrets.compare_digest(sent, session["csrf"]):
                log.warning("rejected POST %s with bad CSRF token", request.path)
                abort(400, "invalid CSRF token")

    @app.context_processor
    def _globals() -> dict[str, Any]:
        active = _active()
        choice = next((c for c in _account_choices() if active and c["id"] == active.id), None)
        return {
            "csrf_token": session.get("csrf", ""),
            "owner_labels": OWNER_LABELS,
            "active_account": active.public_dict() if active else None,
            # The record's current label: only for "No data yet for <name>" and selectors.
            "active_label": choice["label"] if choice else "",
            "account_choices": _account_choices(),
            "header_snap": _snapshot_or_none(),
            "account_label": snapshot_label,
            "scope_count": _scope_config().count if active else 0,
        }

    @app.template_filter("pct")
    def _pct(v: float) -> str:
        return f"{v:.1f}%"

    app.add_template_filter(local_time, "localtime")

    # -- overview / collection ---------------------------------------------

    @app.get("/")
    def overview():
        snap = _snapshot_or_none()
        tree, owners = [], {}
        if snap:
            tree = queries.vpc_tree(_db(), snap["id"], _scope())
            owners = queries.owner_breakdown(_db(), snap["id"], _scope())
        ref = _active_ref()
        history = queries.recent_snapshots(_db(), HISTORY_ROWS, ref) if ref is not None else []
        return render_template(
            "overview.html",
            snap=snap,
            tree=tree,
            owners=owners,
            history=history,
            protected=queries.protected_snapshot_ids(_db()),
            confirm_word=DELETE_CONFIRMATION,
        )

    @app.post("/refresh")
    def refresh():
        raw = request.form.get("account_id", "")
        if raw:
            # Discovery's account dropdown: collect that account and switch the views to it.
            chosen = _accounts().get(int(raw)) if raw.isdigit() else None
            if chosen is None:
                abort(400, "unknown account")
            _store().set_active_account_id(chosen.id)
            g.pop("active_account", None)
        active = _active()
        if active is None:
            flash("Add an AWS account in Settings first.", "error")
            return redirect(url_for("settings_page"))
        try:
            account = _accounts().get(active.id, with_secret=True)
            gw = _ext()["gateway_factory"](account)
            result = Collector(gw, _paths().db_path, account.id, account.display_name).run()
            with closing(_paths().db_path) as conn:
                queries.prune_snapshots(conn)
        except Exception as exc:
            # Full details (type, message, traceback) go to the log file only;
            # raw errors can carry ARNs, account ids or request ids.
            log.exception("refresh failed (account=%s)", active.id)
            if is_credential_failure(exc):
                msg = str(exc) if isinstance(exc, CredentialError) else EXPIRED_MESSAGE
                _credential_flash("Refresh failed", msg, active.id)
            else:
                flash("Refresh failed. See the log for details.", "error")
            return redirect(url_for("overview"))
        label = account_label(result.account_id, result.account_alias, account.display_name)
        msg = (
            f"Refreshed {label} · {gw.region}: {result.vpcs} VPCs, {result.subnets} subnets, "
            f"{result.enis} ENIs, {result.ips} IPs"
        )
        flash(msg, "ok")
        mismatch = _accounts().record_identity(account.id, result.account_id)
        if mismatch:
            log.warning("refresh of account=%s: %s", account.id, mismatch)
            _identity_flash(mismatch, account.id)
        for w in result.warnings:
            flash(w, "warn")
        return redirect(url_for("overview"))

    # -- snapshot history ------------------------------------------------------------

    def _confirmed() -> bool:
        if request.form.get("confirm", "").strip() == DELETE_CONFIRMATION:
            return True
        flash(f"Type {DELETE_CONFIRMATION} to confirm.", "error")
        return False

    @app.post("/snapshots/delete")
    def snapshots_delete():
        ref = _active_ref()
        if ref is None or not _confirmed():
            return redirect(url_for("overview"))
        ids = {int(v) for v in request.form.getlist("snapshot_id") if v.isdigit()}
        if not ids:
            flash("Select at least one snapshot.", "error")
            return redirect(url_for("overview"))
        with closing(_paths().db_path) as conn:
            deleted, kept = queries.delete_snapshots(conn, ids, ref)
        log.info("deleted %d snapshot(s) of account=%s", deleted, ref)
        flash(f"Deleted {deleted} snapshot(s).", "ok")
        if kept:
            flash("The latest snapshot of each account is always kept.", "warn")
        return redirect(url_for("overview"))

    @app.post("/snapshots/clear")
    def snapshots_clear():
        ref = _active_ref()
        if ref is None or not _confirmed():
            return redirect(url_for("overview"))
        every = request.form.get("scope") == "all"
        with closing(_paths().db_path) as conn:
            deleted = queries.clear_history(conn, None if every else ref)
        log.info(
            "cleared history (%s): %d snapshot(s)",
            "all accounts" if every else f"account={ref}",
            deleted,
        )
        flash(f"Cleared history: deleted {deleted} snapshot(s), kept the latest per account.", "ok")
        return redirect(url_for("overview"))

    # -- subnet grid / ENI / IP table ----------------------------------------

    @app.get("/subnets/<subnet_id>")
    def subnet(subnet_id: str):
        snap = _snapshot_or_none()
        if not snap:
            return redirect(url_for("overview"))
        st = queries.get_subnet(_db(), snap["id"], subnet_id)
        if st is None:
            abort(404)
        _in_scope_or_404(subnet_id)
        page = request.args.get("page", 0, type=int)
        grid = queries.subnet_grid(_db(), snap["id"], st, page)
        enis = queries.subnet_enis(_db(), snap["id"], subnet_id)
        return render_template("subnet.html", snap=snap, s=st, grid=grid, enis=enis)

    @app.get("/enis/<eni_id>")
    def eni(eni_id: str):
        snap = _snapshot_or_none()
        if not snap:
            return redirect(url_for("overview"))
        detail = queries.eni_detail(_db(), snap["id"], eni_id)
        if detail is None:
            abort(404)
        _in_scope_or_404(detail["subnet_id"])
        return render_template("eni.html", snap=snap, e=detail)

    def _ip_filter() -> queries.IpFilter:
        a = request.args
        owner = a.get("owner", "")
        state = a.get("state", "")
        return queries.IpFilter(
            vpc=a.get("vpc", "").strip(),
            subnet=a.get("subnet", "").strip(),
            owner=owner if owner in OWNER_TYPES else "",
            state=state if state in ("used", "idle") else "",
            q=a.get("q", "").strip(),
        )

    @app.get("/ips")
    def ips():
        snap = _snapshot_or_none()
        flt = _ip_filter()
        rows, tree = [], []
        if snap:
            rows = queries.ip_list(_db(), snap["id"], flt, _scope())
            tree = queries.vpc_tree(_db(), snap["id"], _scope())
        return render_template(
            "ips.html",
            snap=snap,
            rows=rows,
            f=flt,
            tree=tree,
            owner_types=OWNER_TYPES,
            type_label=lambda r: queries.resource_type_label(r, OWNER_LABELS),
        )

    @app.get("/ips/export.xlsx")
    def ips_export():
        snap = _snapshot_or_none()
        flt = _ip_filter()
        rows = queries.ip_list(_db(), snap["id"], flt, _scope()) if snap else []
        body = ips_to_xlsx(rows, OWNER_LABELS)
        log.info("exported %d IP row(s) to xlsx", len(rows))
        name = f"iplens-ips-snapshot-{snap['id']}.xlsx" if snap else "iplens-ips.xlsx"
        return Response(
            body,
            mimetype=XLSX_MIMETYPE,
            headers={"Content-Disposition": f"attachment; filename={name}"},
        )

    # -- visual --------------------------------------------------------------------

    def _edge_types(default: tuple[str, ...] = EDGE_TYPES) -> tuple[str, ...]:
        # Absent means ``default``; the page form always sends an empty "edges"
        # value so that unticking every box is distinguishable.
        values = request.args.getlist("edges") if "edges" in request.args else None
        return parse_edge_types(values, default)

    @app.get("/visual")
    def visual():
        snap = _snapshot_or_none()
        tree = queries.vpc_tree(_db(), snap["id"], _scope()) if snap else []
        vpc = request.args.get("vpc", "")
        if tree and vpc not in {v.vpc_id for v in tree}:
            vpc = tree[0].vpc_id
        ref = _active_ref()
        prefs = viewstate.get_prefs(_db(), ref) if ref is not None else viewstate.DEFAULT_PREFS
        return render_template(
            "visual.html",
            snap=snap,
            tree=tree,
            vpc=vpc,
            edge_types=EDGE_TYPES,
            edge_labels=EDGE_TYPE_LABELS,
            # The data endpoint still returns every type; the browser filters, so
            # ticking "SG refs" later needs no refetch.
            edges_on=_edge_types(DEFAULT_EDGE_TYPES),
            prefs=prefs,
            short_name_max=SHORT_NAME_MAX,
            positions=viewstate.get_layout(_db(), ref, vpc) if ref is not None and vpc else {},
            legend_icons=_legend_icons(),
        )

    def _legend_icons() -> list[tuple[str, str]]:
        icons = [(OWNER_LABELS.get(t, t), f) for t, f in TYPE_ICONS.items() if t != "elb"]
        lbs = [("ALB", LB_ICONS["application"]), ("NLB", LB_ICONS["network"])]
        lbs.append(("GWLB", LB_ICONS["gateway"]))
        return icons[:1] + lbs + icons[1:]

    def _visual_vpc() -> str:
        vpc = request.form.get("vpc", "").strip()
        if not vpc or len(vpc) > 64:
            abort(400, "invalid VPC id")
        return vpc

    def _active_or_400() -> int:
        ref = _active_ref()
        if ref is None:
            abort(400, "no active account")
        return ref

    @app.post("/visual/prefs")
    def visual_prefs():
        ref = _active_or_400()
        # Only the toggles present in the form change; the others keep their value.
        changes = {k: request.form[k] == "1" for k in viewstate.DEFAULT_PREFS if k in request.form}
        with closing(_paths().db_path) as conn:
            viewstate.save_prefs(conn, ref, **changes)
        return "", 204

    @app.post("/visual/layout")
    def visual_layout_save():
        ref = _active_or_400()
        vpc = _visual_vpc()
        try:
            positions = viewstate.parse_positions(request.form.get("positions", ""))
        except ValueError as exc:
            abort(400, str(exc))
        with closing(_paths().db_path) as conn:
            viewstate.save_layout(conn, ref, vpc, positions)
        return "", 204

    @app.post("/visual/layout/reset")
    def visual_layout_reset():
        ref = _active_or_400()
        vpc = _visual_vpc()
        with closing(_paths().db_path) as conn:
            viewstate.reset_layout(conn, ref, vpc)
        log.info("visual layout reset (account=%s, %s)", ref, vpc)
        return "", 204

    def _export(ext: str, render: Callable[[diagram.View], str], mimetype: str) -> Response:
        try:
            view = diagram.parse_view(request.form.get("view", ""))
        except ValueError as exc:
            abort(400, f"invalid view: {exc}")
        name = diagram.export_filename(view, ext)
        body = render(view)
        log.info("exported %s: %d node(s), %d edge(s)", name, len(view.nodes), len(view.edges))
        return Response(
            body,
            mimetype=mimetype,
            headers={"Content-Disposition": f"attachment; filename={name}"},
        )

    @app.post("/visual/export.svg")
    def visual_export_svg():
        return _export("svg", diagram.view_to_svg, "image/svg+xml")

    @app.post("/visual/export.drawio")
    def visual_export_drawio():
        return _export("drawio", diagram.view_to_drawio, "application/vnd.jgraph.mxfile")

    @app.get("/visual/data.json")
    def visual_data():
        snap = _snapshot_or_none()
        if not snap:
            return jsonify({"snapshot_id": None, "vpcs": [], "vpc": None})
        data = queries.visual_data(
            _db(),
            snap["id"],
            request.args.get("vpc", "").strip(),
            OWNER_LABELS,
            _edge_types(),
            _scope(),
        )
        if data is None:
            abort(404)
        return jsonify(data)

    # -- rules -----------------------------------------------------------------

    def _context():
        snap = _snapshot_or_none()
        return (sugg_mod.build_context(_db(), snap["id"], _scope()) if snap else None), snap

    def _account_names() -> dict[int, str]:
        return {c["id"]: c["label"] for c in _account_choices()}

    def _rule_options() -> dict[str, Any]:
        """Choices for the rule form from the active account's latest snapshot (unscoped:
        rules are shared, so every subnet / VPC / load balancer can be picked)."""
        snap = _snapshot_or_none()
        if not snap:
            return {"tree": [], "lbs": [], "ecs": [], "names": {}}
        tree = queries.vpc_tree(_db(), snap["id"])
        lbs = [
            dict(r)
            for r in _db().execute(
                "SELECT name, lb_type, scheme, vpc_id FROM load_balancers WHERE snapshot_id=? "
                "ORDER BY name",
                (snap["id"],),
            )
        ]
        ecs = [
            f"{r['cluster']}/{r['service']}"
            for r in _db().execute(
                "SELECT cluster, service FROM ecs_services WHERE snapshot_id=? "
                "ORDER BY cluster, service",
                (snap["id"],),
            )
        ]
        names = {v.vpc_id: v.name for v in tree if v.name}
        names.update({s.subnet_id: s.name for v in tree for s in v.subnets if s.name})
        return {"tree": tree, "lbs": lbs, "ecs": ecs, "names": names}

    @app.get("/rules")
    def rules_list():
        rules = rules_mod.list_rules(_db())
        ctx, _snap = _context()
        ref = _active_ref()
        violations = {r.id: r.violations(ctx) for r in rules if r.applies_to(ref)} if ctx else {}
        return render_template(
            "rules.html",
            rules=rules,
            violations=violations,
            kinds=rules_mod.RULE_KINDS,
            account_names=_account_names(),
            active_ref=ref,
            names=_rule_options()["names"],
        )

    def _rule_from_form(rule_id: int | None) -> rules_mod.Rule:
        f = request.form
        return rules_mod.Rule(
            id=rule_id,
            name=f.get("name", ""),
            kind=f.get("kind", ""),
            enabled=f.get("enabled") == "on",
            description=f.get("description", ""),
            account_ref=int(f["account_ref"]) if f.get("account_ref", "").isdigit() else None,
            # Multi-selects send repeated values; a typed list (comma/space) also works.
            params={
                "percent": f.get("percent", ""),
                "subnet_ids": f.getlist("subnet_ids"),
                "vpc_ids": f.getlist("vpc_ids"),
                "lb_names": f.getlist("lb_names"),
                "scope": f.get("scope", ""),
                "pattern": f.get("pattern", ""),
                "mode": f.get("mode", ""),
            },
        )

    def _rule_form(rule: rules_mod.Rule, status: int = 200):
        return render_template(
            "rule_form.html",
            rule=rule,
            kinds=rules_mod.RULE_KINDS,
            scopes=rules_mod.INTERNAL_SCOPES,
            ecs_modes=rules_mod.ECS_MODES,
            scope_labels=rules_mod.INTERNAL_SCOPE_LABELS,
            account_names=_account_names(),
            options=_rule_options(),
        ), status

    @app.route("/rules/new", methods=["GET", "POST"])
    def rule_new():
        if request.method == "GET":
            return _rule_form(rules_mod.Rule(name="", kind="min_free_pct", params={"percent": 20}))
        rule = _rule_from_form(None)
        try:
            with closing(_paths().db_path) as conn:
                rules_mod.save_rule(conn, rule)
        except ValueError as exc:
            flash(str(exc), "error")
            return _rule_form(rule, 400)
        log.info("rule created: %s (%s)", rule.name, rule.kind)
        flash(f"Rule '{rule.name}' created", "ok")
        return redirect(url_for("rules_list"))

    @app.route("/rules/<int:rule_id>/edit", methods=["GET", "POST"])
    def rule_edit(rule_id: int):
        existing = rules_mod.get_rule(_db(), rule_id)
        if existing is None:
            abort(404)
        if request.method == "GET":
            return _rule_form(existing)
        rule = _rule_from_form(rule_id)
        try:
            with closing(_paths().db_path) as conn:
                rules_mod.save_rule(conn, rule)
        except ValueError as exc:
            flash(str(exc), "error")
            return _rule_form(rule, 400)
        log.info("rule updated: %s (%s)", rule.name, rule.kind)
        flash(f"Rule '{rule.name}' updated", "ok")
        return redirect(url_for("rules_list"))

    @app.post("/rules/<int:rule_id>/delete")
    def rule_delete(rule_id: int):
        rule = rules_mod.get_rule(_db(), rule_id)
        if rule is None:
            abort(404)
        with closing(_paths().db_path) as conn:
            rules_mod.delete_rule(conn, rule_id)
        log.info("rule deleted: %s", rule.name)
        flash(f"Rule '{rule.name}' deleted", "ok")
        return redirect(url_for("rules_list"))

    @app.get("/rules/export.yaml")
    def rules_export():
        body = rules_mod.export_yaml(rules_mod.list_rules(_db()))
        return Response(
            body,
            mimetype="application/x-yaml",
            headers={"Content-Disposition": "attachment; filename=iplens-rules.yaml"},
        )

    @app.post("/rules/import")
    def rules_import():
        upload = request.files.get("file")
        text = upload.read().decode("utf-8", "replace") if upload and upload.filename else ""
        text = text or request.form.get("yaml", "")
        replace = request.form.get("replace") == "on"
        try:
            parsed = rules_mod.parse_yaml(text)
            with closing(_paths().db_path) as conn:
                n = rules_mod.import_rules(conn, parsed, replace=replace)
        except ValueError as exc:
            flash(f"Import failed: {exc}", "error")
            return redirect(url_for("rules_list"))
        log.info("imported %d rule(s) (replace=%s)", n, replace)
        flash(f"Imported {n} rule(s)", "ok")
        return redirect(url_for("rules_list"))

    # -- suggestions -------------------------------------------------------------

    @app.get("/suggestions")
    def suggestions():
        ctx, snap = _context()
        items: list[sugg_mod.Suggestion] = []
        if ctx:
            rules = rules_mod.applicable(rules_mod.list_rules(_db()), _active_ref())
            items = sugg_mod.generate(ctx, rules)
        return render_template(
            "suggestions.html", snap=snap, items=items, totals=sugg_mod.totals(items)
        )

    # -- scope -------------------------------------------------------------------

    @app.get("/scope")
    def scope_page():
        snap = _snapshot_or_none()
        cfg = _scope_config()
        tree = queries.vpc_tree(_db(), snap["id"]) if snap else []
        scoped = queries.vpc_tree(_db(), snap["id"], _scope()) if snap else []
        return render_template(
            "scope.html",
            snap=snap,
            cfg=cfg,
            tree=tree,
            in_scope={"vpcs": len(scoped), "subnets": sum(len(v.subnets) for v in scoped)},
            totals={"vpcs": len(tree), "subnets": sum(len(v.subnets) for v in tree)},
            modes=scope_mod.MODES,
        )

    @app.post("/scope")
    def scope_save():
        ref = _active_or_400()
        f = request.form
        doc = {
            "vpc_mode": f.get("vpc_mode", ""),
            "vpcs": f.getlist("vpcs"),
            "subnet_mode": f.get("subnet_mode", ""),
            "subnets": f.getlist("subnets"),
            "subnet_patterns": f.get("subnet_patterns", ""),
            "cidr_mode": f.get("cidr_mode", ""),
            "cidrs": f.get("cidrs", ""),
        }
        try:
            cfg = scope_mod.validate(doc)
        except ValueError as exc:
            flash(f"Scope not saved: {exc}", "error")
            return redirect(url_for("scope_page"))
        with closing(_paths().db_path) as conn:
            scope_mod.save(conn, ref, cfg)
        log.info("scope saved (account=%s): %d filter(s)", ref, cfg.count)
        flash(f"Scope saved: {cfg.count} filter(s)" if cfg.count else "Scope cleared", "ok")
        return redirect(url_for("scope_page"))

    @app.post("/scope/clear")
    def scope_clear():
        ref = _active_or_400()
        with closing(_paths().db_path) as conn:
            scope_mod.clear(conn, ref)
        log.info("scope cleared (account=%s)", ref)
        flash("Scope cleared: every VPC, subnet and IP is shown.", "ok")
        return redirect(_safe_next(request.form.get("next")))

    # -- logs --------------------------------------------------------------------

    @app.get("/logs")
    def logs():
        level = request.args.get("level", "")
        q = request.args.get("q", "")
        limit = min(max(request.args.get("limit", 500, type=int), 1), 5000)
        log_dir = _ext()["log_dir"]
        entries = read_log(log_dir, min_level=level, q=q, limit=limit)
        return render_template(
            "logs.html",
            entries=entries,
            level=level,
            q=q,
            limit=limit,
            levels=LEVELS,
            log_dir=log_dir,
        )

    # -- settings and accounts ---------------------------------------------------------

    @app.get("/settings")
    def settings_page():
        return render_template(
            "settings.html",
            s=_store().load(),
            accounts=_account_choices(),
            default_log_dir=_paths().default_log_dir,
        )

    @app.post("/settings")
    def settings_save():
        _store().save(log_dir=request.form.get("log_dir", ""))
        new_dir = apply_log_dir(current_app, _store().load())
        log.info("settings saved: log_dir=%s", new_dir)
        flash("Settings saved", "ok")
        return redirect(url_for("settings_page"))

    @app.post("/accounts/active")
    def account_activate():
        raw = request.form.get("account_id", "")
        acct = _accounts().get(int(raw)) if raw.isdigit() else None
        if acct is None:
            abort(400, "unknown account")
        _store().set_active_account_id(acct.id)
        log.info("active account set to %s", acct.id)
        return redirect(_safe_next(request.form.get("next")))

    def _account_form(acct: Account, status: int = 200):
        profiles = discover_profiles()
        return render_template(
            "account_form.html",
            a=acct.public_dict(),
            modes=AUTH_MODES,
            mode_labels=AUTH_MODE_LABELS,
            regions=REGIONS,
            profiles=profiles,
            profile_known=acct.profile in {p.name for p in profiles},
            max_name=MAX_DISPLAY_NAME,
        ), status

    def _save_account(account_id: int | None):
        f = request.form
        fields: dict[str, Any] = {
            "display_name": f.get("display_name", ""),
            "region": f.get("region_custom", "").strip() or f.get("region", ""),
            "auth_mode": f.get("auth_mode", "env"),
            "profile": f.get("profile", ""),
            "memory_only": f.get("memory_only") == "on",
        }
        try:
            new_id = _accounts().save(
                account_id,
                **fields,
                access_key_id=f.get("access_key_id", ""),
                secret_access_key=f.get("secret_access_key") or None,
                paste=f.get("temporary_paste") or None,
            )
        except ValueError as exc:
            # Messages never quote secrets, and the form is re-rendered without them.
            flash(str(exc), "error")
            shown = _accounts().get(account_id) or Account()
            for key, value in fields.items():
                if key != "auth_mode" or value in AUTH_MODES:
                    setattr(shown, key, value)
            return _account_form(shown, 400)
        if _accounts().get(_store().active_account_id()) is None:
            _store().set_active_account_id(new_id)
        acct = _accounts().get(new_id)
        log.info(
            "account %s: id=%s auth_mode=%s region=%s memory_only=%s",
            "created" if account_id is None else "updated",
            new_id,
            acct.auth_mode,
            acct.region,
            acct.memory_only,
        )
        flash("Account saved", "ok")
        return redirect(url_for("settings_page"))

    @app.route("/accounts/new", methods=["GET", "POST"])
    def account_new():
        if request.method == "GET":
            return _account_form(Account())
        return _save_account(None)

    @app.route("/accounts/<int:account_id>/edit", methods=["GET", "POST"])
    def account_edit(account_id: int):
        acct = _accounts().get(account_id)
        if acct is None:
            abort(404)
        if request.method == "GET":
            return _account_form(acct)
        return _save_account(account_id)

    @app.post("/accounts/<int:account_id>/delete")
    def account_delete(account_id: int):
        if not _accounts().delete(account_id):
            abort(404)
        if _store().active_account_id() == account_id:
            first = next(iter(_accounts().list()), None)
            _store().set_active_account_id(first.id if first else None)
        log.info("account deleted: id=%s", account_id)
        flash("Account deleted together with its snapshots", "ok")
        return redirect(url_for("settings_page"))

    @app.post("/accounts/<int:account_id>/test")
    def account_test(account_id: int):
        acct = _accounts().get(account_id, with_secret=True)
        if acct is None:
            abort(404)
        result = check_connection(acct, _ext()["gateway_factory"])
        if result.credentials_problem:
            prefix, _sep, msg = result.message.partition(": ")
            _credential_flash(prefix, msg, account_id)
        else:
            flash(result.message, "ok" if result.ok else "error")
        mismatch = _accounts().record_identity(account_id, result.account_id)
        if mismatch:
            log.warning("connection test of account=%s: %s", account_id, mismatch)
            _identity_flash(mismatch, account_id)
        return redirect(url_for("settings_page"))

    @app.errorhandler(404)
    def _not_found(e):
        if getattr(e, "description", "") == OUT_OF_SCOPE:
            return render_template("error.html", message=OUT_OF_SCOPE, out_of_scope=True), 404
        return render_template("error.html", message="Not found"), 404

    @app.errorhandler(400)
    def _bad_request(e):
        return render_template("error.html", message=getattr(e, "description", "Bad request")), 400
