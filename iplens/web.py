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

from . import queries
from . import rules as rules_mod
from . import suggestions as sugg_mod
from .attribution import OWNER_LABELS, OWNER_TYPES
from .aws import AwsGateway, check_connection
from .collector import Collector
from .config import AppPaths, default_paths
from .crypto import SecretBox
from .db import closing, connect, init_db
from .export import XLSX_MIMETYPE, ips_to_xlsx
from .logging_setup import LEVELS, configure_logging, read_log
from .settings import AUTH_MODES, REGIONS, Settings, SettingsStore

log = logging.getLogger(__name__)

GatewayFactory = Callable[[Settings], AwsGateway]
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
    store = SettingsStore(paths.db_path, box)

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
        "gateway_factory": gateway_factory or AwsGateway.from_settings,
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


def _snapshot_or_none():
    return queries.latest_snapshot(_db())


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
        settings = _store().load()

        def snap_label(snap: Any) -> str:
            return account_label(
                snap["account_id"], snap["account_alias"], settings.account_display_name
            )

        return {
            "csrf_token": session.get("csrf", ""),
            "owner_labels": OWNER_LABELS,
            "current_settings": settings.public_dict(),
            "header_snap": _snapshot_or_none(),
            "account_label": snap_label,
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
            tree = queries.vpc_tree(_db(), snap["id"])
            owners = queries.owner_breakdown(_db(), snap["id"])
        return render_template(
            "overview.html",
            snap=snap,
            tree=tree,
            owners=owners,
            history=queries.recent_snapshots(_db(), 5),
        )

    @app.post("/refresh")
    def refresh():
        try:
            settings = _store().load(with_secret=True)
            gw = _ext()["gateway_factory"](settings)
            result = Collector(gw, _paths().db_path).run()
            with closing(_paths().db_path) as conn:
                queries.prune_snapshots(conn)
        except Exception:
            # Full details (type, message, traceback) go to the log file only;
            # raw errors can carry ARNs, account ids or request ids.
            log.exception("refresh failed")
            flash("Refresh failed. See the log for details.", "error")
            return redirect(url_for("overview"))
        label = account_label(
            result.account_id, result.account_alias, settings.account_display_name
        )
        msg = (
            f"Refreshed {label} · {gw.region}: {result.vpcs} VPCs, {result.subnets} subnets, "
            f"{result.enis} ENIs, {result.ips} IPs"
        )
        flash(msg, "ok")
        for w in result.warnings:
            flash(w, "warn")
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
            rows = queries.ip_list(_db(), snap["id"], flt)
            tree = queries.vpc_tree(_db(), snap["id"])
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
        rows = queries.ip_list(_db(), snap["id"], flt) if snap else []
        body = ips_to_xlsx(rows, OWNER_LABELS)
        log.info("exported %d IP row(s) to xlsx", len(rows))
        name = f"iplens-ips-snapshot-{snap['id']}.xlsx" if snap else "iplens-ips.xlsx"
        return Response(
            body,
            mimetype=XLSX_MIMETYPE,
            headers={"Content-Disposition": f"attachment; filename={name}"},
        )

    # -- visual --------------------------------------------------------------------

    @app.get("/visual")
    def visual():
        snap = _snapshot_or_none()
        tree = queries.vpc_tree(_db(), snap["id"]) if snap else []
        vpc = request.args.get("vpc", "")
        if tree and vpc not in {v.vpc_id for v in tree}:
            vpc = tree[0].vpc_id
        return render_template("visual.html", snap=snap, tree=tree, vpc=vpc)

    @app.get("/visual/data.json")
    def visual_data():
        snap = _snapshot_or_none()
        if not snap:
            return jsonify({"snapshot_id": None, "vpcs": [], "vpc": None})
        data = queries.visual_data(
            _db(), snap["id"], request.args.get("vpc", "").strip(), OWNER_LABELS
        )
        if data is None:
            abort(404)
        return jsonify(data)

    # -- rules -----------------------------------------------------------------

    def _context():
        snap = _snapshot_or_none()
        return (sugg_mod.build_context(_db(), snap["id"]) if snap else None), snap

    @app.get("/rules")
    def rules_list():
        rules = rules_mod.list_rules(_db())
        ctx, _snap = _context()
        violations = {r.id: r.violations(ctx) for r in rules} if ctx else {}
        return render_template(
            "rules.html", rules=rules, violations=violations, kinds=rules_mod.RULE_KINDS
        )

    def _rule_from_form(rule_id: int | None) -> rules_mod.Rule:
        f = request.form
        return rules_mod.Rule(
            id=rule_id,
            name=f.get("name", ""),
            kind=f.get("kind", ""),
            enabled=f.get("enabled") == "on",
            description=f.get("description", ""),
            params={
                "percent": f.get("percent", ""),
                "subnet_ids": f.get("subnet_ids", ""),
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
            items = sugg_mod.generate(ctx, rules_mod.list_rules(_db()))
        return render_template(
            "suggestions.html", snap=snap, items=items, totals=sugg_mod.totals(items)
        )

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

    # -- settings ----------------------------------------------------------------

    @app.get("/settings")
    def settings_page():
        return render_template(
            "settings.html",
            s=_store().load().public_dict(),
            modes=AUTH_MODES,
            regions=REGIONS,
            default_log_dir=_paths().default_log_dir,
        )

    @app.post("/settings")
    def settings_save():
        f = request.form
        clear = f.get("clear_secret") == "on"
        # The form shows a masked key id; blank means "keep the stored one".
        key_id = f.get("access_key_id", "").strip()
        if not key_id and not clear:
            key_id = _store().load().access_key_id
        try:
            _store().save(
                auth_mode=f.get("auth_mode", "env"),
                region=f.get("region_custom", "").strip() or f.get("region", ""),
                profile=f.get("profile", ""),
                access_key_id=key_id,
                secret_access_key=f.get("secret_access_key") or None,
                clear_secret=clear,
                log_dir=f.get("log_dir", ""),
                account_display_name=f.get("account_display_name", ""),
            )
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("settings_page"))
        settings = _store().load()
        new_dir = apply_log_dir(current_app, settings)
        log.info(
            "settings saved: auth_mode=%s region=%s log_dir=%s",
            settings.auth_mode,
            settings.region,
            new_dir,
        )
        flash("Settings saved", "ok")
        return redirect(url_for("settings_page"))

    @app.post("/settings/test")
    def settings_test():
        settings = _store().load(with_secret=True)
        ok, msg = check_connection(settings, _ext()["gateway_factory"])
        flash(msg, "ok" if ok else "error")
        return redirect(url_for("settings_page"))

    @app.errorhandler(404)
    def _not_found(_e):
        return render_template("error.html", message="Not found"), 404

    @app.errorhandler(400)
    def _bad_request(e):
        return render_template("error.html", message=getattr(e, "description", "Bad request")), 400
