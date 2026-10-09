"""Flask application: settings, collection, views, rules, suggestions, logs."""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from collections.abc import Callable
from dataclasses import replace
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

from . import (
    diagram,
    environment,
    extgraph,
    flowlogs,
    ownership,
    queries,
    terraform,
    tfrepo,
    viewstate,
)
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
from .declutter import DEFAULT_EVIDENCE, FOCUS_HOPS, parse_evidence
from .export import XLSX_MIMETYPE, ips_to_xlsx
from .extended import EVIDENCE_HELP, EVIDENCE_LABELS, EVIDENCE_LEVELS, ExtendedCrawler, latest_crawl
from .jobs import KINDS as JOB_KINDS
from .jobs import JobBusy, JobCancelled, JobContext, JobFailed, JobManager, Progress
from .logging_setup import LEVELS, configure_logging, read_log
from .queries import LB_ICONS, TYPE_ICONS
from .settings import MAX_DISPLAY_NAME, REGIONS, Settings, SettingsStore, parse_tf_timeout
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
MAX_UPLOAD_BYTES = 32 * 1024 * 1024
# Visual page "Group by" choices (kept in the URL like the edge filter).
GROUP_BY = {
    "": "nothing",
    "sg": "security group",
    "tag": "tag",
    "tf": "Terraform root",
    "env": "environment",
    "owner": "owner (ownership source)",
    "team": "team",
}
# Visual page modes: the IP view is the default; "extended" adds regional services.
VIEW_MODES = {"ip": "IP view", "extended": "Extended view"}  # keys: viewstate.VIEWS
# Snapshot warnings shown on the Ownership page (prefixes of the collector's messages).
OWNERSHIP_APIS = ("tag:GetResources", "cloudformation:", "cloudtrail:")
# IP list "Owner" filter: an ownership source, or unmanaged.
OWN_FILTERS = {
    **{s: label for s, label in ownership.SOURCE_LABELS.items() if s},
    ownership.FILTER_UNMANAGED: ownership.SOURCE_LABELS[ownership.UNMANAGED],
}
MAX_CRAWL_WARNINGS_FLASHED = 8


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
    terraform_bin: str | None = None,
    terraform_runner: tfrepo.Runner | None = None,
) -> Flask:
    """Build the app. ``port`` is the port the server listens on; when given,
    the Host header must be ``127.0.0.1:<port>`` or ``localhost:<port>``.
    ``terraform_bin`` (default: found on PATH at sync time) and ``terraform_runner``
    (default: the cancellable :func:`tfrepo.run_process`) are for tests; the command
    allowlist applies to both."""
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
        # Terraform state uploads can be large; everything else is far smaller.
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    )
    app.extensions["iplens"] = {
        "paths": paths,
        "store": store,
        "accounts": account_store,
        "gateway_factory": gateway_factory or AwsGateway.from_account,
        "port": port,
        "terraform_bin": terraform_bin,
        "tf_runner": terraform_runner or tfrepo.run_process,
        # Encrypts the "extra backend-config" values of s3-backend roots at rest.
        "box": box,
        # Background jobs (Refresh, service crawl, Terraform sync): one per account.
        "jobs": JobManager(paths.db_path),
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


def _jobs() -> JobManager:
    return _ext()["jobs"]


def flash_job_messages(job: dict[str, Any]) -> None:
    """Flash a finished job's result lines (forms submitted without JavaScript)."""
    for m in job.get("messages", []):
        if m.get("link_url"):
            flash(
                Markup('{0} <a href="{1}">{2}</a>').format(
                    m["text"], m["link_url"], m["link_text"]
                ),
                m["category"],
            )
        else:
            flash(m["text"], m["category"])


def _credential_message(ctx: Progress, prefix: str, exc: BaseException, edit_url: str) -> None:
    msg = str(exc) if isinstance(exc, CredentialError) else EXPIRED_MESSAGE
    ctx.message("error", f"{prefix}: {msg} —", edit_url, "edit account")


def sync_messages(ctx: Progress, results: list[tfrepo.SyncResult], seconds: float = 0.0) -> None:
    """Result lines of a Terraform sync."""
    if not results:
        ctx.message("warn", "Terraform sync: no confirmed root × environment pairs.")
        return
    ok = all(r.status == tfrepo.OK for r in results)
    took = f" in {seconds:.1f}s" if seconds else ""
    ctx.message("ok" if ok else "warn", f"Terraform sync: {tfrepo.summarise(results)}{took}")
    wrong = [r for r in results if r.status == tfrepo.WRONG_ACCOUNT]
    for r in wrong:
        ctx.message("warn", f"{r.label}: {r.detail}; it is left out of drift.")


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

    # -- background jobs -------------------------------------------------------------

    def _wants_background() -> bool:
        """Pages with JavaScript post ``background=1`` and follow the job in a modal;
        plain form posts run the job to the end and flash its result lines."""
        return request.form.get("background") == "1"

    def _run_job(account_ref: int, kind: str, work: Callable[[JobContext], None], back: str):
        background = _wants_background()
        try:
            job = _jobs().start(account_ref, kind, work, background=background)
        except JobBusy as exc:
            if background:
                return jsonify({"ok": False, "error": str(exc), "job": exc.job}), 409
            flash(str(exc), "error")
            return redirect(back)
        if background:
            return jsonify(
                {"ok": True, "job": job, "status_url": url_for("job_status", job_id=job["id"])}
            )
        flash_job_messages(job)
        return redirect(back)

    def _job_account() -> int:
        """Jobs are keyed by the active account (0 when there is none)."""
        return _active_ref() or 0

    @app.get("/jobs/current")
    def job_current():
        """The active account's running job, else its last one (a reload re-attaches)."""
        job = _jobs().current(_job_account())
        return jsonify({"job": job, "kinds": JOB_KINDS})

    @app.get("/jobs/<job_id>")
    def job_status(job_id: str):
        job = _jobs().status(job_id[:64], _job_account())
        if job is None:
            abort(404)
        return jsonify({"job": job})

    @app.post("/jobs/<job_id>/cancel")
    def job_cancel(job_id: str):
        ok = _jobs().cancel(job_id[:64], _job_account())
        return jsonify({"ok": ok, "job": _jobs().status(job_id[:64], _job_account())})

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
            if _wants_background():
                return jsonify({"ok": False, "error": "Add an AWS account in Settings first."}), 400
            flash("Add an AWS account in Settings first.", "error")
            return redirect(url_for("settings_page"))
        # Everything the job needs is resolved here: the worker never touches the request.
        account = _accounts().get(active.id, with_secret=True)
        factory = _ext()["gateway_factory"]
        db_path = _paths().db_path
        accounts = _accounts()
        edit_url = url_for("account_edit", account_id=account.id)
        own = _own()
        # Terraform is an optional ownership enrichment: mapped repos are only re-synced
        # with every refresh when it is enabled (the Sync buttons always work).
        tf_sync = (
            _tf_syncer()
            if own.tf_enabled and tfrepo.list_envs(_db(), account_ref=account.id)
            else None
        )

        def work(ctx: JobContext) -> None:
            try:
                gw = factory(account)
                result = Collector(
                    gw,
                    db_path,
                    account.id,
                    account.display_name,
                    progress=ctx,
                    ownership_config=own,
                ).run()
                with closing(db_path) as conn:
                    queries.prune_snapshots(conn)
            except (JobCancelled, JobFailed):
                raise
            except Exception as exc:
                # Full details (type, message, traceback) go to the log file only;
                # raw errors can carry ARNs, account ids or request ids.
                log.exception("refresh failed (account=%s)", account.id)
                if is_credential_failure(exc):
                    _credential_message(ctx, "Refresh failed", exc, edit_url)
                else:
                    ctx.message("error", "Refresh failed. See the log for details.")
                raise JobFailed("Refresh failed") from None
            label = account_label(result.account_id, result.account_alias, account.display_name)
            ctx.message(
                "ok",
                f"Refreshed {label} · {gw.region}: {result.vpcs} VPCs, {result.subnets} "
                f"subnets, {result.enis} ENIs, {result.ips} IPs",
            )
            mismatch = accounts.record_identity(account.id, result.account_id)
            if mismatch:
                log.warning("refresh of account=%s: %s", account.id, mismatch)
                ctx.message(
                    "warn", f"Warning: {mismatch} — check the", edit_url, "account settings"
                )
            for w in result.warnings:
                ctx.message("warn", w)
            # Terraform repos mapped to this account are re-synced with every refresh.
            if tf_sync is not None:
                try:
                    t0 = time.monotonic()
                    results = tf_sync(account_ref=account.id, progress=ctx)
                    sync_messages(ctx, results, time.monotonic() - t0)
                except JobCancelled:
                    raise
                except tfrepo.SyncAborted as exc:
                    ctx.message(
                        "warn", f"Terraform sync aborted: {exc} —", edit_url, "edit account"
                    )
                except Exception:
                    log.exception("terraform sync after refresh failed (account=%s)", account.id)
                    ctx.message("warn", "Terraform sync failed. See the log for details.")
            ctx.step("finished")

        return _run_job(account.id, "refresh", work, url_for("overview"))

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
        detail = queries.eni_detail(_db(), snap["id"], eni_id, _own())
        if detail is None:
            abort(404)
        _in_scope_or_404(detail["subnet_id"])
        return render_template(
            "eni.html", snap=snap, e=detail, own=_own(), own_fields=ownership.TAG_FIELDS
        )

    def _ip_filter() -> queries.IpFilter:
        a = request.args
        owner = a.get("owner", "")
        state = a.get("state", "")
        own = a.get("own", "")
        return queries.IpFilter(
            vpc=a.get("vpc", "").strip(),
            subnet=a.get("subnet", "").strip(),
            owner=owner if owner in OWNER_TYPES else "",
            state=state if state in ("used", "idle") else "",
            q=a.get("q", "").strip(),
            tag_key=a.get("tag_key", "").strip()[:128],
            tag_value=a.get("tag_value", "").strip()[:256],
            tf=a.get("tf", "").strip()[: terraform.MAX_ROOT_NAME],
            env=a.get("env", "").strip()[:128],
            own=own if own in OWN_FILTERS else "",
        )

    def _env_keys() -> tuple[str, ...]:
        """Tag keys environments are read from (Settings: Ownership environment key first)."""
        if "env_keys" not in g:
            g.env_keys = _store().load().env_keys
        return g.env_keys

    def _own() -> ownership.OwnershipConfig:
        """Ownership tag keys, CI role patterns and optional sources (Settings)."""
        if "own_config" not in g:
            g.own_config = _store().load().ownership_config()
        return g.own_config

    @app.get("/ips")
    def ips():
        snap = _snapshot_or_none()
        flt = _ip_filter()
        rows, tree, keys, envs = [], [], [], []
        if snap:
            # Without the environment filter first: the dropdown lists every environment.
            every = queries.ip_list(
                _db(), snap["id"], replace(flt, env=""), _scope(), _env_keys(), _own()
            )
            envs = environment.summary(r["environment"] for r in every)
            rows = [r for r in every if environment.matches(r["environment"], flt.env)]
            tree = queries.vpc_tree(_db(), snap["id"], _scope())
            keys = queries.tag_keys(_db(), snap["id"])
        return render_template(
            "ips.html",
            snap=snap,
            rows=rows,
            f=flt,
            tree=tree,
            owner_types=OWNER_TYPES,
            tag_keys=keys,
            environments=envs,
            env_not_set=environment.FILTER_NOT_SET,
            env_sources=environment.SOURCE_LABELS,
            tf_roots=[r["name"] for r in terraform.list_roots(_db())],
            tf_managed=queries.TF_MANAGED,
            tf_unmanaged=queries.TF_UNMANAGED,
            own_filters=OWN_FILTERS,
            type_label=lambda r: queries.resource_type_label(r, OWNER_LABELS),
        )

    @app.get("/ips/export.xlsx")
    def ips_export():
        snap = _snapshot_or_none()
        flt = _ip_filter()
        rows = (
            queries.ip_list(_db(), snap["id"], flt, _scope(), _env_keys(), _own()) if snap else []
        )
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
        group_by = request.args.get("group", "")
        mode = _view_mode()
        evidence_on = viewstate.get_evidence(_db(), ref) if ref is not None else DEFAULT_EVIDENCE
        # Each view keeps its own layout choice, expanded groups and dragged positions.
        layout_key = viewstate.layout_key(vpc, mode)
        has_state = ref is not None and bool(vpc)
        return render_template(
            "visual.html",
            snap=snap,
            tree=tree,
            vpc=vpc,
            view_mode=mode,
            view_modes=VIEW_MODES,
            crawl=latest_crawl(_db(), snap["id"]) if snap and mode == "extended" else None,
            evidence_levels=EVIDENCE_LEVELS,
            evidence_labels=EVIDENCE_LABELS,
            evidence_help=EVIDENCE_HELP,
            evidence_on=evidence_on,
            focus_hops=FOCUS_HOPS,
            flow_windows=flowlogs.WINDOW_LABELS,
            flow_default=flowlogs.DEFAULT_WINDOW,
            edge_types=EDGE_TYPES,
            edge_labels=EDGE_TYPE_LABELS,
            # The data endpoint still returns every type; the browser filters, so
            # ticking "SG refs" later needs no refetch.
            edges_on=_edge_types(DEFAULT_EDGE_TYPES),
            prefs=prefs,
            short_name_max=SHORT_NAME_MAX,
            group_by_choices=GROUP_BY,
            group_by=group_by if group_by in GROUP_BY else "",
            group_tag=request.args.get("tag", "")[:128],
            layouts=viewstate.LAYOUTS,
            layout=viewstate.get_view_layout(_db(), ref, mode)
            if ref is not None
            else viewstate.DEFAULT_LAYOUT,
            layout_key=layout_key,
            positions=viewstate.get_layout(_db(), ref, layout_key) if has_state else {},
            expanded=viewstate.get_expanded(_db(), ref, mode, vpc) if has_state else [],
            legend_icons=_legend_icons(),
        )

    def _view_mode() -> str:
        mode = request.values.get("view", "ip")
        return mode if mode in VIEW_MODES else "ip"

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
        evidence = None
        if "evidence" in request.form:  # Extended view filter, "" = nothing ticked
            try:
                evidence = parse_evidence(request.form["evidence"][:200])
            except ValueError as exc:
                abort(400, str(exc))
        # Per view: the layout choice and (per VPC) the expanded groups.
        view = request.form.get("view", "")
        layout = request.form.get("layout")
        expanded = None
        if (layout is not None or "expanded" in request.form) and view not in VIEW_MODES:
            abort(400, "invalid view")
        if layout is not None and layout not in viewstate.LAYOUTS:
            abort(400, "invalid layout")
        if "expanded" in request.form:
            vpc = _visual_vpc()
            try:
                expanded = viewstate.parse_expanded(request.form["expanded"])
            except ValueError as exc:
                abort(400, str(exc))
        with closing(_paths().db_path) as conn:
            if changes:
                viewstate.save_prefs(conn, ref, **changes)
            if evidence is not None:
                viewstate.save_evidence(conn, ref, evidence)
            if layout is not None:
                viewstate.save_view_layout(conn, ref, view, layout)
            if expanded is not None:
                viewstate.save_expanded(conn, ref, view, vpc, expanded)
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
            _env_keys(),
            _own(),
        )
        if data is None:
            abort(404)
        if _view_mode() == "extended" and data.get("vpc"):
            data["extended"] = extgraph.extended_data(_db(), snap["id"], data, _env_keys())
        return jsonify(data)

    # -- extended view: service crawl and flow logs -------------------------------

    def _gateway_or_flash(prefix: str) -> tuple[Account, AwsGateway] | None:
        """The active account's gateway; on failure flash a safe message and return None."""
        active = _active()
        if active is None:
            flash("Add an AWS account in Settings first.", "error")
            return None
        try:
            account = _accounts().get(active.id, with_secret=True)
            return account, _ext()["gateway_factory"](account)
        except Exception as exc:
            log.exception("%s: could not build AWS session (account=%s)", prefix, active.id)
            if is_credential_failure(exc):
                msg = str(exc) if isinstance(exc, CredentialError) else EXPIRED_MESSAGE
                _credential_flash(prefix, msg, active.id)
            else:
                flash(f"{prefix}. See the log for details.", "error")
            return None

    def _extended_url(vpc: str = "") -> str:
        return url_for("visual", view="extended", vpc=vpc or None)

    @app.post("/visual/extended/crawl")
    def visual_extended_crawl():
        vpc = request.form.get("vpc", "")[:64]
        snap = _snapshot_or_none()
        if not snap:
            msg = "Refresh the account first: the service crawl extends its latest snapshot."
            if _wants_background():
                return jsonify({"ok": False, "error": msg}), 400
            flash(msg, "error")
            return redirect(_extended_url(vpc))
        got = _gateway_or_flash("Service crawl failed")
        if got is None:
            if _wants_background():
                return jsonify(
                    {
                        "ok": False,
                        "error": "Service crawl failed: no AWS session (reload for details).",
                    }
                ), 400
            return redirect(_extended_url(vpc))
        account, gw = got
        db_path, snap_id = _paths().db_path, snap["id"]
        edit_url = url_for("account_edit", account_id=account.id)

        def work(ctx: JobContext) -> None:
            try:
                result = ExtendedCrawler(gw, db_path, snap_id, progress=ctx).run()
            except (JobCancelled, JobFailed):
                raise
            except Exception as exc:
                log.exception("service crawl failed (account=%s)", account.id)
                if is_credential_failure(exc):
                    _credential_message(ctx, "Service crawl failed", exc, edit_url)
                else:
                    ctx.message("error", "Service crawl failed. See the log for details.")
                raise JobFailed("Service crawl failed") from None
            ctx.message(
                "ok",
                f"Crawled services for snapshot #{snap_id}: {result.nodes} node(s), "
                f"{result.edges} evidence line(s), {len(result.warnings)} warning(s).",
            )
            for w in result.warnings[:MAX_CRAWL_WARNINGS_FLASHED]:
                ctx.message("warn", w)
            if len(result.warnings) > MAX_CRAWL_WARNINGS_FLASHED:
                more = len(result.warnings) - MAX_CRAWL_WARNINGS_FLASHED
                ctx.message("warn", f"… and {more} more warning(s), listed on the Extended view.")
            ctx.step("finished")

        return _run_job(account.id, "crawl", work, _extended_url(vpc))

    def _flow_target() -> tuple[Any, str, list[str]]:
        """Latest snapshot, VPC id and its subnet ids for the flow log endpoints."""
        snap = _snapshot_or_none()
        if not snap:
            abort(400, "no snapshot")
        vpc = _visual_vpc()
        tree = queries.vpc_tree(_db(), snap["id"], _scope())
        node = next((v for v in tree if v.vpc_id == vpc), None)
        if node is None:
            abort(400, "unknown VPC")
        return snap, vpc, [s.subnet_id for s in node.subnets]

    def _flow_error(exc: Exception, what: str) -> Response:
        log.warning("%s failed: %s", what, type(exc).__name__)
        if isinstance(exc, flowlogs.FlowLogError):
            message = str(exc)
        elif is_credential_failure(exc):
            message = str(exc) if isinstance(exc, CredentialError) else EXPIRED_MESSAGE
        else:
            message = f"{what} failed. See the log for details."
            log.exception("%s failed", what)
        return jsonify({"ok": False, "error": message})

    def _flow_gateway() -> AwsGateway:
        active = _active()
        if active is None:
            abort(400, "no active account")
        return _ext()["gateway_factory"](_accounts().get(active.id, with_secret=True))

    @app.post("/visual/flowlogs/estimate")
    def visual_flowlogs_estimate():
        snap, vpc, subnets = _flow_target()
        window = flowlogs.parse_window(request.form.get("window"))
        try:
            est = flowlogs.estimate(_flow_gateway(), vpc, subnets, window)
        except Exception as exc:
            return _flow_error(exc, "Flow log estimate")
        return jsonify({"ok": True, **est.as_dict()})

    @app.post("/visual/flowlogs/run")
    def visual_flowlogs_run():
        snap, vpc, subnets = _flow_target()
        # The page shows the estimate first; the query only runs once it is confirmed.
        if request.form.get("confirm") != "1":
            abort(400, "confirm the estimated scan size first")
        window = flowlogs.parse_window(request.form.get("window"))
        try:
            res = flowlogs.run(_flow_gateway(), _paths().db_path, snap["id"], vpc, subnets, window)
        except Exception as exc:
            return _flow_error(exc, "Flow log query")
        return jsonify(
            {
                "ok": True,
                "window": res.window,
                "log_groups": res.log_groups,
                "bytes_scanned": res.bytes_scanned,
                "bytes_label": flowlogs.human_bytes(res.bytes_scanned),
                "pairs": res.pairs,
                "skipped": res.skipped,
            }
        )

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
        snap = _snapshot_or_none()
        s = _store().load()
        # Ownership key dropdowns: the tag keys seen in the active account's latest snapshot
        # (plus the configured ones, so that saving never drops a key not seen yet).
        seen = ownership.tag_keys_seen(_db(), snap["id"] if snap else None)
        configured = [s.own_project_key, s.own_env_key, s.own_team_key, s.own_owner_key]
        return render_template(
            "settings.html",
            s=s,
            own_fields=ownership.TAG_FIELDS,
            own_keys={
                "project": s.own_project_key,
                "env": s.own_env_key,
                "team": s.own_team_key,
                "owner": s.own_owner_key,
            },
            seen_tag_keys=seen,
            tag_key_choices=sorted({*seen, *(k for k in configured if k)}, key=str.lower),
            cloudtrail_days=ownership.CLOUDTRAIL_DAYS,
            cloudtrail_max=ownership.MAX_CLOUDTRAIL_LOOKUPS,
            accounts=_account_choices(),
            default_log_dir=_paths().default_log_dir,
            tf_roots=terraform.list_roots(_db()),
            tf_types=sorted(terraform.MANAGED_TYPES),
            tf_repos=tfrepo.list_repos(_db()),
        )

    # -- Terraform state (read-only; only ids / addresses / types are kept) ----------

    def _tf_flash_loaded(name: str, count: int) -> None:
        log.info("terraform root loaded: %s (%d resource id(s))", name, count)
        flash(f"Terraform root '{name}': {count} resource id(s) loaded", "ok")

    @app.post("/settings/terraform")
    def terraform_add():
        f = request.form
        uploads = [u for u in request.files.getlist("files") if u and u.filename]
        path = f.get("path", "").strip()
        name = f.get("name", "").strip()
        if not uploads and not path:
            flash("Choose a state file to upload or enter a local path.", "error")
            return redirect(url_for("settings_page"))
        if uploads and path:
            flash("Upload files or enter a path, not both.", "error")
            return redirect(url_for("settings_page"))
        if name and len(uploads) > 1:
            flash(
                "A root name applies to one file; leave it empty to name roots after files.",
                "error",
            )
            return redirect(url_for("settings_page"))
        # Parse everything first: nothing is stored unless every file is valid.
        loaded: list[tuple[str, list[terraform.TfResource], str, str]] = []
        try:
            if path:
                resolved, resources = terraform.read_state_file(path)
                root = terraform.validate_root_name(
                    name or terraform.root_name_from_filename(resolved)
                )
                loaded.append((root, resources, resolved, resolved))
            for u in uploads:
                resources = terraform.parse_state(u.read(terraform.MAX_STATE_BYTES + 1))
                root = terraform.validate_root_name(
                    name or terraform.root_name_from_filename(u.filename or "")
                )
                loaded.append((root, resources, Path(u.filename or "").name, ""))
        except (ValueError, OSError) as exc:
            # Messages come from the parser / file system, never from file contents.
            msg = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            flash(f"Terraform state not loaded: {msg}", "error")
            return redirect(url_for("settings_page"))
        with closing(_paths().db_path) as conn:
            for root, resources, source, source_path in loaded:
                terraform.save_root(conn, root, resources, source=source, source_path=source_path)
        for root, resources, _s, _p in loaded:
            _tf_flash_loaded(root, len(resources))
        return redirect(url_for("settings_page"))

    @app.post("/settings/terraform/<int:root_id>/reload")
    def terraform_reload(root_id: int):
        root = terraform.get_root(_db(), root_id)
        if root is None:
            abort(404)
        if not root["source_path"]:
            flash("Uploaded roots are refreshed by uploading the file again.", "error")
            return redirect(url_for("settings_page"))
        try:
            _resolved, resources = terraform.read_state_file(root["source_path"])
        except (ValueError, OSError) as exc:
            msg = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            flash(f"Terraform state not reloaded: {msg}", "error")
            return redirect(url_for("settings_page"))
        with closing(_paths().db_path) as conn:
            terraform.save_root(
                conn,
                root["name"],
                resources,
                source=root["source"],
                source_path=root["source_path"],
            )
        _tf_flash_loaded(root["name"], len(resources))
        return redirect(url_for("settings_page"))

    @app.post("/settings/terraform/<int:root_id>/delete")
    def terraform_delete(root_id: int):
        with closing(_paths().db_path) as conn:
            if not terraform.delete_root(conn, root_id):
                abort(404)
        log.info("terraform root removed: id=%s", root_id)
        flash("Terraform root removed (the state file itself is never touched)", "ok")
        return redirect(url_for("settings_page"))

    # -- Terraform repos (discovery parses files; sync runs allowlisted commands only) --

    def _repo_or_404(repo_id: int) -> dict[str, Any]:
        repo = tfrepo.get_repo(_db(), repo_id)
        if repo is None:
            abort(404)
        return repo

    def _discover(repo_id: int, path: str) -> bool:
        try:
            roots = tfrepo.discover(path)
        except (ValueError, OSError) as exc:
            msg = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            flash(f"Terraform repo not scanned: {msg}", "error")
            return False
        with closing(_paths().db_path) as conn:
            pairs = tfrepo.save_discovery(conn, repo_id, roots, _accounts().list())
        log.info("terraform repo %s discovered: %d root(s), %d env(s)", repo_id, len(roots), pairs)
        flash(
            f"Found {len(roots)} root(s) and {pairs} root × environment pair(s). "
            "Confirm the account of each one below.",
            "ok" if pairs else "warn",
        )
        return True

    @app.post("/settings/tfrepos")
    def tfrepo_add():
        try:
            with closing(_paths().db_path) as conn:
                repo_id = tfrepo.add_repo(conn, request.form.get("path", ""))
        except ValueError as exc:
            flash(f"Terraform repo not added: {exc}", "error")
            return redirect(url_for("settings_page") + "#tfrepos")
        repo = _repo_or_404(repo_id)
        _discover(repo_id, repo["path"])
        return redirect(url_for("settings_tfrepo", repo_id=repo_id))

    @app.get("/settings/tfrepos/<int:repo_id>")
    def settings_tfrepo(repo_id: int):
        repo = _repo_or_404(repo_id)
        envs = tfrepo.list_envs(_db(), repo_id=repo_id)
        _wrong_account_rows(envs)
        return render_template("tfrepo.html", repo=repo, envs=envs, accounts=_account_choices())

    @app.post("/settings/tfrepos/<int:repo_id>")
    def tfrepo_save_mapping(repo_id: int):
        _repo_or_404(repo_id)
        mapping: dict[int, int | None] = {}
        extras: dict[int, str] = {}  # env row id -> extra backend-config ("" clears)
        for key, value in request.form.items():
            env_id = key.removeprefix("account_")
            if key.startswith("account_") and env_id.isdigit():
                mapping[int(env_id)] = int(value) if value.isdigit() else None
            env_id = key.removeprefix("extra_")
            if key.startswith("extra_") and env_id.isdigit() and value.strip():
                extras[int(env_id)] = value
            env_id = key.removeprefix("extra_clear_")
            if key.startswith("extra_clear_") and env_id.isdigit():
                extras[int(env_id)] = ""
        encrypt = _ext()["box"].encrypt
        with closing(_paths().db_path) as conn:
            synced = tfrepo.save_mapping(conn, repo_id, mapping)
            for env_id, text in sorted(extras.items()):
                try:
                    keys = tfrepo.save_backend_extra(conn, repo_id, env_id, text, encrypt)
                except ValueError as exc:  # names the line / key, never a value
                    flash(f"Extra backend-config not saved: {exc}", "error")
                    continue
                # Key names only: the values are never logged or shown.
                log.info(
                    "extra backend-config of env row %s: %s", env_id, ",".join(keys) or "cleared"
                )
        log.info("terraform repo %s mapping saved: %d pair(s) to sync", repo_id, synced)
        flash(f"Mapping saved: {synced} root × environment pair(s) will be synced.", "ok")
        return redirect(url_for("settings_tfrepo", repo_id=repo_id))

    @app.post("/settings/tfrepos/<int:repo_id>/discover")
    def tfrepo_discover(repo_id: int):
        repo = _repo_or_404(repo_id)
        _discover(repo_id, repo["path"])
        return redirect(url_for("settings_tfrepo", repo_id=repo_id))

    @app.post("/settings/tfrepos/<int:repo_id>/delete")
    def tfrepo_delete(repo_id: int):
        with closing(_paths().db_path) as conn:
            if not tfrepo.delete_repo(conn, repo_id):
                abort(404)
        log.info("terraform repo removed: id=%s", repo_id)
        flash("Terraform repo removed from IPLens (the repository itself is never touched)", "ok")
        return redirect(url_for("settings_page") + "#tfrepos")

    def _tf_syncer() -> Callable[..., list[tfrepo.SyncResult]]:
        """A Terraform sync bound to this app's settings, safe to call from a job thread
        (it captures plain values, never the request or app context)."""
        ext = _ext()
        tf_bin = ext["terraform_bin"]
        db_path, cache_dir, runner = _paths().db_path, _paths().tf_cache_dir, ext["tf_runner"]
        accounts = _accounts()
        timeout = float(_store().load().tf_timeout)
        factory, decrypt = ext["gateway_factory"], ext["box"].decrypt

        def run(
            *,
            account_ref: int | None = None,
            repo_id: int | None = None,
            progress: Progress | None = None,
        ) -> list[tfrepo.SyncResult]:
            return tfrepo.sync(
                db_path,
                lambda ref: accounts.get(ref, with_secret=True),
                cache_dir=cache_dir,
                terraform_bin=tfrepo.find_terraform() if tf_bin is None else tf_bin,
                account_ref=account_ref,
                repo_id=repo_id,
                runner=runner,
                timeout=timeout,
                progress=progress,
                gateway_factory=factory,
                decrypt=decrypt,
            )

        return run

    @app.post("/terraform/sync")
    def terraform_sync():
        raw = request.form.get("repo_id", "")
        repo_id = int(raw) if raw.isdigit() else None
        sync = _tf_syncer()
        # Resolved here: the worker has no request context for url_for.
        edit_urls = {a.id: url_for("account_edit", account_id=a.id) for a in _accounts().list()}

        def work(ctx: JobContext) -> None:
            t0 = time.monotonic()
            try:
                results = sync(repo_id=repo_id, progress=ctx)
            except tfrepo.SyncAborted as exc:
                edit = edit_urls.get(exc.account_ref)
                if edit:
                    ctx.message("error", f"Terraform sync aborted: {exc} —", edit, "edit account")
                else:
                    ctx.message("error", f"Terraform sync aborted: {exc}")
                raise JobFailed("Terraform sync aborted") from None
            sync_messages(ctx, results, time.monotonic() - t0)
            ctx.check()
            ctx.step("finished")

        back = _safe_next(request.form.get("next") or url_for("ownership_page"))
        return _run_job(_job_account(), "tfsync", work, back)

    def _wrong_account_rows(envs: list[dict[str, Any]]) -> None:
        """Add the suggested IPLens account to each "wrong account" root (in place)."""
        accounts = _accounts().list()
        labels = {c["id"]: c["label"] for c in _account_choices()}
        for e in envs:
            if e.get("status") == tfrepo.WRONG_ACCOUNT:
                hit = tfrepo.suggest_for_state(e.get("state_account", ""), accounts)
                e["suggest_ref"] = hit.id if hit else None
                e["suggest_label"] = labels.get(hit.id, "") if hit else ""

    @app.get("/ownership")
    @app.get("/terraform")  # the former Terraform / drift page
    def ownership_page():
        ref = _active_ref()
        snap = _snapshot_or_none()
        own = _own()
        envs = tfrepo.list_envs(_db(), account_ref=ref) if ref is not None else []
        _wrong_account_rows(envs)
        drift = tfrepo.drift(_db(), ref, snap) if snap is not None and ref is not None else None
        if drift is not None:
            _wrong_account_rows(drift.wrong_account)
        warnings = json.loads(snap["warnings"] or "[]") if snap is not None else []
        return render_template(
            "ownership.html",
            own=own,
            report=ownership.report(_db(), snap["id"], own) if snap is not None else None,
            # Collection warnings of the ownership sources (missing permissions, caps).
            own_warnings=[w for w in warnings if w.startswith(OWNERSHIP_APIS)],
            cloudtrail_days=ownership.CLOUDTRAIL_DAYS,
            cloudtrail_max=ownership.MAX_CLOUDTRAIL_LOOKUPS,
            envs=envs,
            snap=snap,
            drift=drift,
            any_roots=bool(terraform.list_roots(_db())),
            markers=tfrepo.list_markers(_db(), ref) if ref is not None else [],
            marker_kinds=tfrepo.MARKER_KINDS,
            marker_types=[
                (k, terraform.KIND_LABELS.get(k, k)) for k in (*tfrepo.DRIFT_KINDS, "eni")
            ],
            wrong_account=tfrepo.WRONG_ACCOUNT,
        )

    @app.post("/ownership/terraform")
    def ownership_terraform_toggle():
        enabled = request.form.get("enabled") == "1"
        _store().save_ownership(tf_enrichment=enabled)
        log.info("terraform ownership enrichment %s", "enabled" if enabled else "disabled")
        flash(
            "Terraform enrichment enabled: Terraform roots now count as an ownership source "
            "and mapped repos are re-synced with every Refresh."
            if enabled
            else "Terraform enrichment disabled.",
            "ok",
        )
        return redirect(url_for("ownership_page") + "#terraform")

    @app.post("/terraform/markers")
    def terraform_marker_add():
        ref = _active_or_400()
        f = request.form
        kind = f.get("kind", "")
        value = f.get(f"value_{kind}", "") or f.get("value", "")
        scope_ref = None if f.get("scope") == "all" else ref
        try:
            with closing(_paths().db_path) as conn:
                tfrepo.add_marker(conn, scope_ref, kind, value, f.get("note", ""))
        except ValueError as exc:
            flash(f"Marker not saved: {exc}", "error")
            return redirect(url_for("ownership_page") + "#managed-elsewhere")
        log.info("managed-elsewhere marker added (account=%s, kind=%s)", scope_ref, kind)
        flash("Marked as managed elsewhere: left out of drift.", "ok")
        return redirect(url_for("ownership_page") + "#managed-elsewhere")

    @app.post("/terraform/markers/<int:marker_id>/delete")
    def terraform_marker_delete(marker_id: int):
        ref = _active_or_400()
        if not any(m.id == marker_id for m in tfrepo.list_markers(_db(), ref)):
            abort(404)
        with closing(_paths().db_path) as conn:
            tfrepo.delete_marker(conn, marker_id)
        flash("Marker removed.", "ok")
        return redirect(url_for("ownership_page") + "#managed-elsewhere")

    @app.post("/settings")
    def settings_save():
        f = request.form
        # Fields missing from the form keep their value.
        try:
            timeout = parse_tf_timeout(f["tf_timeout"]) if "tf_timeout" in f else None
        except ValueError as exc:
            flash(f"Settings not saved: {exc}", "error")
            return redirect(url_for("settings_page"))
        _store().save(
            log_dir=f.get("log_dir", ""),
            tf_timeout=timeout,
            env_tag_keys=f.get("env_tag_keys") if "env_tag_keys" in f else None,
        )
        if "own_form" in f:  # the Ownership section (checkboxes are absent when unticked)
            _store().save_ownership(
                keys={name: f.get(f"own_{name}_key", "") for name in ownership.TAG_FIELDS},
                ci_patterns=f.get("ci_patterns", ""),
                tf_enrichment=f.get("tf_enrichment") == "1",
                cloudtrail_lookup=f.get("cloudtrail_lookup") == "1",
            )
        saved = _store().load()
        new_dir = apply_log_dir(current_app, saved)
        log.info(
            "settings saved: log_dir=%s tf_timeout=%ss env_tag_keys=%s ownership keys=%s "
            "tf_enrichment=%s cloudtrail=%s",
            new_dir,
            saved.tf_timeout,
            ",".join(saved.env_tag_keys),
            ",".join(
                (saved.own_project_key, saved.own_env_key, saved.own_team_key, saved.own_owner_key)
            ),
            saved.tf_enrichment,
            saved.cloudtrail_lookup,
        )
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
