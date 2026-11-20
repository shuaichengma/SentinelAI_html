"""SentinelAI 传统 HTTP/HTML 服务端渲染入口。"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import secrets
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from analyzer import AnalysisError, analyze_text, check_model, split_text
from config import load_settings
from file_reader import FileValidationError, read_text_file
from reports import build_report, report_json, report_markdown, result_conclusion
from runtime import AnalysisBusyError, analysis_slot
from schemas import AnalysisReport
from time_utils import CHINA_TIMEZONE, format_china_time
from storage import (
    authenticate, ban_ip, change_password, count_audit_logs, create_user, delete_all_audit_logs,
    delete_audit_log, delete_upload, delete_user, get_effective_ip_ban, get_report_owner,
    get_upload, get_user, initialize_storage, list_audit_logs, list_audit_logs_for_export,
    list_ip_bans, list_uploads,
    list_users, normalize_ip_address, read_upload, save_report, save_upload, set_user_active,
    unban_ip, write_audit_log, AuditRecord, UserRecord,
)


BASE_DIR = Path(__file__).resolve().parent
SETTINGS = load_settings()
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", str(SETTINGS.data_dir / "reports")))
SECRET_KEY = os.getenv("APP_SECRET_KEY", "sentinelai-html-development-key-change-me")
if len(SECRET_KEY) < 32:
    raise RuntimeError("APP_SECRET_KEY 至少需要 32 个字符")

initialize_storage(SETTINGS.database_path, SETTINGS.uploads_dir)
REPORTS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
REPORTS_DIR.chmod(0o700)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
LOGGER = logging.getLogger("sentinelai-html")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
LOG_CATEGORIES = {"账户操作", "文件操作", "IP 封禁", "日志操作", "网络流量"}


def current_timestamp() -> int:
    """Return Unix time through one seam so session expiry can be tested deterministically."""
    return int(time.time())


templates.env.filters["china_time"] = format_china_time


def csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def audit_logs_csv(logs: list[AuditRecord]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["日志ID", "中国时间（UTC+8）", "账户", "类别", "操作", "来源IP", "方法", "路径", "状态码", "User-Agent", "详情"]
    )
    for item in logs:
        writer.writerow(
            [
                item.id,
                format_china_time(item.occurred_at),
                csv_safe(item.username),
                csv_safe(item.category),
                csv_safe(item.action),
                csv_safe(item.client_ip),
                csv_safe(item.method),
                csv_safe(item.path),
                "" if item.status_code is None else item.status_code,
                csv_safe(item.user_agent),
                csv_safe(item.details),
            ]
        )
    return "\ufeff" + buffer.getvalue()


def request_metadata(request: Request) -> dict[str, str]:
    client_ip = request.client.host if request.client else ""
    return {
        "client_ip": client_ip,
        "method": request.method,
        "path": request.url.path,
        "user_agent": request.headers.get("user-agent", ""),
    }


def audit(request: Request, category: str, action: str, details: str = "", status_code: int | None = None) -> None:
    try:
        write_audit_log(
            SETTINGS.database_path,
            username=request.session.get("username"),
            category=category,
            action=action,
            status_code=status_code,
            details=details,
            **request_metadata(request),
        )
    except Exception:
        LOGGER.exception("audit_log_failed")


class TrafficAuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        started = time.monotonic()
        client_ip = request.client.host if request.client else ""
        try:
            normalized_ip = normalize_ip_address(client_ip)
        except ValueError:
            normalized_ip = ""
        if normalized_ip:
            ban = await run_in_threadpool(
                get_effective_ip_ban,
                SETTINGS.database_path,
                normalized_ip,
            )
            if ban is not None:
                audit(
                    request,
                    "IP 封禁",
                    "IP 封禁拦截",
                    f"IP={ban.ip_address}; ban_id={ban.id}; 原因={ban.reason}; 到期={ban.expires_at}; 路径={request.url.path}",
                    403,
                )
                return PlainTextResponse("访问已被禁止", status_code=403)
        try:
            response = await call_next(request)
        except Exception:
            audit(request, "网络流量", "请求处理异常", "服务端处理请求时发生异常", 500)
            raise
        path = request.url.path
        if not path.startswith("/static/"):
            elapsed_ms = round((time.monotonic() - started) * 1000, 1)
            category = "网络流量"
            action = "HTTP 请求"
            if path in {"/login", "/admin_login"} and request.method == "POST" and response.status_code in {401, 403}:
                action = "登录失败（疑似爆破行为样本）"
            elif response.status_code in {404, 405}:
                action = "异常路径探测（疑似目录扫描样本）"
            details = (
                f"耗时={elapsed_ms}ms; content_length={request.headers.get('content-length', '')}; "
                f"referer={request.headers.get('referer', '')[:500]}"
            )
            audit(request, category, action, details, response.status_code)
        return response


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def valid_csrf(request: Request, supplied: str) -> bool:
    expected = request.session.get("csrf_token", "")
    return bool(expected and secrets.compare_digest(expected, supplied))


_USER_NOT_LOADED = object()


def session_timestamp(request: Request, key: str) -> int | None:
    try:
        return int(request.session[key])
    except (KeyError, TypeError, ValueError):
        return None


def get_authenticated_user(request: Request) -> UserRecord | None:
    cached = getattr(request.state, "authenticated_user", _USER_NOT_LOADED)
    if cached is not _USER_NOT_LOADED:
        return cached
    if not request.session.get("authenticated"):
        request.state.authenticated_user = None
        return None
    now = current_timestamp()
    authenticated_at = session_timestamp(request, "authenticated_at")
    last_activity_at = session_timestamp(request, "last_activity_at")
    if (
        authenticated_at is None
        or last_activity_at is None
        or now - last_activity_at > SETTINGS.auth_session_idle_seconds
        or now - authenticated_at > SETTINGS.auth_session_max_seconds
        or now < last_activity_at
        or now < authenticated_at
    ):
        request.session.clear()
        request.state.authenticated_user = None
        return None
    username = str(request.session.get("username", ""))
    user = get_user(SETTINGS.database_path, username) if username else None
    if user is None or not user.is_active:
        request.session.clear()
        request.state.authenticated_user = None
        return None
    request.session["role"] = user.role
    request.session["last_activity_at"] = now
    request.state.authenticated_user = user
    return user


def login_redirect(user: UserRecord) -> str:
    return "/admin" if user.role == "admin" else "/"


def require_user(
    request: Request,
    login_path: str = "/login",
) -> tuple[UserRecord | None, Response | None]:
    user = get_authenticated_user(request)
    if user is None:
        return None, RedirectResponse(login_path, status_code=303)
    return user, None


def forbidden(request: Request, user: UserRecord | None, message: str = "当前账户没有权限访问此功能。") -> Response:
    return templates.TemplateResponse(
        request,
        "error.html",
        base_context(request, current_user=user, message=message),
        status_code=403,
    )


def require_admin(request: Request) -> tuple[UserRecord | None, Response | None]:
    user = get_authenticated_user(request)
    if user is None or user.role != "admin":
        if user is None:
            return None, RedirectResponse("/admin_login", status_code=303)
        return user, forbidden(request, user)
    return user, None


def base_context(request: Request, **extra: object) -> dict[str, object]:
    current_user = extra.pop("current_user") if "current_user" in extra else get_authenticated_user(request)
    context: dict[str, object] = {
        "request": request,
        "settings": SETTINGS,
        "csrf_token": csrf_token(request),
        "current_user": current_user,
        "role_label": (
            "管理员" if getattr(current_user, "role", "") == "admin"
            else "普通用户" if current_user else ""
        ),
    }
    context.update(extra)
    return context


def user_can_access_upload(user: UserRecord, owner_id: int | None) -> bool:
    return user.role == "admin" or owner_id == user.id


def load_text_record(record_id: int, user: UserRecord):
    record = get_upload(SETTINGS.database_path, record_id)
    if record is None:
        raise FileNotFoundError("上传记录不存在")
    if not user_can_access_upload(user, record.owner_id):
        raise PermissionError("无权访问该上传文件")
    raw = read_upload(SETTINGS.uploads_dir, record)
    return record, read_text_file(record.original_name, raw, SETTINGS.max_file_bytes)


async def index(request: Request) -> Response:
    user, unauthorized = require_user(request)
    if unauthorized:
        return unauthorized
    assert user is not None
    online, model_status = await run_in_threadpool(check_model, SETTINGS)
    upload_id = request.query_params.get("upload_id")
    text_file = None
    record = None
    planned_chunks = None
    error = request.query_params.get("error")
    if upload_id and upload_id.isdigit():
        try:
            record, text_file = await run_in_threadpool(load_text_record, int(upload_id), user)
            planned_chunks = len(split_text(text_file.text, SETTINGS.chunk_chars, SETTINGS.chunk_overlap, SETTINGS.max_chunks))
        except PermissionError:
            return forbidden(request, user, "无权访问该上传文件。")
        except (FileNotFoundError, OSError, FileValidationError, AnalysisError) as exc:
            error = getattr(exc, "user_message", str(exc))
    return templates.TemplateResponse(
        request,
        "index.html",
        base_context(
            request,
            online=online,
            model_status=model_status,
            record=record,
            text_file=text_file,
            planned_chunks=planned_chunks,
            error=error,
            report=None,
            conclusion=None,
        ),
    )


async def upload(request: Request) -> Response:
    user, unauthorized = require_user(request)
    if unauthorized:
        return unauthorized
    assert user is not None
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    uploaded = form.get("file")
    if uploaded is None or not hasattr(uploaded, "read"):
        return RedirectResponse("/?error=请选择文件", status_code=303)
    raw = await uploaded.read(SETTINGS.max_file_bytes + 1)
    try:
        text_file = read_text_file(uploaded.filename or "", raw, SETTINGS.max_file_bytes)
        record = save_upload(
            SETTINGS.database_path,
            SETTINGS.uploads_dir,
            text_file.filename,
            raw,
            text_file.sha256,
            owner_id=user.id,
        )
        LOGGER.info("upload_saved sha256=%s size=%d", text_file.sha256, text_file.raw_size)
        return RedirectResponse(f"/?upload_id={record.id}", status_code=303)
    except FileValidationError as exc:
        return templates.TemplateResponse(request, "error.html", base_context(request, message=exc.user_message), status_code=400)
    except Exception:
        LOGGER.exception("upload_failed")
        return templates.TemplateResponse(request, "error.html", base_context(request, message="文件处理或保存失败"), status_code=500)


def perform_analysis(record_id: int, user: UserRecord) -> tuple[object, object, AnalysisReport]:
    record, text_file = load_text_record(record_id, user)
    with analysis_slot(SETTINGS.max_concurrent_tasks):
        batch = analyze_text(SETTINGS, text_file.filename, text_file.text)
    report = build_report(text_file, batch, SETTINGS)
    (REPORTS_DIR / f"{report.task_id}.json").write_text(report_json(report), encoding="utf-8")
    (REPORTS_DIR / f"{report.task_id}.md").write_text(report_markdown(report), encoding="utf-8")
    save_report(SETTINGS.database_path, report.task_id, record.owner_id, record.id)
    return record, text_file, report


async def analyze(request: Request) -> Response:
    user, unauthorized = require_user(request)
    if unauthorized:
        return unauthorized
    assert user is not None
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    try:
        record_id = int(request.path_params["record_id"])
        record, text_file, report = await run_in_threadpool(perform_analysis, record_id, user)
        LOGGER.info("task_complete sha256=%s chunks=%d", text_file.sha256, report.total_chunks)
        return templates.TemplateResponse(
            request,
            "index.html",
            base_context(
                request,
                online=True,
                model_status=f"模型在线：{SETTINGS.model_name}",
                record=record,
                text_file=text_file,
                planned_chunks=report.total_chunks,
                error=None,
                report=report,
                conclusion=result_conclusion(report.result),
            ),
        )
    except PermissionError:
        return forbidden(request, user, "无权分析该上传文件。")
    except (AnalysisError, AnalysisBusyError, FileNotFoundError, FileValidationError) as exc:
        message = getattr(exc, "user_message", str(exc))
        return templates.TemplateResponse(request, "error.html", base_context(request, message=message), status_code=400)


async def report_download(request: Request) -> Response:
    user, unauthorized = require_user(request)
    if unauthorized:
        return unauthorized
    assert user is not None
    task_id = request.path_params["task_id"]
    extension = request.path_params["extension"]
    if not task_id.startswith("SA-") or extension not in {"json", "md"}:
        return PlainTextResponse("报告不存在", status_code=404)
    owner_id = get_report_owner(SETTINGS.database_path, task_id)
    if user.role != "admin" and owner_id != user.id:
        return PlainTextResponse("报告不存在", status_code=404)
    path = REPORTS_DIR / f"{task_id}.{extension}"
    if not path.is_file():
        return PlainTextResponse("报告不存在", status_code=404)
    media_type = "application/json" if extension == "json" else "text/markdown"
    audit(
        request,
        "文件操作",
        "下载分析报告",
        f"报告={path.name}; task_id={task_id}; 格式={extension}; 账户={user.username}; 角色={user.role}",
        200,
    )
    return FileResponse(path, media_type=media_type, filename=path.name)


def login_template(expected_role: str) -> str:
    return "admin_login.html" if expected_role == "admin" else "login.html"


def login_portal_name(expected_role: str) -> str:
    return "管理员" if expected_role == "admin" else "普通用户"


async def show_login(request: Request, expected_role: str) -> Response:
    user = get_authenticated_user(request)
    if user:
        return RedirectResponse(login_redirect(user), status_code=303)
    return templates.TemplateResponse(
        request,
        login_template(expected_role),
        base_context(request, error=None),
    )


async def authenticate_login(request: Request, expected_role: str) -> Response:
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("请求无效", status_code=403)
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    user = await run_in_threadpool(get_user, SETTINGS.database_path, username)
    disabled = user is not None and not user.is_active
    authenticated = await run_in_threadpool(authenticate, SETTINGS.database_path, username, password)
    if disabled:
        LOGGER.warning("login status=disabled")
        audit(request, "账户操作", "停用账户登录被拒绝", f"提交账户={username}", 401)
        return templates.TemplateResponse(
            request,
            login_template(expected_role),
            base_context(request, error="账号或密码错误"),
            status_code=401,
        )
    if authenticated:
        if user is not None and user.role != expected_role:
            LOGGER.warning(
                "login status=rejected role=%s portal=%s",
                user.role,
                login_portal_name(expected_role),
            )
            audit(
                request,
                "账户操作",
                "账户角色与登录入口不匹配",
                f"账户={username}; 角色={user.role}; 入口={login_portal_name(expected_role)}",
                401,
            )
            return templates.TemplateResponse(
                request,
                login_template(expected_role),
                base_context(request, error="账号或密码错误"),
                status_code=401,
            )
        request.session.clear()
        request.session["authenticated"] = True
        request.session["username"] = username
        request.session["role"] = user.role if user else "user"
        now = current_timestamp()
        request.session["authenticated_at"] = now
        request.session["last_activity_at"] = now
        csrf_token(request)
        LOGGER.info("login status=success role=%s", request.session["role"])
        audit(request, "账户操作", "登录成功", f"账户={username}; 角色={request.session['role']}", 303)
        return RedirectResponse(login_redirect(user) if user else "/", status_code=303)
    LOGGER.warning("login status=failed")
    audit(request, "账户操作", "登录失败", f"提交账户={username or '(空)'}", 401)
    return templates.TemplateResponse(
        request,
        login_template(expected_role),
        base_context(request, error="账号或密码错误"),
        status_code=401,
    )


async def login_get(request: Request) -> Response:
    return await show_login(request, "user")


async def login_post(request: Request) -> Response:
    return await authenticate_login(request, "user")


async def admin_login_get(request: Request) -> Response:
    return await show_login(request, "admin")


async def admin_login_post(request: Request) -> Response:
    return await authenticate_login(request, "admin")


async def admin(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    records = await run_in_threadpool(list_uploads, SETTINGS.database_path)
    return templates.TemplateResponse(request, "admin.html", base_context(request, records=records, active_nav="files"))


async def upload_history(request: Request) -> Response:
    user, unauthorized = require_user(request)
    if unauthorized:
        return unauthorized
    assert user is not None
    owner_id = None if user.role == "admin" else user.id
    records = await run_in_threadpool(list_uploads, SETTINGS.database_path, owner_id)
    return templates.TemplateResponse(
        request,
        "history.html",
        base_context(
            request,
            records=records,
            showing_all=user.role == "admin",
            active_nav="history",
        ),
    )


async def admin_download(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    record = get_upload(SETTINGS.database_path, int(request.path_params["record_id"]))
    if record is None:
        return PlainTextResponse("文件不存在", status_code=404)
    path = SETTINGS.uploads_dir / record.stored_name
    audit(request, "文件操作", "下载上传文件", f"文件={record.original_name}; upload_id={record.id}; size={record.size_bytes}", 200)
    return FileResponse(path, media_type="application/octet-stream", filename=record.original_name)


async def admin_delete(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    record_id = int(request.path_params["record_id"])
    record = await run_in_threadpool(get_upload, SETTINGS.database_path, record_id)
    await run_in_threadpool(delete_upload, SETTINGS.database_path, SETTINGS.uploads_dir, record_id)
    LOGGER.info("admin_delete upload_id=%d", record_id)
    audit(request, "文件操作", "删除上传文件", f"文件={record.original_name if record else '(不存在)'}; upload_id={record_id}", 303)
    return RedirectResponse("/admin", status_code=303)


async def admin_accounts(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    users = await run_in_threadpool(list_users, SETTINGS.database_path)
    return templates.TemplateResponse(
        request, "admin_accounts.html",
        base_context(request, users=users, active_nav="accounts", message=request.query_params.get("message"), error=request.query_params.get("error")),
    )


async def admin_account_create(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    try:
        role = str(form.get("role", "user"))
        user = await run_in_threadpool(
            create_user,
            SETTINGS.database_path,
            str(form.get("username", "")),
            str(form.get("password", "")),
            role,
        )
        audit(request, "账户操作", "新建账户", f"目标账户={user.username}; user_id={user.id}; 角色={user.role}", 303)
        return RedirectResponse("/admin/accounts?message=账户创建成功", status_code=303)
    except ValueError as exc:
        return RedirectResponse(f"/admin/accounts?error={str(exc)}", status_code=303)


async def admin_account_status(request: Request) -> Response:
    current_user, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    assert current_user is not None
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    user_id = int(request.path_params["user_id"])
    active = str(form.get("active", "0")) == "1"
    target = next((u for u in list_users(SETTINGS.database_path) if u.id == user_id), None)
    if target and target.username == current_user.username and not active:
        return RedirectResponse("/admin/accounts?error=不能停用当前登录账户", status_code=303)
    try:
        user = await run_in_threadpool(set_user_active, SETTINGS.database_path, user_id, active)
        if not user:
            return RedirectResponse("/admin/accounts?error=账户不存在", status_code=303)
        audit(request, "账户操作", "启用账户" if active else "停用账户", f"目标账户={user.username}; user_id={user.id}", 303)
        return RedirectResponse("/admin/accounts?message=账户状态已更新", status_code=303)
    except ValueError as exc:
        return RedirectResponse(f"/admin/accounts?error={str(exc)}", status_code=303)


async def admin_account_password(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    user_id = int(request.path_params["user_id"])
    try:
        user = await run_in_threadpool(change_password, SETTINGS.database_path, user_id, str(form.get("password", "")))
        if not user:
            return RedirectResponse("/admin/accounts?error=账户不存在", status_code=303)
        audit(request, "账户操作", "修改账户密码", f"目标账户={user.username}; user_id={user.id}", 303)
        return RedirectResponse("/admin/accounts?message=密码修改成功", status_code=303)
    except ValueError as exc:
        return RedirectResponse(f"/admin/accounts?error={str(exc)}", status_code=303)


async def admin_account_delete(request: Request) -> Response:
    current_user, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    assert current_user is not None
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    user_id = int(request.path_params["user_id"])
    target = next((u for u in list_users(SETTINGS.database_path) if u.id == user_id), None)
    if target and target.username == current_user.username:
        return RedirectResponse("/admin/accounts?error=不能删除当前登录账户", status_code=303)
    if target and target.username == "admin":
        return RedirectResponse("/admin/accounts?error=admin 账户不能删除", status_code=303)
    try:
        user = await run_in_threadpool(delete_user, SETTINGS.database_path, user_id)
        if not user:
            return RedirectResponse("/admin/accounts?error=账户不存在", status_code=303)
        audit(request, "账户操作", "删除账户", f"目标账户={user.username}; user_id={user.id}", 303)
        return RedirectResponse("/admin/accounts?message=账户已删除", status_code=303)
    except ValueError as exc:
        return RedirectResponse(f"/admin/accounts?error={str(exc)}", status_code=303)


async def admin_ip_bans(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    bans = await run_in_threadpool(list_ip_bans, SETTINGS.database_path)
    client_ip = request.client.host if request.client else ""
    return templates.TemplateResponse(
        request,
        "admin_ip_bans.html",
        base_context(
            request,
            bans=bans,
            effective_count=sum(ban.effective for ban in bans),
            client_ip=client_ip,
            active_nav="ip_bans",
            message=request.query_params.get("message"),
            error=request.query_params.get("error"),
        ),
    )


async def admin_ip_ban_create(request: Request) -> Response:
    current_user, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    assert current_user is not None
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    duration_unit = str(form.get("duration_unit", "hours"))
    unit_minutes = {"minutes": 1, "hours": 60, "days": 1440}
    try:
        target_ip = normalize_ip_address(str(form.get("ip_address", "")))
        current_ip = request.client.host if request.client else ""
        try:
            normalized_current_ip = normalize_ip_address(current_ip)
        except ValueError:
            normalized_current_ip = ""
        if normalized_current_ip and target_ip == normalized_current_ip:
            raise ValueError("不能封禁当前管理请求来源 IP")
        if duration_unit not in unit_minutes:
            raise ValueError("封禁时长单位无效")
        duration_value = int(str(form.get("duration_value", "")))
        if duration_value < 1:
            raise ValueError("封禁时长必须大于 0")
        duration_minutes = duration_value * unit_minutes[duration_unit]
        reason = str(form.get("reason", ""))
        ban = await run_in_threadpool(
            ban_ip,
            SETTINGS.database_path,
            target_ip,
            duration_minutes,
            reason,
            current_user.username,
        )
        audit(
            request,
            "IP 封禁",
            "封禁恶意IP",
            f"IP={ban.ip_address}; ban_id={ban.id}; 原因={ban.reason}; 到期={ban.expires_at}",
            303,
        )
        return RedirectResponse(
            "/admin/ip-bans?"
            + urlencode({"message": f"{ban.ip_address} 已封禁至 {format_china_time(ban.expires_at)}"}),
            status_code=303,
        )
    except (TypeError, ValueError) as exc:
        return RedirectResponse(
            "/admin/ip-bans?" + urlencode({"error": str(exc)}),
            status_code=303,
        )


async def admin_ip_ban_revoke(request: Request) -> Response:
    current_user, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    assert current_user is not None
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    ban_id = int(request.path_params["ban_id"])
    ban = await run_in_threadpool(
        unban_ip,
        SETTINGS.database_path,
        ban_id,
        current_user.username,
    )
    if ban is None:
        return RedirectResponse(
            "/admin/ip-bans?" + urlencode({"error": "封禁记录不存在"}),
            status_code=303,
        )
    audit(
        request,
        "IP 封禁",
        "解除IP封禁",
        f"IP={ban.ip_address}; ban_id={ban.id}; 原因={ban.reason}",
        303,
    )
    return RedirectResponse(
        "/admin/ip-bans?" + urlencode({"message": f"{ban.ip_address} 已解除封禁"}),
        status_code=303,
    )


async def admin_logs(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    category = request.query_params.get("category", "")
    if category not in LOG_CATEGORIES and category:
        category = ""
    try:
        per_page = int(request.query_params.get("per_page", "100"))
    except ValueError:
        per_page = 100
    per_page = max(10, min(per_page, 500))
    try:
        page = max(1, int(request.query_params.get("page", "1")))
    except ValueError:
        page = 1
    total = await run_in_threadpool(count_audit_logs, SETTINGS.database_path, category)
    all_total = total if not category else await run_in_threadpool(count_audit_logs, SETTINGS.database_path)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    logs = await run_in_threadpool(list_audit_logs, SETTINGS.database_path, per_page, category, (page - 1) * per_page)
    return templates.TemplateResponse(
        request, "admin_logs.html",
        base_context(request, logs=logs, category=category, page=page, per_page=per_page,
                     total=total, all_total=all_total, total_pages=total_pages, active_nav="logs"),
    )


async def admin_logs_export(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    category = request.query_params.get("category", "")
    if category not in LOG_CATEGORIES and category:
        category = ""
    logs = await run_in_threadpool(
        list_audit_logs_for_export,
        SETTINGS.database_path,
        category,
    )
    content = await run_in_threadpool(audit_logs_csv, logs)
    audit(
        request,
        "日志操作",
        "导出系统日志",
        f"格式=CSV; 类别={category or '全部'}; 记录数={len(logs)}",
        200,
    )
    filename = datetime.now(CHINA_TIMEZONE).strftime("sentinelai-audit-logs-%Y%m%d-%H%M%S.csv")
    return Response(
        content,
        status_code=200,
        headers={
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


def logs_redirect(form) -> str:
    category = str(form.get("category", ""))
    if category not in LOG_CATEGORIES and category:
        category = ""
    try:
        per_page = max(10, min(int(form.get("per_page", 100)), 500))
        page = max(1, int(form.get("page", 1)))
    except (ValueError, TypeError):
        per_page, page = 100, 1
    return "/admin/logs?" + urlencode({"category": category, "per_page": per_page, "page": page})


async def admin_log_delete(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    log_id = int(request.path_params["log_id"])
    deleted = await run_in_threadpool(delete_audit_log, SETTINGS.database_path, log_id)
    if deleted:
        audit(request, "日志操作", "删除单条日志", f"日志ID={log_id}; 原类别={deleted.category}; 原操作={deleted.action}; 原时间={deleted.occurred_at}", 303)
    else:
        audit(request, "日志操作", "删除单条日志失败", f"日志ID={log_id}; 原因=记录不存在", 303)
    return RedirectResponse(logs_redirect(form), status_code=303)


async def admin_logs_delete_all(request: Request) -> Response:
    _, unauthorized = require_admin(request)
    if unauthorized:
        return unauthorized
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    deleted_count = await run_in_threadpool(delete_all_audit_logs, SETTINGS.database_path)
    audit(request, "日志操作", "删除全部日志", f"已删除数量={deleted_count}", 303)
    try:
        per_page = max(10, min(int(form.get("per_page", 100)), 500))
    except (ValueError, TypeError):
        per_page = 100
    return RedirectResponse("/admin/logs?per_page=" + str(per_page), status_code=303)


async def logout(request: Request) -> Response:
    user, unauthorized = require_user(request)
    if unauthorized:
        return unauthorized
    form = await request.form()
    if not valid_csrf(request, str(form.get("csrf_token", ""))):
        return PlainTextResponse("CSRF 校验失败", status_code=403)
    audit(request, "账户操作", "退出登录", f"账户={user.username if user else ''}", 303)
    redirect_path = "/admin_login" if user.role == "admin" else "/login"
    request.session.clear()
    return RedirectResponse(redirect_path, status_code=303)


routes = [
    Route("/login", login_get, methods=["GET"]),
    Route("/login", login_post, methods=["POST"]),
    Route("/admin_login", admin_login_get, methods=["GET"]),
    Route("/admin_login", admin_login_post, methods=["POST"]),
    Route("/logout", logout, methods=["POST"]),
    Route("/", index, methods=["GET"]),
    Route("/index", index, methods=["GET"]),
    Route("/upload", upload, methods=["POST"]),
    Route("/analyze/{record_id:int}", analyze, methods=["POST"]),
    Route("/history", upload_history, methods=["GET"]),
    Route("/reports/{task_id:str}.{extension:str}", report_download, methods=["GET"]),
    Route("/admin", admin, methods=["GET"]),
    Route("/admin/download/{record_id:int}", admin_download, methods=["GET"]),
    Route("/admin/delete/{record_id:int}", admin_delete, methods=["POST"]),
    Route("/admin/accounts", admin_accounts, methods=["GET"]),
    Route("/admin/accounts/create", admin_account_create, methods=["POST"]),
    Route("/admin/accounts/{user_id:int}/status", admin_account_status, methods=["POST"]),
    Route("/admin/accounts/{user_id:int}/password", admin_account_password, methods=["POST"]),
    Route("/admin/accounts/{user_id:int}/delete", admin_account_delete, methods=["POST"]),
    Route("/admin/ip-bans", admin_ip_bans, methods=["GET"]),
    Route("/admin/ip-bans/create", admin_ip_ban_create, methods=["POST"]),
    Route("/admin/ip-bans/{ban_id:int}/unban", admin_ip_ban_revoke, methods=["POST"]),
    Route("/admin/logs", admin_logs, methods=["GET"]),
    Route("/admin/logs/export", admin_logs_export, methods=["GET"]),
    Route("/admin/logs/delete-all", admin_logs_delete_all, methods=["POST"]),
    Route("/admin/logs/{log_id:int}/delete", admin_log_delete, methods=["POST"]),
]

middleware = [
    Middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=False, max_age=None),
    Middleware(TrafficAuditMiddleware),
]
app = Starlette(debug=False, routes=routes, middleware=middleware)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
