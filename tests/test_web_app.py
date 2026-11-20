import os
import re
import tempfile
from pathlib import Path
from urllib.parse import unquote_plus

_root = Path(tempfile.mkdtemp(prefix="sentinelai-html-test-"))
os.environ["DATA_DIR"] = str(_root / "data")
os.environ["UPLOADS_DIR"] = str(_root / "uploads")
os.environ["REPORTS_DIR"] = str(_root / "reports")
os.environ["APP_SECRET_KEY"] = "test-only-secret-key-with-at-least-32-characters"

from starlette.testclient import TestClient

import web_app
from storage import (
    authenticate,
    create_user,
    get_effective_ip_ban,
    get_ip_ban_by_address,
    get_user,
    list_audit_logs,
    list_uploads,
    save_report,
    set_user_active,
    write_audit_log,
)
from time_utils import format_china_time


def token_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match
    return match.group(1)


def test_time_is_displayed_in_china_standard_time():
    assert format_china_time("2026-11-16T09:30:00+00:00") == "2026-11-16 17:30:00 UTC+8"
    assert format_china_time("2026-11-16T09:30:00") == "2026-11-16 17:30:00 UTC+8"
    assert format_china_time("not-a-time") == "not-a-time"


def login(client: TestClient, username: str = "user1", password: str = "user1@123", path: str = "/login"):
    page = client.get(path)
    assert page.status_code == 200
    return client.post(
        path,
        data={"csrf_token": token_from(page), "username": username, "password": password},
        follow_redirects=False,
    )


def login_admin(client: TestClient, username: str = "admin", password: str = "admin@123"):
    return login(client, username, password, path="/admin_login")


def test_users_and_admins_have_separate_login_pages():
    with TestClient(web_app.app) as client:
        for path in ("/", "/index", "/history"):
            response = client.get(path, follow_redirects=False)
            assert response.status_code == 303
            assert response.headers["location"] == "/login"

        for path in ("/admin", "/admin/accounts", "/admin/ip-bans", "/admin/logs"):
            response = client.get(path, follow_redirects=False)
            assert response.status_code == 303
            assert response.headers["location"] == "/admin_login"

        page = client.get("/login")
        assert page.status_code == 200
        assert 'action="/login" method="post"' in page.text
        assert 'name="username"' in page.text
        assert 'name="password"' in page.text
        assert "<h2>登录</h2>" in page.text
        assert "访问限制" not in page.text
        assert "普通用户" not in page.text
        assert "管理员" not in page.text
        assert "/admin_login" not in page.text

        admin_page = client.get("/admin_login")
        assert admin_page.status_code == 200
        assert 'action="/admin_login" method="post"' in admin_page.text
        assert "<h2>登录</h2>" in admin_page.text
        assert "访问限制" not in admin_page.text
        assert "普通用户" not in admin_page.text
        assert "管理员" not in admin_page.text


def test_admin_login_redirects_to_cms_dashboard(monkeypatch):
    monkeypatch.setattr(web_app, "check_model", lambda settings: (True, "模型在线"))
    with TestClient(web_app.app) as client:
        response = login_admin(client)
        assert response.status_code == 303
        assert response.headers["location"] == "/admin"
        admin_page = client.get("/admin")
        assert admin_page.status_code == 200
        assert "文件管理" in admin_page.text
        assert "账户管理" in admin_page.text
        assert "IP 封禁" in admin_page.text
        assert "系统日志" in admin_page.text
        analysis_page = client.get("/")
        assert analysis_page.status_code == 200
        assert 'action="/upload" method="post" enctype="multipart/form-data"' in analysis_page.text
        assert "_stcore/stream" not in analysis_page.text


def test_login_portals_reject_the_other_role(monkeypatch):
    monkeypatch.setattr(web_app, "check_model", lambda settings: (True, "模型在线"))
    with TestClient(web_app.app) as client:
        admin_at_user_portal = login(client, "admin", "admin@123", path="/login")
        assert admin_at_user_portal.status_code == 401
        assert "账号或密码错误" in admin_at_user_portal.text
        assert "管理员" not in admin_at_user_portal.text
        assert "/admin_login" not in admin_at_user_portal.text
        assert client.get("/", follow_redirects=False).headers["location"] == "/login"
        assert client.get("/admin", follow_redirects=False).headers["location"] == "/admin_login"

    with TestClient(web_app.app) as client:
        user_at_admin_portal = login(client, "user1", "user1@123", path="/admin_login")
        assert user_at_admin_portal.status_code == 401
        assert "账号或密码错误" in user_at_admin_portal.text
        assert "普通用户" not in user_at_admin_portal.text
        assert "/login" not in user_at_admin_portal.text
        assert client.get("/", follow_redirects=False).headers["location"] == "/login"
        assert client.get("/admin", follow_redirects=False).headers["location"] == "/admin_login"


def test_user1_is_regular_user_and_can_only_analyze(monkeypatch):
    monkeypatch.setattr(web_app, "check_model", lambda settings: (True, "模型在线"))
    with TestClient(web_app.app) as client:
        response = login(client, "user1", "user1@123")
        assert response.status_code == 303
        assert response.headers["location"] == "/"
        page = client.get("/")
        assert page.status_code == 200
        assert "普通用户" in page.text
        assert 'href="/admin"' not in page.text
        for path in ("/admin", "/admin/accounts", "/admin/ip-bans", "/admin/logs"):
            forbidden = client.get(path)
            assert forbidden.status_code == 403
            assert "没有权限" in forbidden.text

        uploaded = client.post(
            "/upload",
            data={"csrf_token": token_from(page)},
            files={"file": ("user1.txt", "普通测试内容".encode(), "text/plain")},
            follow_redirects=False,
        )
        assert uploaded.status_code == 303
        assert uploaded.headers["location"].startswith("/?upload_id=")
        uploaded_page = client.get(uploaded.headers["location"])
        assert uploaded_page.status_code == 200
        assert "AI 正在分析" in uploaded_page.text


def test_disabled_account_uses_generic_login_failure():
    user = create_user(web_app.SETTINGS.database_path, "disabled_login_test", "correct-password")
    set_user_active(web_app.SETTINGS.database_path, user.id, False)
    with TestClient(web_app.app) as client:
        for password in ("correct-password", "completely-wrong"):
            page = client.get("/login")
            response = client.post(
                "/login",
                data={"csrf_token": token_from(page), "username": user.username, "password": password},
            )
            assert response.status_code == 401
            assert "账号或密码错误" in response.text
            assert "账户已停用" not in response.text


def test_upload_is_saved_with_owner_and_listed(monkeypatch):
    monkeypatch.setattr(web_app, "check_model", lambda settings: (True, "模型在线"))
    with TestClient(web_app.app) as client:
        login(client, "user1", "user1@123")
        page = client.get("/")
        response = client.post(
            "/upload",
            data={"csrf_token": token_from(page)},
            files={"file": ("demo.txt", "普通测试内容".encode(), "text/plain")},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"].startswith("/?upload_id=")
        record_id = int(response.headers["location"].split("=", 1)[1])
        records = list_uploads(web_app.SETTINGS.database_path)
        record = next(item for item in records if item.id == record_id)
        assert record.original_name == "demo.txt"
        assert record.owner_username == "user1"
        assert record.owner_id == get_user(web_app.SETTINGS.database_path, "user1").id
        assert any(web_app.SETTINGS.uploads_dir.iterdir())


def test_regular_users_cannot_open_another_users_upload(monkeypatch):
    monkeypatch.setattr(web_app, "check_model", lambda settings: (True, "模型在线"))
    second_user = create_user(
        web_app.SETTINGS.database_path,
        "ownership_test_user",
        "ownership-password",
        role="user",
    )
    assert authenticate(web_app.SETTINGS.database_path, second_user.username, "ownership-password")
    with TestClient(web_app.app) as first_client:
        login(first_client, "user1", "user1@123")
        page = first_client.get("/")
        uploaded = first_client.post(
            "/upload",
            data={"csrf_token": token_from(page)},
            files={"file": ("private.txt", "仅所有者可见".encode(), "text/plain")},
            follow_redirects=False,
        )
        record_id = int(uploaded.headers["location"].split("=", 1)[1])

    with TestClient(web_app.app) as second_client:
        login(second_client, second_user.username, "ownership-password")
        response = second_client.get(f"/?upload_id={record_id}")
        assert response.status_code == 403
        assert "无权访问" in response.text


def test_upload_history_is_owner_scoped_for_users_and_complete_for_admin(monkeypatch):
    monkeypatch.setattr(web_app, "check_model", lambda settings: (True, "模型在线"))
    first_user = create_user(
        web_app.SETTINGS.database_path,
        "history_owner_a",
        "history-password-a",
    )
    second_user = create_user(
        web_app.SETTINGS.database_path,
        "history_owner_b",
        "history-password-b",
    )
    with TestClient(web_app.app) as first_client:
        login(first_client, first_user.username, "history-password-a")
        first_page = first_client.get("/")
        first_upload = first_client.post(
            "/upload",
            data={"csrf_token": token_from(first_page)},
            files={"file": ("history-alpha.txt", "第一个用户的文件".encode(), "text/plain")},
            follow_redirects=False,
        )
        first_record_id = int(first_upload.headers["location"].split("=", 1)[1])
        save_report(
            web_app.SETTINGS.database_path,
            "SA-historyalpha",
            first_user.id,
            first_record_id,
        )
        first_history = first_client.get("/history")
        assert first_history.status_code == 200
        assert "我的上传记录" in first_history.text
        assert "history-alpha.txt" in first_history.text
        assert "已分析" in first_history.text
        assert "SA-historyalpha" in first_history.text
        assert "history-beta.txt" not in first_history.text

    with TestClient(web_app.app) as second_client:
        login(second_client, second_user.username, "history-password-b")
        second_page = second_client.get("/")
        second_client.post(
            "/upload",
            data={"csrf_token": token_from(second_page)},
            files={"file": ("history-beta.txt", "第二个用户的文件".encode(), "text/plain")},
            follow_redirects=False,
        )
        second_history = second_client.get("/history")
        assert "history-beta.txt" in second_history.text
        assert "history-alpha.txt" not in second_history.text

    with TestClient(web_app.app) as admin_client:
        login_admin(admin_client)
        all_history = admin_client.get("/history")
        assert all_history.status_code == 200
        assert "全部上传记录" in all_history.text
        assert "history-alpha.txt" in all_history.text
        assert "history-beta.txt" in all_history.text
        assert first_user.username in all_history.text
        assert second_user.username in all_history.text


def test_regular_user_report_downloads_are_audited():
    user = get_user(web_app.SETTINGS.database_path, "user1")
    assert user is not None
    task_id = "SA-reportaudit01"
    save_report(web_app.SETTINGS.database_path, task_id, user.id)
    (web_app.REPORTS_DIR / f"{task_id}.json").write_text('{"result": "ok"}', encoding="utf-8")
    (web_app.REPORTS_DIR / f"{task_id}.md").write_text("# report\n", encoding="utf-8")
    before_ids = {
        item.id
        for item in list_audit_logs(web_app.SETTINGS.database_path, limit=2000, category="文件操作")
    }

    with TestClient(web_app.app) as client:
        login(client, "user1", "user1@123")
        for extension in ("json", "md"):
            response = client.get(f"/reports/{task_id}.{extension}")
            assert response.status_code == 200
            assert response.headers["content-disposition"].startswith("attachment;")

    records = [
        item
        for item in list_audit_logs(web_app.SETTINGS.database_path, limit=2000, category="文件操作")
        if item.id not in before_ids and item.action == "下载分析报告"
    ]
    assert len(records) == 2
    assert {item.username for item in records} == {"user1"}
    assert {item.status_code for item in records} == {200}
    assert all(task_id in item.details and "角色=user" in item.details for item in records)
    assert any("格式=json" in item.details for item in records)
    assert any("格式=md" in item.details for item in records)


def test_login_csrf_is_required():
    for path in ("/login", "/admin_login"):
        with TestClient(web_app.app) as client:
            response = client.post(
                path,
                data={"username": "admin", "password": "admin@123"},
            )
        assert response.status_code == 403


def test_login_cookie_is_browser_scoped_and_session_expires_after_idle_timeout(monkeypatch):
    now = 1_800_000_000
    monkeypatch.setattr(web_app, "current_timestamp", lambda: now)

    with TestClient(web_app.app) as client:
        response = login(client)
        assert response.status_code == 303
        set_cookie = response.headers["set-cookie"].lower()
        assert "max-age" not in set_cookie
        assert "expires=" not in set_cookie
        assert "httponly" in set_cookie

        assert client.get("/").status_code == 200
        now += web_app.SETTINGS.auth_session_idle_seconds + 1
        expired = client.get("/", follow_redirects=False)
        assert expired.status_code == 303
        assert expired.headers["location"] == "/login"
        assert "session=null" in expired.headers["set-cookie"].lower()


def test_login_session_cannot_exceed_absolute_lifetime(monkeypatch):
    now = 1_800_000_000
    monkeypatch.setattr(web_app, "current_timestamp", lambda: now)

    with TestClient(web_app.app) as client:
        assert login(client).status_code == 303
        while now < 1_800_000_000 + web_app.SETTINGS.auth_session_max_seconds:
            now += max(1, web_app.SETTINGS.auth_session_idle_seconds - 1)
            assert client.get("/").status_code == 200
        now += 1
        expired = client.get("/", follow_redirects=False)
        assert expired.status_code == 303
        assert expired.headers["location"] == "/login"


def test_supuser_can_manage_roles_accounts_and_view_logs():
    username = "web_operator"
    with TestClient(web_app.app) as client:
        response = login_admin(client, "supuser", "Supuser@@@123")
        assert response.status_code == 303
        accounts = client.get("/admin/accounts")
        assert accounts.status_code == 200
        assert "管理员" in accounts.text
        assert "普通用户" in accounts.text
        created = client.post(
            "/admin/accounts/create",
            data={
                "csrf_token": token_from(accounts),
                "username": username,
                "password": "test-password-123",
                "role": "user",
            },
            follow_redirects=False,
        )
        assert created.status_code == 303
        assert client.get("/admin/logs").status_code == 200
    created_user = get_user(web_app.SETTINGS.database_path, username)
    assert created_user is not None
    assert created_user.role == "user"
    assert any(
        item.action == "新建账户" and username in item.details
        for item in list_audit_logs(web_app.SETTINGS.database_path)
    )


def test_admin_can_configure_ban_and_unban_ip():
    admin_ip = "198.51.100.20"
    blocked_ip = "203.0.113.77"
    with TestClient(web_app.app, client=(admin_ip, 50000)) as admin_client:
        login_admin(admin_client)
        page = admin_client.get("/admin/ip-bans")
        assert page.status_code == 200
        assert admin_ip in page.text

        self_ban = admin_client.post(
            "/admin/ip-bans/create",
            data={
                "csrf_token": token_from(page),
                "ip_address": admin_ip,
                "duration_value": "24",
                "duration_unit": "hours",
                "reason": "不应允许封禁自身",
            },
            follow_redirects=False,
        )
        assert self_ban.status_code == 303
        assert "不能封禁当前管理请求来源 IP" in unquote_plus(self_ban.headers["location"])
        assert get_ip_ban_by_address(web_app.SETTINGS.database_path, admin_ip) is None

        created = admin_client.post(
            "/admin/ip-bans/create",
            data={
                "csrf_token": token_from(page),
                "ip_address": blocked_ip,
                "duration_value": "90",
                "duration_unit": "minutes",
                "reason": "自动化测试恶意请求",
            },
            follow_redirects=False,
        )
        assert created.status_code == 303
        ban = get_ip_ban_by_address(web_app.SETTINGS.database_path, blocked_ip)
        assert ban is not None and ban.effective
        assert ban.created_by == "admin"
        assert ban.reason == "自动化测试恶意请求"

        with TestClient(web_app.app, client=(blocked_ip, 50001)) as blocked_client:
            blocked = blocked_client.get("/login")
            assert blocked.status_code == 403
            assert blocked.text == "访问已被禁止"

        ip_logs = admin_client.get("/admin/logs?category=IP%20%E5%B0%81%E7%A6%81")
        assert ip_logs.status_code == 200
        assert "IP 封禁拦截" in ip_logs.text
        page = admin_client.get("/admin/ip-bans")
        assert "封禁中" in page.text
        revoked = admin_client.post(
            f"/admin/ip-bans/{ban.id}/unban",
            data={"csrf_token": token_from(page)},
            follow_redirects=False,
        )
        assert revoked.status_code == 303
        assert get_effective_ip_ban(web_app.SETTINGS.database_path, blocked_ip) is None

        history_page = admin_client.get("/admin/ip-bans")
        assert 'data-reban-ip="' + blocked_ip + '"' in history_page.text
        assert '<dialog id="reban-dialog"' in history_page.text
        rebanned = admin_client.post(
            "/admin/ip-bans/create",
            data={
                "csrf_token": token_from(history_page),
                "ip_address": blocked_ip,
                "duration_value": "3",
                "duration_unit": "minutes",
                "reason": "从历史记录再次封禁",
            },
            follow_redirects=False,
        )
        assert rebanned.status_code == 303
        active_ban = get_effective_ip_ban(web_app.SETTINGS.database_path, blocked_ip)
        assert active_ban is not None and active_ban.reason == "从历史记录再次封禁"
        page = admin_client.get("/admin/ip-bans")
        admin_client.post(
            f"/admin/ip-bans/{active_ban.id}/unban",
            data={"csrf_token": token_from(page)},
            follow_redirects=False,
        )

    with TestClient(web_app.app, client=(blocked_ip, 50002)) as blocked_client:
        assert blocked_client.get("/login").status_code == 200
    logs = list_audit_logs(web_app.SETTINGS.database_path, limit=2000, category="IP 封禁")
    assert any(item.action == "封禁恶意IP" and blocked_ip in item.details for item in logs)
    assert any(item.action == "解除IP封禁" and blocked_ip in item.details for item in logs)
    assert any(
        item.action == "IP 封禁拦截" and item.client_ip == blocked_ip and item.status_code == 403
        for item in logs
    )


def test_admin_can_export_filtered_logs_as_csv():
    write_audit_log(
        web_app.SETTINGS.database_path,
        username="csv_export_test",
        category="IP 封禁",
        action="CSV筛选导出测试",
        status_code=200,
        details="=SUM(1,1)",
    )
    with TestClient(web_app.app) as admin_client:
        login_admin(admin_client)
        page = admin_client.get("/admin/logs?category=IP%20%E5%B0%81%E7%A6%81")
        assert page.status_code == 200
        assert "导出当前筛选 CSV" in page.text
        exported = admin_client.get("/admin/logs/export?category=IP%20%E5%B0%81%E7%A6%81")
        assert exported.status_code == 200
        assert exported.headers["content-type"].startswith("text/csv")
        assert exported.headers["content-disposition"].startswith("attachment;")
        assert exported.content.startswith(b"\xef\xbb\xbf")
        csv_text = exported.content.decode("utf-8-sig")
        assert "日志ID" in csv_text
        assert "CSV筛选导出测试" in csv_text
        assert "'=SUM(1,1)" in csv_text
        assert "账户操作" not in csv_text

    assert any(
        item.action == "导出系统日志" and "类别=IP 封禁" in item.details
        for item in list_audit_logs(web_app.SETTINGS.database_path, limit=2000, category="日志操作")
    )
    with TestClient(web_app.app) as user_client:
        login(user_client)
        assert user_client.get("/admin/logs/export").status_code == 403


def test_admin_account_can_be_disabled_but_is_protected_from_deletion():
    admin = get_user(web_app.SETTINGS.database_path, "admin")
    assert admin is not None
    with TestClient(web_app.app) as client:
        login_admin(client, "supuser", "Supuser@@@123")
        page = client.get("/admin/accounts")
        assert "不可删除" in page.text
        disabled = client.post(
            f"/admin/accounts/{admin.id}/status",
            data={"csrf_token": token_from(page), "active": "0"},
            follow_redirects=False,
        )
        assert disabled.status_code == 303
        assert "message=" in disabled.headers["location"]
        assert get_user(web_app.SETTINGS.database_path, "admin").is_active is False

        page = client.get("/admin/accounts")
        response = client.post(
            f"/admin/accounts/{admin.id}/delete",
            data={"csrf_token": token_from(page)},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "admin" in response.headers["location"]
        assert get_user(web_app.SETTINGS.database_path, "admin") is not None
        set_user_active(web_app.SETTINGS.database_path, admin.id, True)
    assert get_user(web_app.SETTINGS.database_path, "admin").is_active is True


def test_network_probe_is_audited():
    with TestClient(web_app.app) as client:
        assert client.get("/definitely-not-a-route").status_code == 404
    assert any(
        item.action == "异常路径探测（疑似目录扫描样本）" and item.path == "/definitely-not-a-route"
        for item in list_audit_logs(web_app.SETTINGS.database_path)
    )


def test_log_page_pagination_and_delete_actions():
    with TestClient(web_app.app) as client:
        login_admin(client, "supuser", "Supuser@@@123")
        page = client.get("/admin/logs?per_page=10&page=1")
        assert page.status_code == 200
        assert "日志总数" in page.text
        assert "删除全部日志" in page.text
        assert 'value="10"' in page.text
        current_logs = list_audit_logs(web_app.SETTINGS.database_path)
        target = current_logs[-1]
        response = client.post(
            f"/admin/logs/{target.id}/delete",
            data={"csrf_token": token_from(page), "per_page": "10", "page": "1", "category": ""},
            follow_redirects=False,
        )
        assert response.status_code == 303
    assert any(item.action == "删除单条日志" for item in list_audit_logs(web_app.SETTINGS.database_path))
