from pathlib import Path

import pytest

from storage import (
    authenticate, ban_ip, change_password, count_audit_logs, create_user, delete_all_audit_logs,
    delete_audit_log, delete_upload, delete_user, get_effective_ip_ban, get_ip_ban_by_address,
    get_report_owner, get_upload, get_user, initialize_storage, list_audit_logs, list_ip_bans,
    list_uploads, list_users, read_upload, save_report, save_upload, set_user_active,
    unban_ip, write_audit_log,
)


def test_default_admin_is_hashed_and_can_authenticate(tmp_path):
    database = tmp_path / "data" / "sentinelai.db"
    uploads = tmp_path / "uploads"
    initialize_storage(database, uploads)

    assert authenticate(database, "admin", "admin@123") is True
    assert authenticate(database, "user1", "user1@123") is True
    assert authenticate(database, "admin", "wrong") is False
    assert b"admin@123" not in database.read_bytes()
    users = {item.username: item for item in list_users(database)}
    assert users["admin"].role == "admin"
    assert users["supuser"].role == "admin"
    assert users["user1"].role == "user"


def test_upload_list_download_and_delete(tmp_path):
    database = tmp_path / "data" / "sentinelai.db"
    uploads = tmp_path / "uploads"
    initialize_storage(database, uploads)
    payload = "虚构测试内容".encode()

    owner = next(item for item in list_users(database) if item.username == "user1")
    saved = save_upload(database, uploads, "../../sample.txt", payload, "abc123", owner.id)
    records = list_uploads(database)

    assert len(records) == 1
    assert records[0] == saved
    assert saved.original_name == "sample.txt"
    assert saved.owner_id == owner.id
    assert saved.owner_username == "user1"
    assert Path(saved.stored_name).name == saved.stored_name
    assert list_uploads(database, owner_id=owner.id) == records
    assert list_uploads(database, owner_id=999999) == []
    assert read_upload(uploads, saved) == payload
    assert delete_upload(database, uploads, saved.id) is True
    assert list_uploads(database) == []
    assert not (uploads / saved.stored_name).exists()


def test_initialization_does_not_reset_admin_password(tmp_path):
    database = tmp_path / "sentinelai.db"
    uploads = tmp_path / "uploads"
    initialize_storage(database, uploads)
    initialize_storage(database, uploads)
    assert authenticate(database, "admin", "admin@123") is True


def test_supuser_and_account_lifecycle(tmp_path):
    database = tmp_path / "sentinelai.db"
    uploads = tmp_path / "uploads"
    initialize_storage(database, uploads)
    assert authenticate(database, "supuser", "Supuser@@@123") is True

    user = create_user(database, "operator_1", "initial-password", role="user")
    assert user.role == "user"
    assert authenticate(database, user.username, "initial-password") is True
    set_user_active(database, user.id, False)
    assert authenticate(database, user.username, "initial-password") is False
    set_user_active(database, user.id, True)
    change_password(database, user.id, "changed-password")
    assert authenticate(database, user.username, "initial-password") is False
    assert authenticate(database, user.username, "changed-password") is True
    assert delete_user(database, user.id).username == user.username
    assert all(item.username != user.username for item in list_users(database))


def test_admin_account_can_be_disabled_but_cannot_be_deleted(tmp_path):
    database = tmp_path / "sentinelai.db"
    initialize_storage(database, tmp_path / "uploads")
    admin = next(item for item in list_users(database) if item.username == "admin")
    set_user_active(database, admin.id, False)
    assert get_user(database, "admin").is_active is False
    assert authenticate(database, "admin", "admin@123") is False
    with pytest.raises(ValueError, match="admin 账户不能删除"):
        delete_user(database, admin.id)
    set_user_active(database, admin.id, True)
    assert get_user(database, "admin").is_active is True
    assert authenticate(database, "admin", "admin@123") is True


def test_ip_ban_expiry_update_and_revoke(tmp_path):
    database = tmp_path / "sentinelai.db"
    initialize_storage(database, tmp_path / "uploads")
    ban = ban_ip(database, "2001:0db8::10", 60, "测试恶意流量", "supuser")
    assert ban.ip_address == "2001:db8::10"
    assert ban.effective is True
    assert get_effective_ip_ban(database, "2001:db8::10").id == ban.id

    extended = ban_ip(database, "2001:db8::10", 1_440, "延长测试封禁", "admin")
    assert extended.id == ban.id
    assert extended.reason == "延长测试封禁"
    assert extended.created_by == "admin"
    assert len(list_ip_bans(database)) == 1

    revoked = unban_ip(database, ban.id, "supuser")
    assert revoked.status == "已解除"
    assert revoked.unbanned_by == "supuser"
    assert get_effective_ip_ban(database, "2001:db8::10") is None

    expiring = ban_ip(database, "203.0.113.99", 1, "到期测试", "admin")
    import sqlite3

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE ip_bans SET expires_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", expiring.id),
        )
    expired = get_ip_ban_by_address(database, "203.0.113.99")
    assert expired is not None and expired.status == "已过期"
    assert get_effective_ip_ban(database, "203.0.113.99") is None

    with pytest.raises(ValueError, match="IP 地址格式无效"):
        ban_ip(database, "not-an-ip", 60, "无效地址", "admin")
    with pytest.raises(ValueError, match="封禁时长"):
        ban_ip(database, "198.51.100.30", 525_601, "超长封禁", "admin")


def test_report_owner_round_trip(tmp_path):
    database = tmp_path / "sentinelai.db"
    uploads = tmp_path / "uploads"
    initialize_storage(database, uploads)
    user = next(item for item in list_users(database) if item.username == "user1")
    upload = save_upload(database, uploads, "report-source.txt", b"content", "abc", user.id)
    save_report(database, "SA-test000001", user.id, upload.id)
    assert get_report_owner(database, "SA-test000001") == user.id
    assert get_report_owner(database, "SA-missing0001") is None
    saved_upload = get_upload(database, upload.id)
    assert saved_upload is not None
    assert saved_upload.latest_report_task_id == "SA-test000001"


def test_legacy_database_is_migrated_to_roles_and_owned_uploads(tmp_path):
    import sqlite3

    database = tmp_path / "sentinelai.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                uploaded_at TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL
            );
            """
        )
    initialize_storage(database, tmp_path / "uploads")
    users = {item.username: item for item in list_users(database)}
    assert users["admin"].role == "admin"
    assert users["user1"].role == "user"
    with sqlite3.connect(database) as connection:
        upload_columns = {row[1] for row in connection.execute("PRAGMA table_info(uploads)")}
        report_columns = {row[1] for row in connection.execute("PRAGMA table_info(reports)")}
    assert "owner_id" in upload_columns
    assert "upload_id" in report_columns


def test_audit_log_round_trip(tmp_path):
    database = tmp_path / "sentinelai.db"
    initialize_storage(database, tmp_path / "uploads")
    write_audit_log(
        database, username="admin", category="账户操作", action="测试操作",
        client_ip="192.0.2.1", method="POST", path="/admin/test", status_code=303,
        user_agent="pytest", details="目标账户=test",
    )
    item = list_audit_logs(database, category="账户操作")[0]
    assert item.username == "admin"
    assert item.action == "测试操作"
    assert item.client_ip == "192.0.2.1"


def test_audit_pagination_count_and_deletion(tmp_path):
    database = tmp_path / "sentinelai.db"
    initialize_storage(database, tmp_path / "uploads")
    for number in range(15):
        write_audit_log(database, username="admin", category="网络流量", action=f"请求{number}")
    assert count_audit_logs(database) == 15
    first_page = list_audit_logs(database, limit=10)
    second_page = list_audit_logs(database, limit=10, offset=10)
    assert len(first_page) == 10
    assert len(second_page) == 5
    assert not {item.id for item in first_page} & {item.id for item in second_page}
    assert delete_audit_log(database, first_page[0].id).id == first_page[0].id
    assert count_audit_logs(database) == 14
    assert delete_all_audit_logs(database) == 14
    assert count_audit_logs(database) == 0
