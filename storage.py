"""SQLite 账户和上传文件持久化。"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


PBKDF2_ITERATIONS = 600_000


@dataclass(frozen=True)
class UploadRecord:
    id: int
    original_name: str
    stored_name: str
    uploaded_at: str
    size_bytes: int
    sha256: str
    owner_id: int | None = None
    owner_username: str | None = None
    latest_report_task_id: str | None = None
    latest_report_created_at: str | None = None


@dataclass(frozen=True)
class UserRecord:
    id: int
    username: str
    role: str
    is_active: bool
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AuditRecord:
    id: int
    occurred_at: str
    username: str | None
    category: str
    action: str
    client_ip: str
    method: str
    path: str
    status_code: int | None
    user_agent: str
    details: str


@dataclass(frozen=True)
class IpBanRecord:
    id: int
    ip_address: str
    reason: str
    created_by: str
    created_at: str
    expires_at: str
    is_active: bool
    unbanned_by: str | None
    unbanned_at: str | None

    @property
    def effective(self) -> bool:
        if not self.is_active:
            return False
        try:
            expires_at = datetime.fromisoformat(self.expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            return expires_at > datetime.now(timezone.utc)
        except (TypeError, ValueError):
            return False

    @property
    def status(self) -> str:
        if not self.is_active:
            return "已解除"
        return "封禁中" if self.effective else "已过期"


def normalize_ip_address(value: str) -> str:
    try:
        return ipaddress.ip_address(str(value).strip()).compressed
    except ValueError as exc:
        raise ValueError("IP 地址格式无效") from exc


def _connect(database_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def _password_matches(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, expected_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(actual, bytes.fromhex(expected_hex))
    except (ValueError, TypeError):
        return False


_DUMMY_PASSWORD_HASH = _password_hash("invalid-login-placeholder", bytes(range(16)))


def initialize_storage(database_path: Path, uploads_dir: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    uploads_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    database_path.parent.chmod(0o700)
    uploads_dir.chmod(0o700)
    with _connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                uploaded_at TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                username TEXT,
                category TEXT NOT NULL,
                action TEXT NOT NULL,
                client_ip TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                status_code INTEGER,
                user_agent TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS reports (
                task_id TEXT PRIMARY KEY,
                owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                upload_id INTEGER REFERENCES uploads(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ip_bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                unbanned_by TEXT,
                unbanned_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(occurred_at DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_category ON audit_logs(category);
            CREATE INDEX IF NOT EXISTS idx_ip_bans_active ON ip_bans(is_active, expires_at);
            """
        )
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        if "role" not in columns:
            # Accounts created before role separation were all effectively administrators.
            connection.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
        if "is_active" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        if "updated_at" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
        upload_columns = {row["name"] for row in connection.execute("PRAGMA table_info(uploads)")}
        if "owner_id" not in upload_columns:
            connection.execute(
                "ALTER TABLE uploads ADD COLUMN owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL"
            )
        report_columns = {row["name"] for row in connection.execute("PRAGMA table_info(reports)")}
        if "upload_id" not in report_columns:
            connection.execute(
                "ALTER TABLE reports ADD COLUMN upload_id INTEGER REFERENCES uploads(id) ON DELETE SET NULL"
            )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_reports_upload ON reports(upload_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_reports_owner ON reports(owner_id)")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        connection.execute("UPDATE users SET updated_at = created_at WHERE updated_at = ''")
        for username, password, role in (
            ("admin", "admin@123", "admin"),
            ("supuser", "Supuser@@@123", "admin"),
            ("user1", "user1@123", "user"),
        ):
            if connection.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone() is None:
                connection.execute(
                    """INSERT INTO users
                       (username, password_hash, role, created_at, is_active, updated_at)
                       VALUES (?, ?, ?, ?, 1, ?)""",
                    (username, _password_hash(password), role, now, now),
                )
    database_path.chmod(0o600)


def authenticate(database_path: Path, username: str, password: str) -> bool:
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT password_hash, is_active FROM users WHERE username = ?", (username,)
        ).fetchone()
    encoded = row["password_hash"] if row is not None and row["is_active"] else _DUMMY_PASSWORD_HASH
    password_matches = _password_matches(password, encoded)
    return bool(row and row["is_active"] and password_matches)


def get_user(database_path: Path, username: str) -> UserRecord | None:
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT id, username, role, is_active, created_at, updated_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if not row:
        return None
    data = dict(row)
    data["is_active"] = bool(data["is_active"])
    return UserRecord(**data)


def list_users(database_path: Path) -> list[UserRecord]:
    with _connect(database_path) as connection:
        rows = connection.execute(
            "SELECT id, username, role, is_active, created_at, updated_at FROM users ORDER BY id"
        ).fetchall()
    return [UserRecord(**{**dict(row), "is_active": bool(row["is_active"])}) for row in rows]


def create_user(database_path: Path, username: str, password: str, role: str = "user") -> UserRecord:
    username = username.strip()
    if not username or len(username) > 64 or not all(c.isalnum() or c in "._-" for c in username):
        raise ValueError("账号只能包含字母、数字、点、下划线或连字符，且不超过 64 个字符")
    if len(password) < 8 or len(password) > 256:
        raise ValueError("密码长度必须为 8 至 256 个字符")
    if role not in {"admin", "user"}:
        raise ValueError("账户角色必须是 admin 或 user")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with _connect(database_path) as connection:
            cursor = connection.execute(
                """INSERT INTO users
                   (username, password_hash, role, created_at, is_active, updated_at)
                   VALUES (?, ?, ?, ?, 1, ?)""",
                (username, _password_hash(password), role, now, now),
            )
            user_id = int(cursor.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise ValueError("账号已存在") from exc
    return UserRecord(user_id, username, role, True, now, now)


def set_user_active(database_path: Path, user_id: int, active: bool) -> UserRecord | None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect(database_path) as connection:
        row = connection.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return None
        if not active:
            active_count = connection.execute("SELECT COUNT(*) AS count FROM users WHERE is_active = 1").fetchone()["count"]
            if active_count <= 1:
                raise ValueError("不能停用最后一个可用账号")
        connection.execute("UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?", (int(active), now, user_id))
    return get_user(database_path, row["username"])


def change_password(database_path: Path, user_id: int, password: str) -> UserRecord | None:
    if len(password) < 8 or len(password) > 256:
        raise ValueError("密码长度必须为 8 至 256 个字符")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect(database_path) as connection:
        row = connection.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return None
        connection.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (_password_hash(password), now, user_id),
        )
    return get_user(database_path, row["username"])


def _ip_ban_from_row(row: sqlite3.Row) -> IpBanRecord:
    return IpBanRecord(
        id=row["id"],
        ip_address=row["ip_address"],
        reason=row["reason"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        is_active=bool(row["is_active"]),
        unbanned_by=row["unbanned_by"],
        unbanned_at=row["unbanned_at"],
    )


def ban_ip(
    database_path: Path,
    ip_address: str,
    duration_minutes: int,
    reason: str,
    created_by: str,
) -> IpBanRecord:
    normalized_ip = normalize_ip_address(ip_address)
    duration_minutes = int(duration_minutes)
    if duration_minutes < 1 or duration_minutes > 525_600:
        raise ValueError("封禁时长必须为 1 分钟至 365 天")
    reason = str(reason).strip()
    if not 1 <= len(reason) <= 500:
        raise ValueError("封禁原因必须为 1 至 500 个字符")
    created_by = str(created_by).strip()[:64]
    if not created_by:
        raise ValueError("封禁操作账户不能为空")
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat(timespec="seconds")
    expires_at = (now_dt + timedelta(minutes=duration_minutes)).isoformat(timespec="seconds")
    with _connect(database_path) as connection:
        connection.execute(
            """INSERT INTO ip_bans
               (ip_address, reason, created_by, created_at, expires_at, is_active, unbanned_by, unbanned_at)
               VALUES (?, ?, ?, ?, ?, 1, NULL, NULL)
               ON CONFLICT(ip_address) DO UPDATE SET
                 reason = excluded.reason,
                 created_by = excluded.created_by,
                 created_at = excluded.created_at,
                 expires_at = excluded.expires_at,
                 is_active = 1,
                 unbanned_by = NULL,
                 unbanned_at = NULL""",
            (normalized_ip, reason, created_by, now, expires_at),
        )
    ban = get_ip_ban_by_address(database_path, normalized_ip)
    assert ban is not None
    return ban


def get_ip_ban_by_address(database_path: Path, ip_address: str) -> IpBanRecord | None:
    normalized_ip = normalize_ip_address(ip_address)
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM ip_bans WHERE ip_address = ?", (normalized_ip,)
        ).fetchone()
    return _ip_ban_from_row(row) if row is not None else None


def get_effective_ip_ban(database_path: Path, ip_address: str) -> IpBanRecord | None:
    ban = get_ip_ban_by_address(database_path, ip_address)
    return ban if ban is not None and ban.effective else None


def list_ip_bans(database_path: Path, limit: int = 500) -> list[IpBanRecord]:
    limit = max(1, min(limit, 2000))
    with _connect(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM ip_bans ORDER BY is_active DESC, created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    bans = [_ip_ban_from_row(row) for row in rows]
    return sorted(bans, key=lambda item: (item.effective, item.is_active, item.created_at), reverse=True)


def unban_ip(database_path: Path, ban_id: int, unbanned_by: str) -> IpBanRecord | None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect(database_path) as connection:
        row = connection.execute("SELECT * FROM ip_bans WHERE id = ?", (ban_id,)).fetchone()
        if row is None:
            return None
        if row["is_active"]:
            connection.execute(
                """UPDATE ip_bans
                   SET is_active = 0, unbanned_by = ?, unbanned_at = ?
                   WHERE id = ?""",
                (str(unbanned_by).strip()[:64], now, ban_id),
            )
            row = connection.execute("SELECT * FROM ip_bans WHERE id = ?", (ban_id,)).fetchone()
    return _ip_ban_from_row(row)


def delete_user(database_path: Path, user_id: int) -> UserRecord | None:
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT id, username, role, is_active, created_at, updated_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            return None
        if row["username"] == "admin":
            raise ValueError("admin 账户不能删除")
        active_count = connection.execute("SELECT COUNT(*) AS count FROM users WHERE is_active = 1").fetchone()["count"]
        if row["is_active"] and active_count <= 1:
            raise ValueError("不能删除最后一个可用账号")
        connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return UserRecord(**{**dict(row), "is_active": bool(row["is_active"])})


def write_audit_log(
    database_path: Path, *, username: str | None, category: str, action: str,
    client_ip: str = "", method: str = "", path: str = "", status_code: int | None = None,
    user_agent: str = "", details: str = "",
) -> None:
    with _connect(database_path) as connection:
        connection.execute(
            """INSERT INTO audit_logs
               (occurred_at, username, category, action, client_ip, method, path, status_code, user_agent, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now(timezone.utc).isoformat(timespec="milliseconds"), username, category, action,
             client_ip[:128], method[:16], path[:2048], status_code, user_agent[:512], details[:4000]),
        )


def list_audit_logs(database_path: Path, limit: int = 100, category: str = "", offset: int = 0) -> list[AuditRecord]:
    limit = max(1, min(limit, 2000))
    offset = max(0, offset)
    query = "SELECT * FROM audit_logs"
    params: list[object] = []
    if category:
        query += " WHERE category = ?"
        params.append(category)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend((limit, offset))
    with _connect(database_path) as connection:
        rows = connection.execute(query, params).fetchall()
    return [AuditRecord(**dict(row)) for row in rows]


def list_audit_logs_for_export(database_path: Path, category: str = "") -> list[AuditRecord]:
    query = "SELECT * FROM audit_logs"
    params: list[object] = []
    if category:
        query += " WHERE category = ?"
        params.append(category)
    query += " ORDER BY id DESC"
    with _connect(database_path) as connection:
        rows = connection.execute(query, params).fetchall()
    return [AuditRecord(**dict(row)) for row in rows]


def count_audit_logs(database_path: Path, category: str = "") -> int:
    query = "SELECT COUNT(*) AS count FROM audit_logs"
    params: tuple[object, ...] = ()
    if category:
        query += " WHERE category = ?"
        params = (category,)
    with _connect(database_path) as connection:
        return int(connection.execute(query, params).fetchone()["count"])


def delete_audit_log(database_path: Path, log_id: int) -> AuditRecord | None:
    with _connect(database_path) as connection:
        row = connection.execute("SELECT * FROM audit_logs WHERE id = ?", (log_id,)).fetchone()
        if row is None:
            return None
        connection.execute("DELETE FROM audit_logs WHERE id = ?", (log_id,))
    return AuditRecord(**dict(row))


def delete_all_audit_logs(database_path: Path) -> int:
    with _connect(database_path) as connection:
        count = int(connection.execute("SELECT COUNT(*) AS count FROM audit_logs").fetchone()["count"])
        connection.execute("DELETE FROM audit_logs")
    return count


def save_upload(
    database_path: Path,
    uploads_dir: Path,
    original_name: str,
    data: bytes,
    sha256: str,
    owner_id: int | None = None,
) -> UploadRecord:
    original_name = Path(original_name).name
    if not original_name or original_name in {".", ".."}:
        raise ValueError("文件名无效")
    suffix = Path(original_name).suffix.lower()
    stored_name = f"{uuid.uuid4().hex}{suffix}"
    target = uploads_dir / stored_name
    try:
        with target.open("xb") as handle:
            handle.write(data)
        target.chmod(0o600)
        uploaded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with _connect(database_path) as connection:
            cursor = connection.execute(
                """INSERT INTO uploads
                   (original_name, stored_name, uploaded_at, size_bytes, sha256, owner_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (original_name, stored_name, uploaded_at, len(data), sha256, owner_id),
            )
            record_id = int(cursor.lastrowid)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    owner_username = None
    if owner_id is not None:
        with _connect(database_path) as connection:
            owner_row = connection.execute(
                "SELECT username FROM users WHERE id = ?", (owner_id,)
            ).fetchone()
            owner_username = owner_row["username"] if owner_row else None
    return UploadRecord(
        record_id, original_name, stored_name, uploaded_at, len(data), sha256,
        owner_id, owner_username,
    )


def list_uploads(database_path: Path, owner_id: int | None = None) -> list[UploadRecord]:
    with _connect(database_path) as connection:
        where_clause = ""
        params: tuple[object, ...] = ()
        if owner_id is not None:
            where_clause = "WHERE uploads.owner_id = ?"
            params = (owner_id,)
        rows = connection.execute(
            """SELECT uploads.id, uploads.original_name, uploads.stored_name,
                      uploads.uploaded_at, uploads.size_bytes, uploads.sha256,
                      uploads.owner_id, users.username AS owner_username,
                      latest_report.task_id AS latest_report_task_id,
                      latest_report.created_at AS latest_report_created_at
               FROM uploads LEFT JOIN users ON users.id = uploads.owner_id
               LEFT JOIN reports AS latest_report ON latest_report.task_id = (
                   SELECT candidate.task_id
                   FROM reports AS candidate
                   WHERE candidate.upload_id = uploads.id
                   ORDER BY candidate.created_at DESC, candidate.rowid DESC
                   LIMIT 1
               )
               """ + where_clause + """
               ORDER BY uploads.uploaded_at DESC, uploads.id DESC""",
            params,
        ).fetchall()
    return [UploadRecord(**dict(row)) for row in rows]


def get_upload(database_path: Path, record_id: int) -> UploadRecord | None:
    with _connect(database_path) as connection:
        row = connection.execute(
            """SELECT uploads.id, uploads.original_name, uploads.stored_name,
                      uploads.uploaded_at, uploads.size_bytes, uploads.sha256,
                      uploads.owner_id, users.username AS owner_username,
                      latest_report.task_id AS latest_report_task_id,
                      latest_report.created_at AS latest_report_created_at
               FROM uploads LEFT JOIN users ON users.id = uploads.owner_id
               LEFT JOIN reports AS latest_report ON latest_report.task_id = (
                   SELECT candidate.task_id
                   FROM reports AS candidate
                   WHERE candidate.upload_id = uploads.id
                   ORDER BY candidate.created_at DESC, candidate.rowid DESC
                   LIMIT 1
               )
               WHERE uploads.id = ?""",
            (record_id,),
        ).fetchone()
    return UploadRecord(**dict(row)) if row else None


def read_upload(uploads_dir: Path, record: UploadRecord) -> bytes:
    if Path(record.stored_name).name != record.stored_name:
        raise ValueError("数据库中的存储文件名不安全")
    return (uploads_dir / record.stored_name).read_bytes()


def delete_upload(database_path: Path, uploads_dir: Path, record_id: int) -> bool:
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT stored_name FROM uploads WHERE id = ?", (record_id,)
        ).fetchone()
        if row is None or Path(row["stored_name"]).name != row["stored_name"]:
            return False
        (uploads_dir / row["stored_name"]).unlink(missing_ok=True)
        connection.execute("DELETE FROM uploads WHERE id = ?", (record_id,))
    return True


def save_report(
    database_path: Path,
    task_id: str,
    owner_id: int | None,
    upload_id: int | None = None,
) -> None:
    with _connect(database_path) as connection:
        connection.execute(
            """INSERT OR REPLACE INTO reports (task_id, owner_id, upload_id, created_at)
               VALUES (?, ?, ?, ?)""",
            (task_id, owner_id, upload_id, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )


def get_report_owner(database_path: Path, task_id: str) -> int | None:
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT owner_id FROM reports WHERE task_id = ?", (task_id,)
        ).fetchone()
    return row["owner_id"] if row else None
