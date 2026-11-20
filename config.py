"""集中、严格的应用配置。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class ConfigError(ValueError):
    """配置缺失或格式不合法。"""


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"配置 {name} 必须是整数，当前值为 {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"配置 {name} 必须在 {minimum} 到 {maximum} 之间")
    return value


def _number(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"配置 {name} 必须是数字，当前值为 {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"配置 {name} 必须在 {minimum} 到 {maximum} 之间")
    return value


def _boolean(name: str, default: bool) -> bool:
    raw = os.getenv(name, str(default)).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"配置 {name} 必须是 true 或 false，当前值为 {raw!r}")


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_version: str
    auth_session_idle_seconds: int
    auth_session_max_seconds: int
    ollama_host: str
    model_name: str
    max_file_mb: int
    chunk_chars: int
    chunk_overlap: int
    max_chunks: int
    model_temperature: float
    model_timeout_seconds: int
    model_max_tokens: int
    save_raw_file: bool
    show_full_evidence: bool
    max_findings: int
    max_concurrent_tasks: int
    data_dir: Path
    uploads_dir: Path
    database_path: Path

    @property
    def max_file_bytes(self) -> int:
        return self.max_file_mb * 1024 * 1024


def load_settings() -> Settings:
    data_dir = Path(os.getenv("DATA_DIR", "data").strip() or "data").expanduser()
    uploads_dir = Path(os.getenv("UPLOADS_DIR", "uploads").strip() or "uploads").expanduser()
    settings = Settings(
        app_name=os.getenv("APP_NAME", "SentinelAI 敏感数据分析系统").strip(),
        app_version=os.getenv("APP_VERSION", "1.0.0-html").strip(),
        auth_session_idle_seconds=_integer("AUTH_SESSION_IDLE_SECONDS", 30 * 60, 60, 24 * 60 * 60),
        auth_session_max_seconds=_integer("AUTH_SESSION_MAX_SECONDS", 8 * 60 * 60, 5 * 60, 7 * 24 * 60 * 60),
        ollama_host=os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").strip(),
        model_name=os.getenv("MODEL_NAME", "qwen3:0.6b").strip(),
        max_file_mb=_integer("MAX_FILE_MB", 100, 1, 100),
        chunk_chars=_integer("CHUNK_CHARS", 2500, 1000, 50000),
        chunk_overlap=_integer("CHUNK_OVERLAP", 300, 0, 5000),
        max_chunks=_integer("MAX_CHUNKS", 100, 1, 1000),
        model_temperature=_number("MODEL_TEMPERATURE", 0, 0, 2),
        model_timeout_seconds=_integer("MODEL_TIMEOUT_SECONDS", 180, 5, 1800),
        model_max_tokens=_integer("MODEL_MAX_TOKENS", 500, 128, 4096),
        save_raw_file=_boolean("SAVE_RAW_FILE", True),
        show_full_evidence=_boolean("SHOW_FULL_EVIDENCE", False),
        max_findings=_integer("MAX_FINDINGS", 200, 1, 1000),
        max_concurrent_tasks=_integer("MAX_CONCURRENT_TASKS", 1, 1, 8),
        data_dir=data_dir,
        uploads_dir=uploads_dir,
        database_path=data_dir / "sentinelai.db",
    )
    if not settings.app_name or not settings.model_name:
        raise ConfigError("APP_NAME 和 MODEL_NAME 不得为空")
    if settings.auth_session_idle_seconds > settings.auth_session_max_seconds:
        raise ConfigError("AUTH_SESSION_IDLE_SECONDS 不得大于 AUTH_SESSION_MAX_SECONDS")
    parsed_host = urlparse(settings.ollama_host)
    if parsed_host.scheme != "http" or parsed_host.hostname not in {"127.0.0.1", "localhost"}:
        raise ConfigError("第一版 OLLAMA_HOST 必须指向本机回环地址")
    if parsed_host.username or parsed_host.password or parsed_host.query or parsed_host.fragment:
        raise ConfigError("OLLAMA_HOST 不得包含认证信息、查询参数或片段")
    if settings.chunk_overlap >= settings.chunk_chars:
        raise ConfigError("CHUNK_OVERLAP 必须小于 CHUNK_CHARS")
    return settings
