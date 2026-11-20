import pytest

from config import ConfigError, load_settings


def test_default_settings_are_safe(monkeypatch):
    for name in (
        "OLLAMA_HOST",
        "MODEL_NAME",
        "MAX_FILE_MB",
        "CHUNK_CHARS",
        "CHUNK_OVERLAP",
        "MODEL_MAX_TOKENS",
        "SAVE_RAW_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = load_settings()
    assert settings.ollama_host == "http://127.0.0.1:11434"
    assert settings.model_name == "qwen3:0.6b"
    assert settings.auth_session_idle_seconds == 30 * 60
    assert settings.auth_session_max_seconds == 8 * 60 * 60
    assert settings.max_file_bytes == 100 * 1024 * 1024
    assert settings.chunk_chars == 2500
    assert settings.save_raw_file is True
    assert settings.database_path == settings.data_dir / "sentinelai.db"
    assert settings.uploads_dir.name == "uploads"


@pytest.mark.parametrize(
    ("name", "value"),
    [("MAX_FILE_MB", "abc"), ("SAVE_RAW_FILE", "maybe"), ("CHUNK_OVERLAP", "9000")],
)
def test_invalid_config_fails(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigError):
        load_settings()


@pytest.mark.parametrize("host", ["https://example.invalid", "http://localhost.evil:11434", "http://user@localhost:11434"])
def test_remote_ollama_is_rejected(monkeypatch, host):
    monkeypatch.setenv("OLLAMA_HOST", host)
    with pytest.raises(ConfigError):
        load_settings()


def test_idle_session_timeout_cannot_exceed_absolute_timeout(monkeypatch):
    monkeypatch.setenv("AUTH_SESSION_IDLE_SECONDS", "7200")
    monkeypatch.setenv("AUTH_SESSION_MAX_SECONDS", "3600")
    with pytest.raises(ConfigError):
        load_settings()
