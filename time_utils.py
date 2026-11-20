"""中国标准时间显示工具。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


CHINA_TIMEZONE = timezone(timedelta(hours=8), name="CST")
CHINA_TIMEZONE_LABEL = "UTC+8"


def format_china_time(value: object) -> str:
    """将 UTC 或带时区的时间值转换为中国标准时间。"""
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(CHINA_TIMEZONE).strftime(
            f"%Y-%m-%d %H:%M:%S {CHINA_TIMEZONE_LABEL}"
        )
    except (TypeError, ValueError):
        return str(value)
