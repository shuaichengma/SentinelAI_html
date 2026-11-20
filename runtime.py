"""进程级分析并发限制，避免 CPU/内存资源耗尽。"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from collections.abc import Iterator


class AnalysisBusyError(RuntimeError):
    pass


_LOCK = threading.Lock()
_ACTIVE_TASKS = 0


@contextmanager
def analysis_slot(max_concurrent: int) -> Iterator[None]:
    global _ACTIVE_TASKS
    with _LOCK:
        if _ACTIVE_TASKS >= max_concurrent:
            raise AnalysisBusyError("当前分析任务已达上限，请等待现有任务完成后重试")
        _ACTIVE_TASKS += 1
    try:
        yield
    finally:
        with _LOCK:
            _ACTIVE_TASKS -= 1
