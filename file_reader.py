"""上传文本的内存校验、解码和元数据计算。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from charset_normalizer import from_bytes


ALLOWED_EXTENSIONS = frozenset({".txt", ".log", ".csv", ".json", ".md", ".xml", ".yaml", ".yml"})


class FileValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.user_message = message


@dataclass(frozen=True)
class TextFile:
    filename: str
    raw_size: int
    encoding: str
    text: str
    sha256: str
    line_count: int

    @property
    def character_count(self) -> int:
        return len(self.text)

    def preview(self, max_lines: int = 50) -> str:
        lines = self.text.splitlines()
        return "\n".join(f"{index:>6} | {line}" for index, line in enumerate(lines[:max_lines], 1))


def _looks_binary(data: bytes) -> bool:
    sample = data[:8192]
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    control = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return control / len(sample) > 0.05


def _decode(data: bytes) -> tuple[str, str]:
    for encoding in ("utf-8-sig", "gb18030"):
        try:
            text = data.decode(encoding, errors="strict")
            label = "utf-8" if encoding == "utf-8-sig" else "gb18030"
            return text, label
        except UnicodeDecodeError:
            pass

    match = from_bytes(data).best()
    if match is None or match.encoding is None:
        raise FileValidationError("encoding_unknown", "无法可靠识别字符编码，请转换为 UTF-8 或 GBK 后重试")
    try:
        text = str(match)
    except (UnicodeError, LookupError) as exc:
        raise FileValidationError("decode_failed", "文件解码失败，请转换为 UTF-8 后重试") from exc
    if "\ufffd" in text:
        raise FileValidationError("decode_unstable", "文件包含无法稳定解码的字符")
    return text, match.encoding.lower()


def read_text_file(filename: str, data: bytes, max_bytes: int) -> TextFile:
    safe_name = Path(filename).name
    if not safe_name or safe_name in {".", ".."}:
        raise FileValidationError("invalid_filename", "文件名无效")
    extension = Path(safe_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        allowed = "、".join(sorted(ALLOWED_EXTENSIONS))
        raise FileValidationError("extension_not_allowed", f"不支持该扩展名，允许类型：{allowed}")
    if not data:
        raise FileValidationError("empty_file", "文件为空，无法分析")
    if len(data) > max_bytes:
        raise FileValidationError("file_too_large", f"文件超过大小上限 {max_bytes // 1024 // 1024} MB")
    if _looks_binary(data):
        raise FileValidationError("binary_content", "检测到二进制内容，拒绝按文本处理")

    text, encoding = _decode(data)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        raise FileValidationError("blank_file", "文件仅包含空白字符，无法分析")
    printable = sum(char.isprintable() or char in "\n\t" for char in text)
    if printable / max(len(text), 1) < 0.9:
        raise FileValidationError("non_text_content", "文件可打印文本比例过低，疑似非文本内容")

    return TextFile(
        filename=safe_name,
        raw_size=len(data),
        encoding=encoding,
        text=text,
        sha256=hashlib.sha256(data).hexdigest(),
        line_count=text.count("\n") + 1,
    )
