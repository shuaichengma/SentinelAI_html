import hashlib

import pytest

from file_reader import FileValidationError, read_text_file


def test_utf8_text_metadata_and_preview():
    data = "第一行\r\n第二行".encode()
    result = read_text_file("demo.txt", data, 1024)
    assert result.encoding == "utf-8"
    assert result.text == "第一行\n第二行"
    assert result.line_count == 2
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert "     1 | 第一行" in result.preview()


def test_gbk_text_is_decoded():
    result = read_text_file("演练.log", "中文日志内容".encode("gbk"), 1024)
    assert result.text == "中文日志内容"
    assert result.encoding == "gb18030"


@pytest.mark.parametrize(
    ("filename", "data", "limit", "code"),
    [
        ("empty.txt", b"", 100, "empty_file"),
        ("binary.txt", b"abc\x00def", 100, "binary_content"),
        ("large.log", b"a" * 101, 100, "file_too_large"),
        ("script.exe", b"plain", 100, "extension_not_allowed"),
        ("blank.md", b"  \n\t", 100, "blank_file"),
    ],
)
def test_invalid_file_is_rejected(filename, data, limit, code):
    with pytest.raises(FileValidationError) as error:
        read_text_file(filename, data, limit)
    assert error.value.code == code


def test_path_components_are_removed():
    result = read_text_file("../../safe.txt", b"safe text", 100)
    assert result.filename == "safe.txt"
