import json
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from analyzer import AnalysisError, TextChunk, analyze_chunk, analyze_text, detect_structured_personal_data, detect_tabular_personal_data, merge_results, ollama_schema, redact_evidence, split_text
from config import load_settings
from schemas import AnalysisResult, Finding


def finding(line=1, evidence="token=abcdef123456"):
    return Finding(
        category="账号凭据",
        risk_level="high",
        line_start=line,
        line_end=line,
        evidence=evidence,
        reason="该虚构值呈现为访问凭据",
        recommendation="撤销并轮换该凭据",
    )


def result(sensitive=True, risk="high", confidence=90, findings=None):
    return AnalysisResult(
        contains_sensitive_data=sensitive,
        risk_level=risk,
        confidence=confidence,
        summary="测试结果",
        findings=findings or [],
        review_required=True,
    )


def test_split_text_has_no_gaps_and_valid_lines():
    text = "\n".join(f"line-{index:03d}-" + "x" * 20 for index in range(80))
    chunks = split_text(text, target_chars=240, overlap_chars=30, max_chunks=100)
    assert len(chunks) > 1
    assert chunks[0].char_start == 0
    assert chunks[-1].char_end == len(text)
    for previous, current in zip(chunks, chunks[1:]):
        assert current.char_start <= previous.char_end
        assert current.char_start > previous.char_start
        assert current.line_start <= current.line_end


def test_cross_boundary_text_is_fully_present_in_a_chunk():
    marker = "token=TRAINING_CROSS_BOUNDARY_123456789"
    text = "x" * 980 + marker + "y" * 1200
    chunks = split_text(text, target_chars=1000, overlap_chars=100, max_chunks=10)
    assert any(marker in chunk.text for chunk in chunks)


def test_split_rejects_too_many_chunks():
    with pytest.raises(AnalysisError, match="超过"):
        split_text("x" * 10000, target_chars=1000, overlap_chars=100, max_chunks=2)


def test_redaction_masks_credentials_identity_phone_and_email():
    value = "password=supersecret 110105199001011234 13812345678 abcdef@example.com DRILL_SESSION_abcdef1234567890"
    masked = redact_evidence(value)
    assert "supersecret" not in masked
    assert "110105199001011234" not in masked
    assert "13812345678" not in masked
    assert "abcdef@example.com" not in masked
    assert "DRILL_SESSION_abcdef1234567890" not in masked
    assert "****" in masked


def test_merge_deduplicates_and_keeps_highest_risk():
    duplicate = finding()
    low = result(True, "low", 60, [duplicate])
    overlapping = duplicate.model_copy(deep=True)
    overlapping.line_end = 2
    high = result(True, "high", 95, [overlapping])
    merged = merge_results([low, high], max_findings=20)
    assert merged.risk_level == "high"
    assert merged.confidence == 78
    assert len(merged.findings) == 1
    assert merged.findings[0].line_end == 2


def test_merge_uses_findings_not_contradictory_boolean():
    contradictory = AnalysisResult.model_construct(
        contains_sensitive_data=True,
        risk_level="high",
        confidence=92,
        summary="共发现 0 项",
        findings=[],
        review_required=True,
    )
    merged = merge_results([contradictory], max_findings=20)
    assert merged.contains_sensitive_data is False
    assert merged.risk_level == "none"
    assert merged.summary.startswith("未发现敏感信息")


class FakeClient:
    def __init__(self, payloads):
        self.payloads = iter(payloads)
        self.calls = 0

    def chat(self, **kwargs):
        self.calls += 1
        payload = next(self.payloads)
        if isinstance(payload, Exception):
            raise payload
        return SimpleNamespace(message=SimpleNamespace(content=payload))


def test_analyze_chunk_retries_invalid_schema_and_keeps_original_evidence():
    settings = load_settings()
    valid = result(True, "high", 90, [finding()]).model_dump_json()
    client = FakeClient(["not-json", valid])
    chunk = TextChunk(1, "token=abcdef123456", 0, 18, 1, 1)
    analyzed = analyze_chunk(client, settings, "test.txt", chunk)
    assert client.calls == 2
    assert analyzed.findings[0].evidence == "token=abcdef123456"


def test_model_masked_evidence_is_replaced_with_source_line():
    settings = load_settings()
    item = finding(evidence="身份证：110105********1234")
    valid = result(True, "high", 90, [item]).model_dump_json()
    source = "身份证：110105199001011234"
    analyzed = analyze_chunk(FakeClient([valid]), settings, "test.txt", TextChunk(1, source, 0, len(source), 1, 1))
    assert analyzed.findings[0].evidence == source


def test_detects_requested_structured_personal_categories_without_masking():
    text = "\n".join([
        "用户名：zhangsan", "姓名：张三", "部门：安全运营部", "电话号码：13812345678",
        "职位：安全工程师", "身份证：110105199001011234", "住址：北京市朝阳区测试路88号",
    ])
    findings = detect_structured_personal_data(TextChunk(1, text, 0, len(text), 1, 7))
    assert {item.category for item in findings} == {"用户名", "姓名", "部门身份", "电话号码", "职位", "身份证", "住址"}
    assert any("110105199001011234" in item.evidence for item in findings)


def test_detects_unlabelled_tab_separated_personnel_record():
    line = "zhangwei01\t张伟\t治安管理支队\t13800010001\t民警\tTEST-ID-110101-19880101-001X\t测试市安宁区和平路101号\tJH-T001\t普通用户"
    findings = detect_tabular_personal_data(line, 8)
    assert {item.category for item in findings} == {"用户名", "姓名", "部门身份", "电话号码", "职位", "身份证", "住址"}
    assert all(item.evidence == line for item in findings)
    assert all(item.line_start == 8 for item in findings)


def test_analyze_chunk_redacts_secret_repeated_in_reason():
    settings = load_settings()
    item = finding()
    item.reason = "完整值 TRAINING_abcd1234efgh5678 属于凭据"
    valid = result(True, "high", 90, [item]).model_dump_json()
    analyzed = analyze_chunk(FakeClient([valid]), settings, "test.txt", TextChunk(1, "x", 0, 1, 1, 1))
    assert "TRAINING_abcd1234efgh5678" not in analyzed.findings[0].reason


def test_analyze_chunk_rejects_out_of_range_lines():
    settings = load_settings()
    invalid = result(True, "high", 90, [finding(line=9)]).model_dump_json()
    client = FakeClient([invalid, invalid])
    chunk = TextChunk(1, "safe", 0, 4, 1, 2)
    with pytest.raises(AnalysisError, match="连续两次"):
        analyze_chunk(client, settings, "test.txt", chunk)


def test_schema_forbids_review_false():
    payload = result(False, "none", 50).model_dump()
    payload["review_required"] = False
    with pytest.raises(Exception):
        AnalysisResult.model_validate(payload)


def test_ollama_schema_avoids_large_grammar_repetitions():
    schema = json.dumps(ollama_schema())
    assert "maxItems" not in schema
    assert "maxLength" not in schema
    assert "review_required" in schema


def test_batch_keeps_valid_chunks_when_one_schema_fails():
    settings = replace(load_settings(), chunk_chars=1000, chunk_overlap=100)
    invalid = "not-json"
    safe = result(False, "none", 80).model_dump_json()
    client = FakeClient([invalid, invalid, safe, safe])
    batch = analyze_text(settings, "long.log", "x" * 2500, client=client)
    assert batch.total_chunks == 3
    assert batch.successful_chunks == 2
    assert len(batch.failed_chunks) == 1
    assert batch.failed_chunks[0].chunk_index == 1


def test_batch_retries_transient_model_failure_once():
    settings = load_settings()
    safe = result(False, "none", 80).model_dump_json()
    client = FakeClient([httpx.ConnectError("offline"), safe])
    batch = analyze_text(settings, "one.txt", "safe text", client=client)
    assert client.calls == 2
    assert batch.successful_chunks == 1
    assert batch.failed_chunks == []


def test_repeated_timeout_returns_controlled_failure():
    settings = load_settings()
    client = FakeClient([httpx.ReadTimeout("timed out")])
    with pytest.raises(AnalysisError) as error:
        analyze_text(settings, "one.txt", "safe text", client=client)
    assert error.value.code == "all_chunks_failed"
    assert "超时" in error.value.user_message
    assert client.calls == 1


def test_progress_reports_waiting_before_first_model_result():
    settings = load_settings()
    safe = result(False, "none", 80).model_dump_json()
    updates = []
    analyze_text(settings, "one.txt", "safe text", progress=lambda done, total: updates.append((done, total)), client=FakeClient([safe]))
    assert updates == [(0, 1), (1, 1)]


def test_server_disconnect_returns_controlled_failure():
    settings = load_settings()
    client = FakeClient(
        [
            httpx.RemoteProtocolError("server disconnected"),
            httpx.RemoteProtocolError("server disconnected"),
        ]
    )
    with pytest.raises(AnalysisError) as error:
        analyze_text(settings, "one.txt", "safe text", client=client)
    assert error.value.code == "all_chunks_failed"
    assert "无法连接" in error.value.user_message
