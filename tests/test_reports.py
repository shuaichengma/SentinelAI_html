import json

from analyzer import BatchAnalysis
from config import load_settings
from file_reader import read_text_file
from reports import build_report, report_json, report_markdown, result_conclusion
from schemas import AnalysisReport, AnalysisResult, Finding


def test_reports_round_trip_without_raw_file():
    file = read_text_file("safe.txt", b"public documentation", 1024)
    result = AnalysisResult(
        contains_sensitive_data=False,
        risk_level="none",
        confidence=80,
        summary="未发现明显敏感数据",
        findings=[],
        review_required=True,
    )
    report = build_report(file, BatchAnalysis(result, 1, 1, []), load_settings())
    json_text = report_json(report)
    parsed = AnalysisReport.model_validate_json(json_text)
    markdown = report_markdown(report)
    assert parsed.file.sha256 == file.sha256
    assert "public documentation" in json_text
    assert "public documentation" in markdown
    assert "人工复核" in markdown
    assert "### 结论\n\n未发现敏感信息" in markdown
    assert "### AI 评判依据" in markdown
    assert "未识别出明确敏感模式" in markdown
    assert "本次分析成功 1/1 个分段" in markdown
    assert report.analyzed_at.isoformat().endswith("+08:00")


def test_markdown_quotes_ai_evidence_with_lines():
    file = read_text_file("sample.txt", "password=abc****xyz".encode(), 1024)
    result = AnalysisResult(
        contains_sensitive_data=True,
        risk_level="high",
        confidence=90,
        summary="发现凭据",
        findings=[Finding(
            category="账号凭据",
            risk_level="high",
            line_start=1,
            line_end=1,
            evidence="password=abc****xyz",
            reason="出现口令字段",
            recommendation="人工复核",
        )],
        review_required=True,
    )
    markdown = report_markdown(file_report := build_report(file, BatchAnalysis(result, 1, 1, []), load_settings()))
    assert file_report.result.findings[0].evidence in markdown
    assert "文件第 1-1 行" in markdown
    assert "判断理由：出现口令字段" in markdown
    assert "- 风险：high" not in markdown.split("### AI 评判依据", 1)[1].split("## 发现项", 1)[0]


def test_three_state_conclusion_follows_evidence_risk():
    clean = AnalysisResult(contains_sensitive_data=True, risk_level="high", confidence=70, summary="矛盾", findings=[], review_required=True)
    assert result_conclusion(clean) == "未发现敏感信息"

    suspected_finding = Finding(category="内部资料", risk_level="medium", line_start=1, line_end=1, evidence="内部会议", reason="需复核", recommendation="复核")
    suspected = AnalysisResult(contains_sensitive_data=True, risk_level="medium", confidence=65, summary="疑似", findings=[suspected_finding], review_required=True)
    assert result_conclusion(suspected) == "疑似包含敏感信息"

    confirmed_finding = suspected_finding.model_copy(update={"risk_level": "high"})
    confirmed = AnalysisResult(contains_sensitive_data=True, risk_level="high", confidence=90, summary="发现", findings=[confirmed_finding], review_required=True)
    assert result_conclusion(confirmed) == "发现敏感信息"
