"""报告构建与导出。"""

from __future__ import annotations

import json
from datetime import datetime
from uuid import uuid4

from analyzer import BatchAnalysis, redact_evidence
from config import Settings
from file_reader import TextFile
from prompts import PROMPT_VERSION
from schemas import AnalysisReport, AnalysisResult, BasisExcerpt, FileMetadata
from time_utils import CHINA_TIMEZONE


def result_conclusion(result: AnalysisResult) -> str:
    """以实际发现项生成可解释的三态结论。"""
    if not result.findings:
        return "未发现敏感信息"
    if any(item.risk_level == "high" for item in result.findings):
        return "发现敏感信息"
    return "疑似包含敏感信息"


def build_report(file: TextFile, batch: BatchAnalysis, settings: Settings) -> AnalysisReport:
    if batch.result.findings:
        basis_excerpts = [
            BasisExcerpt(line_start=item.line_start, line_end=item.line_end, content=item.evidence)
            for item in batch.result.findings[:20]
        ]
    else:
        basis_excerpts = [
            BasisExcerpt(line_start=line_number, line_end=line_number, content=redact_evidence(line[:500]))
            for line_number, line in enumerate(file.text.splitlines(), 1)
            if line.strip()
        ][:3]
    return AnalysisReport(
        task_id=f"SA-{uuid4().hex[:12]}",
        analyzed_at=datetime.now(CHINA_TIMEZONE),
        model_name=settings.model_name,
        app_version=settings.app_version,
        prompt_version=PROMPT_VERSION,
        file=FileMetadata(
            filename=file.filename,
            sha256=file.sha256,
            size_bytes=file.raw_size,
            encoding=file.encoding,
            character_count=file.character_count,
            line_count=file.line_count,
        ),
        result=batch.result,
        total_chunks=batch.total_chunks,
        successful_chunks=batch.successful_chunks,
        failed_chunks=batch.failed_chunks,
        basis_excerpts=basis_excerpts,
    )


def report_json(report: AnalysisReport) -> str:
    return json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2)


def report_markdown(report: AnalysisReport) -> str:
    conclusion = result_conclusion(report.result)
    lines = [
        "# SentinelAI 敏感数据分析报告",
        "",
        f"- 任务编号：`{report.task_id}`",
        f"- 文件名：`{report.file.filename}`",
        f"- SHA-256：`{report.file.sha256}`",
        f"- 文件大小：{report.file.size_bytes} 字节",
        f"- 字符编码：{report.file.encoding}",
        f"- 分析时间：{report.analyzed_at.isoformat()}",
        f"- 模型：`{report.model_name}`",
        f"- 应用版本：`{report.app_version}`",
        f"- 提示词版本：`{report.prompt_version}`",
        f"- 分段：成功 {report.successful_chunks}/{report.total_chunks}，失败 {len(report.failed_chunks)}",
        "",
        "## 总体结论",
        "",
        "### 结论",
        "",
        conclusion,
        "",
        "### AI 评判依据",
        "",
        f"本次分析成功 {report.successful_chunks}/{report.total_chunks} 个分段。以下摘录是 AI 从文件中识别并用于形成结论的实际原文，未进行脱敏处理。",
        "",
        f"- 模型自评置信度：{report.result.confidence}%",
        f"- 摘要：{report.result.summary}",
        "",
    ]
    if report.result.findings:
        for index, finding in enumerate(report.result.findings, 1):
            lines.extend(
                [
                    f"- 依据 {index}（文件第 {finding.line_start}-{finding.line_end} 行，{finding.category}）：`{finding.evidence}`；判断理由：{finding.reason}",
                ]
            )
        lines.extend(["", "## 发现项", ""])
        for index, finding in enumerate(report.result.findings, 1):
            lines.extend(
                [
                    f"### {index}. {finding.category}",
                    "",
                    f"- 风险：{finding.risk_level}",
                    f"- 行号：{finding.line_start}-{finding.line_end}",
                    f"- 原文证据：`{finding.evidence}`",
                    f"- 理由：{finding.reason}",
                    f"- 建议：{finding.recommendation}",
                    "",
                ]
            )
    else:
        lines.append("- AI 在以下已分析文件内容中未识别出明确敏感模式：")
        for excerpt in report.basis_excerpts:
            lines.append(f"  - 文件第 {excerpt.line_start}-{excerpt.line_end} 行：`{excerpt.content}`")
        lines.extend(["", "## 发现项", "", "没有发现项。", ""])
    if report.failed_chunks:
        lines.extend(["## 失败分段", ""])
        for item in report.failed_chunks:
            lines.append(f"- 分段 {item.chunk_index}（行 {item.line_start}-{item.line_end}）：{item.message} [{item.error_code}]")
        lines.append("")
    lines.extend(["---", "AI 结果仅供研判，必须人工复核。报告中的证据保留原文，可能包含敏感信息，必须严格控制访问。", ""])
    return "\n".join(lines)
