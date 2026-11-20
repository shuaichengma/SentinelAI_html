"""文本分段、Ollama 调用、结构校验、脱敏与结果合并。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Callable

import httpx
import ollama
from pydantic import ValidationError

from config import Settings
from prompts import SYSTEM_PROMPT, build_user_prompt
from schemas import AnalysisResult, FailedChunk, Finding


RISK_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


class AnalysisError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.user_message = message


@dataclass(frozen=True)
class TextChunk:
    index: int
    text: str
    char_start: int
    char_end: int
    line_start: int
    line_end: int


@dataclass(frozen=True)
class BatchAnalysis:
    result: AnalysisResult
    total_chunks: int
    successful_chunks: int
    failed_chunks: list[FailedChunk]


def split_text(text: str, target_chars: int, overlap_chars: int, max_chunks: int) -> list[TextChunk]:
    if not text:
        return []
    chunks: list[TextChunk] = []
    start = 0
    length = len(text)
    while start < length:
        ideal_end = min(start + target_chars, length)
        end = ideal_end
        if ideal_end < length:
            newline = text.rfind("\n", start + max(1, target_chars // 2), ideal_end + 1)
            if newline > start:
                end = newline + 1
        if end <= start:
            end = min(start + target_chars, length)

        line_start = text.count("\n", 0, start) + 1
        line_end = text.count("\n", 0, max(start, end - 1)) + 1
        chunks.append(
            TextChunk(
                index=len(chunks) + 1,
                text=text[start:end],
                char_start=start,
                char_end=end,
                line_start=line_start,
                line_end=line_end,
            )
        )
        if len(chunks) > max_chunks:
            raise AnalysisError("too_many_chunks", f"文件将产生超过 {max_chunks} 个分段，请拆分文件后重试")
        if end >= length:
            break
        start = max(start + 1, end - overlap_chars)
    return chunks


def _mask_middle(value: str, keep: int = 3) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}****{value[-keep:]}"


def redact_evidence(value: str) -> str:
    value = value[:500]
    value = re.sub(r"(?<!\d)(\d{6})\d{8}(\d{4}|\d{3}[Xx])(?!\d)", r"\1********\2", value)
    value = re.sub(r"(?<!\d)(1\d{2})\d{4}(\d{4})(?!\d)", r"\1****\2", value)
    value = re.sub(
        r"\b([A-Za-z0-9._%+-]{1,3})[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
        r"\1****\2",
        value,
    )
    credential = re.compile(
        r"(?i)(password|passwd|pwd|token|api[_-]?key|secret|cookie|session|authorization|credential[_-]?value)(\s*[:=]\s*)([^\s,;]{4,})"
    )
    value = credential.sub(lambda m: f"{m.group(1)}{m.group(2)}{_mask_middle(m.group(3))}", value)
    value = re.sub(
        r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----",
        r"-----BEGIN \1-----\n****REDACTED****\n-----END \1-----",
        value,
    )
    long_value = re.compile(r"[A-Za-z0-9_!@#$%^&*.+-]{12,}")
    value = long_value.sub(
        lambda match: _mask_middle(match.group(0))
        if any(char.isalpha() for char in match.group(0)) and any(char.isdigit() for char in match.group(0))
        else match.group(0),
        value,
    )
    return value


def _validate_chunk_lines(result: AnalysisResult, chunk: TextChunk) -> AnalysisResult:
    result.summary = redact_evidence(result.summary)
    source_lines = chunk.text.splitlines()
    for finding in result.findings:
        if finding.line_start < chunk.line_start or finding.line_end > chunk.line_end:
            raise AnalysisError(
                "invalid_line_number",
                f"模型返回的行号超出分段 {chunk.index} 的有效范围 {chunk.line_start}-{chunk.line_end}",
            )
        relative_start = finding.line_start - chunk.line_start
        relative_end = finding.line_end - chunk.line_start + 1
        original = "\n".join(source_lines[relative_start:relative_end]).strip()
        if original:
            # 模型可能自行遮盖敏感值；证据必须以行号对应的上传文件原文为准。
            finding.evidence = original[:500]
        finding.reason = redact_evidence(finding.reason)
        finding.recommendation = redact_evidence(finding.recommendation)
    return result


STRUCTURED_PERSONAL_PATTERNS = (
    ("用户名", "medium", re.compile(r"(?i)(?:用户名|用户账号|登录名|user(?:name)?|login)[\s:：=]+([^\s,，;；]{2,64})")),
    ("姓名", "medium", re.compile(r"(?:姓名|名字|员工姓名|客户姓名)[\s:：=]+([\u4e00-\u9fff·]{2,20}|[A-Za-z][A-Za-z .'-]{1,60})")),
    ("部门身份", "medium", re.compile(r"(?:部门|科室|组织|单位|所属部门)[\s:：=]+([^\n,，;；]{2,80})")),
    ("电话号码", "medium", re.compile(r"(?:电话号码|联系电话|手机号|电话|手机|tel(?:ephone)?|mobile)[\s:：=]+((?:\+?86[- ]?)?1[3-9]\d{9}|\d{3,4}[- ]?\d{7,8})", re.I)),
    ("职位", "medium", re.compile(r"(?:职位|职务|岗位|职称)[\s:：=]+([^\n,，;；]{2,80})")),
    ("身份证", "high", re.compile(r"(?:身份证号?|公民身份号码)[\s:：=]+(\d{17}[0-9Xx]|\d{15})")),
    ("住址", "medium", re.compile(r"(?:住址|住宅地址|家庭地址|居住地址|通信地址|联系地址)[\s:：=]+([^\n;；]{4,160})")),
)

PHONE_VALUE = re.compile(r"^(?:\+?86[- ]?)?1[3-9]\d{9}$|^\d{3,4}[- ]?\d{7,8}$")
IDENTITY_VALUE = re.compile(r"^(?:\d{17}[0-9Xx]|\d{15}|(?:TEST[-_ ]?)?ID[-_A-Za-z0-9]+)$", re.I)
USERNAME_VALUE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,63}$")
NAME_VALUE = re.compile(r"^[\u4e00-\u9fff·]{2,8}$")
DEPARTMENT_VALUE = re.compile(r"(?:部门|支队|大队|中队|科室|中心|办公室|分局|公安局|公司|学校|医院)$")
POSITION_VALUE = re.compile(r"(?:民警|辅警|警员|工程师|经理|主任|主管|专员|职员|教师|医生|护士)$")
ADDRESS_VALUE = re.compile(r"(?:省|市|区|县|镇|乡|村|街|道|路|巷|号|室)")


def detect_tabular_personal_data(line: str, line_number: int) -> list[Finding]:
    fields = [field.strip() for field in (line.split("\t") if "\t" in line else re.split(r"\s{2,}", line)) if field.strip()]
    if len(fields) < 5:
        return []
    checks = (
        ("用户名", "medium", lambda value: bool(USERNAME_VALUE.fullmatch(value))),
        ("姓名", "medium", lambda value: bool(NAME_VALUE.fullmatch(value))),
        ("部门身份", "medium", lambda value: bool(DEPARTMENT_VALUE.search(value))),
        ("电话号码", "medium", lambda value: bool(PHONE_VALUE.fullmatch(value))),
        ("职位", "medium", lambda value: bool(POSITION_VALUE.search(value))),
        ("身份证", "high", lambda value: bool(IDENTITY_VALUE.fullmatch(value))),
        ("住址", "medium", lambda value: len(value) >= 6 and bool(ADDRESS_VALUE.search(value))),
    )
    matched = [(category, risk) for category, risk, check in checks if any(check(field) for field in fields)]
    # 至少三种身份特征共同出现才按无标签人员记录处理，避免普通制表数据误报。
    if len(matched) < 3:
        return []
    return [Finding(
        category=category,
        risk_level=risk,
        line_start=line_number,
        line_end=line_number,
        evidence=line.strip()[:500],
        reason=f"该表格行与其他身份字段组合出现具体{category}，构成人员身份记录。",
        recommendation="限制人员记录的访问、导出和传播，并实施最小权限控制。",
    ) for category, risk in matched]


def detect_structured_personal_data(chunk: TextChunk) -> list[Finding]:
    """补足小模型容易漏掉的带标签个人数据，证据按用户要求保留原文。"""
    findings: list[Finding] = []
    for offset, line in enumerate(chunk.text.splitlines()):
        line_number = chunk.line_start + offset
        for category, risk, pattern in STRUCTURED_PERSONAL_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    category=category,
                    risk_level=risk,
                    line_start=line_number,
                    line_end=line_number,
                    evidence=line.strip()[:500],
                    reason=f"该行包含带具体值的{category}字段，属于需要保护的个人相关信息。",
                    recommendation="限制访问范围，并按数据分类分级要求安全存储和传输。",
                ))
        findings.extend(detect_tabular_personal_data(line, line_number))
    return findings


def ollama_schema() -> dict:
    """移除会让 llama.cpp grammar 指数展开的上限，返回后仍执行完整 Pydantic 校验。"""
    schema = AnalysisResult.model_json_schema()

    def simplify(node: object) -> None:
        if isinstance(node, dict):
            node.pop("maxLength", None)
            node.pop("maxItems", None)
            for value in node.values():
                simplify(value)
        elif isinstance(node, list):
            for value in node:
                simplify(value)

    simplify(schema)
    return schema


def analyze_chunk(client: ollama.Client, settings: Settings, filename: str, chunk: TextChunk) -> AnalysisResult:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_user_prompt(filename, chunk.line_start, chunk.line_end, chunk.text)},
    ]
    last_error: Exception | None = None
    for attempt in range(2):
        retry_suffix = "" if attempt == 0 else "\n上次输出未通过校验。请严格只返回符合 Schema 的 JSON 对象。"
        if retry_suffix:
            messages[-1] = {"role": "user", "content": messages[-1]["content"] + retry_suffix}
        try:
            response = client.chat(
                model=settings.model_name,
                messages=messages,
                format=ollama_schema(),
                think=False,
                options={
                    "temperature": settings.model_temperature,
                    "num_predict": settings.model_max_tokens,
                    "num_ctx": 8192,
                },
                keep_alive="10m",
            )
            content = response.message.content
            result = AnalysisResult.model_validate_json(content)
            return _validate_chunk_lines(result, chunk)
        except (ValidationError, ValueError, AnalysisError) as exc:
            last_error = exc
        except ollama.ResponseError as exc:
            if exc.status_code == 404:
                raise AnalysisError("model_missing", f"本地模型 {settings.model_name} 未安装") from exc
            raise AnalysisError("model_response_error", "本地模型返回错误，请检查 Ollama 服务") from exc
        except httpx.TimeoutException as exc:
            raise AnalysisError("model_timeout", "本地模型分析超时，请缩小文件或检查系统负载") from exc
        except (httpx.TransportError, ollama.RequestError, ConnectionError, TimeoutError, OSError) as exc:
            raise AnalysisError("model_unavailable", "无法连接本地模型服务，请检查 Ollama 是否运行") from exc
    raise AnalysisError("schema_validation_failed", "模型连续两次返回了无法校验的结构化结果") from last_error


def merge_results(results: list[AnalysisResult], max_findings: int) -> AnalysisResult:
    if not results:
        raise AnalysisError("no_valid_results", "没有可用的分段分析结果")
    deduplicated: list[Finding] = []
    for result in results:
        for finding in result.findings:
            evidence_key = re.sub(r"\s+", "", finding.evidence).lower()
            duplicate_index: int | None = None
            for index, existing in enumerate(deduplicated):
                if existing.category != finding.category:
                    continue
                ranges_overlap = finding.line_start <= existing.line_end and existing.line_start <= finding.line_end
                existing_key = re.sub(r"\s+", "", existing.evidence).lower()
                similar = (
                    evidence_key in existing_key
                    or existing_key in evidence_key
                    or SequenceMatcher(None, evidence_key, existing_key).ratio() >= 0.8
                )
                if ranges_overlap and similar:
                    duplicate_index = index
                    break
            if duplicate_index is None:
                deduplicated.append(finding)
            else:
                existing = deduplicated[duplicate_index]
                existing.line_start = min(existing.line_start, finding.line_start)
                existing.line_end = max(existing.line_end, finding.line_end)
                if len(finding.evidence) > len(existing.evidence):
                    existing.evidence = finding.evidence
    deduplicated.sort(key=lambda item: (item.line_start, item.line_end, item.category))
    deduplicated = deduplicated[:max_findings]

    contains = bool(deduplicated)
    highest = (
        max(deduplicated, key=lambda item: RISK_RANK[item.risk_level]).risk_level
        if deduplicated
        else "none"
    )
    confidence = round(sum(item.confidence for item in results) / len(results))
    if contains:
        categories = "、".join(dict.fromkeys(item.category for item in deduplicated))
        summary = f"共发现 {len(deduplicated)} 项需要人工复核的敏感或疑似敏感内容"
        if categories:
            summary += f"，涉及：{categories}"
    else:
        summary = "未发现敏感信息；该结论仍需人工复核"
    return AnalysisResult(
        contains_sensitive_data=contains,
        risk_level=highest,
        confidence=confidence,
        summary=summary,
        findings=deduplicated,
        review_required=True,
    )


def analyze_text(
    settings: Settings,
    filename: str,
    text: str,
    progress: Callable[[int, int], None] | None = None,
    client: ollama.Client | None = None,
) -> BatchAnalysis:
    chunks = split_text(text, settings.chunk_chars, settings.chunk_overlap, settings.max_chunks)
    if not chunks:
        raise AnalysisError("empty_text", "没有可分析的文本")
    model_client = client or ollama.Client(
        host=settings.ollama_host,
        timeout=settings.model_timeout_seconds,
        trust_env=False,
    )
    valid: list[AnalysisResult] = []
    failed: list[FailedChunk] = []
    if progress:
        progress(0, len(chunks))
    for position, chunk in enumerate(chunks, 1):
        chunk_result: AnalysisResult | None = None
        chunk_error: AnalysisError | None = None
        for chunk_attempt in range(2):
            try:
                chunk_result = analyze_chunk(model_client, settings, filename, chunk)
                chunk_error = None
                break
            except AnalysisError as exc:
                chunk_error = exc
                if exc.code in {
                    "model_missing",
                    "model_timeout",
                    "schema_validation_failed",
                    "invalid_line_number",
                }:
                    break
        if chunk_result is not None:
            remaining = max(0, 200 - len(chunk_result.findings))
            chunk_result.findings.extend(detect_structured_personal_data(chunk)[:remaining])
            # 重新触发一致性校验，使规则补充项同步更新文件级布尔值和风险等级。
            chunk_result = AnalysisResult.model_validate(chunk_result.model_dump())
            valid.append(chunk_result)
        elif chunk_error is not None:
            failed.append(
                FailedChunk(
                    chunk_index=chunk.index,
                    line_start=chunk.line_start,
                    line_end=chunk.line_end,
                    error_code=chunk_error.code,
                    message=chunk_error.user_message,
                )
            )
        if progress:
            progress(position, len(chunks))
    if not valid:
        first = failed[0] if failed else None
        message = first.message if first else "全部分段分析失败"
        raise AnalysisError("all_chunks_failed", message)
    return BatchAnalysis(
        result=merge_results(valid, settings.max_findings),
        total_chunks=len(chunks),
        successful_chunks=len(valid),
        failed_chunks=failed,
    )


def check_model(settings: Settings) -> tuple[bool, str]:
    try:
        client = ollama.Client(host=settings.ollama_host, timeout=5, trust_env=False)
        models = client.list().models
        names = {model.model for model in models}
        if settings.model_name not in names:
            return False, f"模型未安装：{settings.model_name}"
        return True, f"模型在线：{settings.model_name}"
    except Exception:
        return False, "Ollama 服务离线，请启动本地模型服务"
