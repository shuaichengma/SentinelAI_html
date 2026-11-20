"""AI 结构化输出和最终报告数据模型。"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


RiskLevel = Literal["high", "medium", "low", "none"]
Category = Literal[
    "用户名",
    "姓名",
    "部门身份",
    "电话号码",
    "职位",
    "身份证",
    "住址",
    "个人身份信息",
    "联系信息",
    "账号凭据",
    "网络与系统信息",
    "业务数据",
    "敏感系统日志",
    "内部资料",
    "其他不宜公开信息",
]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    category: Category
    risk_level: Literal["high", "medium", "low"]
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    evidence: str = Field(min_length=1, max_length=500)
    reason: str = Field(min_length=1, max_length=1000)
    recommendation: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def valid_line_range(self) -> "Finding":
        if self.line_end < self.line_start:
            raise ValueError("line_end 不得小于 line_start")
        return self


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    contains_sensitive_data: bool
    risk_level: RiskLevel
    confidence: int = Field(ge=0, le=100)
    summary: str = Field(min_length=1, max_length=2000)
    findings: list[Finding] = Field(default_factory=list, max_length=200)
    review_required: Literal[True]

    @model_validator(mode="after")
    def consistent_result(self) -> "AnalysisResult":
        # 最终判断必须由可核验的发现项支撑，纠正小模型偶发的字段自相矛盾。
        self.contains_sensitive_data = bool(self.findings)
        if self.findings:
            ranks = {"low": 1, "medium": 2, "high": 3}
            self.risk_level = max(self.findings, key=lambda item: ranks[item.risk_level]).risk_level
        else:
            self.risk_level = "none"
        return self


class FailedChunk(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chunk_index: int = Field(ge=1)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    error_code: str
    message: str


class FileMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1)
    encoding: str
    character_count: int = Field(ge=0)
    line_count: int = Field(ge=1)


class BasisExcerpt(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    content: str = Field(min_length=1, max_length=500)


class AnalysisReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    analyzed_at: datetime
    model_name: str
    app_version: str
    prompt_version: str
    file: FileMetadata
    result: AnalysisResult
    total_chunks: int = Field(ge=1)
    successful_chunks: int = Field(ge=0)
    failed_chunks: list[FailedChunk] = Field(default_factory=list)
    basis_excerpts: list[BasisExcerpt] = Field(default_factory=list, max_length=20)

    @field_validator("task_id")
    @classmethod
    def task_id_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("task_id 不得为空")
        return value
