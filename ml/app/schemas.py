"""Request and response models for the ML service."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from .config import MAX_TEXT_LENGTH


class MessageRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Message body, e-mail text, SMS or chat content")
    top_k: int = Field(8, ge=1, le=25, description="How many explanation tokens to return")

    @field_validator("text")
    @classmethod
    def _cap_length(cls, value: str) -> str:
        if len(value) > MAX_TEXT_LENGTH:
            return value[:MAX_TEXT_LENGTH]
        return value


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    top_k: int = Field(8, ge=1, le=25)


class BatchRequest(BaseModel):
    texts: list[str] = Field(default_factory=list, max_length=200)
    urls: list[str] = Field(default_factory=list, max_length=200)


class Indicator(BaseModel):
    description: str
    contribution: float
    direction: Literal["phishing", "legitimate"]
    token: str | None = None
    feature: str | None = None
    value: float | None = None


class MessagePrediction(BaseModel):
    model: str
    probability: float
    label: Literal["phishing", "legitimate"]
    threshold: float
    risk_contribution: float
    top_indicators: list[Indicator]
    character_ngram_contribution: float
    normalized_text: str
    statistics: dict[str, float]
    latency_ms: float
    model_version: str


class UrlPrediction(BaseModel):
    model: str
    url: str
    probability: float
    label: Literal["phishing", "legitimate"]
    threshold: float
    risk_contribution: float
    top_indicators: list[Indicator]
    features: dict[str, float]
    latency_ms: float
    model_version: str


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    service: str
    version: str
    models: dict[str, bool]
    uptime_seconds: float


class ModelInfoResponse(BaseModel):
    service_version: str
    thresholds: dict[str, Any]
    message_model: dict[str, Any] | None
    url_model: dict[str, Any] | None
    gold_set_metrics: dict[str, Any]
