"""
PhishGuard AI — ML inference service (FastAPI).

Started separately from the Node API and consumed over HTTP:

    uvicorn app.main:app --host 127.0.0.1 --port 8000

The Node tier treats this service as optional. If it is down or slow, the rule
engine still produces a full explainable verdict and simply notes that the ML
layer was unavailable, so the product degrades in quality rather than failing.

Endpoints
---------
    GET  /health              liveness plus which artifacts are loaded
    GET  /model/info          training metadata, thresholds, gold-set metrics
    POST /predict/message     phishing probability + token-level explanation
    POST /predict/url         phishing probability + feature-level explanation
    POST /predict/batch       many messages/URLs in one call
    POST /admin/reload        re-read artifacts after retraining
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .config import HOST, PORT
from .inference import load_models, model_info, models_ready, predict_message, predict_url
from .schemas import (
    BatchRequest,
    HealthResponse,
    MessagePrediction,
    MessageRequest,
    ModelInfoResponse,
    UrlPrediction,
    UrlRequest,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(message)s")
logger = logging.getLogger("phishguard.ml")

STARTED_AT = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load artifacts at start-up so the first request is not the slow one."""
    state = load_models()
    ready = models_ready()
    logger.info("artifacts loaded: %s", ready)
    if not all(ready.values()):
        logger.warning("some models are missing - run the training scripts in ml/training")
    logger.info("decision threshold: %s (%s)", state["thresholds"]["message"], state["thresholds"]["source"])
    yield
    logger.info("ml service shutting down")


app = FastAPI(
    title="PhishGuard AI - ML service",
    description="Phishing and social-engineering classification with exact per-feature explanations.",
    version=__version__,
    lifespan=lifespan,
)

# The service is intended to be reachable only by the Node API on localhost.
# CORS is opened for the Vite dev origins so the UI can also be pointed straight
# at it during debugging.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    ready = models_ready()
    return HealthResponse(
        status="ok" if all(ready.values()) else "degraded",
        service="phishguard-ml",
        version=__version__,
        models=ready,
        uptime_seconds=round(time.time() - STARTED_AT, 1),
    )


@app.get("/model/info", response_model=ModelInfoResponse)
def info() -> ModelInfoResponse:
    return ModelInfoResponse(**model_info())


@app.post("/predict/message", response_model=MessagePrediction)
def message(request: MessageRequest) -> MessagePrediction:
    try:
        return MessagePrediction(**predict_message(request.text, request.top_k))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/predict/url", response_model=UrlPrediction)
def url(request: UrlRequest) -> UrlPrediction:
    try:
        return UrlPrediction(**predict_url(request.url, request.top_k))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/predict/batch")
def batch(request: BatchRequest) -> dict:
    if not request.texts and not request.urls:
        raise HTTPException(status_code=422, detail="provide at least one of texts[] or urls[]")
    started = time.perf_counter()
    try:
        messages = [predict_message(text, top_k=4) for text in request.texts]
        urls = [predict_url(item, top_k=4) for item in request.urls]
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "messages": messages,
        "urls": urls,
        "count": len(messages) + len(urls),
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
    }


@app.post("/admin/reload")
def reload_models() -> dict:
    load_models(force=True)
    return {"reloaded": True, "models": models_ready()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False)
