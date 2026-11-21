"""FastAPI application factory."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings, mask_secrets, resolve_database_url
from app.db import create_all


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    logger = logging.getLogger("app")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        os.makedirs(str(_app.state.data_dir), exist_ok=True) if hasattr(_app.state, "data_dir") else None
        create_all()
        logger.info("%s v%s starting (llm_mode=%s, db=%s)", settings.APP_NAME,
                    settings.APP_VERSION, settings.LLM_MODE,
                    resolve_database_url(settings.DATABASE_URL))
        yield

    app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION,
                  lifespan=lifespan)
    app.state.llm_provider = None  # lazy; agents use get_provider()

    # CORS from environment only -- no wildcard reflection of credentials.
    origins = settings.cors_origin_list()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False if origins == ["*"] else True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # ---- safe error handlers (no internals leaked) --------------------------
    @app.exception_handler(Exception)
    async def unhandled(_req: Request, exc: Exception):
        logger.error("unhandled error: %s: %s", type(exc).__name__, str(exc)[:300])
        return JSONResponse(status_code=500,
                            content={"error": "internal error",
                                     "detail": type(exc).__name__})

    from app.api.routes_meta import router as meta_router
    from app.api.routes_simulator import router as simulator_router
    from app.api.routes_scans import router as scans_router
    from app.api.routes_investigations import router as investigations_router
    from app.api.routes_findings import router as findings_router
    from app.api.routes_graph import router as graph_router
    from app.api.routes_ai_identities import router as ai_router
    from app.api.routes_proposals import router as proposals_router
    from app.api.routes_approvals import router as approvals_router
    from app.api.routes_metrics import router as metrics_router
    from app.api.routes_evaluation import router as evaluation_router

    app.include_router(meta_router)
    app.include_router(simulator_router)
    app.include_router(scans_router)
    app.include_router(investigations_router)
    app.include_router(findings_router)
    app.include_router(graph_router)
    app.include_router(ai_router)
    app.include_router(proposals_router)
    app.include_router(approvals_router)
    app.include_router(metrics_router)
    app.include_router(evaluation_router)

    # ---- static SPA mounted LAST so API routes win --------------------------
    static_dir = os.path.join(str(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              "..", "frontend")
    static_dir = os.path.normpath(static_dir)
    if os.path.isdir(static_dir):
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="spa")

    return app


app = create_app()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8012)
