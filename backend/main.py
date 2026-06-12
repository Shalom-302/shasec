"""monshaapi application entry point.

The top-level FastAPI app is a thin parent that mounts the feature
sub-applications (currently ``/admin``: auth, users, roles, RBAC...).
Each sub-app owns its own middleware, lifespan and OpenAPI docs.
"""
import logging

import uvicorn
from fastapi import FastAPI

from backend.core.conf import settings
from backend.core.registrar import register_app, register_init
from backend.app.api import api_router

# The parent app owns the lifespan (DB tables, Redis, rate limiter) because
# Starlette does not run the lifespan of mounted sub-applications.
app = FastAPI(
    title=settings.FASTAPI_TITLE,
    lifespan=register_init,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Observability (opt-in). Enable with OBSERVABILITY_ENABLED=true and a valid
# OTLP_GRPC_ENDPOINT. Kept out of the lean core so the app boots without the
# OpenTelemetry/Prometheus stack installed.
if settings.OBSERVABILITY_ENABLED and settings.OTLP_GRPC_ENDPOINT:
    from backend.utils.prometheus import EndpointFilter, metrics, setting_otlp

    setting_otlp(app, settings.APP_NAME, settings.OTLP_GRPC_ENDPOINT)
    logging.getLogger("uvicorn.access").addFilter(EndpointFilter())
    app.add_route("/metrics", metrics)


@app.get("/health", tags=["health"])
async def health() -> dict:
    """Liveness probe."""
    return {"status": "ok"}


# Mount the single feature app at the root. The parent app only owns the
# lifespan (DB/Redis/limiter) and /health; everything else lives under /api/v1
# with one Swagger at /api/v1/docs.
app.mount("/", register_app(api_router, "shasec"))


if __name__ == "__main__":
    # Handy for IDE debugging. In Docker the entrypoint runs uvicorn directly.
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.ENVIRONMENT == "dev",
    )
