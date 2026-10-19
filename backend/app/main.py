"""Main entry point for PacketLens FastAPI backend server."""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.core.config import settings
from app.core.database import init_db

# Configure application logging
logging.basicConfig(
    level=logging.INFO if settings.DEBUG else logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("packetlens")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events."""
    logger.info("Initializing PacketLens database schema...")
    init_db()
    logger.info("PacketLens API server ready.")
    yield
    logger.info("PacketLens API server shutting down.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "High-performance Network Traffic Analyzer backend API. "
        "Dissects .pcap and .pcapng captures, computes protocol breakdowns, "
        "and exposes filterable packet logs and traffic metrics."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure Cross-Origin Resource Sharing (CORS) for React development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API endpoints under /api
app.include_router(api_router, prefix="/api")


@app.get("/", tags=["System"])
def root_redirect():
    """Welcome endpoint providing service overview and documentation links."""
    return {
        "message": "Welcome to PacketLens — Network Traffic Analyzer API",
        "version": settings.VERSION,
        "docs_url": "/docs",
        "health_check": "/api/health",
        "analyze_endpoint": "/api/analyze",
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global fallback exception handler preventing server traceback leakage."""
    logger.error("Unhandled exception at %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred while processing the request."},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
