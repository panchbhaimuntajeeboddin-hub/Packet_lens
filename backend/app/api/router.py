"""API router aggregation."""

# pyrefly: ignore[missing-import]
from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.endpoints import router as endpoints_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(endpoints_router)
