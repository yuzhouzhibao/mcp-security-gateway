from typing import TypedDict

from fastapi import APIRouter, Request

from mcp_security_gateway import __version__
from mcp_security_gateway.settings import Settings

router = APIRouter()


class HealthResponse(TypedDict):
    status: str


class VersionResponse(TypedDict):
    app_name: str
    version: str


@router.get("/health")
async def health() -> HealthResponse:
    return {"status": "ok"}


@router.get("/version")
async def version(request: Request) -> VersionResponse:
    settings: Settings = request.app.state.settings
    return {"app_name": settings.app_name, "version": __version__}
