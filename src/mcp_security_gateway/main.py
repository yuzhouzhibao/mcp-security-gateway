from fastapi import FastAPI

from mcp_security_gateway.api.errors import install_error_handlers
from mcp_security_gateway.api.routes.admin_agents import router as admin_agents_router
from mcp_security_gateway.api.routes.agent_self import router as agent_self_router
from mcp_security_gateway.api.routes.health import router as health_router
from mcp_security_gateway.infrastructure.db.session import (
    create_database_engine,
    create_session_factory,
)
from mcp_security_gateway.settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings()
    app = FastAPI(title=resolved_settings.app_name)
    app.state.settings = resolved_settings
    engine = create_database_engine(resolved_settings.database_url)
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    install_error_handlers(app)
    app.include_router(health_router)
    app.include_router(admin_agents_router)
    app.include_router(agent_self_router)
    return app


app = create_app()
