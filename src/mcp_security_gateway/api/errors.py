from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from mcp_security_gateway.application.services.errors import (
    AgentDisabledError,
    AgentNameConflictError,
    AgentNotFoundError,
    ApplicationError,
    ArgumentSchemaInvalidError,
    IdempotencyConflictError,
    McpClientNotConfiguredError,
    TenantNotFoundError,
    ToolDisabledError,
    ToolNotFoundError,
    ToolServerNotFoundError,
    UnauthenticatedError,
)


class APIError(ApplicationError):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(code, message, details)
        self.status_code = status_code


def error_response(
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    raw_details = details or {}
    trace_id = raw_details.get("trace_id")
    response_details = {key: value for key, value in raw_details.items() if key != "trace_id"}
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": response_details,
                "trace_id": trace_id,
            }
        },
    )


def status_code_for_error(error: ApplicationError) -> int:
    if isinstance(error, UnauthenticatedError):
        return 401
    if isinstance(error, AgentDisabledError):
        return 403
    if isinstance(error, TenantNotFoundError | AgentNotFoundError):
        return 404
    if isinstance(error, AgentNameConflictError):
        return 409
    if isinstance(error, ToolServerNotFoundError | ToolNotFoundError):
        return 404
    if isinstance(error, ToolDisabledError):
        return 409
    if isinstance(error, ArgumentSchemaInvalidError):
        return 422
    if isinstance(error, IdempotencyConflictError):
        return 409
    if isinstance(error, McpClientNotConfiguredError):
        return 500
    return 500


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(APIError)
    async def handle_api_error(request: Request, error: APIError) -> JSONResponse:
        return error_response(error.status_code, error.code, error.message, error.details)

    @app.exception_handler(ApplicationError)
    async def handle_application_error(
        request: Request,
        error: ApplicationError,
    ) -> JSONResponse:
        return error_response(
            status_code_for_error(error), error.code, error.message, error.details
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        return error_response(
            422,
            "validation_error",
            "Request validation failed",
            {"errors": error.errors()},
        )

    @app.exception_handler(RuntimeError)
    async def handle_runtime_error(request: Request, error: RuntimeError) -> JSONResponse:
        return error_response(500, "internal_error", "Internal server error")
