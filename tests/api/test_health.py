from fastapi.testclient import TestClient

from mcp_security_gateway import __version__
from mcp_security_gateway.main import create_app
from mcp_security_gateway.settings import Settings


def test_health_returns_ok(test_settings: Settings) -> None:
    client = TestClient(create_app(test_settings))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_version_returns_app_name_and_version(test_settings: Settings) -> None:
    client = TestClient(create_app(test_settings))

    response = client.get("/version")

    assert response.status_code == 200
    assert response.json() == {
        "app_name": test_settings.app_name,
        "version": __version__,
    }
