from dataclasses import asdict
from uuid import UUID

from mcp_security_gateway.application.services.agent_service import AgentDTO
from mcp_security_gateway.domain.enums import AgentRole, EntityStatus


def test_agent_dto_does_not_expose_api_key_hash(sample_uuid: UUID) -> None:
    dto = AgentDTO(
        id=sample_uuid,
        tenant_id=sample_uuid,
        name="github-agent",
        role=AgentRole.AGENT,
        status=EntityStatus.ACTIVE,
    )

    serialized = asdict(dto)

    assert "api_key_hash" not in serialized
    assert "api_key" not in serialized
