# Roadmap

This roadmap lists planned work. These items are not implemented unless another document explicitly says they are.

## Near Term

- Phase 7B: Streamable HTTP MCP adapter.
- Admin Policy API for managing policies without direct database access.
- Audit Query API for admin inspection of AuditEvent rows.
- Better demo tooling around local bootstrap and sample policies.

## Security Hardening

- Encrypt approval execution payloads with KMS or another managed key service.
- Add per-admin identities with OAuth / SSO.
- Add Redis-backed idempotency coordination and rate limiting.
- Add stricter admin review workflows for policy and tool classification changes.

## Observability

- OpenTelemetry tracing with strict secret redaction.
- Metrics for policy decisions, approval latency, MCP failures, and tool usage.

## Policy And Tooling

- More expressive but still safe policy matching.
- Policy dry-run and explanation tooling.
- Tool registry review workflow.
- Optional UI dashboard.

## Integrations

- Additional MCP transports after Streamable HTTP.
- Deployment examples for common platforms.
