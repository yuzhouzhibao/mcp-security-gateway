import hmac

import pytest

from mcp_security_gateway.infrastructure.auth import api_keys


def test_generate_api_key_uses_gateway_prefix() -> None:
    generated = api_keys.generate_api_key()

    assert generated.startswith("msgw_")
    assert len(generated) > len("msgw_")


def test_hash_api_key_is_stable_for_same_key() -> None:
    first = api_keys.hash_api_key("test-agent-key", "test-api-key-pepper")
    second = api_keys.hash_api_key("test-agent-key", "test-api-key-pepper")

    assert first == second


def test_different_api_keys_have_different_hashes() -> None:
    first = api_keys.hash_api_key("test-agent-key-a", "test-api-key-pepper")
    second = api_keys.hash_api_key("test-agent-key-b", "test-api-key-pepper")

    assert first != second


def test_verify_api_key_hash_accepts_correct_key() -> None:
    expected_hash = api_keys.hash_api_key("test-agent-key", "test-api-key-pepper")

    assert api_keys.verify_api_key_hash(
        "test-agent-key",
        expected_hash,
        "test-api-key-pepper",
    )


def test_verify_api_key_hash_rejects_wrong_key() -> None:
    expected_hash = api_keys.hash_api_key("test-agent-key", "test-api-key-pepper")

    assert not api_keys.verify_api_key_hash(
        "wrong-agent-key",
        expected_hash,
        "test-api-key-pepper",
    )


def test_verify_api_key_hash_uses_constant_time_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    def record_compare(left: str, right: str) -> bool:
        calls.append((left, right))
        return True

    monkeypatch.setattr(hmac, "compare_digest", record_compare)

    assert api_keys.verify_api_key_hash("test-agent-key", "expected", "test-api-key-pepper")
    assert calls == [
        (
            api_keys.hash_api_key("test-agent-key", "test-api-key-pepper"),
            "expected",
        )
    ]
