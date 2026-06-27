import hashlib
import hmac
import secrets

API_KEY_PREFIX = "msgw_"


def generate_api_key() -> str:
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str, pepper: str) -> str:
    return hmac.new(
        pepper.encode("utf-8"),
        api_key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_api_key_hash(api_key: str, expected_hash: str, pepper: str) -> bool:
    candidate_hash = hash_api_key(api_key, pepper)
    return hmac.compare_digest(candidate_hash, expected_hash)
