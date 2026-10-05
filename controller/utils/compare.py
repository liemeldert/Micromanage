"""Constant-time comparison for secrets that arrive on unauthenticated requests."""
import hmac
from typing import Optional


def constant_time_eq(provided: Optional[str], expected: str) -> bool:
    """Compares UTF-8 bytes, since hmac.compare_digest over str raises TypeError on non-ASCII input. A value that
    cannot be encoded compares unequal."""
    try:
        provided_b = (provided or "").encode("utf-8", "surrogatepass")
        expected_b = expected.encode("utf-8", "surrogatepass")
    except Exception:
        return False
    return hmac.compare_digest(provided_b, expected_b)
