"""External identity providers (Clerk and generic OIDC).

Verifies provider-issued JWTs against published JWKS and maps to local User rows.
"""

import asyncio
from typing import Any, Dict, List, Optional

import jwt
from jwt import PyJWKClient

# One client per JWKS URL; PyJWKClient keeps its own in-memory cache of the signing keys it has fetched.
_JWK_CLIENTS: Dict[str, PyJWKClient] = {}


def _jwk_client(jwks_url: str) -> PyJWKClient:
    client = _JWK_CLIENTS.get(jwks_url)
    if client is None:
        client = PyJWKClient(jwks_url, cache_keys=True)
        _JWK_CLIENTS[jwks_url] = client
    return client


class ExternalAuthError(Exception):
    pass


class ExternalJWTProvider:
    """Verifies a provider-issued JWT against the provider's JWKS."""

    def __init__(self, provider: str, cfg: Dict[str, Any]):
        self.provider = provider
        self.issuer: Optional[str] = cfg.get("issuer")
        if not self.issuer:
            raise ExternalAuthError(f"{provider} auth_config missing 'issuer'")
        self.jwks_url: str = cfg.get("jwks_url") or (
            self.issuer.rstrip("/") + "/.well-known/jwks.json"
        )
        self.audience: Optional[str] = cfg.get("audience")
        self.authorized_parties: List[str] = cfg.get("authorized_parties") or []
        self.email_claim: str = cfg.get("email_claim", "email")
        self.sub_claim: str = cfg.get("sub_claim", "sub")
        self.algorithms: List[str] = cfg.get("algorithms", ["RS256"])

    def _verify_sync(self, token: str) -> Dict[str, Any]:
        signing_key = _jwk_client(self.jwks_url).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=self.algorithms,
            audience=self.audience if self.audience else None,
            issuer=self.issuer,
            leeway=30,
            options={"verify_aud": bool(self.audience)},
        )
        # Clerk recommends validating the authorized party (azp) against the set of origins you actually serve.
        if self.authorized_parties:
            azp = claims.get("azp")
            if azp not in self.authorized_parties:
                raise jwt.InvalidTokenError("azp not in authorized_parties")
        return claims

    async def verify(self, token: str) -> Dict[str, Any]:
        # JWKS fetch + verify are blocking; keep the event loop free.
        return await asyncio.to_thread(self._verify_sync, token)
