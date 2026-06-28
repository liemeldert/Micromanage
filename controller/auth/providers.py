"""External identity providers (Clerk / generic OIDC).

A production tenant can delegate authentication to Clerk or any OIDC provider.
The frontend obtains a provider-issued JWT and presents it as a normal Bearer
token; the controller verifies it against the provider's published JWKS using
PyJWT's built-in JWKS client (no hand-rolled crypto, no secret shared with the
provider). The verified subject/email is then mapped to a local ``User`` row,
which is what carries tenant membership and role.

Tenant ``auth_config`` shape for external providers::

    {
      "provider": "clerk" | "oidc",
      "issuer": "https://your-app.clerk.accounts.dev",   # required
      "jwks_url": "https://.../.well-known/jwks.json",    # optional, derived from issuer
      "audience": "your-api-audience",                    # optional
      "authorized_parties": ["https://app.example.com"],  # optional (Clerk azp check)
      "email_claim": "email",                              # optional, default "email"
      "sub_claim": "sub",                                  # optional, default "sub"
      "algorithms": ["RS256"]                              # optional
    }
"""

import asyncio
from typing import Any, Dict, List, Optional

import jwt
from jwt import PyJWKClient

# Cache one JWKS client per URL so signing keys are fetched once and cached
# (PyJWKClient keeps its own in-memory key cache).
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
        # Clerk recommends validating the authorized party (azp) against the
        # set of origins you actually serve.
        if self.authorized_parties:
            azp = claims.get("azp")
            if azp not in self.authorized_parties:
                raise jwt.InvalidTokenError("azp not in authorized_parties")
        return claims

    async def verify(self, token: str) -> Dict[str, Any]:
        # JWKS fetch + verify are blocking; keep the event loop free.
        return await asyncio.to_thread(self._verify_sync, token)
