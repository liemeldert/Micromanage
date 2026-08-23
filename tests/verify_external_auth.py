"""External-provider sign-in (Clerk / OIDC), on in-memory sqlite.

A tenant can hand authentication to an external IdP: the client sends the provider's own JWT as a Bearer token, and
controller.auth.dependencies._resolve_external maps the verified claims onto a local User row, which is what carries
tenant membership and role. The signature check is stubbed here; providers.py verifies against a live JWKS endpoint.

The guard worth a suite is the email fallback. A provider subject is IdP-controlled and stable, an email is not:
many IdPs let anyone set an arbitrary address and only mark it verified once it has been proved. The check is
email_verified is True, identity rather than truthiness, so the string "true" an IdP might send has to fail it.

Also covered: an unmatched subject resolves nobody rather than the first user in the tenant, first sign-in binds the
subject to the row, an inactive user is refused whichever way they matched, a tenant whose issuer disagrees with the
token is skipped, and a local-auth tenant is unreachable through this path.

Run:  PYTHONPATH=. ./.venv/bin/python tests/verify_external_auth.py Exits non-zero if any check fails.
"""

import os
from typing import Any, Dict, Optional

os.environ.setdefault("JWT_SECRET", "verify-external-auth-secret-long-enough-for-hs256")

import jwt
from tortoise import Tortoise

from controller.auth import providers as providers_mod
from controller.auth.dependencies import _resolve_external
from controller.models.tenant import Tenant, User

PASS, FAIL = [], []

ISSUER = "https://idp.example.com"
OTHER_ISSUER = "https://other-idp.example.com"

# What the stubbed verifier hands back for the next _resolve_external call.
_STUB_CLAIMS: Dict[str, Any] = {}


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def token_for(claims: Dict[str, Any]) -> str:
    """A token _resolve_external can read the issuer out of.

    It decodes once with verify_signature off to pick the tenant, so the signature never matters here.
    """
    return jwt.encode(claims, "unused-signing-key-long-enough-for-hs256", algorithm="HS256")


async def resolve(claims: Dict[str, Any], tenant_hint: Optional[str] = None):
    """Run the real resolver over one set of provider claims."""
    global _STUB_CLAIMS
    _STUB_CLAIMS = dict(claims)
    return await _resolve_external(token_for(claims), tenant_hint)


async def main():
    # The stub stands in for signature and JWKS verification. Patched on the class that dependencies.py holds, so the
    # instance it builds sees it too.
    async def _stub_verify(self, token):
        return dict(_STUB_CLAIMS)

    providers_mod.ExternalJWTProvider.verify = _stub_verify

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    tenant = await Tenant.create(
        id="ext", name="External Tenant",
        auth_config={"provider": "oidc", "issuer": ISSUER},
    )
    # A second tenant on the same provider with a different issuer, and a local one. Neither may ever answer for the
    # token below.
    await Tenant.create(
        id="ext2", name="Other IdP",
        auth_config={"provider": "oidc", "issuer": OTHER_ISSUER},
    )
    local = await Tenant.create(id="loc", name="Local Tenant")
    await User.create(tenant=local, email="shared@example.com", role="admin")

    bound = await User.create(
        tenant=tenant, email="bound@example.com", role="admin",
        external_id="idp-sub-bound",
    )
    by_email = await User.create(
        tenant=tenant, email="byemail@example.com", role="member",
    )
    inactive = await User.create(
        tenant=tenant, email="inactive@example.com", role="member",
        external_id="idp-sub-inactive", is_active=False,
    )

    #  1. The subject is the primary binding.
    print("1) a matching provider subject resolves the user")
    p = await resolve({"iss": ISSUER, "sub": "idp-sub-bound",
                       "email": "bound@example.com"})
    check("a pre-provisioned external_id resolves its user",
          p is not None and str(p.user.id) == str(bound.id))
    check("...on the right tenant, with the role off the row",
          p is not None and p.tenant.id == "ext" and p.role == "admin"
          and p.email == "bound@example.com")

    # The subject wins even when no email claim is present at all.
    p = await resolve({"iss": ISSUER, "sub": "idp-sub-bound"})
    check("...and needs no email claim to do it",
          p is not None and str(p.user.id) == str(bound.id))

    #  2. Email fallback, allowed only against a verified email.
    print("2) the email fallback requires email_verified is True")
    p = await resolve({"iss": ISSUER, "sub": "idp-sub-new",
                       "email": "byemail@example.com", "email_verified": True})
    check("a verified email resolves a user with no external_id yet",
          p is not None and str(p.user.id) == str(by_email.id))

    # First sign-in binds the subject, so later logins no longer go through the email.
    await by_email.refresh_from_db()
    check("...and the subject is bound to the row on that first sign-in",
          by_email.external_id == "idp-sub-new")

    #  3. The account-takeover guard. Anything that is not the boolean True has to fail, including the string an
    #  IdP may send instead.
    print("3) an unverified email resolves nobody")
    unverifiable = await User.create(
        tenant=tenant, email="victim@example.com", role="admin",
    )
    for label, claims in (
            ("absent", {"iss": ISSUER, "sub": "attacker", "email": "victim@example.com"}),
            ("false", {"iss": ISSUER, "sub": "attacker", "email": "victim@example.com",
                       "email_verified": False}),
            ("the string 'true'", {"iss": ISSUER, "sub": "attacker",
                                   "email": "victim@example.com",
                                   "email_verified": "true"}),
            ("the string 'false'", {"iss": ISSUER, "sub": "attacker",
                                    "email": "victim@example.com",
                                    "email_verified": "false"}),
            ("1", {"iss": ISSUER, "sub": "attacker", "email": "victim@example.com",
                   "email_verified": 1}),
    ):
        p = await resolve(claims)
        check(f"email_verified {label} does not resolve the account", p is None)

    await unverifiable.refresh_from_db()
    check("...and none of those bound the attacker's subject to the row",
          unverifiable.external_id is None)

    #  4. An unmatched subject falls through to nobody.
    print("4) an unknown subject with no email match resolves nobody")
    p = await resolve({"iss": ISSUER, "sub": "nobody-here",
                       "email": "stranger@example.com", "email_verified": True})
    check("an email nobody in the tenant holds resolves nobody", p is None)

    #  5. Deactivated users are refused, however they matched.
    print("5) an inactive user is refused")
    p = await resolve({"iss": ISSUER, "sub": "idp-sub-inactive"})
    check("a subject match on a deactivated user is refused", p is None)
    inactive.external_id = None
    await inactive.save()
    p = await resolve({"iss": ISSUER, "sub": "another-sub",
                       "email": "inactive@example.com", "email_verified": True})
    check("a verified-email match on a deactivated user is refused too", p is None)

    #  6. Tenant selection: issuer mismatch and local tenants.
    print("6) only a tenant configured for this issuer answers")
    p = await resolve({"iss": OTHER_ISSUER, "sub": "idp-sub-bound",
                       "email": "bound@example.com", "email_verified": True})
    check("a token from another issuer does not reach this tenant's users",
          p is None)

    p = await resolve({"iss": ISSUER, "sub": "whoever",
                       "email": "shared@example.com", "email_verified": True},
                      tenant_hint="loc")
    check("a local-auth tenant is never resolvable through the external path",
          p is None)

    p = await resolve({"iss": ISSUER, "sub": "idp-sub-bound"}, tenant_hint="ext2")
    check("a tenant hint naming the wrong tenant resolves nobody", p is None)

    p = await resolve({"iss": ISSUER, "sub": "idp-sub-bound"}, tenant_hint="ext")
    check("...while the right hint still resolves", p is not None)

    #  7. A deactivated tenant is out of the population entirely.
    print("7) a deactivated tenant answers for nobody")
    tenant.is_active = False
    await tenant.save()
    p = await resolve({"iss": ISSUER, "sub": "idp-sub-bound"})
    check("an inactive tenant's users are unreachable", p is None)
    tenant.is_active = True
    await tenant.save()

    #  8. A token that is not a JWT at all is refused before any tenant is read.
    print("8) an unreadable token is refused")
    p = await _resolve_external("not-a-jwt", None)
    check("a malformed token resolves nobody", p is None)

    await Tortoise.close_connections()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for f in FAIL:
        print(f"  FAILED: {f}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
