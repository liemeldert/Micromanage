"""Tests for service token creation, hashing, expiration, revocation, throttling, and mutual route refusal."""

import hashlib
import os
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from tortoise import Tortoise

os.environ["JWT_SECRET"] = "verify-service-tokens-jwt-secret-long-enough"

import controller.api.routes.integrations as integration_routes
from controller.auth.dependencies import Principal, get_current_principal, require_admin
from controller.auth.service_tokens import (
    TOKEN_PREFIX,
    create_service_token,
    generate_service_token,
    hash_service_token,
    revoke_service_token,
    verify_service_token,
)
from controller.auth.tokens import decode_session_token, issue_session_token
from controller.models.tenant import AuditLog, ServiceToken, Tenant, User
from tests._verify_harness import make_check

PASS, FAIL = [], []

check = make_check(FAIL, PASS)


class FakeRequest:
    headers = {}
    client = None


async def main():
    await Tortoise.init(
        db_url="sqlite://:memory:",
        modules={"models": ["controller.models.tenant"]},
    )
    await Tortoise.generate_schemas()

    tenant = await Tenant.create(id="tenant_a", name="Tenant A")
    tenant_inactive = await Tenant.create(id="tenant_b", name="Tenant B", is_active=False)

    admin_user = await User.create(tenant=tenant, email="admin@tenant_a", role="admin")
    admin_principal = Principal(tenant=tenant, user=admin_user, email="admin@tenant_a", role="admin")

    print("1) Service token format, generation, and hashing")
    raw_token = generate_service_token()
    check("raw token starts with prefix", raw_token.startswith(TOKEN_PREFIX))
    check("raw token has expected length (mm_st_ + 64 hex chars)", len(raw_token) == 70)

    thash = hash_service_token(raw_token)
    check("token hash is 64-char sha256 hex string", len(thash) == 64)
    check("hash matches hashlib sha256", thash == hashlib.sha256(raw_token.encode("ascii")).hexdigest())

    print("2) Service token creation and mandatory expiration")
    now = datetime.now(timezone.utc)
    future_exp = now + timedelta(days=30)
    past_exp = now - timedelta(days=1)

    raised = False
    try:
        await create_service_token(tenant, "test-missing-exp", ["inventory:read"], None)
    except ValueError:
        raised = True
    check("creation without expiration raises ValueError", raised)

    raised = False
    try:
        await create_service_token(tenant, "test-past-exp", ["inventory:read"], past_exp)
    except ValueError:
        raised = True
    check("creation with past expiration raises ValueError", raised)

    st, plaintext = await create_service_token(
        tenant, "ansible-token", ["inventory:read"], future_exp, created_by="admin@tenant_a"
    )
    check("token object created", st is not None)
    check("plaintext token matches raw prefix", plaintext.startswith(TOKEN_PREFIX))
    check("st.token_hash matches hashed plaintext", st.token_hash == hash_service_token(plaintext))
    check("st.scopes is list", st.scopes == ["inventory:read"])
    check("st.revoked_at is None initially", st.revoked_at is None)
    check("st.last_used_at is None initially", st.last_used_at is None)

    audit_created = await AuditLog.get_or_none(
        tenant=tenant, action="service_token.created", target_id=str(st.id)
    )
    check("audit log entry recorded on creation", audit_created is not None)

    print("3) Service token verification and scope enforcement")
    verified = await verify_service_token(plaintext, required_scope="inventory:read")
    check("valid token verifies with matching scope", verified is not None and verified.id == st.id)

    missing_scope = await verify_service_token(plaintext, required_scope="admin:write")
    check("verification fails when required scope is absent", missing_scope is None)

    invalid_token = await verify_service_token(
        "mm_st_0000000000000000000000000000000000000000000000000000000000000000"
    )
    check("non-existent token fails verification", invalid_token is None)
    check("non-ASCII token body is refused without raising", await verify_service_token("mm_st_\u00e9") is None)
    check("wrong-length token body is refused", await verify_service_token("mm_st_abc") is None)

    for bad_scopes, label in ((["*"], "wildcard scope"), (["admin:write"], "unknown scope"), ([], "empty scopes")):
        try:
            await create_service_token(tenant, f"bad-{label}", bad_scopes,
                                       datetime.now(timezone.utc) + timedelta(days=1))
            refused_scope = False
        except ValueError:
            refused_scope = True
        check(f"creation with {label} raises ValueError", refused_scope)

    st_expired, pt_expired = await create_service_token(
        tenant, "expired-token", ["inventory:read"], now + timedelta(seconds=1)
    )
    st_expired.expires_at = now - timedelta(seconds=10)
    await st_expired.save(update_fields=["expires_at"])
    check("expired token fails verification", await verify_service_token(pt_expired) is None)

    st_inactive, pt_inactive = await create_service_token(
        tenant_inactive, "inactive-token", ["inventory:read"], future_exp
    )
    check("token for inactive tenant fails verification", await verify_service_token(pt_inactive) is None)

    print("4) Service token revocation")
    await revoke_service_token(st, revoked_by="admin@tenant_a")
    reloaded_st = await ServiceToken.get(id=st.id)
    check("revoked token has revoked_at set", reloaded_st.revoked_at is not None)
    check("revoked token fails verification", await verify_service_token(plaintext) is None)

    audit_revoked = await AuditLog.get_or_none(
        tenant=tenant, action="service_token.revoked", target_id=str(st.id)
    )
    check("audit log entry recorded on revocation", audit_revoked is not None)

    print("5) Daily audit throttling on service token usage")
    st_audit, pt_audit = await create_service_token(
        tenant, "audit-test-token", ["inventory:read"], future_exp
    )
    await AuditLog.filter(target_id=str(st_audit.id), action="service_token.used").delete()

    await verify_service_token(pt_audit, required_scope="inventory:read")
    used_logs = await AuditLog.filter(target_id=str(st_audit.id), action="service_token.used").all()
    check("first use creates service_token.used audit log", len(used_logs) == 1)

    await verify_service_token(pt_audit, required_scope="inventory:read")
    used_logs_2 = await AuditLog.filter(target_id=str(st_audit.id), action="service_token.used").all()
    check("immediate second use is throttled (no duplicate audit log)", len(used_logs_2) == 1)

    st_audit = await ServiceToken.get(id=st_audit.id)
    st_audit.last_used_at = now - timedelta(hours=25)
    await st_audit.save(update_fields=["last_used_at"])

    await verify_service_token(pt_audit, required_scope="inventory:read")
    used_logs_3 = await AuditLog.filter(target_id=str(st_audit.id), action="service_token.used").all()
    check("use after 24 hours creates new audit log entry", len(used_logs_3) == 2)

    print("6) Mutual route refusal")
    service_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=pt_audit)
    fake_req = FakeRequest()

    refused = False
    try:
        await get_current_principal(fake_req, service_creds)
    except HTTPException as exc:
        refused = (exc.status_code == 401)
    check("get_current_principal rejects service token with 401", refused)

    refused_admin = False
    try:
        await require_admin(await get_current_principal(fake_req, service_creds))
    except HTTPException as exc:
        refused_admin = (exc.status_code == 401)
    check("require_admin rejects service token with 401", refused_admin)

    check("decode_session_token returns None for service token", decode_session_token(pt_audit) is None)

    user_jwt = issue_session_token(
        user_id=str(admin_user.id),
        tenant_id=tenant.id,
        email=admin_user.email,
        role=admin_user.role,
    )
    user_creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=user_jwt)

    inventory_refused = False
    try:
        await integration_routes.require_inventory_service_token(user_creds)
    except HTTPException as exc:
        inventory_refused = (exc.status_code == 401)
    check("require_inventory_service_token rejects user JWT with 401", inventory_refused)

    token_result = await integration_routes.require_inventory_service_token(service_creds)
    check("require_inventory_service_token accepts valid service token", token_result.id == st_audit.id)

    print("7) Admin management endpoints for service tokens")
    create_req = integration_routes.CreateServiceTokenRequest(
        name="cli-inventory",
        scopes=["inventory:read"],
        expires_in_days=14,
    )
    created_res = await integration_routes.create_new_service_token(create_req, admin=admin_principal)
    check("create endpoint returns plaintext token", created_res.get("token", "").startswith(TOKEN_PREFIX))
    check("create endpoint returns token metadata", created_res.get("name") == "cli-inventory")
    cli_token_id = created_res["id"]

    tokens_list = await integration_routes.list_service_tokens(admin=admin_principal)
    check("list endpoint returns tokens list", isinstance(tokens_list, list))
    check("list endpoint includes created token", any(t["id"] == cli_token_id for t in tokens_list))
    check("list endpoint never leaks plaintext token", all("token" not in t for t in tokens_list))

    revoke_res = await integration_routes.revoke_existing_service_token(cli_token_id, admin=admin_principal)
    check("revoke endpoint returns revoked status", revoke_res.get("status") == "revoked")
    revoked_row = await ServiceToken.get(id=cli_token_id)
    check("revoked token has revoked_at stamped", revoked_row.revoked_at is not None)

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        return 1
    return 0


from tests._verify_harness import run  # noqa: E402

run(main)
