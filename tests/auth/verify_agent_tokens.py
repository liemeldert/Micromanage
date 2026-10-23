"""Agent tokens and codes, require_agent, the rotation rules and the agent tables, on in-memory sqlite.

Run: PYTHONPATH=. python tests/auth/verify_agent_tokens.py
"""

import asyncio
import hashlib
import os
from datetime import timedelta

from cryptography.fernet import Fernet

os.environ["JWT_SECRET"] = "verify-agent-tokens-jwt-secret-long-enough"
os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["MDM_AGENT_ENABLED"] = "1"
for _name in ("AGENT_ENROLLMENT_CODE_TTL_HOURS", "AGENT_TOKEN_ROTATE_DAYS", "AGENT_TOKEN_GRACE_MINUTES",
              "AGENT_TOKEN_OVERLAP_MINUTES"):
    os.environ.pop(_name, None)

from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request
from tortoise import Tortoise

from controller.auth import agent_tokens
from controller.auth.agent_tokens import (
    AGENT_ERRORS,
    TOKEN_REUSE_RULE,
    VIA_CURRENT,
    VIA_PENDING,
    VIA_PREVIOUS,
    authenticate_agent,
    generate_agent_token,
    generate_enrollment_code,
    hash_secret,
    require_agent,
    require_agent_result,
    rotation_token,
)
from controller.auth.dependencies import get_current_principal
from controller.auth.service_tokens import generate_service_token, verify_service_token
from controller.auth.tokens import issue_session_token
from controller.models.tenant import (
    AgentEnrollmentCode,
    AgentEvent,
    AgentTask,
    Alert,
    AuditLog,
    Device,
    DeviceAgent,
    ElevationRequest,
    Tenant,
    User,
)
from controller.utils.timeutil import utcnow
from tests._verify_harness import make_check, run

PASS, FAIL = [], []

check = make_check(FAIL, PASS)

AGENT_TABLES = ("device_agents", "agent_enrollment_codes", "agent_tasks", "agent_elevation_requests", "agent_events")


def _agent_request(token=None, path="/api/v1/agent/heartbeat", ip="203.0.113.5"):
    headers = [(b"user-agent", b"micromanaged/1.0"), (b"accept", b"application/json")]
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode("latin-1")))
    scope = {"type": "http", "method": "POST", "path": path, "headers": headers, "query_string": b"",
             "client": (ip, 0), "server": ("testserver", 80), "scheme": "http"}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


async def _call(dependency, token, path="/api/v1/agent/heartbeat"):
    """(status, detail, principal) from a dependency, with the header parsed the way FastAPI parses it."""
    from fastapi import HTTPException

    request = _agent_request(token, path)
    credentials = await agent_tokens._agent_bearer(request)
    try:
        return 200, None, await dependency(request, credentials)
    except HTTPException as exc:
        return exc.status_code, exc.detail, None


async def _make_agent(tenant, serial, token=None, **fields):
    device = await Device.create(tenant=tenant, serial_number=serial, udid=f"UDID-{serial}", device_model="Mac",
                                 os_version="26.0")
    token = token or generate_agent_token()
    now = utcnow()
    agent = await DeviceAgent.create(tenant=tenant, device=device, token_hash=hash_secret(token),
                                     token_prefix=token[:12], token_issued_at=now, enrolled_at=now,
                                     reported_serial=serial, reported_hardware_uuid=device.udid, agent_version="1.0",
                                     **fields)
    return device, agent, token


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    print("1) format and hashing")
    token = generate_agent_token()
    code = generate_enrollment_code()
    check("an agent token is mm_ag_ and 70 characters", token.startswith("mm_ag_") and len(token) == 70)
    check("an enrollment code is mm_ec_ and 38 characters", code.startswith("mm_ec_") and len(code) == 38)
    check("the hash is sha256 hex of the ASCII value",
          hash_secret(token) == hashlib.sha256(token.encode("ascii")).hexdigest() and len(hash_secret(code)) == 64)
    check("the display prefix is 12 characters", agent_tokens.display_prefix(token) == token[:12])
    check("format checks accept their own kind only",
          agent_tokens.is_agent_token(token) and not agent_tokens.is_agent_token(code)
          and agent_tokens.is_enrollment_code(code) and not agent_tokens.is_enrollment_code(token))
    check("the enrollment code TTL defaults to 24 hours", agent_tokens.enrollment_code_ttl() == timedelta(hours=24))
    check("every AGENT_ERRORS text is ASCII and under 300 bytes",
          all(v.isascii() and len(v.encode()) < 300 for v in AGENT_ERRORS.values()))

    print("2) require_agent refusals")
    tenant = await Tenant.create(id="t1", name="Tenant One")
    other_tenant = await Tenant.create(id="t2", name="Tenant Two")
    inactive = await Tenant.create(id="t3", name="Inactive", is_active=False)
    device, agent, token = await _make_agent(tenant, "C02AGENT1")
    status, _, principal = await _call(require_agent, token)
    check("the current token authenticates", status == 200 and principal.via == VIA_CURRENT
          and principal.device.id == device.id and principal.tenant.id == tenant.id, str(status))
    await agent.refresh_from_db()
    check("the request stamps last_seen_at, last_ip and user_agent",
          agent.last_seen_at is not None and agent.last_ip == "203.0.113.5" and agent.user_agent == "micromanaged/1.0")
    seen = agent.last_seen_at
    await _call(require_agent, token)
    await agent.refresh_from_db()
    check("a second request within a minute does not stamp again", agent.last_seen_at == seen)

    invalid = AGENT_ERRORS["token_invalid"]
    cases = (
        ("missing header", None),
        ("wrong prefix", "mm_xx_" + "0" * 64),
        ("wrong length", "mm_ag_" + "0" * 63),
        ("upper-case hex", "mm_ag_" + "A" * 64),
        ("unknown token", generate_agent_token()),
    )
    for label, value in cases:
        status, detail, _ = await _call(require_agent, value)
        check(f"{label}: 401 token_invalid", status == 401 and detail == invalid, f"{status} {detail}")

    revoked_device, revoked, revoked_token = await _make_agent(tenant, "C02REVOKED", status="revoked")
    status, detail, _ = await _call(require_agent, revoked_token)
    check("revoked row: 401 token_invalid", status == 401 and detail == invalid, f"{status} {detail}")

    _, _, inactive_token = await _make_agent(inactive, "C02INACTIVE")
    status, detail, _ = await _call(require_agent, inactive_token)
    check("inactive tenant: 403 tenant_inactive", status == 403 and detail == AGENT_ERRORS["tenant_inactive"],
          f"{status} {detail}")

    os.environ["MDM_AGENT_ENABLED"] = "0"
    status, detail, _ = await _call(require_agent, token)
    check("flag off: 404 Not Found", status == 404 and detail == "Not Found", f"{status} {detail}")
    status, _, _ = await _call(require_agent_result, None)
    check("flag off: 404 before the credential is read", status == 404)
    os.environ["MDM_AGENT_ENABLED"] = "1"

    print("2b) a device that left MDM or moved tenant keeps no agent credential")
    for state in ("unenrolled", "pending"):
        moved_device, moved, moved_token = await _make_agent(tenant, f"C02{state.upper()}")
        await Device.filter(id=moved_device.id).update(enrollment_state=state)
        status, detail, _ = await _call(require_agent, moved_token)
        check(f"enrollment_state {state} with an active row: 401 token_invalid",
              status == 401 and detail == invalid, f"{status} {detail}")
        status, _, _ = await _call(require_agent_result, moved_token, "/api/v1/agent/tasks/x/result")
        check(f"and on the result route too ({state})", status == 401)
    moved_device, moved, moved_token = await _make_agent(tenant, "C02MOVED")
    await Device.filter(id=moved_device.id).update(tenant_id=other_tenant.id)
    status, detail, _ = await _call(require_agent, moved_token)
    check("device row now in another tenant: 401 token_invalid", status == 401 and detail == invalid,
          f"{status} {detail}")

    print("3) mutual refusal")
    from fastapi import HTTPException

    user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    try:
        await get_current_principal(_agent_request(token),
                                    HTTPAuthorizationCredentials(scheme="Bearer", credentials=token))
        refused = None
    except HTTPException as exc:
        refused = (exc.status_code, exc.detail)
    check("get_current_principal refuses an mm_ag_ token with 401",
          refused == (401, "Agent tokens cannot be used for user session endpoints"), str(refused))
    jwt_token = issue_session_token(user_id=str(user.id), tenant_id=tenant.id, email=user.email, role=user.role)
    status, detail, _ = await _call(require_agent, jwt_token)
    check("require_agent refuses a session JWT with 401", status == 401 and detail == invalid, str(status))
    status, detail, _ = await _call(require_agent, generate_service_token())
    check("require_agent refuses an mm_st_ token with 401", status == 401 and detail == invalid, str(status))
    check("verify_service_token returns None for an mm_ag_ token", await verify_service_token(token) is None)

    print("4) rotation")
    rot_device, rot, old_token = await _make_agent(tenant, "C02ROTATE")
    rot.token_issued_at = utcnow() - timedelta(days=31)
    await rot.save(update_fields=["token_issued_at"])
    status, _, principal = await _call(require_agent, old_token)
    await rot.refresh_from_db()
    check("require_agent never issues a pending token, even when rotation is due",
          status == 200 and rot.pending_token_hash is None and rot.pending_token_enc is None)
    check("rotation is due after AGENT_TOKEN_ROTATE_DAYS", agent_tokens.rotation_due(rot, utcnow()))

    first = await rotation_token(principal, utcnow())
    await rot.refresh_from_db()
    check("the heartbeat helper issues a pending token, stored as hash and sealed",
          agent_tokens.is_agent_token(first) and rot.pending_token_hash == hash_secret(first)
          and rot.pending_token_enc and first not in rot.pending_token_enc)
    _, _, again = await _call(require_agent, old_token)
    second = await rotation_token(again, utcnow())
    concurrent = await asyncio.gather(*(rotation_token(again, utcnow()) for _ in range(2)))
    check("the same pending token is sent again, never reissued", second == first and list(concurrent) == [first] * 2)

    status, _, principal = await _call(require_agent_result, first, "/api/v1/agent/tasks/x/result")
    await rot.refresh_from_db()
    check("first use of the pending token from the result route promotes it",
          status == 200 and principal.via == VIA_PENDING and rot.token_hash == hash_secret(first)
          and rot.previous_token_hash == hash_secret(old_token) and rot.pending_token_hash is None
          and rot.pending_token_enc is None and rot.token_prefix == first[:12])
    check("promotion clears the rotation request and restarts the token age",
          rot.rotation_requested_at is None and not agent_tokens.rotation_due(rot, utcnow()))
    check("promotion writes agent.token.rotate",
          await AuditLog.filter(action="agent.token.rotate", target_id=str(rot_device.id)).count() == 1)
    status, _, principal = await _call(require_agent, first)
    check("the promoted token is then current", status == 200 and principal.via == VIA_CURRENT)

    for path, dependency in (("/api/v1/agent/heartbeat", require_agent),
                             ("/api/v1/agent/jit/requests", require_agent),
                             ("/api/v1/agent/tasks/x/result", require_agent_result)):
        status, _, principal = await _call(dependency, old_token, path)
        check(f"the previous token is accepted inside the overlap window on {path}",
              status == 200 and principal.via == VIA_PREVIOUS, str(status))
    check("and no rotate_token goes back to it", await rotation_token(principal, utcnow()) is None)
    check("and no reuse alert is raised", not await Alert.filter(rule_id=TOKEN_REUSE_RULE).exists())

    rot.previous_promoted_at = utcnow() - timedelta(minutes=30)
    await rot.save(update_fields=["previous_promoted_at"])
    status, _, principal = await _call(require_agent_result, old_token, "/api/v1/agent/tasks/x/result")
    check("after the overlap the result route still accepts it inside the grace window",
          status == 200 and principal.via == VIA_PREVIOUS)
    status, detail, _ = await _call(require_agent, old_token, "/api/v1/agent/heartbeat")
    alert = await Alert.filter(rule_id=TOKEN_REUSE_RULE, device_id=rot_device.id).first()
    check("the heartbeat refuses it with 401", status == 401 and detail == invalid, str(status))
    check("and raises a red agent:token_reuse alert", alert is not None and alert.severity == "red")
    check("and writes agent.token.reuse",
          await AuditLog.filter(action="agent.token.reuse", target_id=str(rot_device.id)).exists())

    rot.previous_token_valid_until = utcnow() - timedelta(minutes=1)
    await rot.save(update_fields=["previous_token_valid_until"])
    for path, dependency in (("/api/v1/agent/heartbeat", require_agent),
                             ("/api/v1/agent/jit/requests", require_agent),
                             ("/api/v1/agent/tasks/x/result", require_agent_result)):
        status, _, _ = await _call(dependency, old_token, path)
        check(f"after the grace window the previous token is refused on {path}", status == 401)
    status, _, _ = await _call(require_agent, first)
    check("the current token is unaffected by the refusals", status == 200)

    print("4b) two requests promoting the same pending token")
    race_device, race, race_old = await _make_agent(tenant, "C02RACE", rotation_requested_at=utcnow())
    _, _, principal = await _call(require_agent, race_old)
    pending = await rotation_token(principal, utcnow())
    results = await asyncio.gather(_call(require_agent, pending), _call(require_agent, pending))
    check("both are accepted", all(r[0] == 200 for r in results), str([r[0] for r in results]))
    check("one rotation is recorded",
          await AuditLog.filter(action="agent.token.rotate", target_id=str(race_device.id)).count() == 1)
    await race.refresh_from_db()
    check("the row holds the promoted token and the old one as previous",
          race.token_hash == hash_secret(pending) and race.previous_token_hash == hash_secret(race_old))

    print("4c) clearing a credential clears the sealed pending token with it")
    clear_device, clear, clear_token = await _make_agent(tenant, "C02CLEAR", rotation_requested_at=utcnow())
    _, _, principal = await _call(require_agent, clear_token)
    pending = await rotation_token(principal, utcnow())
    await clear.refresh_from_db()
    check("a pending token is sealed on the row", pending is not None and clear.pending_token_enc is not None)
    await DeviceAgent.filter(id=clear.id).update(status="revoked", **agent_tokens.cleared_credential())
    await clear.refresh_from_db()
    check("cleared_credential nulls every hash and the sealed pending token",
          clear.token_hash is None and clear.pending_token_hash is None and clear.pending_token_enc is None
          and clear.previous_token_hash is None and clear.pending_token_issued_at is None)
    for label, value in (("current", clear_token), ("pending", pending)):
        status, _, _ = await _call(require_agent, value)
        check(f"the {label} token no longer authenticates", status == 401)
    check("and no rotation token is issued for the cleared row",
          await rotation_token(agent_tokens.AgentPrincipal(clear, clear_device, tenant, VIA_CURRENT), utcnow())
          is None)

    print("5) the agent tables come from controller.models.tenant")
    conn = Tortoise.get_connection("default")
    rows = await conn.execute_query_dict("SELECT name FROM sqlite_master WHERE type = 'table'")
    names = {r["name"] for r in rows}
    for table in AGENT_TABLES:
        check(f"table {table} exists", table in names)
    registered = set(Tortoise.apps["models"])
    check("the five models are registered", {"DeviceAgent", "AgentEnrollmentCode", "AgentTask", "ElevationRequest",
                                             "AgentEvent"} <= registered, str(sorted(registered)))
    check("Tenant.agent_policy is null by default", (await Tenant.get(id="t1")).agent_policy is None)
    check("Device.agent reaches the agent row", (await (await Device.get(id=device.id)).agent).id == agent.id)
    now = utcnow()
    code_row = await AgentEnrollmentCode.create(tenant=tenant, device=device, code_hash=hash_secret(code),
                                                code_prefix=code[:12], created_by="admin@t1",
                                                expires_at=now + agent_tokens.enrollment_code_ttl(),
                                                delivery="download")
    task = await AgentTask.create(tenant=tenant, device=device, type="collect_facts", created_by="admin@t1",
                                  expires_at=now + timedelta(days=7))
    request_row = await ElevationRequest.create(tenant=tenant, device=device, username="alice", requested_minutes=30,
                                                expires_at=now + timedelta(hours=1))
    await AgentEvent.create(tenant=tenant, device=device, event_id="e1", kind="admin.granted", at=now,
                            detail={"grant_id": "g"})
    check("rows take their defaults", code_row.failed_attempts == 0 and task.status == "queued"
          and task.params == {} and request_row.status == "pending")
    from tortoise.exceptions import IntegrityError
    try:
        await AgentEvent.create(tenant=tenant, device=device, event_id="e1", kind="admin.granted", at=now)
        duplicate = False
    except IntegrityError:
        duplicate = True
    check("an event id is stored once per device", duplicate)
    await device.delete()
    check("deleting the device removes its agent rows",
          not await DeviceAgent.filter(id=agent.id).exists() and not await AgentTask.filter(id=task.id).exists())

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    return 1 if FAIL else 0


if __name__ == "__main__":
    run(main)
