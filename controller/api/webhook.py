# In the future, maybe we should migrate this to a separate microservice

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
from typing import Optional

from controller.models.database import _pooled_url, DATABASE_URL, enforce_database_url
from controller.services import readiness
from controller.services.webhook_handler import WebhookHandler
from controller.utils import compare
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from tortoise.contrib.fastapi import register_tortoise

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
# Needed so INFO lines on this path are not dropped by python's WARNING-only fallback; safe because uvicorn's
# own loggers propagate=False and never touch the root.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Registered before the router include and register_tortoise below, so a deployment that cannot read its own
# secrets refuses at boot rather than answering 200 while it decrypts nothing. Uses os._exit rather than raising,
# so supervisord sees a clean CRITICAL line instead of a repeated traceback.
@app.on_event("startup")
async def _readiness_boot_check():
    try:
        readiness.enforce_boot()
        enforce_database_url()
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        logging.shutdown()
        os._exit(code)


# Declarative Device Management check-in endpoints (NanoMDM's -dm proxy target). Lives on this app so both NanoMDM
# callbacks share the same internal port.
from controller.api.ddm import router as ddm_router  # noqa: E402

app.include_router(ddm_router)

# NanoMDM calls are authenticated by the body HMAC in X-Hmac-Signature. The key is read per call, never snapshotted, so
# an environment change is picked up immediately.
#   https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/service.go
#   https://github.com/micromdm/nanomdm/blob/v0.9.0/http/hashbody/hashbody.go
#   https://github.com/micromdm/nanomdm/blob/v0.9.0/cmd/nanomdm/main.go

# NanoMDM's header name for the body HMAC.
HMAC_HEADER = "X-Hmac-Signature"


def _hmac_key() -> str:
    """Key for the body HMAC. Falls back to WEBHOOK_SECRET, which is the same fallback docker-compose.prod.yml passes to
    -webhook-hmac-key, so an installation that sets neither still has both sides agreeing."""
    return os.getenv("WEBHOOK_HMAC_KEY") or os.getenv("WEBHOOK_SECRET") or ""


def constant_time_eq(provided: str, expected: str) -> bool:
    """Constant-time compare that reads a missing expected value as empty."""
    return compare.constant_time_eq(provided, expected or "")


def verify_body_hmac(body: bytes, signature: str) -> bool:
    """Verify NanoMDM's X-Hmac-Signature over the raw request body. Fails closed when no key is configured."""
    key = _hmac_key()
    if not key:
        return False
    expected = base64.b64encode(
        hmac.new(key.encode(), body or b"", hashlib.sha256).digest()
    ).decode()
    return constant_time_eq(signature, expected)


# Logged once per mode, so a running deployment shows the scheme its NanoMDM uses without a line per check-in.
_MODES_SEEN: set = set()


def _authorized(request: Request, body: bytes) -> Optional[str]:
    """Return "body-hmac" when the body HMAC verifies, or None."""
    signature = request.headers.get(HMAC_HEADER, "")
    if signature and verify_body_hmac(body, signature):
        return "body-hmac"

    if not _hmac_key():
        # No HMAC key is set, so every call is refused.
        logger.error(
            "neither WEBHOOK_HMAC_KEY nor WEBHOOK_SECRET is configured; rejecting webhook call"
        )
    elif signature:
        logger.debug("webhook: X-Hmac-Signature present but did not verify")
    return None


def log_auth_modes() -> None:
    """One line at boot saying whether a call can be accepted, and with which key."""
    if _hmac_key():
        logger.info(
            "webhook auth accepts: body HMAC (%s)",
            "WEBHOOK_HMAC_KEY" if os.getenv("WEBHOOK_HMAC_KEY") else "WEBHOOK_SECRET",
        )
    else:
        logger.error(
            "webhook auth has no key configured; every NanoMDM call will be refused. Set WEBHOOK_SECRET (and "
            "WEBHOOK_HMAC_KEY if you want the two domains separated)."
        )


log_auth_modes()


@app.post("/webhook/mdm")
async def mdm_webhook(request: Request):
    """NanoMDM's webhook target: authenticate the call, then hand the payload to WebhookHandler. Answers 200 for
    anything it accepted, including a payload it could not process, so NanoMDM does not retry."""
    # Read once: the body HMAC is over these exact bytes, and re-reading a consumed request body gets nothing.
    body = await request.body()
    mode = _authorized(request, body)
    if mode is None:
        raise HTTPException(status_code=403, detail="Forbidden")
    if mode not in _MODES_SEEN:
        _MODES_SEEN.add(mode)
        logger.info("webhook: first call accepted by %s", mode)
    else:
        logger.debug("webhook: accepted by %s", mode)

    try:
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("webhook body is not a JSON object")
    except ValueError:
        # Authenticated but unparseable. Answered 200 like any other handling failure below, since a 5xx would only make
        # NanoMDM retry it.
        logger.warning("webhook: body is not a JSON object (%d bytes); ignored", len(body))
        return {"status": "error", "detail": "logged"}
    logger.info(f"Received MDM webhook: topic={payload.get('topic', 'unknown')}")
    try:
        await WebhookHandler().handle_webhook(payload)
        return {"status": "success"}
    except Exception:
        # Best-effort: a 5xx back to NanoMDM would only spam its logs, and the device's MDM flow does not depend on this
        # event being recorded. Keep the full traceback here instead.
        logger.exception(f"Error processing webhook (topic={payload.get('topic')})")
        return {"status": "error", "detail": "logged"}


# step-ca's SCEPCHALLENGE webhook. Its secret and id are files written by the step-ca init job, read per call.
#   https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/webhook.go
SCEP_SIGNATURE_HEADER = "X-Smallstep-Signature"
SCEP_WEBHOOK_ID_HEADER = "X-Smallstep-Webhook-ID"


def _scep_request_verified(headers, body: bytes) -> bool:
    """Whether the signature and webhook id on a step-ca call match the configured secret and id."""
    key = readiness.scep_webhook_key()
    if key is None:
        logger.error("scep webhook: no usable secret in SCEP_WEBHOOK_SECRET_FILE; refusing every challenge")
        return False
    expected = hmac.new(key, body or b"", hashlib.sha256).hexdigest()
    if not constant_time_eq(headers.get(SCEP_SIGNATURE_HEADER, "").strip().lower(), expected):
        logger.warning("scep webhook: signature did not verify")
        return False
    webhook_id = readiness.scep_webhook_id()
    if not webhook_id or not constant_time_eq(headers.get(SCEP_WEBHOOK_ID_HEADER, "").strip(), webhook_id):
        logger.warning("scep webhook: webhook id does not match SCEP_WEBHOOK_ID_FILE")
        return False
    return True


def _scep_fields(body: bytes):
    """The validate_and_consume keyword arguments from a step-ca body, or None."""
    payload = json.loads(body)
    if not isinstance(payload, dict):
        return None
    csr = payload.get("x509CertificateRequest")
    if not isinstance(csr, dict):
        return None
    subject = csr.get("subject") if isinstance(csr.get("subject"), dict) else {}
    raw = csr.get("raw")
    values = (payload.get("scepChallenge"), payload.get("scepTransactionID"), payload.get("provisionerName"),
              subject.get("commonName", ""), raw)
    if not all(isinstance(v, str) for v in values):
        return None
    challenge, transaction_id, provisioner, common_name, raw = values
    return {"challenge_plaintext": challenge, "provisioner_name": provisioner, "transaction_id": transaction_id,
            "csr_cn": common_name, "csr_der": base64.b64decode(raw, validate=True)}


@app.post("/webhook/scep-challenge")
async def scep_challenge_webhook(request: Request):
    """step-ca's SCEPCHALLENGE webhook. Returns HTTP 200 in every case, with allow true only when the challenge is
    consumed."""
    allowed = False
    try:
        body = await request.body()
        if _scep_request_verified(request.headers, body):
            fields = None
            try:
                fields = _scep_fields(body)
            except ValueError:
                pass
            if fields is None:
                logger.warning("scep webhook: malformed body (%d bytes); refused", len(body))
            else:
                from controller.services import enrollment_links
                allowed, _reason, _row = await enrollment_links.validate_and_consume(**fields)
    except Exception:
        logger.exception("scep webhook: deciding a challenge failed; refused")
        allowed = False
    return JSONResponse({"allow": bool(allowed)}, status_code=200)


@app.get("/health")
async def health_check():
    """Up, and able to reach the database. Used by the container healthcheck."""
    from tortoise import Tortoise
    try:
        await Tortoise.get_connection("default").execute_query("SELECT 1")
    except Exception:
        logger.exception("health: database check failed")
        raise HTTPException(status_code=503, detail="database unreachable")
    return {"status": "healthy"}


# How long a clean shutdown waits for deferred fan-out to finish before letting the process die with the remainder
# undone.
_SHUTDOWN_DRAIN_SECONDS = float(os.getenv("MDM_WEBHOOK_SHUTDOWN_DRAIN_SECONDS", "10"))


# Registered before register_tortoise below, so the DB connections it needs are still open when this drains
# (register_tortoise's shutdown hook closes them).
@app.on_event("shutdown")
async def _drain_deferred_fanout():
    """Give queued dispatcher and ATC fan-out a bounded window to finish.

    Past the window the remainder is dropped; the dispatcher re-derives state at the next inventory or sweep.
    """
    from controller.services.webhook_handler import drain_deferred
    try:
        await asyncio.wait_for(drain_deferred(), timeout=_SHUTDOWN_DRAIN_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(
            "shutdown: deferred webhook fan-out still pending after %.0fs; "
            "dropping the remainder", _SHUTDOWN_DRAIN_SECONDS,
        )
    except Exception:
        logger.exception("shutdown: draining deferred webhook fan-out failed")


# Own supervisord process, so it needs its own Tortoise init. Uses _pooled_url, not the raw DSN, so this
# process gets DB_POOL_MAX_SIZE instead of asyncpg's default of five connections.
register_tortoise(
    app,
    db_url=_pooled_url(DATABASE_URL),
    modules={"models": ["controller.models.tenant"]},
    generate_schemas=False,
    add_exception_handlers=True,
)


# generate_schemas stays False; models.database.init_schema creates the schema under an advisory lock, since all
# three supervisord processes race on a fresh database otherwise. Runs after register_tortoise so the connection exists.
@app.on_event("startup")
async def _init_schema():
    from controller.models.database import init_schema
    await init_schema()
