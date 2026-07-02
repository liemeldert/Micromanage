# In the future, maybe we should migrate this to a seperaate microservice

import hmac
import logging
import os

from fastapi import FastAPI, Request, HTTPException
from tortoise.contrib.fastapi import register_tortoise

from controller.models.database import DATABASE_URL
from controller.services.webhook_handler import WebhookHandler

app = FastAPI()
logger = logging.getLogger(__name__)

# Shared secret between NanoMDM and the controller. NanoMDM is configured with
# the webhook URL carrying this secret (?secret=...); the controller rejects any
# call that does not present it. Without it the endpoint is forgeable by anyone
# who can reach the controller's internal port.
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")


def _authorized(request: Request) -> bool:
    if not WEBHOOK_SECRET:
        # Fail closed: an unset secret means the webhook cannot be trusted.
        logger.error("WEBHOOK_SECRET is not configured; rejecting webhook call")
        return False
    provided = request.query_params.get("secret") or request.headers.get("X-Webhook-Secret", "")
    return hmac.compare_digest(provided, WEBHOOK_SECRET)


@app.post("/webhook/mdm")
async def mdm_webhook(request: Request):
    """Handle MDM webhook from NanoMDM"""
    if not _authorized(request):
        raise HTTPException(status_code=403, detail="Forbidden")

    payload = await request.json()
    logger.info(f"Received MDM webhook: topic={payload.get('topic', 'unknown')}")
    try:
        await WebhookHandler().handle_webhook(payload)
        return {"status": "success"}
    except Exception:
        # Webhook delivery is best-effort: never return 5xx to NanoMDM — that would
        # just spam its logs and the device's MDM flow must not depend on the
        # controller recording the event. Log the full traceback for diagnosis.
        logger.exception(f"Error processing webhook (topic={payload.get('topic')})")
        return {"status": "error", "detail": "logged"}


# The webhook runs as its own process (supervisord) and needs its own DB
# connection — it does not share the controller/API process's Tortoise init.
register_tortoise(
    app,
    db_url=DATABASE_URL,
    modules={"models": ["controller.models.tenant"]},
    generate_schemas=True,
    add_exception_handlers=True,
)
