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

    try:
        # Get webhook payload
        payload = await request.json()

        # Log webhook for debugging
        logger.info(f"Received MDM webhook: {payload.get('message_type', 'unknown')}")

        # Process webhook
        handler = WebhookHandler()
        await handler.handle_webhook(payload)

        return {"status": "success"}

    except HTTPException:
        raise
    except Exception as e:
        # Log the detail server-side; do not leak internals to the caller.
        logger.error(f"Error processing webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal error processing webhook")


# The webhook runs as its own process (supervisord) and needs its own DB
# connection — it does not share the controller/API process's Tortoise init.
register_tortoise(
    app,
    db_url=DATABASE_URL,
    modules={"models": ["controller.models.tenant"]},
    generate_schemas=True,
    add_exception_handlers=True,
)
