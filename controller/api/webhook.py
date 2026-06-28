# In the future, maybe we should migrate this to a seperaate microservice

from fastapi import FastAPI, Request, HTTPException
from controller.services.webhook_handler import WebhookHandler
import logging

app = FastAPI()
logger = logging.getLogger(__name__)

@app.post("/webhook/mdm")
async def mdm_webhook(request: Request):
    """Handle MDM webhook from NanoMDM"""
    try:
        # Get webhook payload
        payload = await request.json()
        
        # Log webhook for debugging
        logger.info(f"Received MDM webhook: {payload.get('message_type', 'unknown')}")
        
        # Process webhook
        handler = WebhookHandler()
        await handler.handle_webhook(payload)
        
        return {"status": "success"}
        
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        raise HTTPException(status_code=500, detail=str(e))
