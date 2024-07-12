# webhook_server.py
from fastapi import FastAPI, Request
import os
from redis import Redis
import json

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", 6379)
REDIS_DB = os.getenv("REDIS_DB", 0)

app = FastAPI()
redis_client = Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

@app.post("/webhook")
async def webhook(request: Request):
    data = await request.json()
    device_id = data.get("uuid")
    if device_id:
        redis_client.set(device_id, json.dumps(data))
    return {"status": "success"}

@app.get("/device/{device_id}")
async def get_device(device_id: str):
    device_data = redis_client.get(device_id)
    if device_data:
        return json.loads(device_data)
    return {"status": "device not found"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
