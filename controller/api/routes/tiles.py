"""A same-origin proxy for OpenStreetMap raster tiles, so the device-location map works under the app's strict CSP
(img-src 'self' blob:) and without a third-party CDN."""
from collections import OrderedDict
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Response

from controller.auth.dependencies import Principal, get_current_principal

logger = logging.getLogger(__name__)

router = APIRouter()

_TILE_CACHE: "OrderedDict[str, bytes]" = OrderedDict()
_TILE_CACHE_MAX = 4096
_tile_client: Optional[Any] = None


def _get_tile_client():
    global _tile_client
    if _tile_client is None:
        import httpx
        _tile_client = httpx.AsyncClient(
            timeout=10.0,
            # OSM's tile usage policy requires an identifying User-Agent.
            headers={"User-Agent": "Micromanage/1.0 (self-hosted MDM; device location map)"},
        )
    return _tile_client


@router.get("/api/v1/map/tile/{z}/{x}/{y}")
async def map_tile(z: int, x: int, y: int, principal: Principal = Depends(get_current_principal)):
    """Proxy a single OSM raster tile (cached). Coordinates are strictly bounded to the standard slippy-map range, so
    this can only ever fetch public tiles."""
    if not (0 <= z <= 19):
        raise HTTPException(status_code=404, detail="bad zoom")
    n = 1 << z
    if not (0 <= x < n and 0 <= y < n):
        raise HTTPException(status_code=404, detail="tile out of range")

    key = f"{z}/{x}/{y}"
    data = _TILE_CACHE.get(key)
    if data is None:
        try:
            resp = await _get_tile_client().get(f"https://tile.openstreetmap.org/{z}/{x}/{y}.png")
            resp.raise_for_status()
            data = resp.content
        except Exception as exc:
            logger.warning(f"tile fetch failed for {key}: {exc}")
            raise HTTPException(status_code=502, detail="tile fetch failed")
        _TILE_CACHE[key] = data
        _TILE_CACHE.move_to_end(key)
        while len(_TILE_CACHE) > _TILE_CACHE_MAX:
            _TILE_CACHE.popitem(last=False)

    return Response(content=data, media_type="image/png",
                    headers={"Cache-Control": "private, max-age=86400"})


async def _close_tile_client():
    """Close the tile proxy's httpx client on the way down.

    Built lazily and lives at module scope, so its sockets would otherwise leak across uvicorn reloads.
    """
    global _tile_client
    client, _tile_client = _tile_client, None
    if client is not None:
        try:
            await client.aclose()
        except Exception:
            logger.warning("tile client close failed", exc_info=True)
