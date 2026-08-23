"""The only module that speaks Apple's DEP protocol.

Talks to https://mdmenrollment.apple.com for DEP enrollment (OAuth 1.0a, device/profile endpoints, token refresh).
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse
import uuid
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://mdmenrollment.apple.com"
DEFAULT_USER_AGENT = "micromanage-mdm/1.0"
# Apple production clients send "7"; higher versions are supersets. Override via DEP_SERVER_PROTOCOL_VERSION.
SERVER_PROTOCOL_VERSION = os.getenv("DEP_SERVER_PROTOCOL_VERSION", "7")

# Apple's stated limit for POST /profile/devices, applied to all bulk device endpoints.
MAX_DEVICES_PER_REQUEST = 1000

# A transport takes (method, url, headers, body_bytes) and returns (status_code, response_headers, response_body_bytes).
# Injected in tests; the default uses httpx. Header keys are looked up case-insensitively.
Transport = Callable[
    [str, str, Dict[str, str], Optional[bytes]],
    Awaitable[Tuple[int, Dict[str, str], bytes]],
]


class DepError(Exception):
    """A DEP API call failed. code is Apple's error code (or an HTTP-derived stand-in), status the HTTP status, message
    the failure text."""

    def __init__(self, code: str, message: str = "", status: Optional[int] = None):
        self.code = code
        self.status = status
        super().__init__(f"{code}: {message}" if message else code)


class DepAuthError(DepError):
    """Authentication/session failure that a retry could not resolve."""


def _percent(value: str) -> str:
    """RFC 3986 / RFC 5849 percent-encoding (unreserved chars left as-is)."""
    return urllib.parse.quote(str(value), safe="-._~")


def _oauth_authorization_header(
    token: Dict[str, Any], method: str, url: str
) -> str:
    """Build OAuth 1.0a HMAC-SHA1 Authorization header for GET /session. url is the request URL without query."""
    oauth_params = {
        "oauth_consumer_key": token["consumer_key"],
        "oauth_token": token["access_token"],
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_nonce": uuid.uuid4().hex,
        "oauth_version": "1.0",
    }
    # Signature base string: METHOD & enc(url) & enc(sorted &-joined params)
    param_str = "&".join(
        f"{_percent(k)}={_percent(v)}"
        for k, v in sorted(oauth_params.items())
    )
    base_string = "&".join([method.upper(), _percent(url), _percent(param_str)])
    signing_key = f"{_percent(token['consumer_secret'])}&{_percent(token['access_secret'])}"
    digest = hmac.new(signing_key.encode(), base_string.encode(), hashlib.sha1).digest()
    signature = base64.b64encode(digest).decode()

    header_params = dict(oauth_params)
    header_params["oauth_signature"] = signature
    parts = ['realm="ADM"'] + [
        f'{_percent(k)}="{_percent(v)}"' for k, v in sorted(header_params.items())
    ]
    return "OAuth " + ", ".join(parts)


def _as_int(value: Any) -> Optional[int]:
    """An int from whatever Apple put in a numeric field, or None. Apple sends retry_after_seconds as a number, but a
    string would still be usable."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _hget(headers: Dict[str, str], name: str) -> Optional[str]:
    lname = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == lname:
            return v
    return None


async def _httpx_transport(
    method: str, url: str, headers: Dict[str, str], body: Optional[bytes]
) -> Tuple[int, Dict[str, str], bytes]:
    import httpx

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.request(method, url, headers=headers, content=body)
        return resp.status_code, dict(resp.headers), resp.content


class DepClient:
    def __init__(
        self,
        token: Dict[str, Any],
        *,
        base_url: str = DEFAULT_BASE_URL,
        user_agent: str = DEFAULT_USER_AGENT,
        transport: Optional[Transport] = None,
    ):
        self._token = token
        self._base = base_url.rstrip("/")
        self._ua = user_agent
        self._transport = transport or _httpx_transport
        self._session_token: Optional[str] = None

    #  auth
    async def _authenticate(self) -> None:
        url = f"{self._base}/session"
        headers = {
            "Authorization": _oauth_authorization_header(self._token, "GET", url),
            "User-Agent": self._ua,
            "X-Server-Protocol-Version": SERVER_PROTOCOL_VERSION,
            "Content-Type": "application/json;charset=UTF8",
        }
        status, resp_headers, body = await self._transport("GET", url, headers, None)
        if status != 200:
            raise DepAuthError(
                self._error_code(status, body),
                "DEP session authentication failed",
                status,
            )
        try:
            data = json.loads(body.decode("utf-8"))
            self._session_token = data["auth_session_token"]
        except Exception:
            raise DepAuthError("BAD_SESSION_RESPONSE", "No auth_session_token", status)

    #  request core
    async def _request(
        self, method: str, path: str, body: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        if self._session_token is None:
            await self._authenticate()
        # One transparent retry on an auth failure.
        for attempt in (1, 2):
            url = f"{self._base}{path}"
            payload = json.dumps(body).encode() if body is not None else None
            headers = {
                "X-ADM-Auth-Session": self._session_token or "",
                "User-Agent": self._ua,
                "X-Server-Protocol-Version": SERVER_PROTOCOL_VERSION,
                "Content-Type": "application/json;charset=UTF8",
            }
            status, resp_headers, raw = await self._transport(method, url, headers, payload)

            # Adopt a rolling session token if Apple issued a fresh one.
            refreshed = _hget(resp_headers, "X-ADM-Auth-Session")
            if refreshed:
                self._session_token = refreshed

            text = raw.decode("utf-8", errors="replace") if raw else ""
            # Case-sensitive on purpose: a looser match would re-auth on any 403 page that carries the word in prose.
            if status == 401 or (status == 403 and "FORBIDDEN" in text):
                if attempt == 1:
                    self._session_token = None
                    await self._authenticate()
                    continue
                raise DepAuthError(self._error_code(status, raw), text[:200], status)
            if status >= 400:
                raise DepError(self._error_code(status, raw), text[:200], status)
            if not text:
                return {}
            try:
                return json.loads(text)
            except Exception:
                raise DepError("BAD_RESPONSE", "Non-JSON response body", status)
        raise DepAuthError("AUTH_RETRY_EXHAUSTED", "", None)  # unreachable

    @staticmethod
    def _error_code(status: int, body: bytes) -> str:
        """Best-effort extraction of Apple's error code from a failure body."""
        try:
            text = (body or b"").decode("utf-8", errors="replace").strip()
        except Exception:
            text = ""
        if not text:
            return f"HTTP_{status}"
        # Apple returns short codes like EXPIRED_CURSOR or T_C_NOT_SIGNED as bare text or inside a JSON envelope;
        # surface the first token that looks like one.
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                for key in ("code", "error", "errorCode", "message"):
                    if data.get(key):
                        return str(data[key])
        except Exception:
            pass
        token = text.split()[0].strip('".,{}')
        return token[:60] or f"HTTP_{status}"

    #  endpoints
    async def account(self) -> Dict[str, Any]:
        return await self._request("GET", "/account")

    async def fetch_devices(
        self, limit: int = 100, cursor: Optional[str] = None
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"limit": limit}
        if cursor:
            body["cursor"] = cursor
        return await self._request("POST", "/server/devices", body)

    async def sync_devices(self, cursor: str, limit: int = 100) -> Dict[str, Any]:
        return await self._request(
            "POST", "/devices/sync", {"cursor": cursor, "limit": limit}
        )

    async def device_details(self, serials: List[str]) -> Dict[str, Any]:
        return await self._batched(
            "POST", "/devices", serials, lambda batch: {"devices": batch})

    async def define_profile(self, profile: Dict[str, Any]) -> Dict[str, Any]:
        return await self._request("POST", "/profile", profile)

    # Deliberate DEP API surface: no caller today.
    async def get_profile(self, profile_uuid: str) -> Dict[str, Any]:
        return await self._request("GET", f"/profile?profile_uuid={_percent(profile_uuid)}")

    async def assign_profile(
        self, profile_uuid: str, serials: List[str]
    ) -> Dict[str, Any]:
        return await self._batched(
            "POST", "/profile/devices", serials,
            lambda batch: {"profile_uuid": profile_uuid, "devices": batch},
        )

    async def clear_profile(self, serials: List[str]) -> Dict[str, Any]:
        return await self._batched(
            "DELETE", "/profile/devices", serials, lambda batch: {"devices": batch})

    async def disown(self, serials: List[str]) -> Dict[str, Any]:
        return await self._batched(
            "POST", "/devices/disown", serials, lambda batch: {"devices": batch})

    #  batching
    async def _batched(
        self, method: str, path: str, serials: List[str],
        make_body: Callable[[List[str]], Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Split a serial list on MAX_DEVICES_PER_REQUEST and merge the responses. A failing batch raises after earlier batches are already applied at Apple."""
        if not serials:
            return {}
        merged: Dict[str, Any] = {}
        devices: Dict[str, Any] = {}
        for start in range(0, len(serials), MAX_DEVICES_PER_REQUEST):
            batch = serials[start:start + MAX_DEVICES_PER_REQUEST]
            resp = await self._request(method, path, make_body(batch))
            if not isinstance(resp, dict):
                continue
            page = resp.get("devices")
            if isinstance(page, dict):
                devices.update(page)
            for key, value in resp.items():
                if key in ("devices", "retry_after_seconds"):
                    continue
                merged.setdefault(key, value)
            retry_after = _as_int(resp.get("retry_after_seconds"))
            if retry_after is not None:
                merged["retry_after_seconds"] = max(
                    retry_after, _as_int(merged.get("retry_after_seconds")) or 0)
        merged["devices"] = devices
        return merged
