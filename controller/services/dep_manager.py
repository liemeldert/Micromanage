"""DEP orchestration: link ABM/ASM, sync devices, define/assign enrollment profiles.

Tenant-scoped and defensive. This is the layer the API + scheduler call; it owns
the DepServer lifecycle and translates between the local config/model world and the
Apple protocol (services.dep_client). It never speaks OAuth/HTTP itself and never
returns or logs secret material.

Device sync reuses the existing serial-placeholder invariant: a DEP-assigned device
becomes a ``pending`` Device row keyed by serial, adopted by the webhook when the
physical device enrolls (docs/specs/dep-ade-spec.md §3.4).
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from controller.models.tenant import DepProfile, DepServer, Device, Tenant
from controller.services import crypto_secrets, dep_pki, tenant_config
from controller.services.dep_client import DepClient, DepError, Transport
from controller.services.skip_keys import filter_valid_skip_keys

logger = logging.getLogger(__name__)

# How many devices to request per DEP fetch/sync page.
_SYNC_PAGE = 100


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── client construction ───────────────────────────────────────────────────────

def build_client(dep_server: DepServer, transport: Optional[Transport] = None) -> Optional[DepClient]:
    """Decrypt the stored token and construct a DepClient, or None if unavailable.

    ``transport`` is injected only in tests; production uses the httpx default."""
    token_json = crypto_secrets.decrypt(dep_server.token_enc)
    if not token_json:
        return None
    try:
        token = json.loads(token_json)
    except Exception:
        logger.error("DEP: stored token for server %s is not valid JSON", dep_server.id)
        return None
    from controller.services.dep_client import DEFAULT_BASE_URL
    import os
    base = os.getenv("DEP_BASE_URL", DEFAULT_BASE_URL)
    ua = os.getenv("DEP_USER_AGENT", "micromanage-mdm/1.0")
    return DepClient(token, base_url=base, user_agent=ua, transport=transport)


# ── link lifecycle ────────────────────────────────────────────────────────────

async def begin_link(tenant: Tenant, name: str) -> DepServer:
    """Create (or reset) a DepServer and generate its PKI keypair. Returns the row
    with ``public_cert_pem`` populated (the cert the admin uploads to ABM)."""
    private_pem, cert_pem, cert_expires = dep_pki.generate_keypair(
        common_name=f"micromanage-dep-{name}"
    )
    # Encrypt the private key at rest (it can decrypt a re-downloaded token).
    private_enc = crypto_secrets.encrypt(private_pem)

    server = await DepServer.get_or_none(tenant=tenant, name=name)
    if server is None:
        server = DepServer(tenant=tenant, name=name)
    server.private_key_enc = private_enc
    server.public_cert_pem = cert_pem
    server.cert_expires_at = cert_expires
    # Regenerating the keypair invalidates any previously-issued token.
    server.token_enc = None
    server.token_expires_at = None
    server.status = "awaiting_token"
    server.last_error = None
    await server.save()
    return server


async def complete_link(dep_server: DepServer, p7m: bytes) -> DepServer:
    """Decrypt the uploaded ``.p7m`` server token, verify it against Apple via
    /account, and store it encrypted. Raises on failure (with ``status='error'``
    persisted and a non-secret message)."""
    private_pem = crypto_secrets.decrypt(dep_server.private_key_enc)
    if not private_pem or not dep_server.public_cert_pem:
        raise DepError("NO_KEYPAIR", "Generate a keypair before uploading a token")
    try:
        token = dep_pki.decrypt_server_token(p7m, private_pem, dep_server.public_cert_pem)
    except Exception as exc:
        await _mark_error(dep_server, f"Token decryption failed: {exc}")
        raise DepError("TOKEN_DECRYPT_FAILED", str(exc))

    # Verify the token actually authenticates, and capture org detail.
    import os
    from controller.services.dep_client import DEFAULT_BASE_URL
    client = DepClient(
        token,
        base_url=os.getenv("DEP_BASE_URL", DEFAULT_BASE_URL),
        user_agent=os.getenv("DEP_USER_AGENT", "micromanage-mdm/1.0"),
        transport=_default_transport_override(),
    )
    try:
        account = await client.account()
    except DepError as exc:
        await _mark_error(dep_server, f"Apple rejected the token ({exc.code})")
        raise

    dep_server.token_enc = crypto_secrets.encrypt(json.dumps(token))
    dep_server.token_expires_at = dep_pki.token_expiry(token)
    dep_server.account_detail = _safe_account(account)
    dep_server.status = "linked"
    dep_server.last_error = None
    await dep_server.save()
    logger.info("DEP: linked server %s (org=%s)", dep_server.name,
                dep_server.account_detail.get("org_name"))
    return dep_server


def _default_transport_override() -> Optional[Transport]:
    """Hook so tests can force a transport into complete_link without threading it
    through the API. Returns None in production (httpx default)."""
    return _TEST_TRANSPORT


# Test seam: verify_dep.py sets this to a FakeDepTransport; None in production.
_TEST_TRANSPORT: Optional[Transport] = None


def _safe_account(account: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only the non-secret account fields we display."""
    keep = ("server_name", "server_uuid", "org_name", "org_email", "org_phone",
            "org_id", "org_id_hash", "org_type", "org_version", "admin_id",
            "facilitator_id")
    return {k: account.get(k) for k in keep if account.get(k) is not None}


async def _mark_error(dep_server: DepServer, message: str) -> None:
    # Log the specific reason (decrypt/algorithm/key-mismatch, Apple rejection) — the
    # API only returns a generic code to the client, so this is where operators see it.
    logger.warning("DEP: link failed for %s (%s): %s", dep_server.name, dep_server.id, message)
    dep_server.status = "error"
    dep_server.last_error = message[:500]
    try:
        await dep_server.save(update_fields=["status", "last_error", "updated_at"])
    except Exception:
        logger.exception("DEP: failed to persist error state for %s", dep_server.id)


async def unlink(dep_server: DepServer) -> None:
    """Wipe all secret material for a DepServer (keeps the row for audit/history)."""
    dep_server.token_enc = None
    dep_server.private_key_enc = None
    dep_server.public_cert_pem = None
    dep_server.token_expires_at = None
    dep_server.sync_cursor = None
    dep_server.status = "unlinked"
    await dep_server.save()


# ── device sync ───────────────────────────────────────────────────────────────

async def sync_devices(dep_server: DepServer, transport: Optional[Transport] = None) -> Dict[str, Any]:
    """Delta-sync assigned devices from Apple into local placeholders.

    Uses the stored cursor when present (and <7 days old); falls back to a full
    fetch on first sync or an expired/invalid cursor. Idempotent. Returns a summary
    dict; never raises into the scheduler (records the error on the row)."""
    client = build_client(dep_server, transport=transport)
    if client is None:
        await _mark_error(dep_server, "Not linked (no token)")
        return {"ok": False, "error": "not_linked"}

    summary = {"ok": True, "added": 0, "modified": 0, "deleted": 0, "pages": 0}
    try:
        records = await _collect_devices(client, dep_server, summary)
    except DepError as exc:
        # Expired/invalid cursor -> restart with a full fetch once.
        if exc.code in ("EXPIRED_CURSOR", "INVALID_CURSOR", "CURSOR_REQUIRED",
                        "CURSOR_EXPIRED", "EXHAUSTED_CURSOR"):
            logger.warning("DEP: cursor problem (%s); doing a full refetch", exc.code)
            dep_server.sync_cursor = None
            try:
                records = await _collect_devices(client, dep_server, summary)
            except DepError as exc2:
                return await _finish_sync(dep_server, summary, exc2)
        else:
            return await _finish_sync(dep_server, summary, exc)
    except Exception as exc:  # noqa: BLE001 -- defensive on the sched path
        logger.exception("DEP: sync failed for %s", dep_server.id)
        return await _finish_sync(dep_server, summary, exc)

    # Resolve duplicate serials within the batch by latest op_date.
    latest: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        serial = str(rec.get("serial_number") or "").strip()
        if not serial:
            continue
        prev = latest.get(serial)
        if prev is None or str(rec.get("op_date") or "") >= str(prev.get("op_date") or ""):
            latest[serial] = rec

    default_pushed_uuid = await _default_profile_uuid(dep_server)
    assign_serials: List[str] = []
    for serial, rec in latest.items():
        try:
            op = str(rec.get("op_type") or "added").lower()
            if op == "deleted":
                await _handle_deleted(dep_server, serial)
                summary["deleted"] += 1
            else:
                created = await _upsert_device(dep_server, serial, rec)
                summary["added" if created else "modified"] += 1
                if created and default_pushed_uuid:
                    assign_serials.append(serial)
        except Exception:
            logger.exception("DEP: upserting device %s failed", serial)

    # Auto-assign the default profile to newly-added devices (best-effort).
    if assign_serials and default_pushed_uuid:
        try:
            await _assign_and_record(dep_server, default_pushed_uuid, assign_serials, client)
        except Exception:
            logger.exception("DEP: default-profile auto-assign failed for %s", dep_server.id)

    return await _finish_sync(dep_server, summary, None)


async def _collect_devices(client: DepClient, dep_server: DepServer,
                           summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Page through fetch/sync until ``more_to_follow`` is false, updating the
    stored cursor. Returns all device records across pages."""
    records: List[Dict[str, Any]] = []
    # Mode is fixed for the whole run: a stored cursor means "delta sync"
    # (/devices/sync); no stored cursor means "full fetch" (/server/devices), which
    # is ITSELF cursor-paged -- keep calling the same endpoint with the returned
    # cursor until more_to_follow is false. Switching endpoints mid-pagination would
    # drop pages.
    delta = bool(dep_server.sync_cursor)
    cursor = dep_server.sync_cursor
    guard = 0
    while True:
        guard += 1
        if guard > 500:  # backstop against a server that never sets more_to_follow=false
            logger.error("DEP: sync paging backstop hit for %s", dep_server.id)
            break
        if delta:
            resp = await client.sync_devices(cursor, limit=_SYNC_PAGE)
        else:
            resp = await client.fetch_devices(limit=_SYNC_PAGE, cursor=cursor)
        summary["pages"] += 1
        page = resp.get("devices") or []
        if isinstance(page, list):
            records.extend(r for r in page if isinstance(r, dict))
        cursor = resp.get("cursor") or cursor
        if not resp.get("more_to_follow"):
            break
    # Stage the final cursor in-memory only; sync_devices persists it (via
    # _finish_sync) ONLY after every record has been processed, so a crash
    # mid-processing re-fetches rather than silently skipping un-upserted devices.
    dep_server.sync_cursor = cursor
    dep_server.cursor_fetched_at = _now()
    return records


async def _upsert_device(dep_server: DepServer, serial: str,
                         rec: Dict[str, Any]) -> bool:
    """Create or update a Device placeholder for a DEP-assigned serial. Returns True
    if a new placeholder was created."""
    tenant_id = dep_server.tenant_id
    device = await Device.filter(tenant_id=tenant_id, serial_number=serial).first()
    created = False
    if device is None:
        device = Device(
            tenant_id=tenant_id,
            udid=None,
            serial_number=serial,
            device_model=str(rec.get("model") or ""),
            os_version="",
            enrollment_state="pending",
            management_type="apple_mdm",
            groups=[],
        )
        created = True
    # Stamp DEP metadata without clobbering enrollment lifecycle for an already-
    # enrolled device (only these DEP fields are written).
    device.dep_server_id = dep_server.id
    device.dep_profile_uuid = rec.get("profile_uuid") or device.dep_profile_uuid
    device.dep_profile_status = rec.get("profile_status") or device.dep_profile_status
    device.dep_last_synced_at = _now()
    if created:
        if not device.device_model:
            device.device_model = str(rec.get("model") or "")
        await device.save()
    else:
        await device.save(update_fields=[
            "dep_server_id", "dep_profile_uuid", "dep_profile_status",
            "dep_last_synced_at",
        ])
    return created


async def _handle_deleted(dep_server: DepServer, serial: str) -> None:
    """A device was removed from the org in ABM. If it never enrolled (still a
    placeholder) forget it; if it's enrolled, just drop the DEP linkage (the MDM
    channel is still live and independent)."""
    device = await Device.filter(
        tenant_id=dep_server.tenant_id, serial_number=serial
    ).first()
    if device is None:
        return
    if device.enrollment_state == "pending" and not device.udid:
        await device.delete()
    else:
        device.dep_server_id = None
        device.dep_profile_status = "removed"
        await device.save(update_fields=["dep_server_id", "dep_profile_status"])


async def _finish_sync(dep_server: DepServer, summary: Dict[str, Any],
                       error: Optional[Exception]) -> Dict[str, Any]:
    dep_server.last_sync_at = _now()
    # Advance the stored cursor ONLY on a clean sync (all records processed). On
    # error we leave the previously-committed cursor untouched so the next run
    # re-fetches the same window rather than skipping devices.
    fields = ["last_sync_at", "last_sync_status", "last_sync_error", "updated_at"]
    if error is None:
        dep_server.last_sync_status = "ok"
        dep_server.last_sync_error = None
        fields += ["sync_cursor", "cursor_fetched_at"]
    else:
        summary["ok"] = False
        code = getattr(error, "code", None) or type(error).__name__
        summary["error"] = code
        dep_server.last_sync_status = "error"
        dep_server.last_sync_error = str(error)[:500]
    try:
        await dep_server.save(update_fields=fields)
    except Exception:
        logger.exception("DEP: persisting sync result failed for %s", dep_server.id)
    return summary


# ── enrollment profiles ───────────────────────────────────────────────────────

def _load_profile_yaml(tenant_id: str, profile_id: str) -> Optional[Dict[str, Any]]:
    profiles = tenant_config._load(str(tenant_id), "profiles.yaml").get("profiles", [])
    for p in profiles:
        if isinstance(p, dict) and str(p.get("id")) == str(profile_id):
            return p
    return None


def _build_apple_profile(profile_yaml: Dict[str, Any], dep_server: DepServer,
                         tenant: Tenant, enroll_url: str) -> Dict[str, Any]:
    """Map an authored enrollment profile (profiles.yaml) to the Apple /profile
    JSON. Unknown/empty keys are omitted."""
    payload = profile_yaml.get("payload") or profile_yaml.get("enrollment") or {}
    out: Dict[str, Any] = {
        "profile_name": str(profile_yaml.get("name") or profile_yaml.get("id"))[:125],
        "url": enroll_url,
        "org_magic": f"micromanage-{dep_server.id}",
    }
    # Boolean/string passthroughs with Apple's field names.
    bool_keys = ("is_supervised", "is_multi_user", "is_mandatory", "is_mdm_removable",
                 "await_device_configured", "auto_advance_setup", "allow_pairing")
    for k in bool_keys:
        if k in payload and payload[k] is not None:
            out[k] = bool(payload[k])
    str_keys = ("support_phone_number", "support_email_address", "department",
                "language", "region")
    for k in str_keys:
        if payload.get(k):
            out[k] = str(payload[k])
    # skip_setup_items validated against the SkipKeys registry (drop unknowns).
    skip = payload.get("skip_setup_items")
    if isinstance(skip, list) and skip:
        valid, _dropped = filter_valid_skip_keys([str(s) for s in skip])
        if valid:
            out["skip_setup_items"] = valid
    return out


async def push_profile(dep_server: DepServer, profile_id: str, enroll_url: str,
                       transport: Optional[Transport] = None) -> DepProfile:
    """Define (or re-define on edit) an enrollment profile at Apple and store the
    returned ``profile_uuid``. Returns the DepProfile mapping row."""
    tenant = await Tenant.get_or_none(id=dep_server.tenant_id)
    profile_yaml = _load_profile_yaml(str(dep_server.tenant_id), profile_id)
    if tenant is None or profile_yaml is None:
        raise DepError("PROFILE_NOT_FOUND", f"No profile '{profile_id}' in profiles.yaml")

    apple_profile = _build_apple_profile(profile_yaml, dep_server, tenant, enroll_url)
    payload_hash = hashlib.sha256(
        json.dumps(apple_profile, sort_keys=True).encode()
    ).hexdigest()

    mapping, _ = await DepProfile.get_or_create(
        tenant_id=dep_server.tenant_id, dep_server=dep_server, profile_id=profile_id
    )
    # Skip a redundant re-push if the definition is unchanged and already pushed.
    if mapping.profile_uuid and mapping.payload_hash == payload_hash:
        return mapping

    client = build_client(dep_server, transport=transport)
    if client is None:
        raise DepError("NOT_LINKED", "DEP server is not linked")
    resp = await client.define_profile(apple_profile)
    profile_uuid = resp.get("profile_uuid")
    if not profile_uuid:
        mapping.last_error = "Apple did not return a profile_uuid"
        await mapping.save()
        raise DepError("NO_PROFILE_UUID", mapping.last_error)

    mapping.profile_uuid = profile_uuid
    mapping.payload_hash = payload_hash
    mapping.pushed_at = _now()
    mapping.last_error = None
    await mapping.save()
    logger.info("DEP: pushed profile %s -> %s on server %s",
                profile_id, profile_uuid, dep_server.name)
    return mapping


async def _default_profile_uuid(dep_server: DepServer) -> Optional[str]:
    if not dep_server.default_profile_id:
        return None
    mapping = await DepProfile.get_or_none(
        dep_server=dep_server, profile_id=dep_server.default_profile_id
    )
    return mapping.profile_uuid if mapping else None


async def _assign_and_record(dep_server: DepServer, profile_uuid: str,
                             serials: List[str], client: DepClient) -> Dict[str, Any]:
    """Assign a profile to serials at Apple and reflect the per-serial result onto
    the local Device rows."""
    resp = await client.assign_profile(profile_uuid, serials)
    results = resp.get("devices") or {}
    for serial in serials:
        status = str(results.get(serial, "")).upper()
        device = await Device.filter(
            tenant_id=dep_server.tenant_id, serial_number=serial
        ).first()
        if device is None:
            continue
        if status == "SUCCESS":
            device.dep_profile_uuid = profile_uuid
            device.dep_profile_status = "assigned"
        await device.save(update_fields=["dep_profile_uuid", "dep_profile_status"])
    return results


async def assign_profile(dep_server: DepServer, profile_id: str, serials: List[str],
                         enroll_url: str, transport: Optional[Transport] = None) -> Dict[str, Any]:
    """Ensure a profile is defined at Apple, then assign it to the given serials."""
    mapping = await push_profile(dep_server, profile_id, enroll_url, transport=transport)
    client = build_client(dep_server, transport=transport)
    if client is None:
        raise DepError("NOT_LINKED", "DEP server is not linked")
    return await _assign_and_record(dep_server, mapping.profile_uuid, serials, client)


async def unassign_profile(dep_server: DepServer, serials: List[str],
                           transport: Optional[Transport] = None) -> Dict[str, Any]:
    client = build_client(dep_server, transport=transport)
    if client is None:
        raise DepError("NOT_LINKED", "DEP server is not linked")
    resp = await client.clear_profile(serials)
    for serial in serials:
        device = await Device.filter(
            tenant_id=dep_server.tenant_id, serial_number=serial
        ).first()
        if device:
            device.dep_profile_status = "removed"
            await device.save(update_fields=["dep_profile_status"])
    return resp.get("devices") or {}


async def disown_devices(dep_server: DepServer, serials: List[str],
                         transport: Optional[Transport] = None) -> Dict[str, Any]:
    """Release devices from the org's ADE in ABM. IRREVERSIBLE -- admin action only,
    never automatic."""
    client = build_client(dep_server, transport=transport)
    if client is None:
        raise DepError("NOT_LINKED", "DEP server is not linked")
    resp = await client.disown(serials)
    # Local placeholders are meaningless once disowned; forget the un-enrolled ones.
    for serial in serials:
        if str(resp.get("devices", {}).get(serial, "")).upper() == "SUCCESS":
            await _handle_deleted(dep_server, serial)
    return resp.get("devices") or {}
