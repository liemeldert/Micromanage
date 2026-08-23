"""DEP orchestration: link ABM/ASM, sync devices, define and assign profiles.

Never speaks OAuth/HTTP itself or returns/logs secret material.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from controller.models.tenant import DepProfile, DepServer, Device, Tenant
from controller.services import crypto_secrets, dep_pki, tenant_config
from controller.services.dep_client import DepClient, DepError, Transport
from controller.services.skip_keys import filter_valid_skip_keys

logger = logging.getLogger(__name__)

# Devices per DEP fetch/sync page. Apple's maximum (fetchdevicerequest docs); see dep_manager.md.
_SYNC_PAGE = 1000

# Pagination backstop against a server that never clears more_to_follow. See dep_manager.md.
_MAX_SYNC_PAGES = 500

# Apple expires a sync cursor after 7 days (EXPIRED_CURSOR); dropped locally first. See dep_manager.md.
_CURSOR_MAX_AGE = timedelta(days=7)

# Serials per local IN-query, sized for sqlite's bound-parameter limit. See dep_manager.md.
_DB_IN_CHUNK = 500


def _now() -> datetime:
    return datetime.now(timezone.utc)


#  client construction

def _binding(tenant_id: Any, kind: str) -> str:
    """What a DEP credential's ciphertext is bound to. Order/separator are part of the stored format; changing
    them makes every already-bound row undecryptable. See dep_manager.md."""
    return f"{tenant_id}|dep|{kind}"


def build_client(dep_server: DepServer, transport: Optional[Transport] = None) -> Optional[DepClient]:
    """Decrypt the stored token and construct a DepClient, or None if unavailable.

    transport is injected only in tests; production uses the httpx default."""
    token_json = crypto_secrets.decrypt(
        dep_server.token_enc, aad=_binding(dep_server.tenant_id, "token"))
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


#  link lifecycle 

async def begin_link(tenant: Tenant, name: str) -> DepServer:
    """Create (or reset) a DepServer and generate its PKI keypair. Returns the row with public_cert_pem populated (the
    cert the admin uploads to ABM)."""
    private_pem, cert_pem, cert_expires = dep_pki.generate_keypair(
        common_name=f"micromanage-dep-{name}"
    )
    # Encrypt the private key at rest (it can decrypt a re-downloaded token).
    private_enc = crypto_secrets.encrypt(
        private_pem, aad=_binding(tenant.id, "private_key"))

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
    """Decrypt the uploaded .p7m server token, verify it against Apple, and store it encrypted. Raises on failure
    (status='error' persisted, non-secret message)."""
    key_aad = _binding(dep_server.tenant_id, "private_key")
    private_pem, key_bound = crypto_secrets.decrypt_bound(
        dep_server.private_key_enc, aad=key_aad)
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

    dep_server.token_enc = crypto_secrets.encrypt(
        json.dumps(token), aad=_binding(dep_server.tenant_id, "token"))
    if not key_bound:
        # Predates the binding; re-bound here since the row is being written anyway. See dep_manager.md.
        rebound = crypto_secrets.rebind(private_pem, aad=key_aad)
        if rebound:
            dep_server.private_key_enc = rebound
    dep_server.token_expires_at = dep_pki.token_expiry(token)
    dep_server.account_detail = _safe_account(account)
    dep_server.status = "linked"
    dep_server.last_error = None
    await dep_server.save()
    logger.info("DEP: linked server %s (org=%s)", dep_server.name,
                dep_server.account_detail.get("org_name"))
    return dep_server


def _default_transport_override() -> Optional[Transport]:
    """Hook so tests can force a transport into complete_link without threading it through the API. Returns None in
    production (httpx default)."""
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
    # Log the specific reason (decrypt/algorithm/key-mismatch, Apple rejection). The API only returns a generic code to
    # the client, so this is where operators see it.
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


async def remove(dep_server: DepServer) -> None:
    """Fully delete a DepServer and its profile mappings, unlike unlink which keeps the row re-linkable. See
    dep_manager.md."""
    await DepProfile.filter(dep_server=dep_server).delete()
    await Device.filter(
        tenant_id=dep_server.tenant_id, dep_server_id=dep_server.id
    ).update(dep_server_id=None, dep_profile_status="removed")
    await dep_server.delete()


async def _upgrade_token_binding(dep_server: DepServer) -> None:
    """Re-encrypt a pre-binding server token in place, best-effort, once, since the scheduled sync opens it anyway.
    See dep_manager.md."""
    aad = _binding(dep_server.tenant_id, "token")
    plaintext, bound = crypto_secrets.decrypt_bound(dep_server.token_enc, aad=aad)
    if plaintext is None or bound:
        return
    rebound = crypto_secrets.rebind(plaintext, aad=aad)
    if not rebound:
        return
    dep_server.token_enc = rebound
    try:
        await dep_server.save(update_fields=["token_enc", "updated_at"])
    except Exception:
        logger.exception("DEP: could not persist the re-bound token for %s",
                         dep_server.id)


#  device sync

async def sync_devices(dep_server: DepServer, transport: Optional[Transport] = None) -> Dict[str, Any]:
    """Delta-sync assigned devices from Apple into local placeholders. Idempotent. Returns a summary dict; never
    raises into the scheduler (records the error on the row). See dep_manager.md."""
    client = build_client(dep_server, transport=transport)
    if client is None:
        await _mark_error(dep_server, "Not linked (no token)")
        return {"ok": False, "error": "not_linked"}

    await _upgrade_token_binding(dep_server)
    _drop_aged_cursor(dep_server)
    summary = {"ok": True, "added": 0, "modified": 0, "deleted": 0, "pages": 0}
    try:
        records = await _collect_devices(client, dep_server, summary)
    except DepError as exc:
        # A cursor Apple refuses to accept at all -> restart with a full fetch once. EXHAUSTED_CURSOR is excluded: it
        # means the sync is finished. See dep_manager.md.
        if exc.code in ("EXPIRED_CURSOR", "INVALID_CURSOR", "CURSOR_REQUIRED"):
            logger.warning("DEP: cursor rejected (%s); doing a full refetch", exc.code)
            dep_server.sync_cursor = None
            dep_server.cursor_fetched_at = None
            try:
                records = await _collect_devices(client, dep_server, summary)
            except DepError as exc2:
                return await _finish_sync(dep_server, summary, exc2)
        else:
            return await _finish_sync(dep_server, summary, exc)
    except Exception as exc:  # noqa: BLE001, defensive on the scheduler path
        logger.exception("DEP: sync failed for %s", dep_server.id)
        return await _finish_sync(dep_server, summary, exc)

    # Resolve duplicate serials within the batch by latest op_date, Apple's last known state (sync-devices docs).
    latest: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        serial = str(rec.get("serial_number") or "").strip()
        if not serial:
            continue
        prev = latest.get(serial)
        if prev is None or _op_date_at_least(rec.get("op_date"), prev.get("op_date")):
            latest[serial] = rec

    default_pushed_uuid = await _default_profile_uuid(dep_server)
    assign_serials: List[str] = []

    # Optimization, not a requirement: a transient DB error here costs this sync its batching, and _upsert_device
    # falls back to a per-record query when the map is None. See dep_manager.md.
    device_map: Optional[Dict[str, Device]] = None
    if latest:
        try:
            device_map = await _prefetch_devices_by_serial(dep_server.tenant_id)
        except Exception:
            logger.warning("DEP: device prefetch failed for %s; falling back to "
                           "per-record queries this sync", dep_server.id, exc_info=True)

    for serial, rec in latest.items():
        try:
            op = str(rec.get("op_type") or "added").lower()
            if op == "deleted":
                await _handle_deleted(dep_server, serial)
                summary["deleted"] += 1
            else:
                created = await _upsert_device(dep_server, serial, rec, device_map)
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

    # An abandoned pagination has upserted whatever it did read, but the fleet was never fully listed, so the run is an
    # error: _finish_sync leaves the stored cursor where it was and the next tick re-reads the same window.
    incomplete = None
    if summary.get("incomplete"):
        incomplete = DepError(
            "SYNC_PAGING_INCOMPLETE",
            f"stopped after {summary['pages']} pages with more_to_follow still set",
        )
    return await _finish_sync(dep_server, summary, incomplete)


async def _collect_devices(client: DepClient, dep_server: DepServer,
                           summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Page through fetch/sync until more_to_follow is false, updating the stored cursor. Returns all device records
    across pages."""
    records: List[Dict[str, Any]] = []
    # Mode is fixed for the whole run (cursor present = delta /devices/sync, else full /server/devices); switching
    # endpoints halfway through pagination drops pages. See dep_manager.md.
    delta = bool(dep_server.sync_cursor)
    cursor = dep_server.sync_cursor
    issued_cursor = False
    guard = 0
    while True:
        guard += 1
        if guard > _MAX_SYNC_PAGES:
            # Listing unfinished: records so far are returned but no cursor is staged. See dep_manager.md.
            logger.error(
                "DEP: sync paging stopped after %s pages for server %s with more "
                "pages still outstanding; the device list is incomplete and the "
                "stored cursor is left where it was",
                _MAX_SYNC_PAGES, dep_server.id)
            summary["incomplete"] = True
            return records
        try:
            if delta:
                resp = await client.sync_devices(cursor, limit=_SYNC_PAGE)
            else:
                resp = await client.fetch_devices(limit=_SYNC_PAGE, cursor=cursor)
        except DepError as exc:
            # EXHAUSTED_CURSOR: listing is complete, cursor kept as-is (sync-devices docs; dep_manager.md).
            if exc.code != "EXHAUSTED_CURSOR":
                raise
            logger.info("DEP: cursor for server %s had already returned every "
                        "device; nothing further to read this run", dep_server.id)
            break
        summary["pages"] += 1
        page = resp.get("devices") or []
        if isinstance(page, list):
            records.extend(r for r in page if isinstance(r, dict))
        if resp.get("cursor"):
            cursor = resp["cursor"]
            issued_cursor = True
        if not resp.get("more_to_follow"):
            break
    # Staged in memory only; sync_devices persists it after every record is processed. See dep_manager.md.
    dep_server.sync_cursor = cursor
    if issued_cursor:
        dep_server.cursor_fetched_at = _now()
    return records


def _drop_aged_cursor(dep_server: DepServer) -> None:
    """Forget a stored cursor past Apple's 7-day expiry, so the run starts from a full fetch instead of spending a
    call Apple will reject with EXPIRED_CURSOR. See dep_manager.md."""
    fetched_at = dep_server.cursor_fetched_at
    if not dep_server.sync_cursor or fetched_at is None:
        return
    if fetched_at.tzinfo is None:
        fetched_at = fetched_at.replace(tzinfo=timezone.utc)
    age = _now() - fetched_at
    if age < _CURSOR_MAX_AGE:
        return
    logger.info("DEP: stored cursor for server %s is %s old (Apple expires them "
                "after %s); starting from a full fetch",
                dep_server.id, age, _CURSOR_MAX_AGE)
    dep_server.sync_cursor = None
    dep_server.cursor_fetched_at = None


def _parse_op_date(value: Any) -> Optional[datetime]:
    """An ADE record's op_date as an aware datetime, or None when it is missing or unreadable. Apple's ISO 8601
    does not sort lexicographically; see dep_manager.md."""
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        # fromisoformat gained "Z" support in 3.11; normalize it for older ones.
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _op_date_at_least(candidate: Any, current: Any) -> bool:
    """Is candidate the same age or newer than current? Unparseable op_date compares as older than any real
    timestamp. See dep_manager.md."""
    a, b = _parse_op_date(candidate), _parse_op_date(current)
    if a is None:
        return b is None
    if b is None:
        return True
    return a >= b


# Columns _upsert_device reads or writes on a Device row; a prefetched (.only()) row must list every touched
# field or save(update_fields=...) raises IncompleteInstanceError. See dep_manager.md.
_DEVICE_PREFETCH_FIELDS = (
    "id", "tenant_id", "serial_number", "dep_server_id", "dep_profile_uuid",
    "dep_profile_status", "dep_last_synced_at",
)


async def _prefetch_devices_by_serial(tenant_id) -> Dict[str, Device]:
    """Tenant-wide serial -> Device map, so a first full sync costs one query instead of one per record. Keyed
    stripped, no case-folding, to match the (tenant_id, serial_number) unique index. See dep_manager.md."""
    mapping: Dict[str, Device] = {}
    for device in await Device.filter(tenant_id=tenant_id).only(*_DEVICE_PREFETCH_FIELDS):
        key = str(device.serial_number or "").strip()
        if not key:
            continue
        mapping.setdefault(key, device)
    return mapping


async def _upsert_device(dep_server: DepServer, serial: str, rec: Dict[str, Any],
                         device_map: Optional[Dict[str, Device]] = None) -> bool:
    """Create or update a Device placeholder for a DEP-assigned serial. Returns True if created. device_map is
    the optional tenant-wide prefetch; None falls back to a per-record query. See dep_manager.md."""
    tenant_id = dep_server.tenant_id
    if device_map is not None:
        device = device_map.get(serial)
    else:
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
    # Stamp DEP metadata without clobbering the enrollment lifecycle of an already-enrolled device: only these DEP
    # fields are written.
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
    if device_map is not None:
        device_map[serial] = device
    return created


async def _handle_deleted(dep_server: DepServer, serial: str) -> None:
    """A device was removed from the org in ABM. If it never enrolled (still a placeholder) forget it; if it's enrolled,
    just drop the DEP linkage (the MDM channel is still live and independent)."""
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
    # Advance the stored cursor only on a clean sync, all records processed. On error we leave the previously-committed
    # cursor untouched so the next run re-fetches the same window rather than skipping devices.
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


#  enrollment profiles 

def _load_profile_yaml(tenant_id: str, profile_id: str) -> Optional[Dict[str, Any]]:
    profiles = tenant_config._load(str(tenant_id), "profiles.yaml").get("profiles", [])
    for p in profiles:
        if isinstance(p, dict) and str(p.get("id")) == str(profile_id):
            return p
    return None


# Apple's define-profile 400 list gives a max length per field; text fields are trimmed to fit, the URL is not
# (a truncated enrollment URL can't enroll a device). See dep_manager.md.
_PROFILE_NAME_MAX = 125
_URL_MAX = 2000
_STR_FIELD_MAX = {
    "support_phone_number": 50,
    "support_email_address": 250,
    "department": 125,
}


def _build_apple_profile(profile_yaml: Dict[str, Any], dep_server: DepServer,
                         tenant: Tenant, enroll_url: str) -> Dict[str, Any]:
    """Map an authored enrollment profile (profiles.yaml) to the Apple /profile JSON. Unknown/empty keys are
    omitted. Raises DepError naming the specific rule for anything Apple's define-profile 400 list will refuse."""
    payload = profile_yaml.get("payload") or profile_yaml.get("enrollment") or {}
    if len(enroll_url) > _URL_MAX:
        raise DepError("CONFIG_URL_INVALID",
                       f"The enrollment URL is {len(enroll_url)} characters; Apple "
                       f"accepts at most {_URL_MAX}")
    out: Dict[str, Any] = {
        "profile_name": str(
            profile_yaml.get("name") or profile_yaml.get("id"))[:_PROFILE_NAME_MAX],
        "url": enroll_url,
        "org_magic": f"micromanage-{dep_server.id}",
    }
    # Boolean/string passthroughs with Apple's field names.
    bool_keys = ("is_supervised", "is_multi_user", "is_mandatory", "is_mdm_removable",
                 "await_device_configured", "auto_advance_setup", "allow_pairing")
    for k in bool_keys:
        if k in payload and payload[k] is not None:
            out[k] = bool(payload[k])
    # Apple rejects is_mdm_removable=false without is_supervised=true as FLAGS_INVALID
    # (https://developer.apple.com/documentation/devicemanagement/define-profile). See dep_manager.md.
    if out.get("is_mdm_removable") is False and out.get("is_supervised") is not True:
        raise DepError(
            "FLAGS_INVALID",
            "Apple only allows a non-removable MDM profile on a supervised "
            "device: turn Supervised on, or allow the profile to be removed")
    str_keys = ("support_phone_number", "support_email_address", "department",
                "language", "region")
    for k in str_keys:
        if payload.get(k):
            value = str(payload[k])
            limit = _STR_FIELD_MAX.get(k)
            if limit and len(value) > limit:
                logger.warning("DEP: profile %s trims %s to Apple's %s-character "
                               "maximum", profile_yaml.get("id"), k, limit)
                value = value[:limit]
            out[k] = value
    # Trusted anchors for a controller behind a private/enterprise CA, base64 DER
    # (https://developer.apple.com/documentation/devicemanagement/profile). See dep_manager.md.
    anchors = payload.get("anchor_certs")
    if isinstance(anchors, list) and anchors:
        certs = [str(c).strip() for c in anchors if str(c or "").strip()]
        if certs:
            out["anchor_certs"] = certs
    # skip_setup_items validated against the SkipKeys registry (drop unknowns).
    skip = payload.get("skip_setup_items")
    if isinstance(skip, list) and skip:
        valid, dropped = filter_valid_skip_keys([str(s) for s in skip])
        if dropped:
            # A dropped key means its Setup Assistant pane keeps appearing on every device with nothing else saying why,
            # including a key Apple shipped after services.skip_keys was last updated.
            logger.warning(
                "DEP: profile %s asks to skip Setup Assistant pane(s) this build "
                "does not recognize, so they are not being sent to Apple: %s",
                profile_yaml.get("id"), ", ".join(dropped))
        if valid:
            out["skip_setup_items"] = valid
    return out


async def push_profile(dep_server: DepServer, profile_id: str, enroll_url: str,
                       transport: Optional[Transport] = None) -> DepProfile:
    """Define (or re-define on edit) an enrollment profile at Apple and store the returned profile_uuid. Returns the
    DepProfile mapping row."""
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


async def repush_changed_profiles(dep_server: DepServer, enroll_url: str,
                                  transport: Optional[Transport] = None) -> Dict[str, int]:
    """Re-define at Apple every mapped profile whose profiles.yaml definition has changed since it was pushed. One
    profile failing does not stop the others. See dep_manager.md."""
    result = {"checked": 0, "pushed": 0, "failed": 0}
    for mapping in await DepProfile.filter(dep_server=dep_server):
        result["checked"] += 1
        before = mapping.payload_hash
        try:
            updated = await push_profile(dep_server, mapping.profile_id, enroll_url,
                                         transport=transport)
        except Exception as exc:  # noqa: BLE001, one bad profile can't stop the sweep
            result["failed"] += 1
            logger.warning("DEP: re-push of profile %s on server %s failed: %s",
                           mapping.profile_id, dep_server.name, exc)
            try:
                mapping.last_error = str(exc)[:500]
                await mapping.save(update_fields=["last_error", "updated_at"])
            except Exception:
                logger.exception("DEP: recording re-push error for %s failed", mapping.profile_id)
            continue
        if updated.payload_hash != before:
            result["pushed"] += 1
    return result


async def _default_profile_uuid(dep_server: DepServer) -> Optional[str]:
    """The Apple profile_uuid auto-assigned to newly-synced devices, or None. See dep_manager.md."""
    tcfg = tenant_config._load(str(dep_server.tenant_id), "config.yaml").get("tenant")
    dep_cfg = tcfg.get("dep") if isinstance(tcfg, dict) else None
    profile_id = ""
    if isinstance(dep_cfg, dict):
        profile_id = str(dep_cfg.get("default_profile") or "").strip()
    profile_id = profile_id or (dep_server.default_profile_id or "")
    if not profile_id:
        return None
    mapping = await DepProfile.get_or_none(dep_server=dep_server, profile_id=profile_id)
    return mapping.profile_uuid if mapping else None


# Columns the assign/unassign paths read or write on a Device row. See dep_manager.md.
_ASSIGN_FIELDS = (
    "id", "tenant_id", "serial_number", "dep_profile_uuid", "dep_profile_status",
    "attributes",
)


def _serial_list(serials: List[str], cap: int = 20) -> str:
    """Serials for a log line, capped so a fleet-wide failure stays one readable line. Calls routinely cover thousands
    of serials; the per-device record on each row carries the detail for the ones the line elides."""
    if len(serials) <= cap:
        return ", ".join(serials)
    return f"{', '.join(serials[:cap])} and {len(serials) - cap} more"


async def _devices_by_serial(tenant_id, serials: List[str]) -> Dict[str, Device]:
    """serial -> Device for the given serials, in as few queries as the database will take them. See
    dep_manager.md."""
    found: Dict[str, Device] = {}
    unique = list(dict.fromkeys(s for s in serials if s))
    for start in range(0, len(unique), _DB_IN_CHUNK):
        batch = unique[start:start + _DB_IN_CHUNK]
        rows = await Device.filter(
            tenant_id=tenant_id, serial_number__in=batch
        ).only(*_ASSIGN_FIELDS)
        for device in rows:
            found.setdefault(str(device.serial_number or "").strip(), device)
    return found


async def _assign_and_record(dep_server: DepServer, profile_uuid: str,
                             serials: List[str], client: DepClient) -> Dict[str, Any]:
    """Assign a profile to serials at Apple and reflect the per-serial result onto the local Device rows. Only
    SUCCESS stamps the row. Returns the results map and retry_after_seconds. See dep_manager.md."""
    resp = await client.assign_profile(profile_uuid, serials)
    results = resp.get("devices") or {}
    retry_after = resp.get("retry_after_seconds")
    retry_after = int(retry_after) if isinstance(retry_after, (int, float)) else None
    devices = await _devices_by_serial(dep_server.tenant_id, serials)
    by_status: Dict[str, List[str]] = {}
    for serial in serials:
        status = str(results.get(serial, "")).upper() or "NO_RESULT"
        by_status.setdefault(status, []).append(serial)
        device = devices.get(serial)
        if device is None:
            continue
        fields: List[str] = []
        record = None
        if status == "SUCCESS":
            device.dep_profile_uuid = profile_uuid
            device.dep_profile_status = "assigned"
            fields += ["dep_profile_uuid", "dep_profile_status"]
        else:
            record = {
                "status": status,
                "profile_uuid": profile_uuid,
                "at": _now().isoformat(),
                **({"retry_after_seconds": retry_after} if retry_after is not None else {}),
            }
        # attributes is a whole-column write; only rows whose result changes it are re-read and written, so the
        # merge is against current content, not the bulk-read snapshot. See dep_manager.md.
        if record is not None or "dep_assign_result" in (device.attributes or {}):
            fresh = await Device.filter(id=device.id).only("id", "attributes").first()
            attrs = dict((fresh.attributes if fresh else device.attributes) or {})
            if record is None:
                attrs.pop("dep_assign_result", None)
            else:
                attrs["dep_assign_result"] = record
            device.attributes = attrs
            fields.append("attributes")
        if fields:
            await device.save(update_fields=fields)
    unhappy = {k: v for k, v in by_status.items() if k != "SUCCESS"}
    if unhappy:
        logger.warning(
            "DEP: Apple did not assign profile %s to every device on server %s: %s%s",
            profile_uuid, dep_server.id,
            "; ".join(f"{status} {_serial_list(items)}" for status, items in unhappy.items()),
            f" (retry_after_seconds={retry_after})" if retry_after is not None else "")
    return {"results": results, "retry_after_seconds": retry_after}


async def assign_profile(dep_server: DepServer, profile_id: str, serials: List[str],
                         enroll_url: str, transport: Optional[Transport] = None) -> Dict[str, Any]:
    """Ensure a profile is defined at Apple, then assign it to the given serials. See dep_manager.md."""
    mapping = await push_profile(dep_server, profile_id, enroll_url, transport=transport)
    client = build_client(dep_server, transport=transport)
    if client is None:
        raise DepError("NOT_LINKED", "DEP server is not linked")
    return await _assign_and_record(dep_server, mapping.profile_uuid, serials, client)


async def unassign_profile(dep_server: DepServer, serials: List[str],
                           transport: Optional[Transport] = None) -> Dict[str, Any]:
    """Clear the assigned profile from serials at Apple, marking locally only the ones Apple reports as SUCCESS.
    See dep_manager.md."""
    client = build_client(dep_server, transport=transport)
    if client is None:
        raise DepError("NOT_LINKED", "DEP server is not linked")
    resp = await client.clear_profile(serials)
    results = resp.get("devices") or {}
    cleared = [s for s in serials if str(results.get(s, "")).upper() == "SUCCESS"]
    cleared_set = set(cleared)
    refused = [s for s in serials if s not in cleared_set]
    if refused:
        logger.warning("DEP: Apple did not clear the profile from %s device(s) on "
                       "server %s: %s", len(refused), dep_server.id,
                       _serial_list(refused))
    devices = await _devices_by_serial(dep_server.tenant_id, cleared)
    for serial in cleared:
        device = devices.get(serial)
        if device is None:
            continue
        device.dep_profile_status = "removed"
        await device.save(update_fields=["dep_profile_status"])
    return results


async def disown_devices(dep_server: DepServer, serials: List[str],
                         transport: Optional[Transport] = None) -> Dict[str, Any]:
    """Release devices from the org's ADE in ABM. Irreversible, so this is an admin action and never happens on its own.
    """
    client = build_client(dep_server, transport=transport)
    if client is None:
        raise DepError("NOT_LINKED", "DEP server is not linked")
    resp = await client.disown(serials)
    # Local placeholders are meaningless once disowned; forget the un-enrolled ones.
    for serial in serials:
        if str(resp.get("devices", {}).get(serial, "")).upper() == "SUCCESS":
            await _handle_deleted(dep_server, serial)
    return resp.get("devices") or {}
