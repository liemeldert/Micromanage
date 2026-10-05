"""Declarative Device Management (DDM) and scope preview endpoints."""
import asyncio
import logging
import time
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from controller.api.ids import get_owned_or_404
from controller.auth.dependencies import Principal, get_current_principal, require_admin
from controller.models.tenant import Device
from controller.services import scoping
from controller.services.audit import record_audit

logger = logging.getLogger(__name__)

router = APIRouter()

_DDM_AUTO_NAMES = {
    "mm.cfg.status-subscriptions": "Status subscriptions",
    "mm.act.status-subscriptions": "Status subscriptions (activation)",
    "mm.mgmt.org-info": "Organization info",
    "mm.mgmt.properties": "Device properties",
    "mm.mgmt.server-capabilities": "Server capabilities",
}


def _ddm_desired_entry(decl: Dict[str, Any], names_by_id: Dict[str, str],
                       include_payload: bool) -> Dict[str, Any]:
    """One computed declaration as the API returns it: source is the yaml id for authored items and their paired
    activations, "auto" for the rest."""
    identifier = str(decl.get("Identifier") or "")
    source = "auto"
    if identifier not in _DDM_AUTO_NAMES:
        for prefix in ("mm.cfg.", "mm.act."):
            if identifier.startswith(prefix):
                source = identifier[len(prefix):]
                break
    if source != "auto":
        name = names_by_id.get(source) or source
    else:
        name = _DDM_AUTO_NAMES.get(identifier, identifier)
    entry = {
        "identifier": identifier,
        "type": decl.get("Type"),
        "server_token": decl.get("ServerToken"),
        "source": source,
        "name": name,
    }
    if include_payload:
        entry["payload"] = decl.get("Payload") or {}
    return entry


@router.get("/api/v1/devices/{device_id}/ddm")
async def get_device_ddm(
    device_id: str,
    include_payloads: bool = False,
    principal: Principal = Depends(get_current_principal),
):
    """DDM state for a device: the desired declaration set, computed now, joined with what the device last reported,
    plus the raw status-item tree. Payloads are omitted unless include_payloads=1, which keeps the response small."""
    tenant = principal.tenant
    device = await get_owned_or_404(Device, device_id, tenant, "Device not found")

    from controller.services import ddm_manager
    from controller.services.tenant_config import load_declarations

    desired_full = await ddm_manager.compute_device_declarations(device, tenant)
    names_by_id = {
        str(d.get("id")): d.get("name")
        for d in load_declarations(tenant.id).get("declarations") or []
        if isinstance(d, dict) and d.get("id")
    }
    reported = device.ddm_declaration_status or {}

    predicated = set()
    for d in desired_full:
        if d.get("Type") == "com.apple.activation.simple" \
            and (d.get("Payload") or {}).get("Predicate"):
            ident = d.get("Identifier") or ""
            predicated.add(ident)
            if ident.startswith("mm.act."):
                predicated.add("mm.cfg." + ident[len("mm.act."):])
    drift: List[str] = []
    if device.ddm_enabled_at:
        for d in desired_full:
            ident = d.get("Identifier")
            if (d.get("Type") or "").startswith("com.apple.management."):
                continue
            state = reported.get(ident)
            if not isinstance(state, dict):
                drift.append(ident)
            elif state.get("valid") == "invalid" \
                or (state.get("active") is not True and ident not in predicated):
                drift.append(ident)
    return {
        "supported": ddm_manager.device_supports_ddm(device),
        "tenant_enabled": tenant.ddm_enabled,
        "enabled_at": device.ddm_enabled_at,
        "last_sync_at": device.ddm_last_sync_at,
        "last_published_token": device.ddm_last_published_token,
        "desired": [_ddm_desired_entry(d, names_by_id, include_payloads)
                    for d in desired_full],
        "reported": reported,
        "status_items": device.ddm_status or {},
        "client_capabilities": device.ddm_client_capabilities or {},
        "drift": drift,
    }


@router.post("/api/v1/devices/{device_id}/ddm/sync")
async def force_device_ddm_sync(
    device_id: str,
    admin: Principal = Depends(require_admin),
):
    """Force a declarative sync now (admin only).

    Clears the published token (so an unchanged set still sends) and the recorded failure (so backoff is bypassed)."""
    tenant = admin.tenant
    device = await get_owned_or_404(Device, device_id, tenant, "Device not found")
    if device.enrollment_state != "enrolled":
        raise HTTPException(
            status_code=409,
            detail=f"Device is {device.enrollment_state}; commands can only be sent to enrolled devices",
        )

    from controller.services import ddm_manager
    device.ddm_last_published_token = None
    device.attributes = {k: v for k, v in (device.attributes or {}).items()
                         if k != ddm_manager.SYNC_FAILURE_KEY}
    await device.save(update_fields=["ddm_last_published_token", "attributes"])
    queued = await ddm_manager.sync_device(device, reason="manual")
    failure = queued if isinstance(queued, ddm_manager.EnqueueFailed) else None
    await record_audit(
        admin,
        "device.ddm_sync",
        target_type="device",
        target_id=device_id,
        detail={"serial_number": device.serial_number,
                "queued": False if failure is not None else bool(queued),
                **({"error": failure.reason} if failure is not None else {})},
    )
    if failure is not None:
        raise HTTPException(
            status_code=502,
            detail=f"The declarative sync could not be queued: {failure.reason}",
        )
    return {"queued": bool(queued)}


_DECLARATION_SCOPE_FIELDS = (
    "id", "serial_number", "device_model", "os_version", "hostname",
    "enrollment_date", "tags", "attributes",
)


@router.get("/api/v1/declarations")
async def list_declarations(principal: Principal = Depends(get_current_principal)):
    """Declarations listing: parsed declarations.yaml plus, per item, how many enrolled devices its scope matches right
    now. Platform and unified scope only; rollout waves are not simulated here.
    """
    tenant = principal.tenant
    from controller.services import ddm_manager
    from controller.services.group_manager import GroupManager
    from controller.services.profile_manager import ProfileManager
    from controller.services.scoping import evaluate_scope
    from controller.services.tenant_config import load_declarations, load_groups

    cfg = load_declarations(tenant.id)
    groups_config = load_groups(tenant.id)
    devices = await Device.filter(
        tenant=tenant, enrollment_state="enrolled"
    ).only(*_DECLARATION_SCOPE_FIELDS).all()
    gm = GroupManager(tenant.id)
    memberships = []
    for d in devices:
        try:
            memberships.append((d, ProfileManager._device_platform(d),
                                gm.evaluate_device_groups(d, groups_config)))
        except Exception:
            logger.exception("declarations: group eval failed for %s", d.serial_number)

    items: List[Dict[str, Any]] = []
    for item in cfg.get("declarations") or []:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        platforms = item.get("platforms") or []
        scoped = 0
        for device, platform, device_groups in memberships:
            try:
                if platforms and platform not in platforms:
                    continue
                if evaluate_scope(device, device_groups, item):
                    scoped += 1
            except Exception:
                continue  # a bad condition skips the device, not the listing
        entry: Dict[str, Any] = {
            "id": str(item["id"]),
            "name": item.get("name") or str(item["id"]),
            "type": item.get("type"),
            "scope": {
                "platforms": platforms,
                "groups": item.get("groups") or [],
                "conditions": len(item.get("conditions") or []),
                "include_devices": len(item.get("include_devices") or []),
                "exclude_devices": len(item.get("exclude_devices") or []),
                "rollout": bool(item.get("rollout")),
            },
            "scoped_count": scoped,
        }
        blocked = ddm_manager.undeliverable_reason(item, tenant.id)
        if blocked:
            entry["not_served"] = blocked
        if item.get("description"):
            entry["description"] = item["description"]
        items.append(entry)
    return {"declarations": items, "ddm_enabled": tenant.ddm_enabled}


# ==Scope preview==

SCOPE_PREVIEW_SCAN_CAP = 5000
SCOPE_PREVIEW_MAX_SAMPLE = 25

# Time budget for the walk, so a slow scope answers late rather than never.
SCOPE_PREVIEW_TIME_BUDGET_SECONDS = 2.0

_SCOPE_PREVIEW_FIELDS = (
    "id", "name", "serial_number", "device_model", "os_version", "hostname",
    "enrollment_date", "tags", "attributes", "groups", "dep_profile_uuid",
)

_scope_is_empty = scoping.scope_is_empty


class ScopePreviewRequest(BaseModel):
    # The scope as authored. Passed verbatim to services.scoping.evaluate_scope.
    scope: Optional[Dict[str, Any]] = None
    # Required, no default: empty means every device to a flow start/dispatcher rule but none to a profile/app
    # version, so an undecided caller gets a 422 rather than a confident wrong number.
    empty_scope: Literal["all", "none"]
    # A flow start only runs for devices of its own trigger kind, which is narrower than every device. Absent means the
    # whole enrolled fleet.
    trigger_kind: Optional[
        Literal["enroll_dep", "enroll_profile", "checkin", "schedule"]
    ] = None
    sample_limit: int = 5


class _ScopePreviewExpired(Exception):
    """The preview walk ran out of time partway through one device."""


class _DeadlineConditions(list):
    """A scope's condition list that stops the walk once its budget is spent.

    Only safe where the caller treats a partial count as a floor, as this endpoint's truncated flag does.
    """

    def __init__(self, conditions: List[Any], deadline: float):
        super().__init__(conditions)
        self._deadline = deadline

    def __iter__(self):
        for condition in list.__iter__(self):
            if time.monotonic() > self._deadline:
                raise _ScopePreviewExpired()
            yield condition


def _walk_scope_preview(rows: List[Device], scope: Dict[str, Any], sample_limit: int):
    """Count the devices a non-empty scope matches, as (matched, scanned, sample, expired).

    Synchronous and CPU-bound, so the endpoint runs it through asyncio.to_thread; the rows arrive already loaded.
    """
    from controller.services.scoping import evaluate_scope

    deadline = time.monotonic() + SCOPE_PREVIEW_TIME_BUDGET_SECONDS
    walk_scope = dict(scope)
    conditions = walk_scope.get("conditions")
    if isinstance(conditions, list) and conditions:
        walk_scope["conditions"] = _DeadlineConditions(conditions, deadline)

    matched = 0
    scanned = 0
    sample: List[Device] = []
    for device in rows:
        if time.monotonic() > deadline:
            return matched, scanned, sample, True
        try:
            hit = evaluate_scope(device, list(device.groups or []), walk_scope)
        except _ScopePreviewExpired:
            return matched, scanned, sample, True
        scanned += 1
        if not hit:
            continue
        matched += 1
        if len(sample) < sample_limit:
            sample.append(device)
    return matched, scanned, sample, False


def _scope_preview_row(device: Device) -> Dict[str, Any]:
    """One named example of a matched device."""
    from controller.services.naming import display_name
    return {
        "id": str(device.id),
        "display_name": display_name(device),
        "serial_number": device.serial_number,
        "device_model": device.device_model,
    }


@router.post("/api/v1/scope/preview")
async def preview_scope(
    body: ScopePreviewRequest,
    principal: Principal = Depends(get_current_principal),
):
    """Count how many devices this scope matches right now, with a sample of them, computed the same way
    sweep_scheduled_starts does and read-only by construction."""
    tenant = principal.tenant
    from tortoise.expressions import Q
    from controller.services.scoping import MAX_SCOPE_CONDITIONS

    scope = body.scope or {}
    sample_limit = max(0, min(int(body.sample_limit), SCOPE_PREVIEW_MAX_SAMPLE))

    # kaboom goes the CPU
    conditions = scope.get("conditions")
    if isinstance(conditions, list) and len(conditions) > MAX_SCOPE_CONDITIONS:
        raise HTTPException(
            status_code=400,
            detail=(f"A scope preview accepts at most {MAX_SCOPE_CONDITIONS} conditions; "
                    f"this one has {len(conditions)}. Narrow it with a group instead."),
        )

    base = Device.filter(tenant=tenant, enrollment_state="enrolled")
    total = await base.count()

    eligible_q = base
    if body.trigger_kind == "enroll_dep":
        eligible_q = base.exclude(dep_profile_uuid__isnull=True).exclude(dep_profile_uuid="")
    elif body.trigger_kind == "enroll_profile":
        eligible_q = base.filter(Q(dep_profile_uuid__isnull=True) | Q(dep_profile_uuid=""))
    eligible = await eligible_q.count()

    is_empty = _scope_is_empty(scope)
    scanned = 0
    truncated = False
    sample_rows: List[Device] = []

    if is_empty:
        matched = eligible if body.empty_scope == "all" else 0
        if matched and sample_limit:
            sample_rows = (
                await eligible_q.order_by("id").limit(sample_limit)
                .only(*_SCOPE_PREVIEW_FIELDS).all()
            )
    else:
        rows = (
            await eligible_q.order_by("id").limit(SCOPE_PREVIEW_SCAN_CAP)
            .only(*_SCOPE_PREVIEW_FIELDS).all()
        )
        truncated = eligible > SCOPE_PREVIEW_SCAN_CAP
        matched, scanned, sample_rows, expired = await asyncio.to_thread(
            _walk_scope_preview, rows, scope, sample_limit)
        truncated = truncated or expired

    return {
        "matched": matched,
        "eligible": eligible,
        "total": total,
        # The reading that produced matched, echoed so the count cannot be attributed to the wrong one.
        "scope_is_empty": is_empty,
        "empty_scope": body.empty_scope,
        "trigger_kind": body.trigger_kind,
        # scanned and truncated describe the walk; truncated makes matched a floor rather than a total.
        "scanned": scanned,
        "truncated": truncated,
        "sample": [_scope_preview_row(d) for d in sample_rows],
    }
