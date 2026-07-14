"""Apple Declarative Device Management (DDM) core.

Computes each device's desired declaration set from declarations.yaml (plus
auto-managed status-subscriptions / org-info / device-properties declarations),
serves it to NanoMDM's ``-dm`` check-in proxy (controller/api/ddm.py), ingests
device StatusReports, and enqueues the DeclarativeManagement command that tells
a device to (re)synchronize.

Everything is computed on the fly from YAML + device state -- there is no
stored declaration table -- so tokens/manifest/declarations are always mutually
consistent. Removal happens by omission from the manifest (a non-200 from us
reaches the device as a 500, so 404 semantics are never load-bearing).

Identifier conventions (must stay stable -- devices key on them):
  mm.cfg.<yaml id> / mm.act.<yaml id>      YAML-authored configuration + activation
  mm.cfg.status-subscriptions (+ mm.act.)  auto status subscriptions
  mm.mgmt.org-info / mm.mgmt.properties    auto management declarations
"""

import base64
import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from controller.models.tenant import Device, Task, Tenant
from controller.services.group_manager import GroupManager
from controller.services.profile_manager import ProfileManager
from controller.services.scoping import device_in_rollout, device_platform_category, evaluate_scope

logger = logging.getLogger(__name__)

#  OS support gates (device channel) 
# iOS 15 supports DDM on user enrollments only -- out of scope for v1, so the
# device-channel floor is 16. Unknown platform/version means "unsupported".
_DDM_MIN_OS = {
    "Mac": "13",
    "iPhone": "16",
    "iPad": "16",
    "iPod": "16",
    "Apple TV": "16",
    "Apple Watch": "10",
}

# Status items every DDM device is subscribed to by default (yaml
# ``status_subscriptions:`` adds to this). Unsupported items just come back as
# per-item Errors; when client-capabilities are known they are filtered out.
DEFAULT_STATUS_SUBSCRIPTIONS = [
    "device.identifier.serial-number",
    "device.model.family",
    "device.operating-system.version",
    "device.operating-system.build-version",
    "passcode.is-compliant",
    "passcode.is-present",
    "softwareupdate.install-state",
    "softwareupdate.pending-version",
    "softwareupdate.failure-reason",
    "diskmanagement.filevault.enabled",
    "device.power.battery-health",
]


def device_supports_ddm(device: Device) -> bool:
    """Whether a device's platform/OS meets the DDM device-channel floor."""
    minimum = _DDM_MIN_OS.get(device_platform_category(getattr(device, "device_model", "")))
    if not minimum:
        return False
    from packaging import version
    try:
        return version.parse(getattr(device, "os_version", "") or "") >= version.parse(minimum)
    except Exception:
        return False


#  Tokens & manifest 

def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def server_token(decl_type: str, identifier: str, payload: Dict[str, Any],
                 extra: Optional[str] = None) -> str:
    """Content hash of one declaration -- MUST change whenever its payload does
    (devices diff on it). ``extra`` folds in out-of-band content the payload
    doesn't carry (the legacy bridge's referenced-profile hash)."""
    doc = {"Type": decl_type, "Identifier": identifier, "Payload": payload}
    if extra:
        doc["Extra"] = extra
    return hashlib.sha256(_canonical_json(doc).encode()).hexdigest()[:32]


def declarations_token(declarations: List[Dict[str, Any]]) -> str:
    """Opaque token over the whole declaration set; any change re-syncs."""
    lines = sorted(f"{d['Identifier']}:{d['ServerToken']}" for d in declarations)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()[:48]


def _ddm_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tokens_response(token: str) -> Dict[str, Any]:
    return {"SyncTokens": {"DeclarationsToken": token, "Timestamp": _ddm_timestamp()}}


def manifest_group(decl_type: str) -> str:
    """The declaration-items array (and URL path group) a Type belongs to."""
    if decl_type.startswith("com.apple.activation."):
        return "activation"
    if decl_type.startswith("com.apple.asset."):
        return "asset"
    if decl_type.startswith("com.apple.management."):
        return "management"
    return "configuration"


def build_manifest(declarations: List[Dict[str, Any]], token: str) -> Dict[str, Any]:
    """The declaration-items response: all four arrays required, [] when empty."""
    groups: Dict[str, List[Dict[str, str]]] = {
        "Activations": [], "Configurations": [], "Assets": [], "Management": [],
    }
    key = {"activation": "Activations", "configuration": "Configurations",
           "asset": "Assets", "management": "Management"}
    for d in declarations:
        groups[key[manifest_group(d["Type"])]].append(
            {"Identifier": d["Identifier"], "ServerToken": d["ServerToken"]}
        )
    return {"Declarations": groups, "DeclarationsToken": token}


#  HMAC (NanoMDM -dm-send-hmac-key / legacy-bridge URL signing) 

def _ddm_secret() -> str:
    return os.getenv("DDM_HMAC_SECRET") or os.getenv("WEBHOOK_SECRET") or ""


def verify_hmac_signature(body: bytes, signature: str) -> bool:
    """Verify NanoMDM's X-Hmac-Signature (base64 HMAC-SHA256 over the raw body;
    empty body for GETs). Fails closed when the secret is unconfigured."""
    secret = _ddm_secret()
    if not secret:
        logger.error("DDM: no DDM_HMAC_SECRET/WEBHOOK_SECRET configured; rejecting")
        return False
    expected = base64.b64encode(
        hmac.new(secret.encode(), body or b"", hashlib.sha256).digest()
    ).decode()
    return hmac.compare_digest(signature or "", expected)


def profile_bridge_sig(tenant_id: str, profile_id: str) -> str:
    """Signature gating the legacy-bridge mobileconfig URL. Deliberately has no
    expiry: any expiry component would churn the URL, hence the ServerToken,
    hence a pointless device re-sync. The endpoint additionally requires the
    profile to actually be bridged in declarations.yaml."""
    return hmac.new(
        _ddm_secret().encode(), f"{tenant_id}/{profile_id}".encode(), hashlib.sha256
    ).hexdigest()


def verify_profile_bridge_sig(tenant_id: str, profile_id: str, sig: str) -> bool:
    if not _ddm_secret():
        logger.error("DDM: no DDM_HMAC_SECRET/WEBHOOK_SECRET configured; rejecting")
        return False
    return hmac.compare_digest(sig or "", profile_bridge_sig(tenant_id, profile_id))


def profile_bridge_url(tenant_id: str, profile_id: str) -> Optional[str]:
    """Public download URL for a bridged legacy profile (None without PUBLIC_API_URL)."""
    public = (os.getenv("PUBLIC_API_URL") or "").rstrip("/")
    if not public:
        return None
    sig = profile_bridge_sig(tenant_id, profile_id)
    return f"{public}/public/ddm/profile/{tenant_id}/{profile_id}?sig={sig}"


#  Payload variable substitution 
# Deliberately NOT services.variables.render: that is hardened for device names
# (brace-stripping, whitespace collapsing) and would mangle arbitrary payload
# strings. Only these four placeholders are substituted, single-pass.

def _render_payload(value: Any, context: Dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {k: _render_payload(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_render_payload(v, context) for v in value]
    if isinstance(value, str):
        for key, sub in context.items():
            value = value.replace("{%s}" % key, sub)
        return value
    return value


def _device_context(device: Device) -> Dict[str, str]:
    return {
        "serial_number": device.serial_number or "",
        "udid": device.udid or "",
        "device_name": device.name or device.hostname or device.serial_number or "",
        "hostname": device.hostname or "",
    }


#  Status report merging 

def _is_identifier_list(value: Any) -> bool:
    return (isinstance(value, list) and value
            and all(isinstance(x, dict) and "identifier" in x for x in value))


def _merge_identifier_list(current: List[Dict[str, Any]],
                           delta: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply an incremental array delta keyed by "identifier": replace/insert
    entries, drop the ones flagged ``_removed``. Existing order is kept."""
    merged = {x.get("identifier"): x for x in current if isinstance(x, dict)}
    for item in delta:
        ident = item.get("identifier")
        if item.get("_removed"):
            merged.pop(ident, None)
        else:
            merged[ident] = item
    return list(merged.values())


def merge_status_items(base: Dict[str, Any], delta: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-merge an incremental StatusItems delta into the stored state.

    Dicts merge recursively; identifier-keyed arrays merge per element (with
    ``_removed`` honored); everything else (scalars, non-keyed arrays) replaces.
    """
    out = dict(base or {})
    for key, value in (delta or {}).items():
        current = out.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            out[key] = merge_status_items(current, value)
        elif _is_identifier_list(value):
            out[key] = _merge_identifier_list(
                current if isinstance(current, list) else [], value
            )
        else:
            out[key] = value
    return out


class DDMManager:
    """Per-tenant DDM orchestration (constructed like ProfileManager)."""

    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self.group_manager = GroupManager(tenant.id)

    #  Declaration set computation 

    async def build_device_declarations(
        self,
        device: Device,
        declarations_config: Dict[str, Any],
        groups_config: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """The full desired declaration set ({Type, Identifier, ServerToken,
        Payload}) for a device: scoped YAML items (config + paired activation),
        then the auto-managed declarations, then client-capabilities filtering.
        """
        device_groups = self.group_manager.evaluate_device_groups(device, groups_config)
        device_platform = ProfileManager._device_platform(device)
        context = _device_context(device)
        now = datetime.now(timezone.utc)
        declarations: List[Dict[str, Any]] = []

        profiles_by_id: Optional[Dict[str, Dict[str, Any]]] = None  # lazy (bridge only)

        for item in declarations_config.get("declarations") or []:
            item_id = item.get("id")
            if not item_id or not item.get("type"):
                continue  # validator rejects these; never crash the serve path

            platforms = item.get("platforms")
            if platforms and device_platform not in platforms:
                continue
            if not evaluate_scope(device, device_groups, item):
                continue
            rollout = item.get("rollout")
            if rollout and not device_in_rollout(device, rollout, f"declaration:{item_id}", now):
                continue  # held by rollout: simply not in the set yet

            cfg_id = f"mm.cfg.{item_id}"
            extra = None
            if item.get("type") == "com.apple.configuration.legacy" and item.get("profile"):
                # Legacy bridge: serve an existing profiles.yaml profile via a
                # signed public URL. The ServerToken folds in the profile
                # definition hash so a profile edit re-syncs the declaration.
                if profiles_by_id is None:
                    from controller.services.tenant_config import load_profiles
                    profiles_by_id = {p.get("id"): p for p in load_profiles(self.tenant.id)}
                profile = profiles_by_id.get(item["profile"])
                if profile is None:
                    logger.warning(
                        "DDM[%s]: declaration '%s' bridges unknown profile '%s'; skipping",
                        self.tenant.id, item_id, item["profile"],
                    )
                    continue
                url = profile_bridge_url(self.tenant.id, item["profile"])
                if not url:
                    logger.warning(
                        "DDM[%s]: PUBLIC_API_URL unset; cannot bridge profile '%s'",
                        self.tenant.id, item["profile"],
                    )
                    continue
                payload = {"ProfileURL": url}
                extra = ProfileManager.desired_hash(profile)
            else:
                payload = _render_payload(item.get("payload") or {}, context)

            declarations.append({
                "Type": item["type"],
                "Identifier": cfg_id,
                "ServerToken": server_token(item["type"], cfg_id, payload, extra=extra),
                "Payload": payload,
            })
            declarations.append(self._activation(f"mm.act.{item_id}", [cfg_id],
                                                 predicate=item.get("predicate")))

        declarations.extend(self._auto_declarations(device, device_groups, declarations_config))
        return self._filter_by_capabilities(device, declarations)

    def _activation(self, identifier: str, config_ids: List[str],
                    predicate: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"StandardConfigurations": config_ids}
        if predicate:
            payload["Predicate"] = predicate
        return {
            "Type": "com.apple.activation.simple",
            "Identifier": identifier,
            "ServerToken": server_token("com.apple.activation.simple", identifier, payload),
            "Payload": payload,
        }

    def _auto_declarations(self, device: Device, device_groups: List[str],
                           declarations_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """The always-on declarations: status subscriptions, org info and the
        device-properties declaration authors can reference in predicates
        (e.g. ``"kiosk" IN @property(tags)``)."""
        out: List[Dict[str, Any]] = []

        items = list(DEFAULT_STATUS_SUBSCRIPTIONS)
        for extra in declarations_config.get("status_subscriptions") or []:
            if extra not in items:
                items.append(extra)
        known = self._capability_status_items(device)
        if known:
            items = [i for i in items if i in known]
        sub_id = "mm.cfg.status-subscriptions"
        sub_type = "com.apple.configuration.management.status-subscriptions"
        sub_payload = {"StatusItems": [{"Name": name} for name in items]}
        out.append({
            "Type": sub_type,
            "Identifier": sub_id,
            "ServerToken": server_token(sub_type, sub_id, sub_payload),
            "Payload": sub_payload,
        })
        out.append(self._activation("mm.act.status-subscriptions", [sub_id]))

        org = declarations_config.get("organization_info") or {}
        org_payload = {"Name": org.get("name") or self.tenant.name}
        if org.get("email"):
            org_payload["Email"] = org["email"]
        if org.get("url"):
            org_payload["Website"] = org["url"]
        org_id = "mm.mgmt.org-info"
        org_type = "com.apple.management.organization-info"
        out.append({
            "Type": org_type,
            "Identifier": org_id,
            "ServerToken": server_token(org_type, org_id, org_payload),
            "Payload": org_payload,
        })

        # Freshly-computed memberships (not the stored device.groups snapshot),
        # so a group change re-tokens this declaration on the same reconcile.
        props_payload = {
            "serial": device.serial_number or "",
            "tags": sorted(device.tags or []),
            "groups": sorted(device_groups or []),
        }
        props_id = "mm.mgmt.properties"
        props_type = "com.apple.management.properties"
        out.append({
            "Type": props_type,
            "Identifier": props_id,
            "ServerToken": server_token(props_type, props_id, props_payload),
            "Payload": props_payload,
        })
        return out

    @staticmethod
    def _capability_declaration_types(device: Device) -> Optional[set]:
        """Declaration Types the device advertised support for (None = unknown,
        serve everything)."""
        caps = getattr(device, "ddm_client_capabilities", None) or {}
        decls = ((caps.get("supported-payloads") or {}).get("declarations") or {})
        types: set = set()
        for group in ("activations", "configurations", "assets", "management"):
            types.update(decls.get(group) or [])
        return types or None

    @staticmethod
    def _capability_status_items(device: Device) -> Optional[set]:
        caps = getattr(device, "ddm_client_capabilities", None) or {}
        items = (caps.get("supported-payloads") or {}).get("status-items")
        return set(items) if items else None

    def _filter_by_capabilities(self, device: Device,
                                declarations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Drop declarations the device does not advertise support for, and any
        activation left referencing a dropped configuration."""
        allowed = self._capability_declaration_types(device)
        if allowed is None:
            return declarations
        kept = [d for d in declarations if d["Type"] in allowed]
        kept_ids = {d["Identifier"] for d in kept}
        return [
            d for d in kept
            if not (d["Type"] == "com.apple.activation.simple"
                    and not all(c in kept_ids
                                for c in d["Payload"].get("StandardConfigurations", [])))
        ]

    #  Status report ingest 

    async def ingest_status_report(self, device: Device, report: Dict[str, Any]) -> None:
        """Merge a device StatusReport into stored state and fan out signals."""
        status_items = report.get("StatusItems") or {}
        if report.get("Errors"):
            logger.info("DDM[%s]: status report from %s carries %d error(s)",
                        self.tenant.id, device.serial_number, len(report["Errors"]))

        if report.get("FullReport"):
            # Safety sync: the device re-sends everything; replace, don't merge.
            device.ddm_status = status_items
        else:
            device.ddm_status = merge_status_items(device.ddm_status or {}, status_items)

        management = device.ddm_status.get("management") or {}

        decls = management.get("declarations")
        if isinstance(decls, dict):
            # The per-group arrays were already incrementally merged above, so a
            # flat rebuild reflects the device's full current declaration state.
            flat: Dict[str, Dict[str, Any]] = {}
            for group in ("activations", "configurations", "assets", "management"):
                for entry in decls.get(group) or []:
                    if isinstance(entry, dict) and entry.get("identifier"):
                        flat[entry["identifier"]] = {
                            "active": entry.get("active"),
                            "valid": entry.get("valid"),
                            "server-token": entry.get("server-token"),
                            "reasons": entry.get("reasons") or [],
                        }
            device.ddm_declaration_status = flat

        caps = management.get("client-capabilities")
        if isinstance(caps, dict) and caps:
            device.ddm_client_capabilities = caps

        # Keep inventory fresh: DDM reports the OS version on every update.
        os_version = ((device.ddm_status.get("device") or {})
                      .get("operating-system") or {}).get("version")
        if os_version:
            device.os_version = str(os_version)

        device.ddm_last_sync_at = datetime.now(timezone.utc)
        # Scoped save: status ingest races the webhook's inventory writes, and a
        # full-row save would clobber them.
        await device.save(update_fields=[
            "ddm_status", "ddm_declaration_status", "ddm_client_capabilities",
            "os_version", "ddm_last_sync_at",
        ])

        await self._fire_signals(device)
        await self._dispatcher_eval(device)

    async def _fire_signals(self, device: Device) -> None:
        """Best-effort ATC advancement -- mirrors webhook_handler's lazy-import
        pattern (an ATC failure must never break the device-facing response)."""
        try:
            from controller.services import atc
            await atc.advance_on_signal(str(device.id), "ddm_status")
            for identifier, state in (device.ddm_declaration_status or {}).items():
                if state.get("active") and state.get("valid") == "valid":
                    # wait_for refs use the yaml id for authored declarations.
                    ref = identifier[len("mm.cfg."):] if identifier.startswith("mm.cfg.") \
                        else identifier
                    await atc.advance_on_signal(str(device.id), "declaration_applied", ref)
        except Exception:
            logger.exception("DDM: ATC signal fan-out failed for %s", device.serial_number)

    async def _dispatcher_eval(self, device: Device) -> None:
        try:
            from controller.services import dispatcher
            await dispatcher.evaluate_device(device, reason="ddm")
        except Exception:
            logger.exception("DDM: dispatcher evaluate failed for %s", device.serial_number)

    #  Sync command 

    async def publish_sync_command(self, device: Device, connector: Any,
                                   declarations: Optional[List[Dict[str, Any]]] = None,
                                   ) -> Dict[str, Any]:
        """Enqueue DeclarativeManagement (tokens front-loaded so the device
        skips one GET) and stamp the device bookkeeping. No Task row -- callers
        audit their own way (sync_device / the command-catalog dispatch)."""
        if declarations is None:
            from controller.services.tenant_config import load_declarations, load_groups
            declarations = await self.build_device_declarations(
                device, load_declarations(self.tenant.id), load_groups(self.tenant.id)
            )
        token = declarations_token(declarations)
        tokens_json = json.dumps(tokens_response(token)).encode()
        result = await connector.declarative_management(device.udid, tokens_json)
        if not device.ddm_enabled_at:
            device.ddm_enabled_at = datetime.now(timezone.utc)
        device.ddm_last_published_token = token
        await device.save(update_fields=["ddm_enabled_at", "ddm_last_published_token"])
        return {"command_uuid": result.get("command_uuid"), "declarations_token": token}

    async def sync_device(self, device: Device, reason: str,
                          mdm_connector: Optional[Any] = None) -> bool:
        """Enqueue a DeclarativeManagement command when the published token is
        stale. Returns False on a no-op (unsupported / unchanged)."""
        if not self.tenant.ddm_enabled or not device.udid \
                or device.enrollment_state != "enrolled" or not device_supports_ddm(device):
            return False

        from controller.services.tenant_config import load_declarations, load_groups
        declarations = await self.build_device_declarations(
            device, load_declarations(self.tenant.id), load_groups(self.tenant.id)
        )
        token = declarations_token(declarations)
        if token == device.ddm_last_published_token and device.ddm_enabled_at:
            return False

        from controller.services.mdm_connector import MDMConnector
        own_connector = mdm_connector is None
        connector = mdm_connector or MDMConnector()
        try:
            published = await self.publish_sync_command(device, connector, declarations)
        finally:
            if own_connector:
                await connector.close()

        # A task row so the sync shows on the device Commands tab; the webhook
        # completes/fails it by command_uuid (type "ddm_sync").
        await Task.create(
            tenant=self.tenant,
            type="ddm_sync",
            status="running",
            description=f"Declarative sync ({reason})",
            device=device,
            user="system",
            details={"command_uuid": published["command_uuid"], "reason": reason,
                     "declarations_token": published["declarations_token"]},
        )
        logger.info("DDM[%s]: queued declarative sync for %s (%s)",
                    self.tenant.id, device.serial_number, reason)
        return True


#  Module-level conveniences (webhook/API/ATC call sites) 

async def _manager_for(device: Device) -> Optional[DDMManager]:
    tenant = await Tenant.get_or_none(id=device.tenant_id)
    return DDMManager(tenant) if tenant else None


async def compute_device_declarations(device: Device,
                                      tenant: Optional[Tenant] = None) -> List[Dict[str, Any]]:
    """Desired declaration set for a device, empty when DDM does not apply
    (tenant disabled / unsupported device) -- the clean-neutralization path the
    device-facing endpoints rely on."""
    tenant = tenant or await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None or not tenant.ddm_enabled or not device_supports_ddm(device):
        return []
    from controller.services.tenant_config import load_declarations, load_groups
    return await DDMManager(tenant).build_device_declarations(
        device, load_declarations(tenant.id), load_groups(tenant.id)
    )


async def ingest_status_report(device: Device, report: Dict[str, Any]) -> None:
    manager = await _manager_for(device)
    if manager:
        await manager.ingest_status_report(device, report)


async def sync_device(device: Device, reason: str,
                      mdm_connector: Optional[Any] = None) -> bool:
    manager = await _manager_for(device)
    if manager is None:
        return False
    return await manager.sync_device(device, reason, mdm_connector=mdm_connector)


async def enqueue_sync_command(device: Device, connector: Any) -> Dict[str, Any]:
    """Command-catalog path (services.device_commands): always sends -- a
    manually issued sync must never be silently dropped by the token no-op --
    and the caller creates the audit Task. Raises ValueError when DDM does not
    apply to the device."""
    manager = await _manager_for(device)
    if manager is None or not manager.tenant.ddm_enabled:
        raise ValueError("Declarative Device Management is not enabled for this tenant")
    if not device_supports_ddm(device):
        raise ValueError("This device's OS does not support Declarative Device Management")
    return await manager.publish_sync_command(device, connector)
