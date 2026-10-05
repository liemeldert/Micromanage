"""Apple Declarative Device Management (DDM) core.

Computes each device's declaration set from declarations.yaml plus the auto-managed ones, serves it to NanoMDM's -dm
check-in proxy (controller/api/ddm.py), ingests device StatusReports and queues the DeclarativeManagement command that
tells a device to resynchronize. Nothing is stored, and removal is by omission from the manifest.

Declaration identifiers (mm.cfg.*, mm.act.*, mm.mgmt.*) have to stay stable, because devices key on them.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from collections import OrderedDict
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

from controller.models.tenant import Device, Task, Tenant
from controller.services import readiness
from controller.services.group_manager import GroupManager
from controller.services.profile_manager import ProfileManager
from controller.services.scoping import device_in_rollout, device_platform_category, evaluate_scope
from controller.utils import compare
from controller.utils.timeutil import parse_iso_utc
from packaging import version

logger = logging.getLogger(__name__)

# ==OS support floors (device channel)==
# iOS 15 only does DDM on user enrollments, which we don't handle yet, so the device-channel floor is 16. Unknown
# platform or version means unsupported.
_DDM_MIN_OS = {
    "Mac": "13",
    "iPhone": "16",
    "iPad": "16",
    "iPod": "16",
    "Apple TV": "16",
    "Apple Watch": "10",
    # visionOS carries DDM from 1.1, its first release with the protocol:
    # https://raw.githubusercontent.com/apple/device-management/release/declarative/protocol/tokensresponse.yaml
    "Apple Vision Pro": "1.1",
}

# The DDM protocol version this server implements, advertised to devices in the server-capabilities declaration. Devices
# report the versions they accept in management.client-capabilities as supported-versions.
DDM_PROTOCOL_VERSION = "1.0.0"

# Parsed once at import time: these are hardcoded literal floors, never device or config input, so nothing here can fail
# to parse. device_supports_ddm then parses only the device's own os_version, the one value that changes per call.
_DDM_MIN_OS_PARSED = {platform: version.parse(v) for platform, v in _DDM_MIN_OS.items()}

# Status items every DDM device is subscribed to by default (yaml status_subscriptions: adds to this). Unsupported items
# just come back as per-item Errors; when client-capabilities are known they are filtered out.
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
    minimum = _DDM_MIN_OS_PARSED.get(device_platform_category(getattr(device, "device_model", "")))
    if not minimum:
        return False
    try:
        return version.parse(getattr(device, "os_version", "") or "") >= minimum
    except Exception:
        return False


# ==Tokens & manifest==

def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def server_token(decl_type: str, identifier: str, payload: Dict[str, Any],
                 extra: Optional[str] = None) -> str:
    """Content hash of one declaration. Devices diff on this, so it has to move whenever the payload does. extra folds
    in content the payload doesn't itself carry, like the legacy bridge's referenced-profile hash."""
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


# ==HMAC (NanoMDM -dm-send-hmac-key / legacy-bridge URL signing)==

def _ddm_secret() -> str:
    return readiness.ddm_secret()


_sig_eq = compare.constant_time_eq


def verify_hmac_signature(body: bytes, signature: str) -> bool:
    """Verify NanoMDM's X-Hmac-Signature (base64 HMAC-SHA256 over the raw body; empty body for GETs). Fails closed when
    the secret is unconfigured."""
    secret = _ddm_secret()
    if not secret:
        logger.error("DDM: no DDM_HMAC_SECRET/WEBHOOK_SECRET configured; rejecting")
        return False
    expected = base64.b64encode(
        hmac.new(secret.encode(), body or b"", hashlib.sha256).digest()
    ).decode()
    return _sig_eq(signature, expected)


def profile_bridge_sig(tenant_id: str, profile_id: str) -> str:
    """Signature the legacy-bridge mobileconfig URL carries. No expiry component: it would churn the URL, hence the
    ServerToken, hence a pointless device re-sync. The endpoint additionally requires the profile to actually be bridged
    in declarations.yaml."""
    return hmac.new(
        _ddm_secret().encode(), f"{tenant_id}/{profile_id}".encode(), hashlib.sha256
    ).hexdigest()


def verify_profile_bridge_sig(tenant_id: str, profile_id: str, sig: str) -> bool:
    if not _ddm_secret():
        logger.error("DDM: no DDM_HMAC_SECRET/WEBHOOK_SECRET configured; rejecting")
        return False
    return _sig_eq(sig, profile_bridge_sig(tenant_id, profile_id))


@lru_cache(maxsize=8)
def _warn_bridge_host(public_host: str, server_host: str) -> None:
    """Say once per host pair that the bridged ProfileURL is off the MDM server.

    Cached on its arguments so this logs once rather than once per declaration build (per device per sync burst).
    """
    logger.warning(
        "DDM: the bridged ProfileURL host '%s' is not the MDM server host '%s'; com.apple.configuration.legacy expects "
        "the profile to be hosted by the MDM server, so a device may refuse to download it",
        public_host, server_host,
    )


@lru_cache(maxsize=256)
def _warn_undeliverable(tenant_id: str, declaration_id: str, reason: str) -> None:
    """Say once that an authored declaration cannot be served to anybody. Cached on its arguments, so it logs once per
    declaration and reason rather than once per device per cycle."""
    logger.warning(
        "DDM[%s]: declaration '%s' is authored but cannot be served to any "
        "device: %s. No device will receive it until this is fixed.",
        tenant_id, declaration_id, reason,
    )


def undeliverable_reason(item: Dict[str, Any], tenant_id: str,
                         profiles_by_id: Optional[Dict[str, Any]] = None,
                         ) -> Optional[str]:
    """Why an authored declaration can reach no device at all, or None. Unlike scoping, this covers an item that is in
    scope but cannot be built because something outside declarations.yaml is missing (only the legacy bridge today)."""
    if item.get("type") != "com.apple.configuration.legacy":
        return None
    profile_id = item.get("profile")
    if not profile_id:
        return None  # the validator rejects this; not this function's call
    servable = readiness.check(readiness.DDM_BRIDGE)
    if not servable.ready:
        # Trailing full stop trimmed: this reason is composed into a longer sentence by every caller that shows it.
        return servable.reason.rstrip(".")
    if profiles_by_id is None:
        from controller.services.tenant_config import load_profiles
        profiles_by_id = {p.get("id"): p for p in load_profiles(tenant_id)}
    if profile_id not in profiles_by_id:
        return f"it bridges profile '{profile_id}', which is not in profiles.yaml"
    return None


def profile_bridge_url(tenant_id: str, profile_id: str) -> Optional[str]:
    """Public download URL for a bridged legacy profile, or None when PUBLIC_API_URL cannot carry one. The build path
    asks undeliverable_reason first, which answers the same question with a reason string."""
    if not readiness.check(readiness.DDM_BRIDGE).ready:
        return None
    public = readiness.public_api_url()
    # Warn, don't refuse, if PUBLIC_API_URL and MDM_SERVER_URL name different hosts: they describe what is meant to be
    # one host but nothing else notices drift, and the profile still downloads from wherever it is.
    server = os.getenv("MDM_SERVER_URL") or ""
    if server:
        public_host = urlsplit(public).hostname or ""
        server_host = urlsplit(server).hostname or ""
        if public_host and server_host and public_host != server_host:
            _warn_bridge_host(public_host, server_host)
    sig = profile_bridge_sig(tenant_id, profile_id)
    return f"{public}/public/ddm/profile/{tenant_id}/{profile_id}?sig={sig}"


# ==Payload variable substitution==
# Kept away from services.variables.render, which is hardened for device names (brace-stripping, whitespace collapsing)
# and would mangle arbitrary payload strings. Only these four placeholders are substituted, single-pass.

def json_safe(value: Any) -> Any:
    """A date/datetime leaf as the ISO string the DDM schemas ask for; anything else is returned untouched.

    YAML turns an unquoted timestamp into datetime.datetime, which json.dumps refuses. Naive datetimes keep wall-clock
    form (local time); aware ones normalize to UTC with a Z suffix."""
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return value.strftime("%Y-%m-%dT%H:%M:%S")
    if isinstance(value, date):
        return value.isoformat()
    return value


def _render_payload(value: Any, context: Dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {k: _render_payload(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_render_payload(v, context) for v in value]
    if isinstance(value, str):
        for key, sub in context.items():
            value = value.replace("{%s}" % key, sub)
        return value
    return json_safe(value)


def _device_context(device: Device) -> Dict[str, str]:
    return {
        "serial_number": device.serial_number or "",
        "udid": device.udid or "",
        "device_name": device.name or device.hostname or device.serial_number or "",
        "hostname": device.hostname or "",
    }


# ==Status report merging==

def _is_identifier_list(value: Any) -> bool:
    """Whether a delta array can be merged per element. identifier must be a string, since it becomes a dict key here
    and a set member downstream and an unhashable value would raise; an array that fails this replaces wholesale."""
    return (isinstance(value, list) and value
            and all(isinstance(x, dict) and isinstance(x.get("identifier"), str)
                    for x in value))


def _merge_identifier_list(current: List[Dict[str, Any]],
                           delta: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply an incremental array delta keyed by "identifier": replace/insert entries, drop the ones flagged _removed.
    Existing order is kept.

    management.declarations has no _removed, so removals there are handled by prune_unserved_declarations."""
    merged = {x["identifier"]: x for x in current
              if isinstance(x, dict) and isinstance(x.get("identifier"), str)}
    for item in delta:
        ident = item.get("identifier")
        if item.get("_removed"):
            merged.pop(ident, None)
        else:
            merged[ident] = item
    return list(merged.values())


def merge_status_items(base: Dict[str, Any], delta: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-merge an incremental StatusItems delta into the stored state.

    Dicts merge recursively, identifier-keyed arrays merge per element, and everything else replaces. An empty array
    against a stored identifier-keyed one leaves it as it is instead of clearing it.

    https://raw.githubusercontent.com/apple/device-management/release/declarative/status/management.declarations.yaml
    https://raw.githubusercontent.com/apple/device-management/release/declarative/protocol/statusreport.yaml
    """
    out = dict(base) if isinstance(base, dict) else {}
    for key, value in (delta if isinstance(delta, dict) else {}).items():
        current = out.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            out[key] = merge_status_items(current, value)
        elif _is_identifier_list(value):
            out[key] = _merge_identifier_list(
                current if isinstance(current, list) else [], value
            )
        elif isinstance(value, list) and not value and _is_identifier_list(current):
            continue  # no changes for this array; keep what is stored
        else:
            out[key] = value
    return out


# The four arrays a management.declarations status item is made of, in the order Apple lists them. Also the manifest
# groups declarations are served under.
DECLARATION_GROUPS = ("activations", "configurations", "assets", "management")


def declaration_identifiers(declarations_status: Any) -> set:
    """Every identifier named in one management.declarations value."""
    named: set = set()
    if not isinstance(declarations_status, dict):
        return named
    for group in DECLARATION_GROUPS:
        entries = declarations_status.get(group)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            # str, not merely truthy: a wire value that is a list here would raise on the "in" checks this set answers.
            if isinstance(entry, dict) and isinstance(entry.get("identifier"), str):
                named.add(entry["identifier"])
    return named


def prune_unserved_declarations(declarations_status: Dict[str, Any],
                                served: set, mentioned: set) -> Dict[str, Any]:
    """Drop reported declarations this server has stopped publishing. Returns a new value; the input is left alone.

    management.declarations has no _removed marker, so absence from an incremental report is not evidence of removal.
    An entry drops only when it is in neither served (published by this server) nor mentioned (named in this report).

    https://developer.apple.com/documentation/devicemanagement/statusmanagementdeclarations
    https://raw.githubusercontent.com/apple/device-management/release/declarative/protocol/statusreport.yaml
    https://raw.githubusercontent.com/apple/device-management/release/declarative/status/security.certificate.list.yaml
    """
    pruned: Dict[str, Any] = dict(declarations_status)
    for group in DECLARATION_GROUPS:
        entries = declarations_status.get(group)
        if not isinstance(entries, list):
            continue
        pruned[group] = [
            entry for entry in entries
            if not (isinstance(entry, dict)
                    and isinstance(entry.get("identifier"), str)
                    and entry["identifier"] not in served
                    and entry["identifier"] not in mentioned)
        ]
    return pruned


# Device attributes key recording a refused DeclarativeManagement enqueue: timestamp, consecutive attempt count, reason
# and declarations token. Not in ddm_status, which holds what the device reports and is replaced by a full report.
SYNC_FAILURE_KEY = "ddm_sync_failure"

# Ceiling on the failure phrase below. It goes into a log line, Task.error, the record on the device row and an HTTP
# error detail, and NanoMDM's own text can carry a whole database error, so it is cut rather than letting any of those
# four grow without bound.
_REASON_MAX_CHARS = 300


class EnqueueFailed(int):
    """A refused DeclarativeManagement enqueue (NanoMDM down, or no enrollment for this device).

    Falsy like the False a no-op gives, but carries reason so a caller can tell them apart. Returned, not raised, so a
    fleet loop keeps going."""

    reason: str

    def __new__(cls, reason: str) -> "EnqueueFailed":
        result = super().__new__(cls, 0)
        result.reason = reason
        return result

    def __repr__(self) -> str:
        return f"EnqueueFailed({self.reason!r})"


class SyncHeldOff(int):
    """A sync left unattempted, because the last one was refused.

    Falsy like EnqueueFailed, but not a subclass of it, since a held-off device is the backoff working and not a fresh
    error. A plain False would read as "already in sync". retry_at is when the next attempt is due."""

    reason: str
    retry_at: Optional[datetime]

    def __new__(cls, reason: str,
                retry_at: Optional[datetime] = None) -> "SyncHeldOff":
        result = super().__new__(cls, 0)
        result.reason = reason
        result.retry_at = retry_at
        return result

    def __repr__(self) -> str:
        return f"SyncHeldOff({self.reason!r})"


def _enqueue_failure_reason(exc: BaseException) -> Tuple[str, bool]:
    """A short phrase for a refused enqueue, and whether the failure keeps its traceback. Expected states (no enrollment
    row, NanoMDM unreachable) log one line; anything else logs a traceback."""
    try:
        import httpx

        from controller.services.mdm_connector import EnqueueError
    except Exception:  # pragma: no cover - httpx is a hard dependency of the connector
        return f"{type(exc).__name__}: {exc}", True
    if isinstance(exc, EnqueueError):
        # Already a sentence about this device (NanoMDM's own command_error text); a status prefix would repeat it.
        return str(exc)[:_REASON_MAX_CHARS], False
    if isinstance(exc, httpx.HTTPStatusError):
        # Keep the status in front: a partial failure (207) is worth telling apart from a whole refusal (500).
        summary = f"NanoMDM rejected the enqueue with HTTP {exc.response.status_code}"
        detail = str(exc).strip()
        composed = f"{summary}: {detail}" if detail else summary
        return composed[:_REASON_MAX_CHARS], False
    if isinstance(exc, httpx.HTTPError):
        return f"NanoMDM is unreachable ({type(exc).__name__})", False
    return f"{type(exc).__name__}: {exc}", True


class DDMManager:
    """Per-tenant DDM orchestration (constructed like ProfileManager)."""

    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self.group_manager = GroupManager(tenant.id)

    # ==Declaration set computation==

    async def build_device_declarations(
        self,
        device: Device,
        declarations_config: Dict[str, Any],
        groups_config: List[Dict[str, Any]],
        device_groups: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """The desired declarations for a device, as dicts with Type, Identifier, ServerToken and Payload: scoped YAML
        items (configuration and activation), then the auto-managed ones, filtered by client capabilities.

        device_groups is an optional pre-computed membership list, so a fleet loop does not re-walk the group graph."""
        if device_groups is None:
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
                # Legacy bridge: serve an existing profiles.yaml profile via a signed public URL. The ServerToken folds
                # in the profile definition hash so a profile edit re-syncs the declaration.
                if profiles_by_id is None:
                    from controller.services.tenant_config import load_profiles
                    profiles_by_id = {p.get("id"): p for p in load_profiles(self.tenant.id)}
                blocked = undeliverable_reason(item, self.tenant.id, profiles_by_id)
                if blocked:
                    # Nothing to do with this device: the item can reach no device at all, so it is logged once rather
                    # than once per device per cycle. The same answer is available to callers that list declarations.
                    _warn_undeliverable(self.tenant.id, item_id, blocked)
                    continue
                url = profile_bridge_url(self.tenant.id, item["profile"])
                if not url:
                    # undeliverable_reason just cleared this item, so getting here means the two disagree. Still a drop,
                    # but never a silent one.
                    _warn_undeliverable(self.tenant.id, item_id,
                                        "the bridged profile URL could not be built")
                    continue
                payload = {"ProfileURL": url}
                extra = ProfileManager.desired_hash(profiles_by_id[item["profile"]])
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
        """The always-on declarations: status subscriptions, org info and the device-properties declaration authors can
        reference in predicates (e.g. "kiosk" IN @property(tags))."""
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
            # Apple's organization-info declaration calls this URL, not Website.
            org_payload["URL"] = org["url"]
        org_id = "mm.mgmt.org-info"
        org_type = "com.apple.management.organization-info"
        out.append({
            "Type": org_type,
            "Identifier": org_id,
            "ServerToken": server_token(org_type, org_id, org_payload),
            "Payload": org_payload,
        })

        # The server's half of the capability handshake (device advertises via management.client-capabilities).
        # SupportedFeatures is required; this server implements none, so an empty dict rather than absent.
        caps_payload = {"Version": DDM_PROTOCOL_VERSION, "SupportedFeatures": {}}
        caps_id = "mm.mgmt.server-capabilities"
        caps_type = "com.apple.management.server-capabilities"
        out.append({
            "Type": caps_type,
            "Identifier": caps_id,
            "ServerToken": server_token(caps_type, caps_id, caps_payload),
            "Payload": caps_payload,
        })

        # Freshly-computed memberships (not the stored device.groups snapshot), so a group change re-tokens this
        # declaration on the same reconcile.
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
    def _capability_payloads(device: Device) -> Dict[str, Any]:
        """The device's advertised supported-payloads tree, or {}.

        A non-object anywhere on the way down reads as nothing advertised rather than raising, so a malformed stored
        value means unknown capabilities (everything is served), not an error on the device's endpoints."""
        caps = getattr(device, "ddm_client_capabilities", None)
        payloads = caps.get("supported-payloads") if isinstance(caps, dict) else None
        return payloads if isinstance(payloads, dict) else {}

    @staticmethod
    def _capability_declaration_types(device: Device) -> Optional[set]:
        """Declaration Types the device advertised support for (None = unknown,
        serve everything)."""
        decls = DDMManager._capability_payloads(device).get("declarations")
        if not isinstance(decls, dict):
            return None
        types: set = set()
        for group in ("activations", "configurations", "assets", "management"):
            entries = decls.get(group)
            if isinstance(entries, list):
                types.update(t for t in entries if isinstance(t, str))
        return types or None

    @staticmethod
    def _capability_status_items(device: Device) -> Optional[set]:
        items = DDMManager._capability_payloads(device).get("status-items")
        if not isinstance(items, list):
            return None
        names = {i for i in items if isinstance(i, str)}
        return names or None

    def _filter_by_capabilities(self, device: Device,
                                declarations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Drop declarations the device does not advertise support for, and any activation left referencing a dropped
        configuration."""
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

    # ==Status report ingest==

    async def ingest_status_report(self, device: Device, report: Dict[str, Any]) -> None:
        """Merge a device StatusReport into stored state and fan out signals.

        A malformed report is dropped or ingested in part rather than raised, since an exception in the device-facing
        endpoint becomes a 500 the device retries."""
        status_items = report.get("StatusItems")
        if status_items is None:
            status_items = {}
        elif not isinstance(status_items, dict):
            logger.warning(
                "DDM[%s]: status report from %s carries a non-object StatusItems (%s); ignoring the report",
                self.tenant.id, device.serial_number, type(status_items).__name__,
            )
            return
        errors = report.get("Errors")
        if errors:
            logger.info("DDM[%s]: status report from %s carries %d error(s)",
                        self.tenant.id, device.serial_number,
                        len(errors) if isinstance(errors, (list, dict)) else 1)

        # What this report itself names, read before the merge folds it into everything reported before: half of the
        # prune rule below, the half that keeps a full report authoritative.
        management_delta = status_items.get("management")
        mentioned = declaration_identifiers(
            management_delta.get("declarations")
            if isinstance(management_delta, dict) else None
        )

        if report.get("FullReport"):
            # Safety sync: the device re-sends everything; replace, don't merge.
            device.ddm_status = status_items
        else:
            device.ddm_status = merge_status_items(device.ddm_status, status_items)

        management = device.ddm_status.get("management")
        if not isinstance(management, dict):
            management = {}

        decls = management.get("declarations")
        if isinstance(decls, dict):
            # Declarations no longer served drop out here, not in the merge above, because a device that stops holding
            # one sends no removal marker. See prune_unserved_declarations.
            served = await self._served_identifiers(device)
            if served:
                decls = prune_unserved_declarations(decls, served, mentioned)
                device.ddm_status = {
                    **device.ddm_status,
                    "management": {**management, "declarations": decls},
                }
            # The per-group arrays were already incrementally merged above, so a flat rebuild reflects the device's full
            # current declaration state.
            flat: Dict[str, Dict[str, Any]] = {}
            for group in DECLARATION_GROUPS:
                entries = decls.get(group)
                for entry in entries if isinstance(entries, list) else []:
                    if isinstance(entry, dict) and isinstance(entry.get("identifier"), str):
                        flat[entry["identifier"]] = {
                            "active": entry.get("active"),
                            "valid": entry.get("valid"),
                            "server-token": entry.get("server-token"),
                            "reasons": entry.get("reasons") or [],
                        }
            device.ddm_declaration_status = flat

        caps = management.get("client-capabilities")
        if isinstance(caps, dict) and caps:
            # supported-payloads feeds every later declaration build; a non-object there would be a device handing
            # itself a permanent 500, so it is dropped here and the rest of what the device said is kept.
            if "supported-payloads" in caps \
                and not isinstance(caps["supported-payloads"], dict):
                logger.warning(
                    "DDM[%s]: %s advertised a non-object supported-payloads (%s); ignoring it",
                    self.tenant.id, device.serial_number,
                    type(caps["supported-payloads"]).__name__,
                )
                caps = {k: v for k, v in caps.items() if k != "supported-payloads"}
            if caps:
                device.ddm_client_capabilities = caps

        # Keep inventory fresh: DDM reports the OS version on every update.
        device_tree = device.ddm_status.get("device")
        os_tree = (device_tree.get("operating-system")
                   if isinstance(device_tree, dict) else None)
        os_version = os_tree.get("version") if isinstance(os_tree, dict) else None
        if os_version and isinstance(os_version, (str, int, float)):
            device.os_version = str(os_version)

        device.ddm_last_sync_at = datetime.now(timezone.utc)
        # Scoped save: status ingest races the webhook's inventory writes, and a full-row save would clobber them.
        await device.save(update_fields=[
            "ddm_status", "ddm_declaration_status", "ddm_client_capabilities",
            "os_version", "ddm_last_sync_at",
        ])

        # Deferred behind the webhook's per-device lock: inline fan-out here could overlap a deferred advance for the
        # same device, and two concurrent _apply_tags calls silently lose a tag. Same split as webhook_handler.
        from controller.services.webhook_handler import _defer
        _defer(device.id, self._fire_signals(device.id))
        _defer(device.id, self._dispatcher_eval(device.id))

    async def _served_identifiers(self, device: Device) -> set:
        """Identifiers this server currently publishes to a device.

        Empty both when DDM does not apply and when the set cannot be computed; status ingest treats both as no evidence
        and leaves the reported set alone. Uses the cached build."""
        try:
            served = await compute_device_declarations_cached(device, self.tenant)
        except Exception:
            logger.warning(
                "DDM[%s]: could not compute the served declaration set for %s; leaving the reported declarations alone",
                self.tenant.id, device.serial_number, exc_info=True,
            )
            return set()
        return {d["Identifier"] for d in served}

    async def _fire_signals(self, device_id: Any) -> None:
        """Advance ATC, best-effort. Runs deferred (webhook_handler._defer), so it takes the id and re-reads the row
        rather than pinning the ddm_status blob, and the signals derive from committed state."""
        try:
            device = await Device.get_or_none(id=device_id)
            if device is None:
                return
            from controller.services import atc
            await atc.advance_on_signal(str(device.id), "ddm_status")
            for identifier, state in (device.ddm_declaration_status or {}).items():
                if state.get("active") and state.get("valid") == "valid":
                    # wait_for refs use the yaml id for authored declarations.
                    ref = identifier[len("mm.cfg."):] if identifier.startswith("mm.cfg.") \
                        else identifier
                    await atc.advance_on_signal(str(device.id), "declaration_applied", ref)
        except Exception:
            logger.exception("DDM: ATC signal fan-out failed for device %s", device_id)

    async def _dispatcher_eval(self, device_id: Any) -> None:
        try:
            from controller.services import dispatcher
            await dispatcher.evaluate_device_id(device_id, "ddm")
        except Exception:
            logger.exception("DDM: dispatcher evaluate failed for device %s", device_id)

    # ==Sync command==

    async def publish_sync_command(self, device: Device, connector: Any,
                                   declarations: Optional[List[Dict[str, Any]]] = None,
                                   ) -> Dict[str, Any]:
        """Enqueue DeclarativeManagement and stamp the device bookkeeping.

        Tokens are front-loaded so the device skips a GET. No Task row here; callers do their own auditing."""
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

    # ==Refused enqueues==

    @staticmethod
    def _failure_state(device: Device) -> Dict[str, Any]:
        """The recorded enqueue failure for a device, or {} if it has none."""
        state = (getattr(device, "attributes", None) or {}).get(SYNC_FAILURE_KEY)
        return state if isinstance(state, dict) else {}

    @staticmethod
    def _retry_wait_minutes(attempts: Any) -> int:
        """How long to leave a refused enqueue alone before trying it again.

        Same curve as the failed-deployment retry in services.reconciler, so retuning that retunes this."""
        from controller.services.reconciler import RETRY_MAX_MINUTES, RETRY_MINUTES
        exponent = min(max(int(attempts or 0) - 1, 0), 20)
        return min(RETRY_MINUTES * (2 ** exponent), RETRY_MAX_MINUTES)

    def _held_until(self, device: Device, token: str,
                    now: datetime) -> Optional[datetime]:
        """When the next attempt at this set is due, or None if it is due now.

        Keyed on the declarations token, so editing a declaration takes effect next cycle, not after the backoff."""
        state = self._failure_state(device)
        if not state or state.get("declarations_token") != token:
            return None
        failed_at = parse_iso_utc(state.get("at"))
        if failed_at is None:
            return None  # unreadable stamp: treat it as no backoff at all
        due = failed_at + timedelta(
            minutes=self._retry_wait_minutes(state.get("attempts"))
        )
        return due if now < due else None

    async def _write_failure_state(
        self, device: Device, build: Any,
    ) -> Optional[Dict[str, Any]]:
        """Store or clear the enqueue-failure record, touching nothing else. Returns what was stored.

        build takes the record as it stands on the row now (re-read, not the caller's possibly stale copy) and returns
        the record to store, or None to clear."""
        row = await Device.filter(id=device.id).only("id", "attributes").first()
        attributes = dict((row.attributes if row else device.attributes) or {})
        current = attributes.get(SYNC_FAILURE_KEY)
        state = build(current if isinstance(current, dict) else {})
        if state is None:
            attributes.pop(SYNC_FAILURE_KEY, None)
        else:
            attributes[SYNC_FAILURE_KEY] = state
        await Device.filter(id=device.id).update(attributes=attributes)
        device.attributes = attributes
        return state

    async def _clear_failure_state(self, device: Device) -> None:
        """Drop the enqueue-failure record, if there is one."""
        if self._failure_state(device):
            await self._write_failure_state(device, lambda current: None)

    async def _record_enqueue_failure(self, device: Device, reason: str, token: str,
                                      exc: BaseException) -> EnqueueFailed:
        """Log, record and audit one refused enqueue, then hand back a falsy result.

        Leaves three things: a log line naming the device and the cause, a failed ddm_sync task against the device, and
        the state on the device row that makes the next attempt wait."""
        summary, unexpected = _enqueue_failure_reason(exc)

        def build(current: Dict[str, Any]) -> Dict[str, Any]:
            # Consecutive only while the set is the same one. A different set is a different failure and starts the
            # curve again.
            attempts = (int(current.get("attempts") or 0) + 1
                        if current.get("declarations_token") == token else 1)
            return {
                "at": datetime.now(timezone.utc).isoformat(),
                "attempts": attempts,
                "reason": summary,
                "declarations_token": token,
            }

        try:
            state = await self._write_failure_state(device, build)
        except Exception:
            # Without the record the next cycle simply tries again, worth a line and nothing more; fall back to the row
            # in hand so the count below still has a source.
            logger.warning("DDM[%s]: could not record the sync failure for %s",
                           self.tenant.id, device.serial_number, exc_info=True)
            state = build(self._failure_state(device))
        attempts = int((state or {}).get("attempts") or 1)

        message = "DDM[%s]: declarative sync for %s not queued: %s (attempt %d, next attempt in %dm)"
        args = (self.tenant.id, device.serial_number or device.udid, summary,
                attempts, self._retry_wait_minutes(attempts))
        if unexpected:
            # exc_info by value, not by ambient exception state: this runs one
            # await away from the except block that caught it.
            logger.error(message, *args, exc_info=exc)
        else:
            logger.warning(message, *args)

        try:
            await Task.create(
                tenant=self.tenant,
                type="ddm_sync",
                status="failed",
                description=f"Declarative sync ({reason})",
                device=device,
                user="system",
                details={"reason": reason, "declarations_token": token,
                         "attempts": attempts},
                error=summary,
                # Born terminal, so it never passes through update_progress and nothing else would ever stamp this. Task
                # retention keys on completed_at, and a NULL leaves the row forever: one per refused enqueue per device
                # per retry, which grows the table without bound during an outage.
                completed_at=datetime.now(timezone.utc),
            )
        except Exception:
            logger.warning("DDM[%s]: could not record a failed sync task for %s",
                           self.tenant.id, device.serial_number, exc_info=True)
        return EnqueueFailed(summary)

    async def sync_device(self, device: Device, reason: str,
                          mdm_connector: Optional[Any] = None, *,
                          declarations_config: Optional[Dict[str, Any]] = None,
                          groups_config: Optional[List[Dict[str, Any]]] = None,
                          device_groups: Optional[List[str]] = None,
                          ignore_backoff: bool = False,
                          ) -> Union[bool, EnqueueFailed, SyncHeldOff]:
        """Enqueue a DeclarativeManagement command when the published token is stale.

        Returns True when a command was queued, False when there is nothing to send (unsupported, or the set is
        unchanged), EnqueueFailed when NanoMDM refused this attempt, or SyncHeldOff when an earlier refusal is still
        being waited out. The last two are falsy too, so only False means the device is in the state it should be.
        ignore_backoff skips the wait without discarding the failure record, for a caller acting on an explicit request.
        """
        if not self.tenant.ddm_enabled or not device.udid \
            or device.enrollment_state != "enrolled" or not device_supports_ddm(device):
            return False

        from controller.services.tenant_config import load_declarations, load_groups
        if declarations_config is None:
            declarations_config = load_declarations(self.tenant.id)
        if groups_config is None:
            groups_config = load_groups(self.tenant.id)
        declarations = await self.build_device_declarations(
            device, declarations_config, groups_config, device_groups=device_groups
        )
        token = declarations_token(declarations)
        if token == device.ddm_last_published_token and device.ddm_enabled_at:
            return False

        if not ignore_backoff:
            held_until = self._held_until(device, token, datetime.now(timezone.utc))
            if held_until is not None:
                # This exact set was refused recently; skip silently rather than one attempt and one log line per device
                # per cycle forever. SyncHeldOff still tells the caller which silence this is.
                state = self._failure_state(device)
                return SyncHeldOff(
                    f"waiting until {held_until.strftime('%Y-%m-%dT%H:%M:%SZ')} after {state.get('attempts')} refused "
                    f"attempt(s): {state.get('reason')}",
                    held_until,
                )

        from controller.services.mdm_connector import MDMConnector
        own_connector = mdm_connector is None
        connector = mdm_connector or MDMConnector()
        enqueue_error: Optional[BaseException] = None
        published: Optional[Dict[str, Any]] = None
        try:
            published = await self.publish_sync_command(device, connector, declarations)
        except Exception as exc:
            # An operational state, not a bug; recorded, backed off and reported below instead of raised mid-fleet.
            enqueue_error = exc
        finally:
            if own_connector:
                await connector.close()
        if enqueue_error is not None:
            return await self._record_enqueue_failure(device, reason, token, enqueue_error)
        # It went through, so drop the failure record; a stale one would carry its attempt count into a later failure.
        await self._clear_failure_state(device)

        # A task row so the sync is recorded against the device; the webhook completes/fails it by command_uuid (type
        # "ddm_sync").
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


# ==Module-level conveniences (webhook/API/ATC call sites)==

async def _manager_for(device: Device, tenant: Optional[Tenant] = None) -> Optional[DDMManager]:
    tenant = tenant or await Tenant.get_or_none(id=device.tenant_id)
    return DDMManager(tenant) if tenant else None


async def compute_device_declarations(
    device: Device, tenant: Optional[Tenant] = None,
    device_groups: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Desired declaration set for a device; empty when the tenant is missing or has DDM disabled, or the device does
    not support DDM. The device-facing endpoints serve that empty set and make no DDM check of their own."""
    tenant = tenant or await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None or not tenant.ddm_enabled or not device_supports_ddm(device):
        return []
    from controller.services.tenant_config import load_declarations, load_groups
    return await DDMManager(tenant).build_device_declarations(
        device, load_declarations(tenant.id), load_groups(tenant.id),
        device_groups=device_groups,
    )


# ==Device-facing declaration cache (serves the NanoMDM -dm endpoints)==
# One sync is N+2 requests (tokens, declaration-items, one GET per declaration) that each need the full set, so a
# short-TTL per-device memo serves the whole burst from one build. A hit must be identical to a fresh build, so the
# fingerprint covers everything the build reads, with the clock as the one exception (bounded by the TTL).

_DECL_CACHE: "OrderedDict[str, Tuple[str, float, List[Dict[str, Any]]]]" = OrderedDict()


def _decl_cache_ttl() -> float:
    try:
        return float(os.getenv("DDM_DECL_CACHE_TTL_SECONDS", "30"))
    except ValueError:
        return 30.0


def _decl_cache_max() -> int:
    try:
        return int(os.getenv("DDM_DECL_CACHE_MAX_DEVICES", "4096"))
    except ValueError:
        return 4096


def invalidate_declaration_cache() -> None:
    """Clear the declaration cache by hand (tests, out-of-band edits). Normal invalidation is the fingerprint itself;
    nothing in the serve path needs to call this."""
    _DECL_CACHE.clear()


# Every device field the declaration build can read. verify_ddm's coverage guard asserts the build's actual reads stay
# a subset of this set, so a new condition type or render input without a matching fingerprint extension fails verify
# instead of going silently stale. enrollment_state is not read today but is keyed anyway (cheap, correctness-adjacent).
_FINGERPRINT_DEVICE_FIELDS = frozenset({
    "id", "udid", "serial_number", "name", "hostname", "device_model",
    "os_version", "enrollment_state", "enrollment_date", "tags",
    "attributes", "ddm_client_capabilities",
})

# The only attributes keys the build reads (scoping's enrollment_source condition). Fingerprinting just these keeps an
# arbitrarily large attributes blob out of the per-request hash. Any new attributes key the build starts reading must
# join this set; the verify guard asserts that too.
_FINGERPRINT_ATTRIBUTE_KEYS = frozenset({"enrollment_source"})

# Inputs the cached wrapper takes from its caller rather than from the device row or the YAML. Empty today since the
# wrapper derives everything from the device and its tenant. verify_ddm checks this against the wrapper's own
# signature, so any new caller input fails verify until it is declared here and folded into the hash below.
_FINGERPRINT_SUPPLIED_INPUTS = frozenset()


def _fingerprint_device_value(device: Device, field: str) -> Any:
    value = getattr(device, field, None)
    if field == "tags":
        return sorted(value or [])
    if field == "attributes":
        value = value or {}
        return {k: value.get(k) for k in sorted(_FINGERPRINT_ATTRIBUTE_KEYS)}
    if field == "ddm_client_capabilities":
        return value or {}
    return str(value or "")


def _declaration_fingerprint(tenant: Tenant, device: Device) -> str:
    from controller.services.tenant_config import tenant_dir
    tdir = tenant_dir(tenant.id)
    stamps: List[Any] = []
    for filename in ("declarations.yaml", "groups.yaml", "profiles.yaml"):
        try:
            st = os.stat(tdir / filename)
            stamps.append([st.st_mtime_ns, st.st_size, st.st_ino])
        except OSError:
            stamps.append(None)
    doc = {
        "config": stamps,
        "tenant": [tenant.name or "", bool(tenant.ddm_enabled)],
        "device": {field: _fingerprint_device_value(device, field)
                   for field in sorted(_FINGERPRINT_DEVICE_FIELDS)},
        # Every environment value the build reads; both feed the bridged ProfileURL, so a change to either must
        # invalidate this entry. A build-path read of a new setting has to join this list.
        "env": [readiness.public_api_url(), _ddm_secret()],
    }
    return hashlib.sha256(_canonical_json(doc).encode()).hexdigest()


def _decl_cache_key(device: Device) -> str:
    """One slot per device, whoever is asking. Membership is always derived inside the build, so every caller of the
    wrapper below asks the same question and can share the entry the device-facing endpoints warmed.
    """
    return str(device.id)


async def compute_device_declarations_cached(
    device: Device, tenant: Optional[Tenant] = None,
) -> List[Dict[str, Any]]:
    """compute_device_declarations behind the per-device memo above.

    Membership is always derived, never taken from the caller, so every caller gets the set the device-facing endpoints
    serve. Treat the result as read-only: the same list object serves every request of a sync burst."""
    tenant = tenant or await Tenant.get_or_none(id=device.tenant_id)
    if tenant is None or not tenant.ddm_enabled or not device_supports_ddm(device):
        return []
    key = _decl_cache_key(device)
    fingerprint = _declaration_fingerprint(tenant, device)
    now = time.monotonic()
    hit = _DECL_CACHE.get(key)
    if hit is not None and hit[0] == fingerprint and now < hit[1]:
        _DECL_CACHE.move_to_end(key)
        return hit[2]
    declarations = await compute_device_declarations(device, tenant)
    # Store only when the inputs held still across the build. A config file replaced mid-build would otherwise pair the
    # old fingerprint with content built from the new file.
    if _declaration_fingerprint(tenant, device) == fingerprint:
        _DECL_CACHE[key] = (fingerprint, time.monotonic() + _decl_cache_ttl(),
                            declarations)
        _DECL_CACHE.move_to_end(key)
        while len(_DECL_CACHE) > _decl_cache_max():
            _DECL_CACHE.popitem(last=False)
    return declarations


async def ingest_status_report(device: Device, report: Dict[str, Any]) -> None:
    manager = await _manager_for(device)
    if manager:
        await manager.ingest_status_report(device, report)


async def sync_device(device: Device, reason: str,
                      mdm_connector: Optional[Any] = None, *,
                      tenant: Optional[Tenant] = None,
                      declarations_config: Optional[Dict[str, Any]] = None,
                      groups_config: Optional[List[Dict[str, Any]]] = None,
                      device_groups: Optional[List[str]] = None,
                      ignore_backoff: bool = False,
                      ) -> Union[bool, EnqueueFailed, SyncHeldOff]:
    """Sync one device, returning what DDMManager.sync_device returns. A fleet loop should pass tenant and the pre-read
    config, or this costs a Tenant lookup and two YAML parses per device."""
    manager = await _manager_for(device, tenant)
    if manager is None:
        return False
    return await manager.sync_device(
        device, reason, mdm_connector=mdm_connector,
        declarations_config=declarations_config, groups_config=groups_config,
        device_groups=device_groups, ignore_backoff=ignore_backoff,
    )


async def enqueue_sync_command(device: Device, connector: Any) -> Dict[str, Any]:
    """The command-catalog path, which always sends.

    A sync someone issued by hand does not vanish into the token no-op and does not wait out a backoff. The caller
    creates the audit Task. Raises ValueError if DDM doesn't apply to the device."""
    manager = await _manager_for(device)
    if manager is None or not manager.tenant.ddm_enabled:
        raise ValueError("Declarative Device Management is not enabled for this tenant")
    if not device_supports_ddm(device):
        raise ValueError("This device's OS does not support Declarative Device Management")
    result = await manager.publish_sync_command(device, connector)
    # It went through, so the device is not stuck any more. Without this the record outlives the problem, holding a
    # token nothing will compute again and sitting on the row until some later automatic sync clears it.
    await manager._clear_failure_state(device)
    return result
