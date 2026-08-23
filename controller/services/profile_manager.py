import base64
import binascii
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from controller.models.tenant import Device, ProfileDeployment, Tenant
from controller.services.group_manager import GroupManager
from controller.services.scoping import (
    device_in_rollout, device_platform_category, evaluate_scope,
)
from controller.utils.payload_types import data_keys_for_profile

logger = logging.getLogger(__name__)

# What replaces a secret in a stored copy of a profile definition. The same sentinel written over a flow's or a rule's
# secret parameters.
REDACTED = "***redacted***"

# Payload keys whose value is a secret, matched anywhere in the key name because Apple spells the same idea many ways.
_SECRET_KEY_FRAGMENTS = (
    "password", "passwd", "passphrase", "secret", "challenge", "privatekey",
    "private_key", "credential", "token", "apikey", "api_key",
)

# The short ones, matched whole rather than as a fragment.
_SECRET_KEY_NAMES = ("pin", "psk", "key", "presharedkey", "pre_shared_key", "otp")

# Model family (scoping.device_platform_category) -> the platform name a profile's platforms list uses. "Other" is
# absent deliberately.
_PLATFORM_BY_CATEGORY = {
    "Mac": "macOS",
    "Apple TV": "tvOS",
    "Apple Watch": "watchOS",
    "Apple Vision Pro": "visionOS",
    "iPhone": "iOS",
    "iPad": "iOS",
    "iPod": "iOS",
}

# A payload whose PayloadType lives under this prefix may carry its secret as the payload data itself (PayloadContent).
_CERTIFICATE_PAYLOAD_PREFIX = "com.apple.security"

# Who asked for a profile, when it was installed outside the device's own scope. See
# docs/controller/services/profile_manager.md.
REMEDIATION_SOURCE_PREFIX = "remediation:"

# The other engine that installs outside a device's scope: a flow node installing a profile or an app on the device its
# run is for. Recorded and held the same way.
FLOW_SOURCE_PREFIX = "flow:"

# The details key an install task carries the mark under.
INSTALL_SOURCE_KEY = "install_source"


def flow_source(flow_id: Any) -> str:
    """The install_source value for a deployment a flow node is installing.

    Built here so the prefix is spelled once, for the same reason as remediation_source.
    """
    return f"{FLOW_SOURCE_PREFIX}{flow_id}"


def flow_source_id(install_source: Any) -> Optional[str]:
    """The flow id inside an install_source, or None if it names something else."""
    return _source_id(install_source, FLOW_SOURCE_PREFIX)


def _source_id(install_source: Any, prefix: str) -> Optional[str]:
    if not isinstance(install_source, str):
        return None
    if not install_source.startswith(prefix):
        return None
    return install_source[len(prefix):] or None


def remediation_source(rule_id: Any) -> str:
    """The install_source value for a profile a compliance rule is installing.

    One function so the prefix is spelled once.
    """
    return f"{REMEDIATION_SOURCE_PREFIX}{rule_id}"


def remediation_rule_id(install_source: Any) -> Optional[str]:
    """The rule id inside an install_source, or None if it names something else.

    Never raises.
    """
    return _source_id(install_source, REMEDIATION_SOURCE_PREFIX)


def push_failure_note(result: Any) -> Optional[str]:
    """A sentence for a command that was queued but never woke the device, else None.

    Never a deployment failure.
    """
    if not isinstance(result, dict) or not result.get('push_failed'):
        return None
    errors = result.get('push_errors')
    if isinstance(errors, dict):
        detail = "; ".join(str(v) for v in errors.values() if v)
    elif errors:
        detail = str(errors)
    else:
        detail = ""
    return (
        "Queued, but the push that wakes the device failed"
        + (f": {detail}" if detail else "")
        + ". The device applies this at its next check-in."
    )


def _is_secret_key(name: Any) -> bool:
    if not isinstance(name, str):
        return False
    lowered = name.lower()
    return lowered in _SECRET_KEY_NAMES or any(
        fragment in lowered for fragment in _SECRET_KEY_FRAGMENTS
    )


def _redact_value(value: Any, path: str, hits: List[str]) -> Any:
    """Copy of value with every secret-bearing leaf replaced, recursively; hits collects the paths replaced."""
    if isinstance(value, dict):
        certificate_payload = str(value.get("PayloadType") or "").startswith(
            _CERTIFICATE_PAYLOAD_PREFIX
        )
        out = {}
        for key, item in value.items():
            here = f"{path}.{key}" if path else str(key)
            secret = _is_secret_key(key) or (
                certificate_payload and key == "PayloadContent"
                and not isinstance(item, dict)
            )
            if secret and isinstance(item, bool):
                # Two guessable values protect nothing, and the sentinel string would read as true wherever the flag is
                # consumed. Checked before anything numeric: bool subclasses int, and a numeric passcode is a secret.
                out[key] = item
            elif secret and item not in (None, "", [], {}):
                out[key] = REDACTED
                hits.append(here)
            elif secret:
                out[key] = item  # nothing there to give away
            else:
                out[key] = _redact_value(item, here, hits)
        return out
    if isinstance(value, list):
        return [_redact_value(item, f"{path}[{i}]", hits)
                for i, item in enumerate(value)]
    return value


def _decode_data_values(value: Any, keys: frozenset, key: Any = None) -> Any:
    """Copy of value with every base64 leaf under a data key decoded to bytes.

    Copying, not mutating, matters as much as decoding.
    """
    if isinstance(value, dict):
        return {k: _decode_data_values(v, keys, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode_data_values(item, keys, key) for item in value]
    if key in keys and isinstance(value, str) and value:
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return value  # not base64; the device rejects it, not this walk
    return value


class ProfileManager:
    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self.group_manager = GroupManager(tenant.id)

    def payload_identifier_base(self) -> str:
        """Reverse-DNS base every composed PayloadIdentifier hangs off.

        Derived on every call, never stored.
        """
        prefix = (self.tenant.payload_identifier_prefix or "").strip()
        return prefix if prefix else f"com.mdm.{self.tenant.id}"

    @staticmethod
    def desired_hash(profile_info: Dict[str, Any]) -> str:
        """Stable content hash of a profile definition, as authored in YAML (not the built plist)."""
        return hashlib.sha256(
            json.dumps(profile_info, sort_keys=True, default=str).encode()
        ).hexdigest()

    @staticmethod
    def install_task_details(profile_info: Dict[str, Any], payload_hash: str,
                             source: Optional[str] = None) -> Dict[str, Any]:
        """The task details an install of this profile is recorded with, holding the definition with secrets
        redacted (_redact_value) plus a digest of the real one."""
        raw = profile_info.get("payloads")
        if not raw:
            single = profile_info.get("payload")
            raw = [single] if single else []
        payloads = []
        for payload in raw:
            if not isinstance(payload, dict):
                continue
            payloads.append({
                k: payload[k] for k in ("PayloadIdentifier", "PayloadType")
                if payload.get(k)
            })

        hits: List[str] = []
        redacted = _redact_value(profile_info, "", hits)
        details = {
            "profile_info": redacted,
            "payload_digest": {
                "sha256": payload_hash,
                "bytes": len(json.dumps(profile_info, sort_keys=True,
                                        default=str).encode()),
                "payloads": payloads,
                "redacted": hits,
            },
        }
        # Who asked, when the device's own scope did not (remediation_source). Kept in the details rather than only
        # passed to the handler, so a task retried from the row still records that rule and still holds the profile.
        if source:
            details[INSTALL_SOURCE_KEY] = source
        return details

    @staticmethod
    def _device_platform(device: Device) -> str:
        """Best-effort map a device model to an Apple platform name."""
        category = device_platform_category(device.device_model)
        return _PLATFORM_BY_CATEGORY.get(category, 'iOS')

    async def evaluate_device_profiles(
        self,
        device: Device,
        profiles_config: List[Dict[str, Any]],
        groups_config: List[Dict[str, Any]],
        device_groups: Optional[List[str]] = None,
    ) -> Tuple[List[Dict[str, Any]], Set[str]]:
        """Determine which profiles should be installed on a device.

        Returns (to_install, held_ids).
        """
        if device_groups is None:
            device_groups = self.group_manager.evaluate_device_groups(device, groups_config)
        device_platform = self._device_platform(device)
        now = datetime.now(timezone.utc)

        profiles_to_install: List[Dict[str, Any]] = []
        held_ids: Set[str] = set()

        for profile in profiles_config:
            if profile.get('dep_profile') or profile.get('type') == 'enrollment':
                continue  # Enrollment/DEP profiles are not pushed as managed config

            profile_platforms = profile.get('platforms')
            if profile_platforms and device_platform not in profile_platforms:
                continue

            # Unified scope: groups (any) AND conditions (all), with include_devices/exclude_devices overrides. See
            # services.scoping.
            if not evaluate_scope(device, device_groups, profile):
                continue

            rollout = profile.get('rollout')
            if rollout and not device_in_rollout(
                device, rollout, f"profile:{profile.get('id')}", now
            ):
                held_ids.add(profile.get('id'))
                continue

            profiles_to_install.append(profile)

        return profiles_to_install, held_ids

    async def ensure_deployment(self, device: Device, profile_info: Dict[str, Any],
                                task_id: Optional[str] = None,
                                source: Optional[str] = None) -> ProfileDeployment:
        """Get-or-create the (device, profile) deployment row and link it to the attempt about to run. Idempotent."""
        deployment, created = await ProfileDeployment.get_or_create(
            tenant=self.tenant,
            device=device,
            profile_id=profile_info['id'],
            defaults={
                'status': 'pending',
                'last_task_id': task_id,
                'install_source': source,
            }
        )

        dirty: List[str] = []
        if not created and deployment.status == 'failed':
            deployment.status = 'pending'
            dirty.append('status')
        if task_id and str(deployment.last_task_id) != str(task_id):
            deployment.last_task_id = task_id
            dirty.append('last_task_id')
        if source and deployment.install_source != source:
            deployment.install_source = source
            dirty.append('install_source')
        if dirty:
            await deployment.save(update_fields=dirty)

        return deployment

    async def deploy_profile(self, device: Device, profile_info: Dict[str, Any],
                             mdm_connector: 'MDMConnector', task_id: Optional[str] = None,
                             source: Optional[str] = None) -> ProfileDeployment:
        """Deploy a profile to a device. source names whoever asked for a profile outside the device's own scope."""
        from controller.models.tenant import Task

        # Row and link (see ensure_deployment) before the MDM round trip below. A no-op when a caller made them earlier.
        deployment = await self.ensure_deployment(device, profile_info, task_id,
                                                  source=source)

        if task_id:
            task = await Task.get(id=task_id)
            task.details['profile_id'] = profile_info['id']
            await task.save()

        try:
            profile_payload = self._build_profile_payload(profile_info)
            result = await mdm_connector.install_profile(
                device.udid,
                profile_payload
            )

            deployment.status = 'installing'
            deployment.payload_hash = self.desired_hash(profile_info)
            # A failed push leaves the command queued, so the row stays 'installing' and records why it may sit there a
            # while. Cleared otherwise: this attempt supersedes whatever the last one reported.
            deployment.last_error = push_failure_note(result)
            await deployment.save()

            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'running'
                task.details['command_uuid'] = result.get('command_uuid')
                await task.save()

            logger.info(f"Profile deployment initiated for {device.serial_number}: {result}")

        except Exception as e:
            deployment.status = 'failed'
            deployment.last_error = str(e)
            # The definition that was ATTEMPTED, even though nothing was delivered; see
            # docs/controller/services/profile_manager.md for why the sync loop needs this hash here.
            deployment.payload_hash = self.desired_hash(profile_info)
            await deployment.save()

            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'failed'
                task.error = str(e)
                # Terminal outside update_progress, so stamp what retention keys on.
                task.completed_at = datetime.now(timezone.utc)
                await task.save()

            logger.error(f"Failed to deploy profile to {device.serial_number}: {e}")
            raise

        return deployment

    async def remove_profile(self, device: Device, profile_id: str,
                             mdm_connector: 'MDMConnector', task_id: Optional[str] = None) -> bool:
        """Remove a profile from a device"""
        from controller.models.tenant import Task

        try:
            profile_identifier = f"{self.payload_identifier_base()}.{profile_id}"
            result = await mdm_connector.remove_profile(device.udid, profile_identifier)

            # Delete the deployment record optimistically so the reconcile loop doesn't keep re-issuing removals while
            # the device processes this one.
            deployment = await ProfileDeployment.get_or_none(
                device=device,
                profile_id=profile_id
            )
            if deployment:
                await deployment.delete()

            if task_id:
                # Wait for the device. The webhook completes the task.
                task = await Task.get(id=task_id)
                task.status = 'running'
                task.details['command_uuid'] = result.get('command_uuid')
                await task.save()

            return True

        except Exception as e:
            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'failed'
                task.error = str(e)
                # Terminal outside update_progress, so stamp what retention keys on.
                task.completed_at = datetime.now(timezone.utc)
                await task.save()

            logger.error(f"Failed to remove profile from {device.serial_number}: {e}")
            return False

    def _build_profile_payload(self, profile_info: Dict[str, Any]) -> Dict[str, Any]:
        """Build a configuration profile (PayloadContent) from one or more payloads.

        Accepts a single payload dict (legacy) or a payloads list.
        """
        raw = profile_info.get('payloads')
        if not raw:
            single = profile_info.get('payload')
            raw = [single] if single else []

        content = []
        for idx, payload in enumerate(raw):
            item = dict(payload or {})
            # Base64 text fields (certs, fonts, icons, fingerprints) must reach the plist as <data>, which plistlib
            # emits only for bytes.
            data_keys = data_keys_for_profile(profile_info, item.get('PayloadType'))
            if data_keys:
                item = _decode_data_values(item, data_keys)
            if item.get('PayloadType') == 'com.apple.MCX.FileVault2' \
                and isinstance(item.get('Enable'), bool):
                # Apple types Enable as a string with a rangelist of On/Off; YAML reads the bare word as a boolean, and
                # payloads reach the plist as authored.
                # https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.MCX.FileVault2.yaml
                item['Enable'] = 'On' if item['Enable'] else 'Off'
            item.setdefault('PayloadVersion', 1)
            item.setdefault('PayloadIdentifier', f"{self.payload_identifier_base()}.{profile_info['id']}.{idx}")
            item.setdefault('PayloadUUID', str(uuid.uuid4()))
            item.setdefault('PayloadDisplayName', profile_info.get('name', profile_info['id']))
            content.append(item)

        # Adds the tenant's FileVault escrow payload beside any FileVault payload, unless one already exists.
        from controller.services import filevault_escrow
        filevault_escrow.inject_payloads(
            self.tenant, content,
            identifier_prefix=f"{self.payload_identifier_base()}.{profile_info['id']}")

        return {
            'PayloadContent': content,
            'PayloadDisplayName': profile_info['name'],
            'PayloadIdentifier': f"{self.payload_identifier_base()}.{profile_info['id']}",
            'PayloadOrganization': self.tenant.name,
            'PayloadType': 'Configuration',
            'PayloadUUID': str(uuid.uuid4()),
            'PayloadVersion': 1,
            'PayloadDescription': profile_info.get('description', ''),
            'PayloadRemovalDisallowed': False
        }
