"""Profile payload, FileVault, declaration and legacy-bridge checks run by YAMLValidator.
The first parameter of every function is the YAMLValidator instance."""

import base64
import binascii
import re
from typing import List, Optional, Tuple

from controller.services import readiness
from controller.utils.payload_types import is_undocumented_apple_payload_type
from controller.utils.yaml_config_models import (
    DeclarationItem, FILEVAULT_ENFORCE_PAYLOAD_TYPE, FILEVAULT_ESCROW_PAYLOAD_TYPE, Group,
    LEGACY_BRIDGE_FORBIDDEN_PAYLOAD_TYPES, Profile, _datetime_leaf_paths, _escrow_payload_problems,
    _filevault_escrow_payloads, _is_datetime_value, _model_error, _profile_enables_filevault,
    _profile_has_filevault_escrow, _profile_payload_entries,
)


def _check_profile_payloads(validator, profile: Profile) -> None:
    """Reject payload entries that cannot produce an installable profile. Enrollment/DEP profiles are skipped
    (their payload isn't a mobileconfig payload).."""
    if (profile.type or 'configuration') != 'configuration' or profile.dep_profile:
        return
    entries = list(profile.payloads or ([profile.payload] if profile.payload else []))
    for idx, entry in enumerate(entries):
        where = f"Profile '{profile.id}' payload"
        if len(entries) > 1:
            where += f" {idx + 1}"
        if not isinstance(entry, dict):
            validator.errors.append(f"{where} must be a mapping of profile keys")
            continue
        ptype = str(entry.get('PayloadType') or '').strip()
        if not ptype:
            validator.errors.append(
                f"{where} is missing 'PayloadType' (e.g. com.apple.wifi.managed). "
                "The device rejects a payload that does not declare its type."
            )
            continue
        if is_undocumented_apple_payload_type(ptype):
            validator.warnings.append(
                f"{where}: PayloadType '{ptype}' is not a payload type Apple "
                "documents. Check the spelling: a device that does not recognize a "
                "payload type can still report the profile installed, so a typo "
                "here looks like a successful deployment."
            )


def _check_profile_data_keys(validator, profile: Profile) -> None:
    """A profile's data_keys declaration, checked against its payloads. Two authoring mistakes warn (never error): a
    declared key that no payload carries, and a declared key whose value is not valid base64."""
    if (profile.type or 'configuration') != 'configuration' or profile.dep_profile:
        return
    declared = [k for k in (profile.data_keys or []) if k]
    if not declared:
        return

    declared_set = set(declared)
    seen: set = set()
    bad: List[Tuple[str, str]] = []

    def walk(value, key=None):
        # Mirrors _decode_data_values's traversal.
        if key in declared_set:
            seen.add(key)
            if isinstance(value, str) and value:
                try:
                    base64.b64decode(value, validate=True)
                except (binascii.Error, ValueError):
                    bad.append((key, value))
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, k)
        elif isinstance(value, list):
            for item in value:
                walk(item, key)

    for entry in _profile_payload_entries(profile):
        walk(entry)

    for name in declared:
        if name not in seen:
            validator.warnings.append(
                f"Profile '{profile.id}' declares data key '{name}', but no "
                "payload in the profile carries a key with that name, so the "
                "declaration does nothing. Check the spelling."
            )
    for name, _ in bad:
        validator.warnings.append(
            f"Profile '{profile.id}' declares data key '{name}', but its "
            "value is not valid base64, so it will reach the device as a "
            "string rather than <data>. Data keys must hold the base64 of "
            "the binary value."
        )


def _check_filevault_payloads(validator, profile: Profile) -> None:
    """The FileVault payloads on one profile, checked against Apple's rules for them. See
    https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.MCX.FileVault2.yaml
    """
    if (profile.type or 'configuration') != 'configuration' or profile.dep_profile:
        return

    for entry in _profile_payload_entries(profile):
        if entry.get('PayloadType') != FILEVAULT_ENFORCE_PAYLOAD_TYPE:
            continue
        if isinstance(entry.get('Enable'), bool):
            shipped = 'true' if entry['Enable'] else 'false'
            wanted = 'On' if entry['Enable'] else 'Off'
            validator.warnings.append(
                f"Profile '{profile.id}' ({FILEVAULT_ENFORCE_PAYLOAD_TYPE}) has "
                f"'Enable' as a YAML boolean, which ships to the Mac as <{shipped}/>. "
                f"Apple's FileVault payload takes the string '{wanted}'. Quote it "
                f"(Enable: '{wanted}'), or YAML reads the bare word as a boolean and "
                "the Mac ignores the setting."
            )

    escrows = _filevault_escrow_payloads(profile)
    if len(escrows) > 1:
        validator.errors.append(
            f"Profile '{profile.id}' carries {len(escrows)} "
            f"{FILEVAULT_ESCROW_PAYLOAD_TYPE} payloads. A Mac accepts one "
            "recovery-key escrow payload and errors on a second, so this "
            "profile fails to install. Keep one and remove the rest."
        )
    for entry in escrows:
        problems = _escrow_payload_problems(profile, entry)
        if problems:
            validator.warnings.append(
                f"Profile '{profile.id}' has a {FILEVAULT_ESCROW_PAYLOAD_TYPE} "
                "payload that will not escrow anything: " + "; ".join(problems)
                + ". The Mac refuses a payload missing a key Apple marks "
                  "required, so this profile fails to install as it stands."
            )

    if _profile_enables_filevault(profile) and not _profile_has_filevault_escrow(profile) \
        and not validator.filevault_escrow_configured:
        validator.warnings.append(
            f"Profile '{profile.id}' turns on FileVault but does not carry a "
            "working recovery-key escrow payload "
            f"({FILEVAULT_ESCROW_PAYLOAD_TYPE}) itself. That's fine if another "
            "profile in this tenant escrows the key; if none does, saving this "
            "config will fail."
        )


def _validate_declarations(validator, groups: Optional[List[Group]],
                           profiles: Optional[List[Profile]],
                           known_tags: Optional[set]) -> None:
    """Validate the optional declarations.yaml (DDM; services.ddm_manager)."""
    path = validator.tenant_path / 'declarations.yaml'
    if not path.exists():
        return
    data = validator._load_yaml('declarations.yaml')
    if not data:
        return

    group_names = {g.name for g in groups} if groups else set()
    profiles_by_id = {p.id: p for p in (profiles or [])}
    profile_ids = set(profiles_by_id)

    subs = data.get('status_subscriptions')
    if subs is not None and (
        not isinstance(subs, list) or any(not isinstance(s, str) for s in subs)
    ):
        validator.errors.append(
            "declarations.yaml status_subscriptions must be a list of status-item names"
        )
    org = data.get('organization_info')
    if org is not None:
        if not isinstance(org, dict):
            validator.errors.append("declarations.yaml organization_info must be a mapping")
        else:
            for key in ('name', 'email', 'url'):
                if org.get(key) is not None and not isinstance(org[key], str):
                    validator.errors.append(
                        f"declarations.yaml organization_info.{key} must be a string"
                    )

    seen_ids: set = set()
    ios_only_scoped = []
    for idx, ddata in enumerate(data.get('declarations', []) or []):
        try:
            item = DeclarationItem(**ddata)
        except Exception as e:
            validator.errors.append(f"Invalid declaration at index {idx}: {_model_error(e)}")
            continue
        owner = f"declaration '{item.id}'"
        if validator._ios_without_wearables(item.platforms):
            ios_only_scoped.append(owner)
        if item.id in seen_ids:
            validator.errors.append(f"Duplicate declaration id: {item.id}")
        seen_ids.add(item.id)

        for group in item.groups or []:
            if group not in group_names:
                validator.errors.append(f"{owner} references unknown group: {group}")
        validator._check_conditions(owner, item.conditions or [], group_names)
        if known_tags:
            validator._warn_tag_condition_refs(owner, item.conditions or [], known_tags)
        if not (item.groups or []) and not (item.conditions or []) \
            and not (item.include_devices or []):
            validator.warnings.append(
                f"{owner} has no groups, conditions or included devices "
                "and will apply to no devices"
            )

        if item.profile and item.profile not in profile_ids:
            validator.errors.append(f"{owner} bridges unknown profile: {item.profile}")
        elif item.profile and item.type == 'com.apple.configuration.legacy':
            # Only the legacy bridge sends a profile to the device.
            validator._check_bridged_profile(owner, profiles_by_id[item.profile])

        if item.type == 'com.apple.configuration.legacy':
            validator._warn_unservable_bridge(owner)

        for leaf in _datetime_leaf_paths(item.payload or {}):
            validator.warnings.append(
                f"{owner} payload key '{leaf}' is an unquoted YAML timestamp, so "
                "it parsed as a date rather than as text. Quote it "
                "(TargetLocalDateTime: \"2026-09-01T10:00:00\"): a declaration "
                "payload carries these values as strings."
            )

        # Per-type sanity checks. Warnings only, since Apple's schemas move.
        if item.type == 'com.apple.configuration.softwareupdate.enforcement.specific':
            payload = item.payload or {}
            for req in ('TargetOSVersion', 'TargetLocalDateTime'):
                if not payload.get(req):
                    validator.warnings.append(f"{owner} ({item.type}) requires '{req}'")
            target = payload.get('TargetLocalDateTime')
            if target and not _is_datetime_value(target) and not re.match(
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$', str(target)
            ):
                validator.warnings.append(
                    f"{owner} TargetLocalDateTime must be local time formatted "
                    "YYYY-MM-DDTHH:MM:SS with NO timezone suffix"
                )

    validator._warn_ios_platform_split('declarations.yaml', ios_only_scoped)


def _warn_unservable_bridge(validator, owner: str) -> None:
    """Say at save time when a legacy bridge cannot be served to any device."""
    # The same predicate the build path asks.
    if readiness.check(readiness.DDM_BRIDGE).ready:
        return
    public = readiness.public_api_url()
    setting = f"it is '{public}'" if public else "it is not set on this server"
    validator.warnings.append(
        f"{owner} bridges a profile, and the device downloads a bridged profile "
        f"over https from PUBLIC_API_URL. Right now {setting}, so this "
        "declaration is dropped when the declaration set is built and reaches "
        "no device, however many the console says it is scoped to. Set "
        "PUBLIC_API_URL to an https URL to deploy it."
    )


def _check_bridged_profile(validator, owner: str, profile: Profile) -> None:
    """Refuse a legacy-bridge declaration whose profile carries a payload type Apple forbids in a bridged profile.
    Apple allows any payload type except com.apple.mdm and com.apple.declarations
    (https://raw.githubusercontent.com/apple/device-management/release/declarative/declarations/configurations/legacy.yaml).
    A hard error, unusually for this file."""
    for entry in _profile_payload_entries(profile):
        ptype = str(entry.get('PayloadType') or '').strip()
        if ptype in LEGACY_BRIDGE_FORBIDDEN_PAYLOAD_TYPES:
            validator.errors.append(
                f"{owner} bridges profile '{profile.id}', which carries a "
                f"'{ptype}' payload. A profile served through a legacy "
                "declaration may carry any payload type except "
                + " and ".join(f"'{t}'" for t in
                               sorted(LEGACY_BRIDGE_FORBIDDEN_PAYLOAD_TYPES))
                + ", so the device refuses this one. Bridge a profile without that payload, or deploy this profile "
                  "directly instead of through a declaration."
            )
