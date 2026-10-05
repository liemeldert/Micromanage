"""Pydantic models for the tenant config, group, app, profile, declaration and tag documents, with their helpers."""

import re
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, validator

from controller.utils.coerce import str_list

# Names: letters, digits, hyphens and underscores. Slugs: the same in lowercase.
NAME_RE = re.compile(r'^[a-zA-Z0-9-_]+$')
SLUG_RE = re.compile(r'^[a-z0-9-_]+$')


def _require_match(pattern: re.Pattern, value: Any, message: str) -> Any:
    """value, or a ValueError with message when pattern does not match it."""
    if not pattern.match(value or ''):
        raise ValueError(message)
    return value


class Condition(BaseModel):
    type: str
    operator: str
    value: Union[str, List[str]]
    # Inverts the condition ("device NOT IN group", "model NOT equals ...").
    negate: Optional[bool] = False

    @validator('type')
    def validate_type(cls, v):
        valid_types = ['device_model', 'serial_number', 'hostname', 'os_version',
                       'enrollment_date', 'group', 'platform', 'tag',
                       'enrollment_source']
        if v not in valid_types:
            raise ValueError(f"Invalid condition type: {v}. Must be one of {valid_types}")
        return v

    @validator('operator')
    def validate_operator(cls, v, values):
        condition_type = values.get('type')
        valid_operators = {
            'device_model': ['regex', 'equals', 'contains'],
            'serial_number': ['in', 'equals'],
            'hostname': ['regex', 'equals', 'contains'],
            'os_version': ['gte', 'gt', 'lte', 'lt', 'equals'],
            'enrollment_date': ['after', 'before', 'equals'],
            # Membership in other group(s); combine with negate for NOT IN.
            'group': ['in'],
            # Membership in a device family (Mac/iPhone/...); premade options.
            'platform': ['in'],
            # Membership in the device's imperative tag set (see models.Device).
            'tag': ['in'],
            # How the device enrolled: "ade" (ABM/ASM) or "ota" (manual).
            'enrollment_source': ['in'],
        }

        if condition_type and v not in valid_operators.get(condition_type, []):
            raise ValueError(f"Invalid operator '{v}' for condition type '{condition_type}'")
        return v

    @validator('value')
    def validate_platform_value(cls, v, values):
        if values.get('type') != 'platform':
            return v
        from controller.services.scoping import PLATFORM_CATEGORIES
        vals = v if isinstance(v, list) else [v]
        unknown = [x for x in vals if x not in PLATFORM_CATEGORIES]
        if unknown:
            raise ValueError(
                f"Unknown platform(s) {unknown}. Valid: {PLATFORM_CATEGORIES}"
            )
        return v

    @validator('value')
    def validate_enrollment_source_value(cls, v, values):
        if values.get('type') != 'enrollment_source':
            return v
        valid = {'ade', 'ota'}
        vals = v if isinstance(v, list) else [v]
        unknown = [x for x in vals if x not in valid]
        if unknown:
            raise ValueError(
                f"Unknown enrollment_source {unknown}. Valid: {sorted(valid)} "
                "(ade = ABM/ASM Automated Device Enrollment, ota = manual)"
            )
        return v


def _condition_refs(condition: Condition, kind: str) -> List[str]:
    """Names a condition of this type references (empty for other types)."""
    if condition.type != kind:
        return []
    return str_list(condition.value)


def _condition_group_refs(condition: Condition) -> List[str]:
    return _condition_refs(condition, 'group')


def _condition_tag_refs(condition: Condition) -> List[str]:
    return _condition_refs(condition, 'tag')


def _model_error(exc: Exception) -> str:
    """A model validation failure written for whoever is editing the YAML, not pydantic's own layout. """
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return str(exc)
    try:
        entries = list(errors())
    except Exception:
        return str(exc)
    parts = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # __root__ names a whole-model validator, not a field anyone wrote; drop it.
        loc = ".".join(str(x) for x in (entry.get("loc") or ()) if x != "__root__")
        msg = str(entry.get("msg") or "").strip()
        if not msg:
            continue
        parts.append(f"{loc}: {msg}" if loc else msg)
    return "; ".join(parts) or str(exc)


class Rollout(BaseModel):
    """Gradual (wave-based) rollout gate. See services.scoping.

    start is auto-filled by the API on save when omitted; validation only requires it to be parseable when present.
    """
    percent: int
    interval_hours: float = 24
    skip_weekends: Optional[bool] = False
    start: Optional[str] = None

    @validator('percent')
    def validate_percent(cls, v):
        if not (1 <= v <= 100):
            raise ValueError("rollout.percent must be between 1 and 100")
        return v

    @validator('interval_hours')
    def validate_interval(cls, v):
        # Floor at 1h: sub-hour device rollouts aren't a real use case, and a tiny interval can exhaust the wave-walk's
        # iteration backstop before it clears a skipped weekend (freezing coverage). See services.scoping.
        if v < 1:
            raise ValueError("rollout.interval_hours must be at least 1")
        if v > 24 * 365:
            raise ValueError("rollout.interval_hours is unreasonably large (max 1 year)")
        return v

    @validator('start')
    def validate_start(cls, v):
        if v is None:
            return v
        from datetime import datetime
        try:
            datetime.fromisoformat(str(v))
        except ValueError:
            raise ValueError(f"rollout.start is not an ISO timestamp: {v!r}")
        return v


class DeviceNaming(BaseModel):
    """A naming template scope (per-group here; the tenant scope mirrors it from config.yaml). See
    controller/services/naming.py."""
    template: str
    apply_on_enroll: Optional[bool] = False

    @validator('template')
    def validate_template(cls, v):
        if not (v or '').strip():
            raise ValueError("device_naming.template cannot be empty")
        return v


class Group(BaseModel):
    name: str
    description: Optional[str]
    conditions: Optional[List[Condition]] = []
    # Optional per-group naming template: a device in this group derives its managed name from here (first matching
    # group wins; see services.naming).
    device_naming: Optional[DeviceNaming] = None
    # Cherry-picked serials. include is always a member, exclude never is and beats everything else. Handy for a
    # hand-picked test cohort.
    include_devices: Optional[List[str]] = []
    exclude_devices: Optional[List[str]] = []

    @validator('name')
    def validate_name(cls, v):
        return _require_match(NAME_RE, v,
                              "Group name must contain only alphanumeric characters, hyphens, and underscores")


class AppVersion(BaseModel):
    version: str
    s3_key: str
    sha256: str  # required: device verifies package integrity against this
    groups: List[str]
    conditions: Optional[List[Condition]] = []
    include_devices: Optional[List[str]] = []
    exclude_devices: Optional[List[str]] = []
    rollout: Optional[Rollout] = None
    install_options: Optional[Dict[str, Any]] = {}

    @validator('sha256')
    def validate_sha256(cls, v):
        if not re.match(r'^[a-fA-F0-9]{64}$', v or ''):
            raise ValueError("sha256 must be a 64-character hex digest")
        return v.lower()


class App(BaseModel):
    id: str
    name: str
    bundle_id: str
    versions: List[AppVersion]
    # Off for a package that installs no application bundle. macOS only; only an explicit false turns it off.
    install_as_managed: Optional[bool] = None

    @validator('bundle_id')
    def validate_bundle_id(cls, v):
        if not re.match(r'^[a-zA-Z0-9.-]+$', v):
            raise ValueError("Bundle ID must be in reverse domain notation")
        return v


class Profile(BaseModel):
    id: str
    name: str
    description: Optional[str]
    payload_type: Optional[str]
    # "configuration" (managed config profile pushed to groups) or "enrollment" (Automated Device Enrollment / DEP
    # profile).
    type: Optional[str] = "configuration"
    # Target platforms (iOS | macOS | tvOS | watchOS | visionOS); empty/None means all. iOS means iPhone/iPad/iPod only:
    # watches and Vision Pro have their own values.
    platforms: Optional[List[str]] = None
    groups: Optional[List[str]] = []
    # Unified scope extensions (see services.scoping): all conditions must match; include/exclude cherry-pick serials
    # (exclude wins); rollout gates scoped devices into gradual waves.
    conditions: Optional[List[Condition]] = []
    include_devices: Optional[List[str]] = []
    exclude_devices: Optional[List[str]] = []
    rollout: Optional[Rollout] = None
    dep_profile: Optional[bool] = False
    # A profile may carry a single payload (legacy) or a list of payloads.
    payload: Optional[Dict[str, Any]] = None
    payloads: Optional[List[Dict[str, Any]]] = None
    # Key names whose values are base64 and must reach the device as <data>, beyond the built-in table.
    data_keys: Optional[List[str]] = None
    # DEP-profile settings. services.dep_manager reads payload or enrollment; both must be kept.
    enrollment: Optional[Dict[str, Any]] = None

    @validator('enrollment', pre=True)
    def coerce_enrollment(cls, v):
        # A tenant may have a saved non-dict enrollment block from before this was declared; coerce rather than error.
        return v if isinstance(v, dict) else None

    @validator('type')
    def validate_type(cls, v):
        if v not in (None, 'configuration', 'enrollment'):
            raise ValueError("type must be 'configuration' or 'enrollment'")
        return v or 'configuration'

    @validator('payloads', always=True)
    def require_payload_for_config(cls, v, values):
        ptype = values.get('type') or 'configuration'
        is_dep = ptype == 'enrollment' or values.get('dep_profile')
        if not is_dep and not v and not values.get('payload'):
            raise ValueError("a configuration profile requires 'payload' or 'payloads'")
        return v


# FileVault escrow guard (see YAMLValidator._cross_validate). A profile that turns FileVault on with no escrow route
# creates a Mac nobody can unlock.
FILEVAULT_ENFORCE_PAYLOAD_TYPE = 'com.apple.MCX.FileVault2'
FILEVAULT_ESCROW_PAYLOAD_TYPE = 'com.apple.security.FDERecoveryKeyEscrow'
# The escrow payload names its encryption certificate by the UUID of a payload of this type in the same profile. See
# https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.security.FDERecoveryKeyEscrow.yaml
FILEVAULT_ESCROW_CERT_PAYLOAD_TYPE = 'com.apple.security.pkcs1'

# Payload types Apple forbids inside a profile served through a com.apple.configuration.legacy declaration (see
# _check_bridged_profile).
LEGACY_BRIDGE_FORBIDDEN_PAYLOAD_TYPES = frozenset({
    'com.apple.mdm', 'com.apple.declarations',
})


def _profile_payload_entries(profile: Profile) -> List[Dict[str, Any]]:
    """Every payload dict on a profile, whether it's the single legacy payload or the list-valued payloads."""
    if profile.payloads:
        return [p for p in profile.payloads if isinstance(p, dict)]
    if isinstance(profile.payload, dict):
        return [profile.payload]
    return []


def _profile_enables_filevault(profile: Profile) -> bool:
    """True if the profile carries a com.apple.MCX.FileVault2 payload with FileVault turned on (Enable: On)."""
    for entry in _profile_payload_entries(profile):
        if entry.get('PayloadType') != FILEVAULT_ENFORCE_PAYLOAD_TYPE:
            continue
        enable = entry.get('Enable')
        if isinstance(enable, str) and enable.strip().lower() == 'on':
            return True
        if enable is True:
            return True
    return False


def _filevault_escrow_payloads(profile: Profile) -> List[Dict[str, Any]]:
    """Every com.apple.security.FDERecoveryKeyEscrow payload on the profile."""
    return [entry for entry in _profile_payload_entries(profile)
            if entry.get('PayloadType') == FILEVAULT_ESCROW_PAYLOAD_TYPE]


def _escrow_payload_problems(profile: Profile, entry: Dict[str, Any]) -> List[str]:
    """What stops this escrow payload from escrowing a recovery key, as a list of phrases. Empty means it is complete.
    The referenced UUID has to be one the author wrote down, since a missing PayloadUUID is filled with a random one at
    build time. See
    https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.security.FDERecoveryKeyEscrow.yaml
    """
    problems: List[str] = []
    if not str(entry.get('Location') or '').strip():
        problems.append(
            "no 'Location' (the text the Mac shows the user, naming where the key is escrowed)"
        )
    cert_uuid = str(entry.get('EncryptCertPayloadUUID') or '').strip()
    if not cert_uuid:
        problems.append(
            "no 'EncryptCertPayloadUUID' (the PayloadUUID of the "
            f"{FILEVAULT_ESCROW_CERT_PAYLOAD_TYPE} payload holding the "
            "certificate the key is encrypted to)"
        )
        return problems
    certs = [
        other for other in _profile_payload_entries(profile)
        if other.get('PayloadType') == FILEVAULT_ESCROW_CERT_PAYLOAD_TYPE
           and str(other.get('PayloadUUID') or '').strip() == cert_uuid
    ]
    if not certs:
        problems.append(
            f"its 'EncryptCertPayloadUUID' ({cert_uuid}) does not name a "
            f"{FILEVAULT_ESCROW_CERT_PAYLOAD_TYPE} payload in this profile "
            "with that PayloadUUID"
        )
    return problems


def _profile_has_filevault_escrow(profile: Profile) -> bool:
    """True if the profile carries an escrow payload that would actually escrow the key (see _escrow_payload_problems).
    """
    return any(
        not _escrow_payload_problems(profile, entry)
        for entry in _filevault_escrow_payloads(profile)
    )


def _is_datetime_value(value: Any) -> bool:
    """Whether YAML resolved this leaf to a datetime/date rather than to text (an unquoted timestamp does that, and a
    declaration payload carries these values as strings)."""
    from datetime import date, datetime
    return isinstance(value, (datetime, date))


def _datetime_leaf_paths(value: Any, path: str = '') -> List[str]:
    """Dotted key paths under an authored payload that hold a datetime/date."""
    found: List[str] = []
    if isinstance(value, dict):
        for key, sub in value.items():
            found.extend(_datetime_leaf_paths(sub, f"{path}.{key}" if path else str(key)))
    elif isinstance(value, list):
        for idx, sub in enumerate(value):
            found.extend(_datetime_leaf_paths(sub, f"{path}[{idx}]"))
    elif _is_datetime_value(value):
        found.append(path or 'payload')
    return found


def _is_dep_profile(profile: Profile) -> bool:
    """Whether this is an Automated Enrollment (DEP) profile rather than a managed configuration profile. Either marker
    counts, the same way _validate_profiles reads them."""
    return bool(profile.dep_profile) or (profile.type or 'configuration') == 'enrollment'


def _dep_profile_awaits(profile: Profile) -> bool:
    """Whether this DEP profile holds its devices at Remote Management until the flow releases them. Reads payload or
    enrollment, exactly what dep_manager._build_apple_profile does."""
    settings = profile.payload or profile.enrollment or {}
    return isinstance(settings, dict) and bool(settings.get('await_device_configured'))


# Declaration ids ddm_manager already serves (mm.cfg.<id> / mm.act.<id>); Maps the id to what to write instead.
RESERVED_DECLARATION_IDS = {
    'status-subscriptions':
        "add items to the top-level 'status_subscriptions' list instead",
}


class DeclarationItem(BaseModel):
    """One DDM declaration in declarations.yaml (services.ddm_manager). Authors only write configuration
    declarations; the rest are managed for them."""
    id: str
    name: Optional[str] = None
    type: str
    platforms: Optional[List[str]] = None
    groups: Optional[List[str]] = []
    conditions: Optional[List[Condition]] = []
    include_devices: Optional[List[str]] = []
    exclude_devices: Optional[List[str]] = []
    rollout: Optional[Rollout] = None
    # Optional activation predicate, passed through verbatim (evaluated on the device against @property(...) from the
    # properties declaration).
    predicate: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    profile: Optional[str] = None  # legacy bridge: a profiles.yaml id

    @validator('id')
    def validate_id(cls, v):
        # Identifiers become "mm.cfg.<id>" and must stay short and stable.
        if not re.match(r'^[a-z0-9][a-z0-9-_]{0,47}$', v or ''):
            raise ValueError(
                "Declaration id must be a slug (lowercase letters, digits, hyphens, "
                "underscores) of at most 48 characters"
            )
        hint = RESERVED_DECLARATION_IDS.get(v)
        if hint:
            raise ValueError(
                f"Declaration id '{v}' is reserved: the server already serves 'mm.cfg.{v}' and 'mm.act.{v}', so an "
                f"authored item with this id reaches devices as a duplicate Identifier. {hint}"
            )
        return v

    @validator('type')
    def validate_declaration_type(cls, v):
        if v == 'com.apple.configuration.management.status-subscriptions':
            raise ValueError(
                "status subscriptions are auto-managed; add items to the top-level 'status_subscriptions' list instead"
            )
        if v.startswith(('com.apple.management.', 'com.apple.activation.', 'com.apple.asset.')):
            raise ValueError(
                f"'{v}' declarations are auto-managed and cannot be authored in "
                "declarations.yaml"
            )
        if not v.startswith('com.apple.configuration.'):
            raise ValueError("Declaration type must start with 'com.apple.configuration.'")
        return v

    @validator('platforms')
    def validate_platforms(cls, v):
        valid = ('iOS', 'macOS', 'tvOS', 'watchOS', 'visionOS')
        unknown = [p for p in (v or []) if p not in valid]
        if unknown:
            raise ValueError(f"Unknown platform(s) {unknown}. Valid: {list(valid)}")
        return v

    @validator('profile', always=True)
    def validate_payload_or_profile(cls, v, values):
        if v and values.get('type') != 'com.apple.configuration.legacy':
            raise ValueError(
                "'profile' is only valid with type com.apple.configuration.legacy"
            )
        if v and values.get('payload') is not None:
            raise ValueError("provide either 'payload' or 'profile', not both")
        if not v and values.get('payload') is None:
            raise ValueError(
                "a declaration requires a 'payload' (or 'profile' for the legacy bridge)"
            )
        return v


# Reverse-DNS shape Apple expects a PayloadIdentifier to follow: at least two lowercase labels separated by dots. Shared
# by TenantConfig and the tenant settings endpoint.
PAYLOAD_IDENTIFIER_PREFIX_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def payload_identifier_prefix_error(value: str) -> Optional[str]:
    """Why this cannot be a PayloadIdentifier base, or None when it can."""
    v = (value or "").strip()
    if not v:
        return "cannot be empty; omit it to use the built-in base"
    if len(v) > 120:
        return "must be 120 characters or fewer"
    if not PAYLOAD_IDENTIFIER_PREFIX_RE.match(v):
        return ("must be reverse-DNS notation: two or more dot-separated labels of lowercase letters, digits and "
                "hyphens, like com.example.mdm")
    return None


class TenantConfig(BaseModel):
    """The tenant: block of config.yaml. Every key the sync loop reads back onto the Tenant row (controller/main.py
    sync_tenant) has to be declared here: pydantic v1 silently drops undeclared keys."""
    id: str
    name: str
    allowed_users: List[str]
    # Dict[str, Any] not Dict[str, str]: a str-valued mapping would coerce use_ssl: false into truthy "False".
    s3: Optional[Dict[str, Any]] = {}
    dep: Optional[Dict[str, Any]] = {}
    # Declarative device management toggle, mirrored by PUT /api/v1/tenant.
    ddm: Optional[Dict[str, Any]] = {}
    # Tenant-wide managed-name template. Same shape as Group.device_naming, and the group-level one wins where both
    # apply (services.naming).
    device_naming: Optional[DeviceNaming] = None
    # Reverse-DNS base for composed PayloadIdentifiers, e.g. "com.acme.mdm". Unset means the built-in "com.mdm.<tenant
    # id>". Changing it while profiles are deployed strands the installed copies on devices.
    payload_identifier_prefix: Optional[str] = None
    # Escape hatch for the FileVault-escrow guard in _cross_validate.
    allow_unescrowed_filevault: Optional[bool] = False

    @validator('device_naming', pre=True)
    def _empty_naming_is_unset(cls, v):
        # The tenant mirror writes device_naming: {} to CLEAR the template, so an empty mapping has to mean "unset" and
        # not "missing required template".
        if not v:
            return None
        return v

    @validator('payload_identifier_prefix')
    def _prefix_is_reverse_dns(cls, v):
        if v is None:
            return v
        err = payload_identifier_prefix_error(v)
        if err:
            raise ValueError(f"payload_identifier_prefix: {err}")
        return v.strip()


class Tag(BaseModel):
    """One entry in the advisory tag registry (tags.yaml). Optional: free-form tags are always allowed."""
    name: str
    label: Optional[str] = None
    description: Optional[str] = None
    # Optional Mantine colour name, advisory only.
    color: Optional[str] = None

    @validator('name')
    def validate_name(cls, v):
        return _require_match(NAME_RE, v,
                              "Tag name must contain only alphanumeric characters, hyphens, and underscores")
