import base64
import binascii
import difflib
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml
from controller.services import readiness
from controller.utils.payload_types import is_undocumented_apple_payload_type
from pydantic import BaseModel, validator


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


def _condition_group_refs(condition: Condition) -> List[str]:
    """Group names a group-type condition references (empty for other types)."""
    if condition.type != 'group':
        return []
    value = condition.value
    return [str(n) for n in (value if isinstance(value, list) else [value]) if n]


def _condition_tag_refs(condition: Condition) -> List[str]:
    """Tag names a tag-type condition references (empty for other types)."""
    if condition.type != 'tag':
        return []
    value = condition.value
    return [str(n) for n in (value if isinstance(value, list) else [value]) if n]


def _find_cycle_edges(edges: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    """Back-edges (node, ref) that make edges cyclic. edges maps a node to its successor ids; successors not present as
    keys are ignored (dangling refs are a separate check)."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in edges}
    back: List[Tuple[str, str]] = []
    for root in edges:
        if color[root] != WHITE:
            continue
        stack = [(root, iter(edges[root]))]
        color[root] = GRAY
        while stack:
            node, it = stack[-1]
            advanced = False
            for ref in it:
                if ref not in color:
                    continue  # dangling ref, reported elsewhere
                if color[ref] == GRAY:
                    back.append((node, ref))
                    continue
                if color[ref] == WHITE:
                    color[ref] = GRAY
                    stack.append((ref, iter(edges[ref])))
                    advanced = True
                    break
            if not advanced:
                color[node] = BLACK
                stack.pop()
    return back


# The keys a flow start's match scope understands (services.atc._scope_matches / services.scoping.evaluate_scope).
# Anything else is ignored at runtime; the unknown-scope-key warning reports that.
_FLOW_SCOPE_KEYS = ("groups", "conditions", "include_devices", "exclude_devices")


def _reads_as_int(value: Any) -> bool:
    """Whether services.atc will read this as the number it says. A boolean is not a number here."""
    if isinstance(value, bool):
        return False
    try:
        int(value)
        return True
    except (TypeError, ValueError):
        return False


def _reads_as_true(value: Any) -> bool:
    """How services.atc._truthy_param will read a flag: a string as a word, and anything else by Python's own answer."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "on", "1")
    return bool(value)


# How long a save waits for the Dispatcher's webhook-target predicate to answer. It resolves a hostname, so it is the
# one check here that can be slowed by something outside the process; past this the save goes ahead unwarned.
_WEBHOOK_CHECK_TIMEOUT_SECONDS = 2.0

# Flow steps that put something on the device's queue. A flow built only from the rest (tagging, branching, gates)
# changes nothing the device has to answer, which is what makes a run-on-every-check-in cadence safe for it.
_DEVICE_TOUCHING_STEPS = frozenset({
    "install_profiles", "install_apps", "send_command", "sync_declarations",
    "configure_accounts", "set_firmware_lock", "release_device", "set_name",
})


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


def _scope_is_empty(scope: Any) -> bool:
    """The monitoring engines' own emptiness test, mirrored here."""
    if not scope:
        return True
    if not isinstance(scope, dict):
        return False
    return not any(scope.get(k) for k in _FLOW_SCOPE_KEYS)


def _quoted_list(items: List[str]) -> str:
    """'"a"', '"a" and "b"', '"a", "b" and "c"' for warning prose."""
    quoted = [f'"{i}"' for i in items]
    if len(quoted) <= 1:
        return quoted[0] if quoted else ""
    return ", ".join(quoted[:-1]) + " and " + quoted[-1]


def _reach_nodes(edges: Dict[str, List[str]], roots: List[str],
                 blocked: frozenset = frozenset()) -> set:
    """Node ids reachable from roots by walking edges. A blocked node is never entered."""
    seen: set = set()
    stack = [r for r in roots if r not in blocked]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        for tgt in edges.get(n, []):
            if tgt not in seen and tgt not in blocked:
                stack.append(tgt)
    return seen


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
        if not re.match(r'^[a-zA-Z0-9-_]+$', v):
            raise ValueError("Group name must contain only alphanumeric characters, hyphens, and underscores")
        return v


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


# FileVault escrow guard (see YAMLValidator._cross_validate and docs). A profile that turns FileVault on with no
# escrow route creates a Mac nobody can unlock.
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
    See
    https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.security.FDERecoveryKeyEscrow.yaml
    and docs for why the referenced UUID has to be one the author wrote down."""
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
    """True if the profile carries an escrow payload that would actually escrow the key (see _escrow_payload_problems
    and docs)."""
    return any(
        not _escrow_payload_problems(profile, entry)
        for entry in _filevault_escrow_payloads(profile)
    )


def _is_datetime_value(value: Any) -> bool:
    """Whether YAML resolved this leaf to a datetime/date rather than to text (an unquoted timestamp does that; see
    docs for why it must be quoted)."""
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


# Declaration ids ddm_manager already serves (mm.cfg.<id> / mm.act.<id>); Maps the id to
# what to write instead.
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
                f"Declaration id '{v}' is reserved: the server already serves "
                f"'mm.cfg.{v}' and 'mm.act.{v}', so an authored item with this id "
                f"reaches devices as a duplicate Identifier. {hint}"
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
        return ("must be reverse-DNS notation: two or more dot-separated "
                "labels of lowercase letters, digits and hyphens, "
                "like com.example.mdm")
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
        if not re.match(r'^[a-zA-Z0-9-_]+$', v or ''):
            raise ValueError(
                "Tag name must contain only alphanumeric characters, hyphens, and underscores"
            )
        return v


class FlowNode(BaseModel):
    """One node in a flow graph. params and edge targets are validated per-node-type imperatively, so the
    structural model stays permissive."""
    id: str
    type: str
    params: Optional[Dict[str, Any]] = {}
    next: Optional[str] = None
    on_true: Optional[str] = None
    on_false: Optional[str] = None
    on_timeout: Optional[str] = None
    # manual_gate decision handles (fixed enum; wired from params.options[].edge).
    on_release: Optional[str] = None
    on_cancel: Optional[str] = None
    on_wait: Optional[str] = None
    # Canvas position, kept apart from the logic so the YAML stays diff-friendly.
    ui: Optional[Dict[str, Any]] = None

    @validator('id')
    def validate_id(cls, v):
        if not re.match(r'^[a-zA-Z0-9-_]+$', v or ''):
            raise ValueError(
                "Flow node id must contain only alphanumeric characters, hyphens, and underscores"
            )
        return v


class Flow(BaseModel):
    """One ATC flow out of flows.yaml; see services.flow_step_catalog. permanent marks the tenant's enrollment flow,
    draft_* marks a working copy of another flow."""
    id: str
    name: str
    description: Optional[str] = None
    enabled: Optional[bool] = True
    permanent: Optional[bool] = False
    draft_of: Optional[str] = None
    draft_base_hash: Optional[str] = None
    draft_note: Optional[str] = None
    draft_created_by: Optional[str] = None
    draft_created_at: Optional[Any] = None
    nodes: List[FlowNode]

    @validator('id')
    def validate_id(cls, v):
        if not re.match(r'^[a-z0-9-_]+$', v or ''):
            raise ValueError(
                "Flow id must be a slug (lowercase letters, digits, hyphens, underscores)"
            )
        return v


# ==Dispatcher (dispatcher.yaml)==

VALID_SEVERITIES = ('black', 'red', 'yellow', 'green')


class DispatcherWebhook(BaseModel):
    """A named delivery target. url (and secret if present) are secrets:
    redacted from all API responses (see controller/api/main.py)."""
    name: str
    url: str
    secret: Optional[str] = None

    @validator('name')
    def validate_name(cls, v):
        if not re.match(r'^[a-zA-Z0-9-_]+$', v or ''):
            raise ValueError(
                "Webhook name must contain only alphanumeric characters, hyphens, and underscores"
            )
        return v

    @validator('url')
    def validate_url(cls, v):
        if not str(v or '').strip():
            raise ValueError("Webhook url cannot be empty")
        return v


class DispatcherAction(BaseModel):
    """One rule action. params are validated per action-type imperatively. dry_run records what a remediation WOULD do
    without doing it."""
    type: str
    params: Optional[Dict[str, Any]] = {}
    dry_run: Optional[bool] = False


class DispatcherRule(BaseModel):
    id: str
    name: str
    enabled: Optional[bool] = True
    severity: str
    scope: Optional[Dict[str, Any]] = {}
    check: Dict[str, Any]
    # Anti-flap: only raise after this many minutes continuously non-compliant.
    grace_minutes: Optional[int] = 0
    actions: Optional[List[DispatcherAction]] = []
    auto_resolve: Optional[bool] = False

    @validator('id')
    def validate_id(cls, v):
        if not re.match(r'^[a-z0-9-_]+$', v or ''):
            raise ValueError(
                "Rule id must be a slug (lowercase letters, digits, hyphens, underscores)"
            )
        return v

    @validator('severity')
    def validate_severity(cls, v):
        if v not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {VALID_SEVERITIES}")
        return v

    @validator('grace_minutes')
    def validate_grace(cls, v):
        if v is not None and v < 0:
            raise ValueError("grace_minutes cannot be negative")
        return v


class YAMLValidator:
    def __init__(self, tenant_path: Path, *, filevault_escrow_configured: bool = False):
        self.tenant_path = tenant_path
        # Whether this tenant has a FileVault recovery-key escrow keypair (services.filevault_escrow);. The
        # API passes this in since the validator reads files and cannot see the Tenant row; CLI/tests leave it False.
        self.filevault_escrow_configured = filevault_escrow_configured
        self.errors: List[str] = []
        self.warnings: List[str] = []
        # Structured flow warnings: {node_id, code, message}, one per finding, alongside the plain-string copy in
        # self.warnings. node_id is None for a finding with no single node to point at.
        self.flow_warnings: List[Dict[str, Any]] = []

    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """Validate every YAML file for a tenant. Returns (ok, errors, warnings)."""
        self.errors = []
        self.warnings = []
        self.flow_warnings = []

        required_files = ['config.yaml', 'groups.yaml', 'apps.yaml', 'profiles.yaml']
        for file in required_files:
            if not (self.tenant_path / file).exists():
                self.errors.append(f"Missing required file: {file}")

        if self.errors:
            return False, self.errors, self.warnings

        config = self._validate_config()
        groups = self._validate_groups()
        apps = self._validate_apps(groups)
        profiles = self._validate_profiles(groups)

        # Optional advisory tag registry (tags.yaml). Returns the registered names, or None when there's no non-empty
        # registry, in which case tags are free-form and we never flag a reference.
        known_tags = self._validate_tags()

        # Each is None only on a load/parse error already recorded above; an empty-but-valid list must still reach
        # _cross_validate, so this checks None rather than truthiness.
        if config is not None and groups is not None and apps is not None \
            and profiles is not None:
            self._cross_validate(config, groups, apps, profiles)

        # Warn, never error, on a tag condition referencing something missing from a non-empty registry. It's usually a
        # typo, and free-form tags are still allowed.
        if known_tags:
            self._warn_unknown_tag_refs(groups, apps, profiles, known_tags)

        # Optional new-subsystem documents (no required-file stub). Each returns early if its file is absent. They
        # cross-validate against the docs above.
        self._validate_flows(groups, apps, profiles, known_tags)
        self._validate_dispatcher(groups, apps, profiles, known_tags)
        self._validate_declarations(groups, profiles, known_tags)

        return len(self.errors) == 0, self.errors, self.warnings

    def _load_yaml(self, filename: str) -> Optional[Dict[str, Any]]:
        try:
            with open(self.tenant_path / filename, 'r') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.errors.append(f"YAML syntax error in {filename}: {e}")
            return None
        except Exception as e:
            self.errors.append(f"Error reading {filename}: {e}")
            return None

    def _validate_config(self) -> Optional[TenantConfig]:
        data = self._load_yaml('config.yaml')
        if not data:
            return None

        try:
            tenant_data = data.get('tenant', {})
            config = TenantConfig(**tenant_data)

            if not config.allowed_users:
                self.warnings.append("No allowed users defined")

            self._check_tenant_s3(config)

            # Same naming-template checks the per-group templates get, so a typo in the tenant-wide default isn't the
            # one that slips through.
            if config.device_naming:
                from controller.services.variables import (
                    is_self_referential,
                    unknown_variables,
                )
                for var in unknown_variables(config.device_naming.template):
                    self.warnings.append(
                        f"Tenant naming template references unknown variable '{{{var}}}'"
                    )
                if is_self_referential(config.device_naming.template):
                    self.warnings.append(
                        "Tenant naming template uses {hostname}; the managed name is "
                        "pushed to the device as its hostname, so re-deriving can "
                        "compound the name. Prefer a stable identifier like {serial}."
                    )

            return config

        except Exception as e:
            self.errors.append(f"Invalid config.yaml: {_model_error(e)}")
            return None

    def _check_tenant_s3(self, config: TenantConfig) -> None:
        """A tenant's S3 block has to be complete or absent (services.app_manager.resolve_s3_settings enforces this at
        runtime too; why)."""
        from controller.services.app_manager import (
            REQUIRED_TENANT_S3_KEYS, TENANT_S3_KEYS, _is_set,
        )

        s3 = config.s3 or {}
        declared = [k for k in TENANT_S3_KEYS if _is_set(s3.get(k))]
        if not declared:
            return
        missing = [k for k in REQUIRED_TENANT_S3_KEYS if not _is_set(s3.get(k))]
        if missing:
            self.errors.append(
                f"S3 configuration sets {', '.join(declared)} but not "
                f"{', '.join(missing)}. A tenant that configures its own object "
                "store has to supply its own credentials for it: Micromanage "
                "will not use the AWS credentials in the server environment to "
                "reach a bucket a tenant chose, because those belong to the "
                "deployment. Add the missing keys under tenant.s3, or remove the "
                "s3 block so "
                "this tenant uses the server's own bucket and credentials "
                "together."
            )

    def _validate_groups(self) -> Optional[List[Group]]:
        data = self._load_yaml('groups.yaml')
        if not data:
            return None

        groups = []
        group_names = set()

        for idx, group_data in enumerate(data.get('groups', [])):
            try:
                group = Group(**group_data)

                if group.name in group_names:
                    self.errors.append(f"Duplicate group name: {group.name}")
                group_names.add(group.name)

                # A group with no conditions and no cherry-picked devices matches nothing, and a profile scoped to it
                # deploys nowhere while looking fine.
                if not group.conditions and not group.include_devices:
                    self.warnings.append(
                        f"Group '{group.name}' has no conditions or included devices "
                        "and will match no devices"
                    )

                self._check_conditions(f"group '{group.name}'", group.conditions or [])

                # A typo like {seriall} renders to nothing at all. Not an error, since a new variable can be added
                # before this list catches up.
                if group.device_naming:
                    from controller.services.variables import (
                        is_self_referential,
                        unknown_variables,
                    )
                    for var in unknown_variables(group.device_naming.template):
                        self.warnings.append(
                            f"Group '{group.name}' naming template references unknown "
                            f"variable '{{{var}}}'"
                        )
                    if is_self_referential(group.device_naming.template):
                        self.warnings.append(
                            f"Group '{group.name}' naming template uses {{hostname}}; the "
                            "managed name is pushed to the device as its hostname, so "
                            "re-deriving can compound the name. Prefer a stable "
                            "identifier like {serial}."
                        )

                groups.append(group)

            except Exception as e:
                self.errors.append(f"Invalid group at index {idx}: {_model_error(e)}")

        if not groups:
            self.warnings.append("No groups defined")

        # Group-membership conditions: referenced groups must exist, and the reference graph must be acyclic (a cycle
        # would make membership undefined; the runtime treats it as no-match, but reject it here).
        names = {g.name for g in groups}
        edges: Dict[str, List[str]] = {}
        for g in groups:
            refs = []
            for condition in g.conditions or []:
                for ref in _condition_group_refs(condition):
                    if ref not in names:
                        self.errors.append(
                            f"Group '{g.name}' condition references unknown group: {ref}"
                        )
                    refs.append(ref)
            edges[g.name] = refs

        for node, ref in _find_cycle_edges(edges):
            self.errors.append(
                f"Group membership cycle detected involving '{node}' and '{ref}'"
            )

        return groups

    def _check_conditions(self, owner: str, conditions: List[Condition],
                          group_names: Optional[set] = None) -> None:
        """Shared per-condition checks: the regex compiles, and group refs exist when group_names is given (groups.yaml
        defers that to a graph pass). Also warns above scoping.MAX_SCOPE_CONDITIONS."""
        from controller.services.scoping import MAX_SCOPE_CONDITIONS

        if len(conditions) > MAX_SCOPE_CONDITIONS:
            self.warnings.append(
                f"{owner} has {len(conditions)} conditions, over the "
                f"{MAX_SCOPE_CONDITIONS} this is sized for. All of them are "
                "evaluated for every device on every reconcile pass, and a regex "
                "condition can take seconds on its own. Narrow the scope with a "
                "group instead."
            )
        for condition in conditions:
            if condition.operator == 'regex' and isinstance(condition.value, str):
                try:
                    re.compile(condition.value)
                except re.error as e:
                    self.errors.append(f"Invalid regex in {owner}: {e}")
            if group_names is not None:
                for ref in _condition_group_refs(condition):
                    if ref not in group_names:
                        self.errors.append(
                            f"{owner} condition references unknown group: {ref}"
                        )

    @staticmethod
    def _ios_without_wearables(platforms: Optional[List[str]]) -> bool:
        """True when a platforms list names iOS but neither watchOS nor visionOS. iOS used to be the catch-all (see
        docs)."""
        p = set(platforms or [])
        return 'iOS' in p and not (p & {'watchOS', 'visionOS'})

    def _warn_ios_platform_split(self, doc: str, owners: List[str]) -> None:
        """One warning per document (never per item) when _ios_without_wearables flagged items."""
        if not owners:
            return
        shown = ", ".join(owners[:5]) + (", ..." if len(owners) > 5 else "")
        self.warnings.append(
            f"{doc}: platform lists target iOS without watchOS or visionOS "
            f"({shown}). 'iOS' now means iPhone/iPad/iPod only, so these items "
            "no longer reach Apple Watch or Apple Vision Pro devices; add "
            "'watchOS'/'visionOS' where they should."
        )

    def _validate_apps(self, groups: Optional[List[Group]]) -> Optional[List[App]]:
        data = self._load_yaml('apps.yaml')
        if not data:
            return None

        apps = []
        app_ids = set()
        group_names = {g.name for g in groups} if groups else set()

        for idx, app_data in enumerate(data.get('apps', [])):
            try:
                app = App(**app_data)

                if app.id in app_ids:
                    self.errors.append(f"Duplicate app ID: {app.id}")
                app_ids.add(app.id)

                for version in app.versions:
                    for group in version.groups:
                        if group not in group_names:
                            self.errors.append(f"App '{app.id}' references unknown group: {group}")

                    self._check_conditions(
                        f"app '{app.id}' version {version.version}",
                        version.conditions or [], group_names,
                    )
                    if not version.groups and not (version.conditions or []) \
                        and not (version.include_devices or []):
                        self.warnings.append(
                            f"App '{app.id}' version {version.version} has no groups, "
                            "conditions or included devices and will match no devices"
                        )

                    if not version.s3_key:
                        self.errors.append(f"App '{app.id}' version {version.version} missing S3 key")

                apps.append(app)

            except Exception as e:
                self.errors.append(f"Invalid app at index {idx}: {_model_error(e)}")

        if not apps:
            self.warnings.append("No apps defined")

        return apps

    def _validate_profiles(self, groups: Optional[List[Group]]) -> Optional[List[Profile]]:
        data = self._load_yaml('profiles.yaml')
        if not data:
            return None

        profiles = []
        profile_ids = set()
        ios_only_scoped = []
        group_names = {g.name for g in groups} if groups else set()

        for idx, profile_data in enumerate(data.get('profiles', [])):
            try:
                profile = Profile(**profile_data)

                # The model coerces a non-mapping enrollment block to None so an old document still saves; say so, or
                # the key silently does nothing forever.
                raw_enrollment = profile_data.get('enrollment')
                if raw_enrollment is not None and not isinstance(raw_enrollment, dict):
                    self.warnings.append(
                        f"Profile '{profile.id}' has an 'enrollment' value that is "
                        "not a mapping, so it is ignored. Put the DEP profile "
                        "settings under it as a mapping, or use 'type: enrollment'."
                    )

                if profile.id in profile_ids:
                    self.errors.append(f"Duplicate profile ID: {profile.id}")
                profile_ids.add(profile.id)

                for group in profile.groups or []:
                    if group not in group_names:
                        self.errors.append(f"Profile '{profile.id}' references unknown group: {group}")

                self._check_conditions(
                    f"profile '{profile.id}'", profile.conditions or [], group_names,
                )
                is_managed = (profile.type or 'configuration') == 'configuration' \
                             and not profile.dep_profile
                if is_managed and not (profile.groups or []) \
                    and not (profile.conditions or []) \
                    and not (profile.include_devices or []):
                    self.warnings.append(
                        f"Profile '{profile.id}' has no groups, conditions or included "
                        "devices and will deploy to no devices"
                    )

                if not profile.payload and not profile.payloads \
                    and not profile.enrollment and profile.type != "enrollment":
                    self.warnings.append(f"Profile '{profile.id}' has empty payload")
                self._check_profile_payloads(profile)
                self._check_profile_data_keys(profile)

                self._check_filevault_payloads(profile)

                if self._ios_without_wearables(profile.platforms):
                    ios_only_scoped.append(f"profile '{profile.id}'")

                profiles.append(profile)

            except Exception as e:
                self.errors.append(f"Invalid profile at index {idx}: {_model_error(e)}")

        self._warn_ios_platform_split('profiles.yaml', ios_only_scoped)
        if not profiles:
            self.warnings.append("No profiles defined")

        return profiles

    def _check_profile_payloads(self, profile: Profile) -> None:
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
                self.errors.append(f"{where} must be a mapping of profile keys")
                continue
            ptype = str(entry.get('PayloadType') or '').strip()
            if not ptype:
                self.errors.append(
                    f"{where} is missing 'PayloadType' (e.g. com.apple.wifi.managed). "
                    "The device rejects a payload that does not declare its type."
                )
                continue
            if is_undocumented_apple_payload_type(ptype):
                self.warnings.append(
                    f"{where}: PayloadType '{ptype}' is not a payload type Apple "
                    "documents. Check the spelling: a device that does not recognize a "
                    "payload type can still report the profile installed, so a typo "
                    "here looks like a successful deployment."
                )

    def _check_profile_data_keys(self, profile: Profile) -> None:
        """A profile's data_keys declaration, checked against its payloads. Two authoring mistakes warn (never error):
        an undeclared-but-referenced-looking name, and a declared key whose value isn't valid base64. """
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
                self.warnings.append(
                    f"Profile '{profile.id}' declares data key '{name}', but no "
                    "payload in the profile carries a key with that name, so the "
                    "declaration does nothing. Check the spelling."
                )
        for name, _ in bad:
            self.warnings.append(
                f"Profile '{profile.id}' declares data key '{name}', but its "
                "value is not valid base64, so it will reach the device as a "
                "string rather than <data>. Data keys must hold the base64 of "
                "the binary value."
            )

    def _check_filevault_payloads(self, profile: Profile) -> None:
        """The FileVault payloads on one profile, checked against Apple's rules for them. See
        https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.MCX.FileVault2.yaml
        and docs for the Enable-as-boolean and escrow-completeness rulings."""
        if (profile.type or 'configuration') != 'configuration' or profile.dep_profile:
            return

        for entry in _profile_payload_entries(profile):
            if entry.get('PayloadType') != FILEVAULT_ENFORCE_PAYLOAD_TYPE:
                continue
            if isinstance(entry.get('Enable'), bool):
                shipped = 'true' if entry['Enable'] else 'false'
                wanted = 'On' if entry['Enable'] else 'Off'
                self.warnings.append(
                    f"Profile '{profile.id}' ({FILEVAULT_ENFORCE_PAYLOAD_TYPE}) has "
                    f"'Enable' as a YAML boolean, which ships to the Mac as <{shipped}/>. "
                    f"Apple's FileVault payload takes the string '{wanted}'. Quote it "
                    f"(Enable: '{wanted}'), or YAML reads the bare word as a boolean and "
                    "the Mac ignores the setting."
                )

        escrows = _filevault_escrow_payloads(profile)
        if len(escrows) > 1:
            self.errors.append(
                f"Profile '{profile.id}' carries {len(escrows)} "
                f"{FILEVAULT_ESCROW_PAYLOAD_TYPE} payloads. A Mac accepts one "
                "recovery-key escrow payload and errors on a second, so this "
                "profile fails to install. Keep one and remove the rest."
            )
        for entry in escrows:
            problems = _escrow_payload_problems(profile, entry)
            if problems:
                self.warnings.append(
                    f"Profile '{profile.id}' has a {FILEVAULT_ESCROW_PAYLOAD_TYPE} "
                    "payload that will not escrow anything: " + "; ".join(problems)
                    + ". The Mac refuses a payload missing a key Apple marks "
                      "required, so this profile fails to install as it stands."
                )

        if _profile_enables_filevault(profile) and not _profile_has_filevault_escrow(profile) \
            and not self.filevault_escrow_configured:
            self.warnings.append(
                f"Profile '{profile.id}' turns on FileVault but does not carry a "
                "working recovery-key escrow payload "
                f"({FILEVAULT_ESCROW_PAYLOAD_TYPE}) itself. That's fine if another "
                "profile in this tenant escrows the key; if none does, saving this "
                "config will fail."
            )

    def _cross_validate(self, config: TenantConfig, groups: List[Group],
                        apps: List[App], profiles: List[Profile]):
        """Cross-file validation."""
        if config.dep.get('enabled'):
            dep_profiles = [p for p in profiles if p.dep_profile]
            if not dep_profiles:
                self.warnings.append("DEP enabled but no DEP profiles defined")

            default_profile = config.dep.get('default_profile')
            if default_profile and not any(p.id == default_profile for p in dep_profiles):
                self.errors.append(f"Default DEP profile '{default_profile}' not found")

        used_groups = set()
        for app in apps:
            for version in app.versions:
                used_groups.update(version.groups)
        for profile in profiles:
            used_groups.update(profile.groups or [])

        for group in groups:
            if group.name not in used_groups:
                self.warnings.append(f"Group '{group.name}' is defined but not used")

        # FileVault escrow guard, tenant-wide rather than per-profile.
        fv_profiles = [p for p in profiles if _profile_enables_filevault(p)]
        if fv_profiles and not config.allow_unescrowed_filevault \
            and not self.filevault_escrow_configured:
            escrowed = any(_profile_has_filevault_escrow(p) for p in profiles)
            if not escrowed:
                names = ", ".join(sorted(p.id for p in fv_profiles))
                incomplete = sorted(
                    p.id for p in profiles if _filevault_escrow_payloads(p)
                )
                remedy = (
                    "Fix this by adding an escrow payload to a profile before you deploy "
                    "FileVault (a separate escrow-only profile is fine)"
                    if not incomplete else
                    f"Profile(s) {', '.join(incomplete)} do carry an escrow payload, but "
                    "not one the Mac would install: see the warnings naming what each is "
                    "missing. Complete one of them"
                )
                self.errors.append(
                    f"Profile(s) {names} turn on FileVault (com.apple.MCX.FileVault2), but "
                    "no profile in this tenant escrows the recovery key (a "
                    "com.apple.security.FDERecoveryKeyEscrow payload carrying 'Location' "
                    "and an 'EncryptCertPayloadUUID' that names a "
                    "com.apple.security.pkcs1 payload beside it). Every Mac that "
                    "receives this profile encrypts its disk with a key nobody can recover. "
                    "If the user forgets their password, the disk is unreadable and nothing "
                    f"in Micromanage can unlock it. {remedy}, or, if you accept the risk, "
                    "set allow_unescrowed_filevault: true under tenant: in config.yaml."
                )

        # Apple allows one escrow payload per Mac.
        escrow_profiles = sorted(p.id for p in profiles if _filevault_escrow_payloads(p))
        authored_complete = any(_profile_has_filevault_escrow(p) for p in profiles)
        injected_profiles: List[str] = []
        if self.filevault_escrow_configured and not authored_complete:
            injected_profiles = sorted(
                p.id for p in profiles
                if not _is_dep_profile(p)
                and not _filevault_escrow_payloads(p)
                and any(entry.get('PayloadType') == FILEVAULT_ENFORCE_PAYLOAD_TYPE
                        for entry in _profile_payload_entries(p))
            )
        if len(escrow_profiles) + len(injected_profiles) > 1:
            parts = []
            if escrow_profiles:
                parts.append(
                    f"Profile(s) {', '.join(escrow_profiles)} carry a "
                    "com.apple.security.FDERecoveryKeyEscrow payload"
                )
            if injected_profiles:
                parts.append(
                    f"profile(s) {', '.join(injected_profiles)} get one injected "
                    "at build time (this tenant has an escrow keypair)"
                )
            self.warnings.append(
                " and ".join(parts) + ". A Mac accepts one and errors on a "
                                      "second, so check that no Mac is in scope for more than one of "
                                      "these."
            )

    def _validate_tags(self) -> Optional[set]:
        """Validate the optional advisory tags.yaml registry. Returns the set of registered tag names, or None when
        missing/empty (tags are then free-form)."""
        path = self.tenant_path / 'tags.yaml'
        if not path.exists():
            return None
        data = self._load_yaml('tags.yaml')
        if not data:
            return None  # empty file or load error (the latter already recorded)

        names: set = set()
        for idx, tag_data in enumerate(data.get('tags', []) or []):
            try:
                tag = Tag(**tag_data)
            except Exception as e:
                self.errors.append(f"Invalid tag at index {idx}: {_model_error(e)}")
                continue
            if tag.name in names:
                self.errors.append(f"Duplicate tag name: {tag.name}")
            names.add(tag.name)

        # An empty or all-invalid registry counts as no registry for warning purposes. Otherwise every tag gets flagged
        # as unknown.
        return names or None

    def _warn_unknown_tag_refs(self, groups: Optional[List[Group]],
                               apps: Optional[List[App]],
                               profiles: Optional[List[Profile]],
                               known_tags: set) -> None:
        """Warn on tag conditions referencing a tag not in the registry."""

        def scan(owner: str, conditions: Optional[List[Condition]]) -> None:
            for condition in conditions or []:
                for ref in _condition_tag_refs(condition):
                    if ref not in known_tags:
                        self.warnings.append(
                            f"{owner} references tag '{ref}' which is not defined in "
                            "tags.yaml"
                        )

        for group in groups or []:
            scan(f"group '{group.name}'", group.conditions)
        for app in apps or []:
            for version in app.versions:
                scan(f"app '{app.id}' version {version.version}", version.conditions)
        for profile in profiles or []:
            scan(f"profile '{profile.id}'", profile.conditions)

    # ==ATC flows (flows.yaml)==
    def _validate_flows(self, groups: Optional[List[Group]],
                        apps: Optional[List[App]],
                        profiles: Optional[List[Profile]],
                        known_tags: Optional[set]) -> Optional[set]:
        """Validate the optional flows.yaml (every ATC flow in it). Returns the set of flow ids, or None when there is
        no document."""
        from controller.services.flow_step_catalog import normalize_flow_document

        path = self.tenant_path / 'flows.yaml'
        if not path.exists():
            return None
        data = self._load_yaml('flows.yaml')
        if not data:
            return None

        flow_docs, warns = normalize_flow_document(data)
        for w in warns:
            self.warnings.append(w)
        if not flow_docs:
            return None

        group_names = {g.name for g in groups} if groups else set()
        profile_ids = {p.id for p in profiles} if profiles else set()
        app_ids = {a.id for a in apps} if apps else set()

        flows: List[Flow] = []
        for fdata in flow_docs:
            try:
                flows.append(Flow(**fdata))
            except Exception as e:
                self.errors.append(f"Invalid flow: {_model_error(e)}")
        if not flows:
            return None

        # Normalization adopts a permanent flow when a document has none, so the only shape that survives to here is the
        # one it will not choose between.
        permanent = [f for f in flows if f.permanent and not f.draft_of]
        if len(permanent) > 1:
            self.errors.append(
                "flows.yaml has more than one permanent flow ("
                + _quoted_list(sorted(f.id for f in permanent))
                + "); exactly one flow may carry 'permanent: true'"
            )
        permanent_id = permanent[0].id if len(permanent) == 1 else None

        for flow in flows:
            owner = f"flow '{flow.id}'"

            with self._draft_errors_demoted(flow):
                nodes_by_id: Dict[str, FlowNode] = {}
                for node in flow.nodes:
                    if node.id in nodes_by_id:
                        self.errors.append(f"{owner} has a duplicate node id: {node.id}")
                        continue  # keep the first definition for graph/edge analysis
                    nodes_by_id[node.id] = node

                starts = [n for n in nodes_by_id.values() if n.type == "start"]
                if not starts:
                    self.errors.append(f"{owner} has no 'start' node (add an entry point)")

                edges = self._flow_edges(owner, flow, nodes_by_id)

                for node in flow.nodes:
                    self._check_flow_node_params(
                        owner, node, group_names, profile_ids, app_ids, known_tags
                    )

                self._check_flow_graph(owner, edges, nodes_by_id, [s.id for s in starts])

                # A draft borrows its target's standing: a draft of the enrollment flow is reviewed as the enrollment
                # flow, because that is what it becomes when somebody promotes it.
                is_enrollment = permanent_id is not None and flow.id == permanent_id
                if flow.draft_of and permanent_id is not None:
                    is_enrollment = flow.draft_of == permanent_id
                self._warn_flow_semantics(flow.id, edges, nodes_by_id,
                                          [s.id for s in starts], profiles, is_enrollment)

        return {f.id for f in flows}

    @contextmanager
    def _draft_errors_demoted(self, flow: "Flow"):
        """Send a draft's structural errors to the warning channel instead. A draft never runs; nothing is
        waived, since promotion re-validates it as the live flow."""
        if not flow.draft_of:
            yield
            return
        outer = self.errors
        self.errors = []
        try:
            yield
        finally:
            demoted, self.errors = self.errors, outer
            for message in demoted:
                self.warnings.append(f"{message} (a draft, so it does not block the save)")

    def _check_flow_scope(self, owner: str, scope: Dict[str, Any],
                          group_names: set, known_tags: Optional[set]) -> None:
        """Validate a flow trigger's match scope (conditions + group refs)."""
        if not isinstance(scope, dict):
            self.errors.append(f"{owner} match must be a mapping")
            return
        conditions: List[Condition] = []
        for cdata in scope.get('conditions', []) or []:
            try:
                conditions.append(Condition(**cdata))
            except Exception as e:
                self.errors.append(f"{owner} has an invalid condition: {_model_error(e)}")
        self._check_conditions(owner, conditions, group_names)
        for g in scope.get('groups', []) or []:
            if g not in group_names:
                self.errors.append(f"{owner} references unknown group: {g}")
        for key in ("include_devices", "exclude_devices"):
            vals = scope.get(key)
            if vals is not None and not isinstance(vals, list):
                self.errors.append(f"{owner} {key} must be a list of serial numbers")
        if known_tags:
            self._warn_tag_condition_refs(owner, conditions, known_tags)

    def _warn_tag_condition_refs(self, owner: str, conditions: List[Condition],
                                 known_tags: set) -> None:
        for condition in conditions:
            for ref in _condition_tag_refs(condition):
                if ref not in known_tags:
                    self.warnings.append(
                        f"{owner} references tag '{ref}' which is not defined in tags.yaml"
                    )

    def _flow_edges(self, owner: str, flow: Flow,
                    nodes_by_id: Dict[str, "FlowNode"]) -> Dict[str, List[str]]:
        """Validate each node's edges against the step catalog and return the adjacency map (node id -> [target node
        ids])."""
        from controller.services.flow_step_catalog import (
            GATE_EDGE_HANDLES, VALID_NODE_TYPES, node_edges,
        )

        edges: Dict[str, List[str]] = {}
        for node in flow.nodes:
            if node.type not in VALID_NODE_TYPES:
                self.errors.append(
                    f"{owner} node '{node.id}' has an unknown type: {node.type}"
                )
                edges[node.id] = []
                continue
            handle_field = {
                "next": node.next, "on_true": node.on_true,
                "on_false": node.on_false, "on_timeout": node.on_timeout,
                "on_release": node.on_release, "on_cancel": node.on_cancel,
                "on_wait": node.on_wait,
            }
            # A manual_gate only requires the handles its options name; other gate handles are optional. Everything else
            # uses the static catalog edges (wait_for's on_timeout is optional -> defaults to failing the run).
            allowed = node_edges(node.type)
            if node.type == "manual_gate":
                opts = (node.params or {}).get("options") or []
                required = {o.get("edge") for o in opts
                            if isinstance(o, dict) and o.get("edge") in GATE_EDGE_HANDLES}
            else:
                required = {h for h in allowed
                            if not (node.type == "wait_for" and h == "on_timeout")}
            targets: List[str] = []
            for h in allowed:
                val = handle_field.get(h)
                if val is None:
                    if h in required:
                        self.errors.append(
                            f"{owner} node '{node.id}' ({node.type}) is missing its "
                            f"'{h}' edge"
                        )
                    continue
                if val not in nodes_by_id:
                    self.errors.append(
                        f"{owner} node '{node.id}' edge '{h}' references unknown "
                        f"node: {val}"
                    )
                else:
                    targets.append(val)
            # Reject edges the node type does not have (e.g. a 'next' on a branch).
            for h, val in handle_field.items():
                if val is not None and h not in allowed:
                    self.errors.append(
                        f"{owner} node '{node.id}' ({node.type}) must not define a "
                        f"'{h}' edge"
                    )
            edges[node.id] = targets
        return edges

    def _check_flow_node_params(self, owner: str, node: "FlowNode",
                                group_names: set, profile_ids: set, app_ids: set,
                                known_tags: Optional[set]) -> None:
        from controller.auth import DESTRUCTIVE_COMMANDS
        from controller.services.command_catalog import (
            RETIRED_COMMANDS, VALID_COMMAND_TYPES,
        )
        from controller.services.flow_step_catalog import (
            GATE_EDGE_HANDLES, is_start_kind, is_wait_signal,
        )
        from controller.services.variables import is_self_referential, unknown_variables

        p = node.params or {}
        where = f"{owner} node '{node.id}'"
        t = node.type

        def _str_list(value: Any) -> List[str]:
            items = value if isinstance(value, list) else ([value] if value else [])
            return [str(x) for x in items if x]

        # The engine only honours a literal false for gate; a hand-typed "false" or 0 still holds the flow up.
        if "gate" in p and not isinstance(p.get("gate"), bool):
            self.warnings.append(
                f"{where} has gate: {p.get('gate')!r}, which is neither true nor "
                "false, so the step keeps holding the flow up. Use true or false."
            )

        if t == "start":
            kind = p.get("kind")
            if not is_start_kind(kind):
                self.errors.append(
                    f"{where} (start) has an unknown trigger kind: {kind!r}"
                )
            if kind == "schedule":
                iv = p.get("interval_minutes")
                if isinstance(iv, bool) or not isinstance(iv, int) or iv <= 0:
                    self.errors.append(
                        f"{where} (start) scheduled trigger requires a positive integer "
                        "'interval_minutes'"
                    )
                elif iv < 5:
                    self.warnings.append(
                        f"{where} (start) interval_minutes={iv} is very short; a schedule "
                        "start effectively runs every poll tick below ~5 minutes"
                    )
            if kind == "checkin":
                self._warn_checkin_start_params(where, p)
            self._check_flow_scope(f"{where} match", p.get("match") or {},
                                   group_names, known_tags)
        elif t == "manual_gate":
            if not str(p.get("summary") or "").strip():
                self.errors.append(f"{where} (manual_gate) requires a 'summary'")
            if p.get("severity") not in VALID_SEVERITIES:
                self.errors.append(
                    f"{where} (manual_gate) severity must be one of {VALID_SEVERITIES}"
                )
            opts = p.get("options")
            if not isinstance(opts, list) or not opts:
                self.errors.append(
                    f"{where} (manual_gate) requires a non-empty 'options' list"
                )
            else:
                for o in opts:
                    if not isinstance(o, dict) or not str(o.get("label") or "").strip():
                        self.errors.append(f"{where} (manual_gate) option needs a 'label'")
                    elif o.get("edge") not in GATE_EDGE_HANDLES:
                        self.errors.append(
                            f"{where} (manual_gate) option '{o.get('label')}' has an "
                            f"invalid edge {o.get('edge')!r} (one of {GATE_EDGE_HANDLES})"
                        )
            # Optional, unlike wait_for's: an absent timeout means the engine's escalation ladder. A malformed one is
            # the same hard error as on wait_for, because the engine would silently ignore it.
            tmo = p.get("timeout_minutes")
            if tmo is not None and (isinstance(tmo, bool)
                                    or not isinstance(tmo, int) or tmo <= 0):
                self.errors.append(
                    f"{where} (manual_gate) 'timeout_minutes' is optional, but when "
                    "set it must be a positive integer"
                )
        elif t in ("assign_tag", "remove_tag"):
            tags = _str_list(p.get("tags"))
            if not tags:
                self.errors.append(f"{where} ({t}) requires a non-empty 'tags' list")
            if known_tags:
                for tg in tags:
                    if tg not in known_tags:
                        self.warnings.append(
                            f"{where} references tag '{tg}' which is not defined in tags.yaml"
                        )
        elif t == "set_name":
            tmpl = str(p.get("template") or "").strip()
            if not tmpl:
                self.errors.append(f"{where} (set_name) requires a 'template'")
            else:
                for var in unknown_variables(tmpl):
                    self.warnings.append(
                        f"{where} naming template references unknown variable '{{{var}}}'"
                    )
                if is_self_referential(tmpl):
                    self.warnings.append(
                        f"{where} naming template uses {{hostname}}; prefer a stable "
                        "identifier like {serial}."
                    )
        elif t == "install_profiles":
            ids = p.get("profile_ids")
            if not isinstance(ids, list) or not ids:
                self.errors.append(
                    f"{where} (install_profiles) requires a non-empty 'profile_ids' list"
                )
            for pid in (ids if isinstance(ids, list) else []):
                if pid not in profile_ids:
                    self.errors.append(f"{where} references unknown profile: {pid}")
        elif t == "install_apps":
            ids = p.get("app_ids")
            if not isinstance(ids, list) or not ids:
                self.errors.append(
                    f"{where} (install_apps) requires a non-empty 'app_ids' list"
                )
            for aid in (ids if isinstance(ids, list) else []):
                if aid not in app_ids:
                    self.errors.append(f"{where} references unknown app: {aid}")
        elif t == "send_command":
            cmd = p.get("command")
            cparams = p.get("params")
            if cparams is not None and not isinstance(cparams, dict):
                self.errors.append(f"{where} (send_command) 'params' must be a mapping")
            if cmd in RETIRED_COMMANDS:
                # Retired, not misspelled: warns rather than errors.
                self.warnings.append(
                    f"{where} (send_command) uses '{cmd}', which this deployment "
                    f"retired: {RETIRED_COMMANDS[cmd]}. The step fails when the "
                    "flow reaches it, so drop it from flows.yaml or choose "
                    "another command."
                )
            elif not cmd or cmd not in VALID_COMMAND_TYPES:
                self.errors.append(
                    f"{where} (send_command) references unknown command: {cmd}"
                )
            elif cmd in DESTRUCTIVE_COMMANDS:
                self.errors.append(
                    f"{where} (send_command) uses destructive command '{cmd}', which is "
                    "forbidden as an automated flow step"
                )
            else:
                # Catch missing required parameters at save time (mirrors command_catalog.build_generic_fields).
                # "mac"-required params are device-dependent, so only unconditionally-required ones apply.
                from controller.services.command_catalog import get_command
                entry = get_command(cmd) or {}
                supplied = cparams if isinstance(cparams, dict) else {}
                for pd in entry.get("params", []):
                    if pd.get("required") is True:
                        val = supplied.get(pd["name"])
                        if val is None or (isinstance(val, str) and not val.strip()):
                            self.errors.append(
                                f"{where} (send_command) is missing required parameter "
                                f"'{pd.get('label', pd['name'])}'"
                            )
        elif t == "branch":
            cond = p.get("condition")
            if not isinstance(cond, dict):
                self.errors.append(f"{where} (branch) requires a 'condition' mapping")
            else:
                try:
                    c = Condition(**cond)
                    self._check_conditions(where, [c], group_names)
                    if known_tags:
                        self._warn_tag_condition_refs(where, [c], known_tags)
                except Exception as e:
                    self.errors.append(f"{where} (branch) has an invalid condition: {_model_error(e)}")
        elif t == "wait_for":
            if not is_wait_signal(p.get("signal")):
                self.errors.append(
                    f"{where} (wait_for) has an unknown signal: {p.get('signal')}"
                )
            tmo = p.get("timeout_minutes")
            if isinstance(tmo, bool) or not isinstance(tmo, int) or tmo <= 0:
                self.errors.append(
                    f"{where} (wait_for) requires a positive integer 'timeout_minutes'"
                )
        elif t == "configure_accounts":
            mode = p.get("primary_account")
            if mode not in ("prompt_admin", "prompt_standard", "skip"):
                self.errors.append(
                    f"{where} (configure_accounts) 'primary_account' must be one of "
                    "prompt_admin / prompt_standard / skip"
                )
            if p.get("managed_admin"):
                src = p.get("managed_admin_password_source") or "generate"
                if src not in ("generate", "static"):
                    self.errors.append(
                        f"{where} (configure_accounts) 'managed_admin_password_source' "
                        "must be 'generate' or 'static'"
                    )
                if src == "static" and not str(p.get("managed_admin_password") or "").strip():
                    self.errors.append(
                        f"{where} (configure_accounts) a static managed-admin password "
                        "source requires 'managed_admin_password'"
                    )
                short = str(p.get("managed_admin_shortname") or "").strip()
                if short and not re.match(r'^[a-z_][a-z0-9_.-]*$', short):
                    self.errors.append(
                        f"{where} (configure_accounts) 'managed_admin_shortname' must be a "
                        "valid Unix short name (lowercase, starts with a letter/underscore)"
                    )
            elif mode in ("skip", "prompt_standard"):
                # Warning, not error: the step itself refuses to send in this shape.
                from controller.services.flow_step_catalog import (
                    ACCOUNT_ADMIN_REQUIREMENT,
                )
                self.warnings.append(
                    f"{where} (configure_accounts) is set to '{mode}' with no managed "
                    f"admin, so the Mac could end up with no administrator at all. "
                    f"{ACCOUNT_ADMIN_REQUIREMENT}. Enable 'managed_admin', or the step "
                    "will refuse to send when the flow reaches it."
                )
        elif t == "set_firmware_lock":
            src = p.get("password_source")
            if src not in ("generate", "static"):
                self.errors.append(
                    f"{where} (set_firmware_lock) 'password_source' must be 'generate' or 'static'"
                )
            if src == "static" and not str(p.get("password") or "").strip():
                self.errors.append(
                    f"{where} (set_firmware_lock) a static password source requires 'password'"
                )
        # end: no params.

    def _check_flow_graph(self, owner: str, edges: Dict[str, List[str]],
                          nodes_by_id: Dict[str, "FlowNode"],
                          starts: List[str]) -> None:
        """Reject reachable cycles (a flow must be a DAG), require every start to reach an end, and warn on nodes
        unreachable from any start. Reachability is computed before cycle detection."""
        starts = [s for s in starts if s in nodes_by_id]
        if not starts:
            return  # no-start already reported by the caller

        reachable = _reach_nodes(edges, starts)
        reachable_edges = {
            n: [t for t in edges.get(n, []) if t in reachable] for n in reachable
        }
        cycles = _find_cycle_edges(reachable_edges)
        for node, ref in cycles:
            self.errors.append(
                f"{owner} has a cycle involving '{node}' and '{ref}' "
                "(a flow must be acyclic)"
            )

        if not cycles:
            for s in starts:
                if not any(nodes_by_id[n].type == "end"
                           for n in _reach_nodes(edges, [s]) if n in nodes_by_id):
                    self.errors.append(
                        f"{owner} has no reachable 'end' node from start '{s}'"
                    )
        for nid in nodes_by_id:
            if nid not in reachable:
                self.warnings.append(f"{owner} node '{nid}' is unreachable from any start")

    def _warn_checkin_start_params(self, where: str, params: Dict[str, Any]) -> None:
        """Say when a check-in start's two knobs will not be read as written. services.atc reads both defensively and
        never raises."""
        from controller.services.atc import CHECKIN_COOLDOWN_DEFAULT_MINUTES

        if "cooldown_minutes" in params and not _reads_as_int(params["cooldown_minutes"]):
            # Booleans are the case worth catching: YAML reads a bare yes as True and int(True) is 1, so the key meant
            # to space runs out would set a one-minute cooldown. atc._checkin_cooldown_minutes refuses the coercion too.
            self.warnings.append(
                f"{where} (start) cooldown_minutes is {params['cooldown_minutes']!r}, "
                "which is not a number of minutes, so the engine ignores it and waits "
                f"the default {CHECKIN_COOLDOWN_DEFAULT_MINUTES} minutes between runs "
                "on a device. Write a whole number of minutes, or 0 to run on every "
                "check-in."
            )
        if "once" in params and not isinstance(params["once"], bool):
            # atc._truthy_param reads a string as a word rather than by emptiness, so "false" and "no" are off, and so
            # is anything outside its four words, which is how a start meant to run once ends up running forever.
            reading = "true" if _reads_as_true(params["once"]) else "false"
            self.warnings.append(
                f"{where} (start) once is {params['once']!r}, which is not true or "
                f"false, so the engine reads it as {reading}. Write it as a boolean to "
                "say which you meant."
            )

    def _flow_warn(self, flow_id: str, node_id: Optional[str], code: str,
                   message: str) -> None:
        """One structured flow warning, mirrored into the plain warnings list too."""
        self.warnings.append(message)
        self.flow_warnings.append({"flow_id": flow_id, "node_id": node_id,
                                   "code": code, "message": message})

    # The signal a gated install step's wait_for barrier has to carry, plus the word the warning uses for what the step
    # installs.
    _INSTALL_BARRIERS = {
        "install_profiles": ("profile_installed", "profiles"),
        "install_apps": ("app_installed", "apps"),
    }

    # Each ref-based wait signal, its producer step, and the words the warning uses.
    _WAIT_PRODUCERS = {
        "profile_installed": ("install_profiles", "profiles to be installed",
                              "installs any", "an Install profiles"),
        "app_installed": ("install_apps", "apps to be installed",
                          "installs any", "an Install apps"),
        "command_ack": ("send_command", "the device to answer a command",
                        "sends one", "a Send command"),
        "declaration_applied": ("sync_declarations", "declarations to be applied",
                                "syncs any", "a Sync declarations"),
    }

    def _warn_flow_semantics(self, flow_id: str, edges: Dict[str, List[str]],
                             nodes_by_id: Dict[str, "FlowNode"],
                             starts: List[str],
                             profiles: Optional[List[Profile]],
                             is_enrollment: bool) -> None:
        """Semantic flow warnings: graphs the engine runs fine but that rarely mean what the author meant. Warnings
        only, never errors."""
        live = _reach_nodes(edges, starts)
        release_ids = [nid for nid, n in nodes_by_id.items()
                       if n.type == "release_device"]

        # release-ordering:. Warning, not error: releasing early is a legitimate choice for some fleets.
        for nid, node in nodes_by_id.items():
            barrier = self._INSTALL_BARRIERS.get(node.type)
            if not barrier or nid not in live:
                continue
            if (node.params or {}).get("gate") is False:
                continue
            signal, what = barrier
            barriers = frozenset(
                b for b, bn in nodes_by_id.items()
                if bn.type == "wait_for" and (bn.params or {}).get("signal") == signal
            )
            unbarriered = _reach_nodes(edges, edges.get(nid, []), blocked=barriers)
            for rid in release_ids:
                if rid in unbarriered:
                    self._flow_warn(
                        flow_id, rid, "release-ordering",
                        f'Node "{rid}" can release devices before {what} from '
                        f'"{nid}" are confirmed installed. Add a wait step between '
                        f'them if the {what} must land first.'
                    )

        # A wait that holds nothing back on any run (_wait_already_satisfied skips it).
        for signal, wording in self._WAIT_PRODUCERS.items():
            ptype, subject, none_above, step_label = wording
            waits = frozenset(
                nid for nid, n in nodes_by_id.items()
                if n.type == "wait_for" and (n.params or {}).get("signal") == signal
            )
            producers = [nid for nid, n in nodes_by_id.items()
                         if n.type == ptype and nid in live]
            gated = [p for p in producers
                     if (nodes_by_id[p].params or {}).get("gate") is not False]
            gated_roots = [t for p in gated for t in edges.get(p, [])]
            for wid in sorted(w for w in waits if w in live):
                # gate: false on the wait itself is the author saying this one is allowed to find nothing waiting. Take
                # them at their word.
                if (nodes_by_id[wid].params or {}).get("gate") is False:
                    continue
                if wid in _reach_nodes(edges, gated_roots, blocked=waits - {wid}):
                    continue  # a producer reaches it with its list still intact
                head = f'Node "{wid}" waits for {subject}, but '
                from_producers = _reach_nodes(edges, gated_roots)
                ungated = sorted(p for p in producers if p not in gated
                                 and wid in _reach_nodes(edges, edges.get(p, [])))
                if wid in from_producers:
                    # Reachable from a producer, but only through an earlier wait on the same signal, which took the
                    # list with it.
                    earlier = _quoted_list(sorted(
                        b for b in waits - {wid}
                        if b in from_producers
                        and wid in _reach_nodes(edges, edges.get(b, []))
                    ))
                    body = (f'{earlier} above it already waited for the same thing, '
                            'and a wait clears its list when it finishes, so this one '
                            'holds nothing back and the run carries straight on. Take '
                            f'this wait out, or put {step_label} step between it and '
                            f'{earlier}.')
                elif ungated:
                    names = _quoted_list(ungated)
                    verb = "is" if len(ungated) == 1 else "are"
                    fix = ("Turn that back on" if len(ungated) == 1
                           else "Turn one of those back on")
                    body = (f'{names} above it {verb} set not to hold the flow up '
                            '(gate: false), so nothing is queued for this wait to hold '
                            f'and the run carries straight on. {fix}, or take the wait '
                            'out.')
                else:
                    body = (f'no step above it {none_above}, so this wait holds nothing '
                            'back and the run carries straight on. Put '
                            f'{step_label} step above it, or take the wait out.')
                self._flow_warn(flow_id, wid, "barrier-empty", head + body)

        # accounts-after-release: AccountConfiguration only takes effect before Setup Assistant ends.
        for rid in sorted(r for r in release_ids if r in live):
            for aid in sorted(n for n in _reach_nodes(edges, edges.get(rid, []))
                              if n in nodes_by_id
                                 and nodes_by_id[n].type == "configure_accounts"):
                self._flow_warn(
                    flow_id, aid, "accounts-after-release",
                    f'Node "{aid}" can run after "{rid}" has let the device out of '
                    'Setup Assistant, and account setup only lands while a Mac is '
                    'still in Setup Assistant, so it does nothing there. Move it above '
                    'the release step.'
                )

        # DEP await_device_configured with no release on the path: the device sits at Remote Management until a
        # release_device step (or a human) sends DeviceConfigured, and nothing on the timeline says why.
        dep_profiles = ([p for p in profiles or [] if _is_dep_profile(p)]
                        if is_enrollment else [])
        awaiting = [p.id for p in dep_profiles if _dep_profile_awaits(p)]
        if awaiting:
            names = _quoted_list(awaiting)
            label = "profile" if len(awaiting) == 1 else "profiles"
            verb = "sets" if len(awaiting) == 1 else "set"
            head = (f'DEP {label} {names} {verb} await_device_configured, so '
                    'devices wait at Remote Management until this flow releases them, ')
            dep_starts = [sid for sid in starts
                          if (nodes_by_id[sid].params or {}).get("kind") == "enroll_dep"]
            if not dep_starts:
                self._flow_warn(
                    flow_id, None, "dep-await-no-release",
                    head + 'but this flow has no Automated Enrollment start. Those '
                           'devices stay in Setup Assistant until someone releases '
                           'them by hand.'
                )
            else:
                for sid in dep_starts:
                    if not (_reach_nodes(edges, [sid]) & set(release_ids)):
                        self._flow_warn(
                            flow_id, sid, "dep-await-no-release",
                            head + f'but no path from start "{sid}" has a '
                                   'release_device step. Devices that enroll through '
                                   'this start stay in Setup Assistant.'
                        )
        elif dep_profiles:
            # release-without-await, the converse:.
            for rid in sorted(r for r in release_ids if r in live):
                self._flow_warn(
                    flow_id, rid, "release-without-await",
                    f'Node "{rid}" releases devices from Setup Assistant, but none of '
                    'this tenant\'s enrollment profiles turns on '
                    'await_device_configured ("Await final configuration"), so no '
                    'device is ever held there and this step does nothing. Turn that '
                    'setting on in the enrollment profile if devices should wait for '
                    'this flow to finish.'
                )

        # checkin-every-event:. Only an explicit cooldown_minutes: 0 buys this cadence.
        for sid in starts:
            params = nodes_by_id[sid].params or {}
            if params.get("kind") != "checkin" or _reads_as_true(params.get("once")):
                continue
            # Read as atc._checkin_cooldown_minutes reads it; a non-numeric value draws its own warning elsewhere.
            if not _reads_as_int(params.get("cooldown_minutes")):
                continue
            if max(int(params["cooldown_minutes"]), 0) > 0:
                continue
            touching = sorted(
                nid for nid in _reach_nodes(edges, [sid])
                if nodes_by_id[nid].type in _DEVICE_TOUCHING_STEPS
            )
            if not touching:
                continue
            self._flow_warn(
                flow_id, sid, "checkin-every-event",
                f'Start "{sid}" runs on every check-in (cooldown_minutes: 0) and '
                f'reaches {", ".join(repr(n) for n in touching)}, which queue work '
                'on the device. Each answer the device sends is another check-in, '
                'so the flow can keep restarting itself for as long as the device '
                'stays connected. Leave cooldown_minutes unset for the default '
                'wait, or keep 0 only for a flow that just tags or branches.'
            )

        # Start scope shapes that match something other than what was typed.
        for sid in starts:
            match = (nodes_by_id[sid].params or {}).get("match")
            # No scope matches every device. Plain warnings channel, not _flow_warn, to avoid drowning it.
            if _scope_is_empty(match):
                self.warnings.append(
                    f'Start "{sid}" has no scope, so it fires for every device of '
                    'its trigger kind. That is a normal choice for a fleet-wide '
                    'flow. Add groups or conditions if you meant to narrow it.'
                )
            if not isinstance(match, dict):
                continue
            # Only exclusions set: evaluate_scope needs groups, conditions or include_devices to match anyone, so this
            # start never runs.
            if match.get("exclude_devices") and not any(
                match.get(k) for k in ("groups", "conditions", "include_devices")):
                self._flow_warn(
                    flow_id, sid, "exclude-only-scope",
                    f'Start "{sid}" matches no devices because its scope only '
                    'excludes devices. Add groups or conditions to say which '
                    'devices it covers; an exclude list by itself matches nothing.'
                )
            # Unknown keys are ignored at runtime, so a typo such as "group" for "groups" silently stops narrowing the
            # scope.
            for key in sorted(k for k in match if k not in _FLOW_SCOPE_KEYS):
                close = difflib.get_close_matches(str(key), _FLOW_SCOPE_KEYS, 1, 0.6)
                tail = (f'Did you mean "{close[0]}"?' if close
                        else "Valid keys: " + ", ".join(_FLOW_SCOPE_KEYS) + ".")
                self._flow_warn(
                    flow_id, sid, "unknown-scope-key",
                    f'Start "{sid}" scope has an unknown key "{key}". The engine '
                    'ignores unknown keys, so this key does not narrow which '
                    f'devices match. {tail}'
                )

    # ==Dispatcher rules (dispatcher.yaml)==
    def _validate_dispatcher(self, groups: Optional[List[Group]],
                             apps: Optional[List[App]],
                             profiles: Optional[List[Profile]],
                             known_tags: Optional[set]) -> Optional[set]:
        """Validate the optional dispatcher.yaml (compliance rules + webhooks). Returns the set of rule ids, or None
        when there is no document."""
        path = self.tenant_path / 'dispatcher.yaml'
        if not path.exists():
            return None
        data = self._load_yaml('dispatcher.yaml')
        if not data:
            return None

        group_names = {g.name for g in groups} if groups else set()
        profile_ids = {p.id for p in profiles} if profiles else set()
        app_ids = {a.id for a in apps} if apps else set()
        # Profiles that reach nobody through profiles.yaml, read the way the scope engine reads a profile.
        unscoped_profiles = {
            p.id for p in (profiles or [])
            if not (p.groups or []) and not (p.conditions or [])
               and not (p.include_devices or [])
        }

        webhook_names: set = set()
        for idx, wdata in enumerate(data.get('webhooks', []) or []):
            try:
                webhook = DispatcherWebhook(**wdata)
            except Exception as e:
                self.errors.append(f"Invalid dispatcher webhook at index {idx}: {_model_error(e)}")
                continue
            if webhook.name in webhook_names:
                self.errors.append(f"Duplicate dispatcher webhook name: {webhook.name}")
            webhook_names.add(webhook.name)
            self._warn_webhook_target(webhook)

        rule_ids: set = set()
        for idx, rdata in enumerate(data.get('rules', []) or []):
            try:
                rule = DispatcherRule(**rdata)
            except Exception as e:
                self.errors.append(f"Invalid dispatcher rule at index {idx}: {_model_error(e)}")
                continue
            owner = f"rule '{rule.id}'"
            if rule.id in rule_ids:
                self.errors.append(f"Duplicate rule id: {rule.id}")
            rule_ids.add(rule.id)

            self._check_flow_scope(f"{owner} scope", rule.scope or {}, group_names, known_tags)
            # An unscoped rule watches the whole fleet. "enabled" is read off the raw document, not the pydantic
            # field, because the two disagree on edge cases.
            if rdata.get("enabled", True) and _scope_is_empty(rule.scope):
                self.warnings.append(
                    f"Rule '{rule.id}' has no scope, so it watches every device. "
                    "That is a normal choice for a fleet-wide rule. Add groups "
                    "or conditions if you meant to narrow it."
                )
            self._check_dispatcher_check(owner, rule.check or {}, profile_ids,
                                         enabled=rdata.get("enabled", True))
            for action in rule.actions or []:
                self._check_dispatcher_action(
                    owner, action, webhook_names, profile_ids, app_ids, known_tags,
                    unscoped_profiles=unscoped_profiles,
                )

        return rule_ids

    def _warn_webhook_target(self, webhook: "DispatcherWebhook") -> None:
        """Say at save time what a delivery attempt to this target will do. Warnings, never errors."""
        if not webhook.secret:
            self.warnings.append(
                f"Webhook '{webhook.name}' has no secret, so alerts are delivered "
                "unsigned and whatever receives them cannot tell an alert from this "
                "server apart from anything else that can reach that URL. Set "
                "'secret' to have each delivery carry an HMAC signature."
            )
        if self._webhook_delivery_blocked(webhook.url):
            self.warnings.append(
                f"Webhook '{webhook.name}' points at an address deliveries are "
                "refused for: the target resolves to a private, loopback or "
                "otherwise non-public address, and every alert aimed at it is "
                "dropped before it is sent, leaving only a line in the server log. "
                "Point it at a public address, or list this host in "
                "DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST if this server is meant to "
                "reach an internal collector. (The deprecated "
                "DISPATCHER_WEBHOOK_ALLOW_PRIVATE still works, but it admits every "
                "private target at once rather than this one.)"
            )

    def _webhook_delivery_blocked(self, url: str) -> bool:
        """The Dispatcher's own answer for this URL, asked from synchronous code. Imports the delivery path's own
        predicate rather than restating it, and runs it in a worker thread with a short deadline."""
        from concurrent.futures import ThreadPoolExecutor
        import asyncio

        try:
            from controller.services.dispatcher import _webhook_target_blocked
        except Exception:
            return False
        # No with block: that would join a stuck worker on the way out, defeating the deadline.
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            return bool(pool.submit(
                lambda: asyncio.run(_webhook_target_blocked(str(url)))
            ).result(timeout=_WEBHOOK_CHECK_TIMEOUT_SECONDS))
        except Exception:
            return False
        finally:
            pool.shutdown(wait=False)

    def _check_dispatcher_check(self, owner: str, check: Dict[str, Any],
                                profile_ids: set, enabled: Any = True) -> None:
        """Errors bind whether or not the rule runs; enabled (read the way the engine reads it) suppresses warnings
        only."""
        from controller.services.compliance_catalog import VALID_CHECK_TYPES

        ctype = check.get('type')
        if ctype not in VALID_CHECK_TYPES:
            self.errors.append(f"{owner} has an unknown check type: {ctype}")
            return
        # Inputs may sit under params or flat alongside type; evaluate_check resolves both the same way.
        params = check.get('params') or {k: v for k, v in check.items() if k != 'type'}
        if ctype == 'os_below' and not str(params.get('min') or '').strip():
            self.errors.append(f"{owner} check os_below requires a 'min' version")
        if ctype == 'not_seen_for':
            try:
                int(params.get('days'))
            except (TypeError, ValueError):
                self.errors.append(f"{owner} check not_seen_for requires an integer 'days'")
        if ctype == 'missing_profile':
            pid = params.get('profile_id')
            if not pid:
                self.errors.append(f"{owner} check missing_profile requires a 'profile_id'")
            elif pid not in profile_ids:
                self.errors.append(f"{owner} check references unknown profile: {pid}")
        if ctype == 'tagged':
            tags = params.get('tags')
            if not isinstance(tags, list) or not tags:
                self.errors.append(f"{owner} check tagged requires a non-empty 'tags' list")
        if ctype == 'flow_parked_for' and enabled:
            # Warning, unlike os_below/not_seen_for above: harmless, it simply never matches.
            try:
                float(params.get('hours'))
            except (TypeError, ValueError):
                self.warnings.append(
                    f"{owner} check flow_parked_for has no numeric 'hours', so "
                    "it never fires. Set 'hours' to how long a run may sit "
                    "parked before somebody should hear about it."
                )
        if ctype == 'attribute':
            if not str(params.get('key') or '').strip():
                self.errors.append(f"{owner} check attribute requires a 'key' path")
            if params.get('operator') not in (
                    'equals', 'not_equals', 'exists', 'gt', 'lt', 'regex'
            ):
                self.errors.append(
                    f"{owner} check attribute has an invalid operator: {params.get('operator')}"
                )
        if ctype == 'declaration_drift':
            ids = params.get('ids')
            if ids is not None and not isinstance(ids, list):
                self.errors.append(
                    f"{owner} check declaration_drift 'ids' must be a list of declaration ids"
                )
        if ctype == 'ddm_status':
            if not str(params.get('path') or '').strip():
                self.errors.append(f"{owner} check ddm_status requires a 'path'")
            if params.get('operator') not in (
                    'equals', 'not_equals', 'contains', 'gte', 'lte', 'exists', 'not_exists'
            ):
                self.errors.append(
                    f"{owner} check ddm_status has an invalid operator: {params.get('operator')}"
                )

    def _check_dispatcher_action(self, owner: str, action: "DispatcherAction",
                                 webhook_names: set, profile_ids: set, app_ids: set,
                                 known_tags: Optional[set],
                                 unscoped_profiles: Optional[set] = None) -> None:
        from controller.auth import DESTRUCTIVE_COMMANDS
        from controller.services.command_catalog import (
            RETIRED_COMMANDS, VALID_COMMAND_TYPES, get_command,
        )

        t = action.type
        p = action.params or {}
        valid = {"webhook", "assign_tag", "remove_tag", "install_profiles",
                 "install_apps", "send_command"}
        if t not in valid:
            self.errors.append(f"{owner} has an unknown action type: {t}")
            return

        if t == "webhook":
            target = p.get("target")
            if not target or target not in webhook_names:
                self.errors.append(
                    f"{owner} webhook action targets unknown webhook: {target}"
                )
        elif t in ("assign_tag", "remove_tag"):
            tags = p.get("tags")
            tags = tags if isinstance(tags, list) else ([tags] if tags else [])
            if not tags:
                self.errors.append(f"{owner} {t} action requires a non-empty 'tags' list")
            if known_tags:
                for tg in (str(x) for x in tags if x):
                    if tg not in known_tags:
                        self.warnings.append(
                            f"{owner} references tag '{tg}' which is not defined in tags.yaml"
                        )
        elif t == "install_profiles":
            ids = p.get("profile_ids")
            if not isinstance(ids, list) or not ids:
                self.errors.append(f"{owner} install_profiles action requires 'profile_ids'")
            # A remediation install is held on the device for as long as the rule exists.
            unscoped = unscoped_profiles or set()
            for pid in (ids if isinstance(ids, list) else []):
                if pid not in profile_ids:
                    self.errors.append(f"{owner} references unknown profile: {pid}")
                elif pid in unscoped:
                    self.warnings.append(
                        f"{owner} installs profile '{pid}' as a remediation, and nothing "
                        f"in profiles.yaml scopes '{pid}' to a device on its own, so "
                        "nothing releases it while this rule exists: resolving the alert "
                        "does not take it off the device, and neither does disabling the "
                        "rule."
                    )
                else:
                    self.warnings.append(
                        f"{owner} installs profile '{pid}' as a remediation, and nothing "
                        "releases it while this rule exists: resolving the alert does not "
                        "take it off the device, and neither does disabling the rule."
                    )
        elif t == "install_apps":
            ids = p.get("app_ids")
            if not isinstance(ids, list) or not ids:
                self.errors.append(f"{owner} install_apps action requires 'app_ids'")
            for aid in (ids if isinstance(ids, list) else []):
                if aid not in app_ids:
                    self.errors.append(f"{owner} references unknown app: {aid}")
        elif t == "send_command":
            cmd = p.get("command")
            cparams = p.get("params")
            if cparams is not None and not isinstance(cparams, dict):
                self.errors.append(f"{owner} send_command action 'params' must be a mapping")
            if cmd in RETIRED_COMMANDS:
                # Legal when written, warns rather than errors.
                self.warnings.append(
                    f"{owner} send_command names '{cmd}', which this deployment "
                    f"retired: {RETIRED_COMMANDS[cmd]}. The action fails when the "
                    "rule fires, so drop it from dispatcher.yaml or choose "
                    "another command."
                )
            elif not cmd or cmd not in VALID_COMMAND_TYPES:
                self.errors.append(f"{owner} send_command references unknown command: {cmd}")
            elif cmd in DESTRUCTIVE_COMMANDS:
                # Allowed, but the engine turns it into a pending-approval task an admin has to confirm, which is worth
                # flagging at save time.
                self.warnings.append(
                    f"{owner} send_command '{cmd}' is destructive; it will require "
                    "manual admin approval and never auto-remediates"
                )
            else:
                entry = get_command(cmd) or {}
                supplied = cparams if isinstance(cparams, dict) else {}
                for pd in entry.get("params", []):
                    if pd.get("required") is True:
                        val = supplied.get(pd["name"])
                        if val is None or (isinstance(val, str) and not val.strip()):
                            self.errors.append(
                                f"{owner} send_command is missing required parameter "
                                f"'{pd.get('label', pd['name'])}'"
                            )

    # ==DDM declarations (declarations.yaml)==
    def _validate_declarations(self, groups: Optional[List[Group]],
                               profiles: Optional[List[Profile]],
                               known_tags: Optional[set]) -> None:
        """Validate the optional declarations.yaml (DDM; services.ddm_manager)."""
        path = self.tenant_path / 'declarations.yaml'
        if not path.exists():
            return
        data = self._load_yaml('declarations.yaml')
        if not data:
            return

        group_names = {g.name for g in groups} if groups else set()
        profiles_by_id = {p.id: p for p in (profiles or [])}
        profile_ids = set(profiles_by_id)

        subs = data.get('status_subscriptions')
        if subs is not None and (
            not isinstance(subs, list) or any(not isinstance(s, str) for s in subs)
        ):
            self.errors.append(
                "declarations.yaml status_subscriptions must be a list of status-item names"
            )
        org = data.get('organization_info')
        if org is not None:
            if not isinstance(org, dict):
                self.errors.append("declarations.yaml organization_info must be a mapping")
            else:
                for key in ('name', 'email', 'url'):
                    if org.get(key) is not None and not isinstance(org[key], str):
                        self.errors.append(
                            f"declarations.yaml organization_info.{key} must be a string"
                        )

        seen_ids: set = set()
        ios_only_scoped = []
        for idx, ddata in enumerate(data.get('declarations', []) or []):
            try:
                item = DeclarationItem(**ddata)
            except Exception as e:
                self.errors.append(f"Invalid declaration at index {idx}: {_model_error(e)}")
                continue
            owner = f"declaration '{item.id}'"
            if self._ios_without_wearables(item.platforms):
                ios_only_scoped.append(owner)
            if item.id in seen_ids:
                self.errors.append(f"Duplicate declaration id: {item.id}")
            seen_ids.add(item.id)

            for group in item.groups or []:
                if group not in group_names:
                    self.errors.append(f"{owner} references unknown group: {group}")
            self._check_conditions(owner, item.conditions or [], group_names)
            if known_tags:
                self._warn_tag_condition_refs(owner, item.conditions or [], known_tags)
            if not (item.groups or []) and not (item.conditions or []) \
                and not (item.include_devices or []):
                self.warnings.append(
                    f"{owner} has no groups, conditions or included devices "
                    "and will apply to no devices"
                )

            if item.profile and item.profile not in profile_ids:
                self.errors.append(f"{owner} bridges unknown profile: {item.profile}")
            elif item.profile and item.type == 'com.apple.configuration.legacy':
                # Only the legacy bridge sends a profile to the device.
                self._check_bridged_profile(owner, profiles_by_id[item.profile])

            if item.type == 'com.apple.configuration.legacy':
                self._warn_unservable_bridge(owner)

            for leaf in _datetime_leaf_paths(item.payload or {}):
                self.warnings.append(
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
                        self.warnings.append(f"{owner} ({item.type}) requires '{req}'")
                target = payload.get('TargetLocalDateTime')
                if target and not _is_datetime_value(target) and not re.match(
                    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$', str(target)
                ):
                    self.warnings.append(
                        f"{owner} TargetLocalDateTime must be local time formatted "
                        "YYYY-MM-DDTHH:MM:SS with NO timezone suffix"
                    )

        self._warn_ios_platform_split('declarations.yaml', ios_only_scoped)

    def _warn_unservable_bridge(self, owner: str) -> None:
        """Say at save time when a legacy bridge cannot be served to any device."""
        # The same predicate the build path asks.
        if readiness.check(readiness.DDM_BRIDGE).ready:
            return
        public = readiness.public_api_url()
        setting = f"it is '{public}'" if public else "it is not set on this server"
        self.warnings.append(
            f"{owner} bridges a profile, and the device downloads a bridged profile "
            f"over https from PUBLIC_API_URL. Right now {setting}, so this "
            "declaration is dropped when the declaration set is built and reaches "
            "no device, however many the console says it is scoped to. Set "
            "PUBLIC_API_URL to an https URL to deploy it."
        )

    def _check_bridged_profile(self, owner: str, profile: Profile) -> None:
        """Refuse a legacy-bridge declaration whose profile carries a payload type Apple forbids in a bridged profile.
        Apple allows any payload type except com.apple.mdm and com.apple.declarations
        (https://raw.githubusercontent.com/apple/device-management/release/declarative/declarations/configurations/legacy.yaml).
        A hard error, unusually for this file:."""
        for entry in _profile_payload_entries(profile):
            ptype = str(entry.get('PayloadType') or '').strip()
            if ptype in LEGACY_BRIDGE_FORBIDDEN_PAYLOAD_TYPES:
                self.errors.append(
                    f"{owner} bridges profile '{profile.id}', which carries a "
                    f"'{ptype}' payload. A profile served through a legacy "
                    "declaration may carry any payload type except "
                    + " and ".join(f"'{t}'" for t in
                                   sorted(LEGACY_BRIDGE_FORBIDDEN_PAYLOAD_TYPES))
                    + ", so the device refuses this one. Bridge a profile "
                      "without that payload, or deploy this profile directly "
                      "instead of through a declaration."
                )
