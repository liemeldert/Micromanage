import yaml
from typing import Dict, Any, List, Tuple
from pathlib import Path
import re
from pydantic import BaseModel, validator, Field
from typing import Optional, Union


class Condition(BaseModel):
    type: str
    operator: str
    value: Union[str, List[str]]
    # Inverts the condition ("device NOT IN group", "model NOT equals ...").
    negate: Optional[bool] = False

    @validator('type')
    def validate_type(cls, v):
        valid_types = ['device_model', 'serial_number', 'hostname', 'os_version',
                       'enrollment_date', 'group', 'platform', 'tag']
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
    """Back-edges ``(node, ref)`` that make ``edges`` cyclic, via an iterative
    3-color DFS (WHITE/GRAY/BLACK). ``edges`` maps a node to its successor ids;
    successors not present as keys are ignored (dangling refs are a separate
    check). Shared by the group-membership graph and the ATC flow graph so the
    two can't drift."""
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


class Rollout(BaseModel):
    """Gradual (wave-based) rollout gate. See services.scoping.

    ``start`` is auto-filled by the API on save when omitted; validation only
    requires it to be parseable when present.
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
        # Floor at 1h: sub-hour device rollouts aren't a real use case, and a
        # tiny interval can exhaust the wave-walk's iteration backstop before it
        # clears a skipped weekend (freezing coverage). See services.scoping.
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
    """A naming template scope (per-group here; the tenant scope mirrors the same
    shape from config.yaml). See controller/services/naming.py."""
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
    # Optional per-group naming template: a device in this group derives its
    # managed name from here (first matching group wins; see services.naming).
    device_naming: Optional[DeviceNaming] = None
    # Cherry-picked serials: always members (include) / never members (exclude
    # -- wins over everything). Enables hand-picked test cohorts.
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
    # "configuration" (managed config profile pushed to groups) or
    # "enrollment" (Automated Device Enrollment / DEP profile).
    type: Optional[str] = "configuration"
    # Target platforms (iOS | macOS | tvOS); empty/None means all.
    platforms: Optional[List[str]] = None
    groups: Optional[List[str]] = []
    # Unified scope extensions (see services.scoping): all conditions must
    # match; include/exclude cherry-pick serials (exclude wins); rollout gates
    # scoped devices into gradual waves.
    conditions: Optional[List[Condition]] = []
    include_devices: Optional[List[str]] = []
    exclude_devices: Optional[List[str]] = []
    rollout: Optional[Rollout] = None
    dep_profile: Optional[bool] = False
    # A profile may carry a single payload (legacy) or a list of payloads.
    payload: Optional[Dict[str, Any]] = None
    payloads: Optional[List[Dict[str, Any]]] = None

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


class TenantConfig(BaseModel):
    id: str
    name: str
    allowed_users: List[str]
    s3: Optional[Dict[str, str]] = {}
    dep: Optional[Dict[str, Any]] = {}


class Tag(BaseModel):
    """One entry in the advisory tag registry (tags.yaml).

    The registry is optional: free-form tags are always allowed, so a tag not in
    the registry is a *warning*, never an error. Registered entries drive the UI
    picker and chip colours. See models.Device.tags / services.scoping.
    """
    name: str
    label: Optional[str] = None
    description: Optional[str] = None
    # Optional Mantine colour name for the chip (advisory; not validated against a
    # palette so new Mantine colours don't require a controller change).
    color: Optional[str] = None

    @validator('name')
    def validate_name(cls, v):
        if not re.match(r'^[a-zA-Z0-9-_]+$', v or ''):
            raise ValueError(
                "Tag name must contain only alphanumeric characters, hyphens, "
                "and underscores"
            )
        return v


class TagRegistry(BaseModel):
    tags: List[Tag] = []


class FlowTrigger(BaseModel):
    """When a flow starts. v1 supports ``on: enroll`` only; ``match`` is a scope
    dict (same shape as a profile/app scope) selecting which devices it fires
    for. See services.atc / services.scoping."""
    on: str
    match: Optional[Dict[str, Any]] = None

    @validator('on')
    def validate_on(cls, v):
        if v not in ('enroll',):
            raise ValueError(
                f"Unsupported flow trigger 'on': {v!r} (v1 supports: enroll)"
            )
        return v


class FlowNode(BaseModel):
    """One node in a flow graph. ``params`` and the edge targets are validated
    per-node-type imperatively (see YAMLValidator._check_flow_node_params /
    _check_flow_graph) against the step catalog, so the structural model stays
    permissive."""
    id: str
    type: str
    params: Optional[Dict[str, Any]] = {}
    next: Optional[str] = None
    on_true: Optional[str] = None
    on_false: Optional[str] = None
    on_timeout: Optional[str] = None
    # Canvas position -- kept separate from logic so the YAML stays diff-friendly.
    ui: Optional[Dict[str, Any]] = None

    @validator('id')
    def validate_id(cls, v):
        if not re.match(r'^[a-zA-Z0-9-_]+$', v or ''):
            raise ValueError(
                "Flow node id must contain only alphanumeric characters, hyphens, "
                "and underscores"
            )
        return v


class Flow(BaseModel):
    id: str
    name: str
    enabled: Optional[bool] = True
    # Higher priority wins when multiple flows match an enroll; ties broken by id.
    priority: Optional[int] = 0
    trigger: FlowTrigger
    start: str
    nodes: List[FlowNode]

    @validator('id')
    def validate_id(cls, v):
        if not re.match(r'^[a-z0-9-_]+$', v or ''):
            raise ValueError(
                "Flow id must be a slug (lowercase letters, digits, hyphens, underscores)"
            )
        return v


# ── Dispatcher (dispatcher.yaml) ─────────────────────────────────────────────

VALID_SEVERITIES = ('black', 'red', 'yellow', 'green')


class DispatcherWebhook(BaseModel):
    """A named delivery target. ``url`` (and ``secret`` if present) are secrets:
    redacted from all API responses (see controller/api/main.py)."""
    name: str
    url: str
    secret: Optional[str] = None

    @validator('name')
    def validate_name(cls, v):
        if not re.match(r'^[a-zA-Z0-9-_]+$', v or ''):
            raise ValueError(
                "Webhook name must contain only alphanumeric characters, hyphens, "
                "and underscores"
            )
        return v

    @validator('url')
    def validate_url(cls, v):
        if not str(v or '').strip():
            raise ValueError("Webhook url cannot be empty")
        return v


class DispatcherAction(BaseModel):
    """One rule action. ``params`` are validated per action-type imperatively.
    ``dry_run`` records what a remediation WOULD do without doing it."""
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
    # Anti-flap: only fire once non-compliant continuously for this many minutes.
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
    def __init__(self, tenant_path: Path):
        self.tenant_path = tenant_path
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """Validate all YAML files for a tenant"""
        self.errors = []
        self.warnings = []

        # Check required files
        required_files = ['config.yaml', 'groups.yaml', 'apps.yaml', 'profiles.yaml']
        for file in required_files:
            if not (self.tenant_path / file).exists():
                self.errors.append(f"Missing required file: {file}")

        if self.errors:
            return False, self.errors, self.warnings

        # Validate each file
        config = self._validate_config()
        groups = self._validate_groups()
        apps = self._validate_apps(groups)
        profiles = self._validate_profiles(groups)

        # Optional advisory tag registry (tags.yaml). Returns the registered tag
        # names, or None when there is no (non-empty) registry -- in which case
        # tags are purely free-form and references are never flagged.
        known_tags = self._validate_tags()

        # Cross-validation
        if config and groups and apps and profiles:
            self._cross_validate(config, groups, apps, profiles)

        # Warn (never error) on tag conditions that reference a tag absent from a
        # non-empty registry -- most often a typo. Free-form tags stay allowed.
        if known_tags:
            self._warn_unknown_tag_refs(groups, apps, profiles, known_tags)

        # Optional new-subsystem documents (no required-file stub). Each returns
        # early if its file is absent. They cross-validate against the docs above.
        self._validate_flows(groups, apps, profiles, known_tags)
        self._validate_dispatcher(groups, apps, profiles, known_tags)

        return len(self.errors) == 0, self.errors, self.warnings

    def _load_yaml(self, filename: str) -> Optional[Dict[str, Any]]:
        """Load and parse YAML file"""
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
        """Validate config.yaml"""
        data = self._load_yaml('config.yaml')
        if not data:
            return None

        try:
            tenant_data = data.get('tenant', {})
            config = TenantConfig(**tenant_data)

            # Additional validations
            if not config.allowed_users:
                self.warnings.append("No allowed users defined")

            if config.s3 and not config.s3.get('bucket'):
                self.errors.append("S3 configuration missing bucket name")

            return config

        except Exception as e:
            self.errors.append(f"Invalid config.yaml: {e}")
            return None

    def _validate_groups(self) -> Optional[List[Group]]:
        """Validate groups.yaml"""
        data = self._load_yaml('groups.yaml')
        if not data:
            return None

        groups = []
        group_names = set()

        for idx, group_data in enumerate(data.get('groups', [])):
            try:
                group = Group(**group_data)

                # Check for duplicate names
                if group.name in group_names:
                    self.errors.append(f"Duplicate group name: {group.name}")
                group_names.add(group.name)

                # With neither conditions nor cherry-picked devices, a group
                # matches NO devices -- surface it, since a profile scoped to
                # such a group silently deploys nowhere.
                if not group.conditions and not group.include_devices:
                    self.warnings.append(
                        f"Group '{group.name}' has no conditions or included devices "
                        "and will match no devices"
                    )

                self._check_conditions(f"group '{group.name}'", group.conditions or [])

                # Warn (don't fail) on naming-template variables the controller
                # can't resolve -- a typo like {seriall} would silently render to
                # nothing. Not an error: forward-compat with future variables.
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
                self.errors.append(f"Invalid group at index {idx}: {e}")

        if not groups:
            self.warnings.append("No groups defined")

        # Group-membership conditions: referenced groups must exist, and the
        # reference graph must be acyclic (a cycle would make membership
        # undefined; the runtime treats it as no-match, but reject it here).
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

        # Cycle detection: a reference cycle makes membership undefined.
        for node, ref in _find_cycle_edges(edges):
            self.errors.append(
                f"Group membership cycle detected involving '{node}' and '{ref}'"
            )

        return groups

    def _check_conditions(self, owner: str, conditions: List[Condition],
                          group_names: Optional[set] = None) -> None:
        """Shared per-condition checks: regex compiles; group refs exist (when
        ``group_names`` is supplied -- groups.yaml defers that to a graph pass)."""
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

    def _validate_apps(self, groups: Optional[List[Group]]) -> Optional[List[App]]:
        """Validate apps.yaml"""
        data = self._load_yaml('apps.yaml')
        if not data:
            return None

        apps = []
        app_ids = set()
        group_names = {g.name for g in groups} if groups else set()

        for idx, app_data in enumerate(data.get('apps', [])):
            try:
                app = App(**app_data)

                # Check for duplicate IDs
                if app.id in app_ids:
                    self.errors.append(f"Duplicate app ID: {app.id}")
                app_ids.add(app.id)

                # Validate version references to groups
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

                    # Validate S3 keys
                    if not version.s3_key:
                        self.errors.append(f"App '{app.id}' version {version.version} missing S3 key")

                apps.append(app)

            except Exception as e:
                self.errors.append(f"Invalid app at index {idx}: {e}")

        if not apps:
            self.warnings.append("No apps defined")

        return apps

    def _validate_profiles(self, groups: Optional[List[Group]]) -> Optional[List[Profile]]:
        """Validate profiles.yaml"""
        data = self._load_yaml('profiles.yaml')
        if not data:
            return None

        profiles = []
        profile_ids = set()
        group_names = {g.name for g in groups} if groups else set()

        for idx, profile_data in enumerate(data.get('profiles', [])):
            try:
                profile = Profile(**profile_data)

                # Check for duplicate IDs
                if profile.id in profile_ids:
                    self.errors.append(f"Duplicate profile ID: {profile.id}")
                profile_ids.add(profile.id)

                # Validate group references
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

                # Validate payload (single or list)
                if not profile.payload and not profile.payloads and profile.type != "enrollment":
                    self.warnings.append(f"Profile '{profile.id}' has empty payload")

                profiles.append(profile)

            except Exception as e:
                self.errors.append(f"Invalid profile at index {idx}: {e}")

        if not profiles:
            self.warnings.append("No profiles defined")

        return profiles

    def _cross_validate(self, config: TenantConfig, groups: List[Group],
                        apps: List[App], profiles: List[Profile]):
        """Perform cross-file validation"""

        # Check DEP configuration
        if config.dep.get('enabled'):
            dep_profiles = [p for p in profiles if p.dep_profile]
            if not dep_profiles:
                self.warnings.append("DEP enabled but no DEP profiles defined")

            default_profile = config.dep.get('default_profile')
            if default_profile and not any(p.id == default_profile for p in dep_profiles):
                self.errors.append(f"Default DEP profile '{default_profile}' not found")

        # Check for unused groups
        used_groups = set()
        for app in apps:
            for version in app.versions:
                used_groups.update(version.groups)
        for profile in profiles:
            used_groups.update(profile.groups or [])

        for group in groups:
            if group.name not in used_groups:
                self.warnings.append(f"Group '{group.name}' is defined but not used")

    def _validate_tags(self) -> Optional[set]:
        """Validate the optional advisory tags.yaml registry.

        Returns the set of registered tag names, or None when there is no
        registry (or it is empty) -- in that case tags are purely free-form and
        callers should not warn on any tag reference. A malformed registry is an
        error; duplicate/ill-named entries are errors, mirroring groups.
        """
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
                self.errors.append(f"Invalid tag at index {idx}: {e}")
                continue
            if tag.name in names:
                self.errors.append(f"Duplicate tag name: {tag.name}")
            names.add(tag.name)

        # An empty (or all-invalid) registry means "no registry" for the purpose
        # of reference warnings -- don't flag every tag as unknown.
        return names or None

    def _warn_unknown_tag_refs(self, groups: Optional[List[Group]],
                               apps: Optional[List[App]],
                               profiles: Optional[List[Profile]],
                               known_tags: set) -> None:
        """Warn on ``tag`` conditions referencing a tag not in the registry."""
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

    # ── ATC flows (flows.yaml) ────────────────────────────────────────────────
    def _validate_flows(self, groups: Optional[List[Group]],
                        apps: Optional[List[App]],
                        profiles: Optional[List[Profile]],
                        known_tags: Optional[set]) -> Optional[set]:
        """Validate the optional flows.yaml (ATC enrollment flows).

        Returns the set of flow ids, or None when there is no flows document.
        Checks (per spec 1.5): unique flow ids; a valid trigger; ``start`` and
        every edge target exist; the graph is a DAG with a reachable ``end``;
        per-node params are well-formed and cross-reference real profile/app/tag
        ids and non-destructive commands.
        """
        path = self.tenant_path / 'flows.yaml'
        if not path.exists():
            return None
        data = self._load_yaml('flows.yaml')
        if not data:
            return None

        group_names = {g.name for g in groups} if groups else set()
        profile_ids = {p.id for p in profiles} if profiles else set()
        app_ids = {a.id for a in apps} if apps else set()

        flow_ids: set = set()
        for idx, fdata in enumerate(data.get('flows', []) or []):
            try:
                flow = Flow(**fdata)
            except Exception as e:
                self.errors.append(f"Invalid flow at index {idx}: {e}")
                continue

            owner = f"flow '{flow.id}'"
            if flow.id in flow_ids:
                self.errors.append(f"Duplicate flow id: {flow.id}")
            flow_ids.add(flow.id)

            nodes_by_id: Dict[str, FlowNode] = {}
            for node in flow.nodes:
                if node.id in nodes_by_id:
                    self.errors.append(f"{owner} has a duplicate node id: {node.id}")
                    continue  # keep the first definition for graph/edge analysis
                nodes_by_id[node.id] = node

            if flow.start not in nodes_by_id:
                self.errors.append(f"{owner} start node '{flow.start}' does not exist")

            # Trigger scope (which devices the flow fires for).
            self._check_flow_scope(f"{owner} trigger", flow.trigger.match or {},
                                   group_names, known_tags)

            edges = self._flow_edges(owner, flow, nodes_by_id)

            for node in flow.nodes:
                self._check_flow_node_params(
                    owner, node, group_names, profile_ids, app_ids, known_tags
                )

            self._check_flow_graph(owner, edges, nodes_by_id, flow.start)

        return flow_ids

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
                self.errors.append(f"{owner} has an invalid condition: {e}")
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
        """Validate each node's edges against the step catalog and return the
        adjacency map (node id -> [target node ids])."""
        from controller.services.flow_step_catalog import VALID_NODE_TYPES, node_edges

        edges: Dict[str, List[str]] = {}
        for node in flow.nodes:
            if node.type not in VALID_NODE_TYPES:
                self.errors.append(
                    f"{owner} node '{node.id}' has an unknown type: {node.type}"
                )
                edges[node.id] = []
                continue
            handles = node_edges(node.type)
            handle_field = {
                "next": node.next, "on_true": node.on_true,
                "on_false": node.on_false, "on_timeout": node.on_timeout,
            }
            targets: List[str] = []
            for h in handles:
                val = handle_field.get(h)
                # on_timeout is optional (defaults to failing the run on timeout).
                optional = node.type == "wait_for" and h == "on_timeout"
                if val is None:
                    if not optional:
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
                if val is not None and h not in handles:
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
        from controller.services.command_catalog import VALID_COMMAND_TYPES
        from controller.services.flow_step_catalog import is_wait_signal
        from controller.services.variables import is_self_referential, unknown_variables

        p = node.params or {}
        where = f"{owner} node '{node.id}'"
        t = node.type

        def _str_list(value: Any) -> List[str]:
            items = value if isinstance(value, list) else ([value] if value else [])
            return [str(x) for x in items if x]

        if t in ("assign_tag", "remove_tag"):
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
            if not cmd or cmd not in VALID_COMMAND_TYPES:
                self.errors.append(
                    f"{where} (send_command) references unknown command: {cmd}"
                )
            elif cmd in DESTRUCTIVE_COMMANDS:
                self.errors.append(
                    f"{where} (send_command) uses destructive command '{cmd}', which is "
                    "forbidden as an automated flow step"
                )
            else:
                # Catch missing required parameters at save time (mirrors
                # command_catalog.build_generic_fields). "mac"-required params are
                # device-dependent, so only unconditionally-required ones apply.
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
                    self.errors.append(f"{where} (branch) has an invalid condition: {e}")
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
        # end: no params.

    def _check_flow_graph(self, owner: str, edges: Dict[str, List[str]],
                         nodes_by_id: Dict[str, "FlowNode"], start: str) -> None:
        """Reject reachable cycles (a flow must be a DAG) and require a reachable
        ``end``; warn on unreachable nodes.

        Reachability is computed FIRST, and cycle detection runs over only the
        reachable subgraph, so a cycle in dead (unreachable) nodes cannot mask a
        genuine 'no reachable end' failure in the live portion -- and only the
        graph a device would actually execute is validated as a DAG."""
        if start not in nodes_by_id:
            return  # start-missing already reported by the caller

        reachable: set = set()
        stack = [start]
        while stack:
            n = stack.pop()
            if n in reachable:
                continue
            reachable.add(n)
            for tgt in edges.get(n, []):
                if tgt not in reachable:
                    stack.append(tgt)

        reachable_edges = {
            n: [t for t in edges.get(n, []) if t in reachable] for n in reachable
        }
        cycles = _find_cycle_edges(reachable_edges)
        for node, ref in cycles:
            self.errors.append(
                f"{owner} has a cycle involving '{node}' and '{ref}' "
                "(a flow must be acyclic)"
            )

        reached_end = any(
            nodes_by_id[n].type == "end" for n in reachable if n in nodes_by_id
        )
        if not reached_end and not cycles:
            self.errors.append(
                f"{owner} has no reachable 'end' node from start '{start}'"
            )
        for nid in nodes_by_id:
            if nid not in reachable:
                self.warnings.append(f"{owner} node '{nid}' is unreachable from start")

    # ── Dispatcher rules (dispatcher.yaml) ────────────────────────────────────
    def _validate_dispatcher(self, groups: Optional[List[Group]],
                            apps: Optional[List[App]],
                            profiles: Optional[List[Profile]],
                            known_tags: Optional[set]) -> Optional[set]:
        """Validate the optional dispatcher.yaml (compliance rules + webhooks).

        Returns the set of rule ids, or None when there is no document. Checks:
        unique webhook names / rule ids; a valid scope; a real check with valid
        params; a valid severity; actions that reference real webhook targets /
        profile / app / tag ids and (for send_command) a real command -- a
        destructive command is allowed but flagged as approval-required (the
        engine never auto-fires it)."""
        path = self.tenant_path / 'dispatcher.yaml'
        if not path.exists():
            return None
        data = self._load_yaml('dispatcher.yaml')
        if not data:
            return None

        group_names = {g.name for g in groups} if groups else set()
        profile_ids = {p.id for p in profiles} if profiles else set()
        app_ids = {a.id for a in apps} if apps else set()

        webhook_names: set = set()
        for idx, wdata in enumerate(data.get('webhooks', []) or []):
            try:
                webhook = DispatcherWebhook(**wdata)
            except Exception as e:
                self.errors.append(f"Invalid dispatcher webhook at index {idx}: {e}")
                continue
            if webhook.name in webhook_names:
                self.errors.append(f"Duplicate dispatcher webhook name: {webhook.name}")
            webhook_names.add(webhook.name)

        rule_ids: set = set()
        for idx, rdata in enumerate(data.get('rules', []) or []):
            try:
                rule = DispatcherRule(**rdata)
            except Exception as e:
                self.errors.append(f"Invalid dispatcher rule at index {idx}: {e}")
                continue
            owner = f"rule '{rule.id}'"
            if rule.id in rule_ids:
                self.errors.append(f"Duplicate rule id: {rule.id}")
            rule_ids.add(rule.id)

            self._check_flow_scope(f"{owner} scope", rule.scope or {}, group_names, known_tags)
            self._check_dispatcher_check(owner, rule.check or {}, profile_ids)
            for action in rule.actions or []:
                self._check_dispatcher_action(
                    owner, action, webhook_names, profile_ids, app_ids, known_tags
                )

        return rule_ids

    def _check_dispatcher_check(self, owner: str, check: Dict[str, Any],
                               profile_ids: set) -> None:
        from controller.services.compliance_catalog import VALID_CHECK_TYPES

        ctype = check.get('type')
        if ctype not in VALID_CHECK_TYPES:
            self.errors.append(f"{owner} has an unknown check type: {ctype}")
            return
        if ctype == 'os_below' and not str(check.get('min') or '').strip():
            self.errors.append(f"{owner} check os_below requires a 'min' version")
        if ctype == 'not_seen_for':
            try:
                int(check.get('days'))
            except (TypeError, ValueError):
                self.errors.append(f"{owner} check not_seen_for requires an integer 'days'")
        if ctype == 'missing_profile':
            pid = check.get('profile_id')
            if not pid:
                self.errors.append(f"{owner} check missing_profile requires a 'profile_id'")
            elif pid not in profile_ids:
                self.errors.append(f"{owner} check references unknown profile: {pid}")
        if ctype == 'tagged':
            tags = check.get('tags')
            if not isinstance(tags, list) or not tags:
                self.errors.append(f"{owner} check tagged requires a non-empty 'tags' list")
        if ctype == 'attribute':
            if not str(check.get('key') or '').strip():
                self.errors.append(f"{owner} check attribute requires a 'key' path")
            if check.get('operator') not in (
                'equals', 'not_equals', 'exists', 'gt', 'lt', 'regex'
            ):
                self.errors.append(
                    f"{owner} check attribute has an invalid operator: {check.get('operator')}"
                )

    def _check_dispatcher_action(self, owner: str, action: "DispatcherAction",
                                webhook_names: set, profile_ids: set, app_ids: set,
                                known_tags: Optional[set]) -> None:
        from controller.auth import DESTRUCTIVE_COMMANDS
        from controller.services.command_catalog import VALID_COMMAND_TYPES, get_command

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
            for pid in (ids if isinstance(ids, list) else []):
                if pid not in profile_ids:
                    self.errors.append(f"{owner} references unknown profile: {pid}")
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
            if not cmd or cmd not in VALID_COMMAND_TYPES:
                self.errors.append(f"{owner} send_command references unknown command: {cmd}")
            elif cmd in DESTRUCTIVE_COMMANDS:
                # Allowed, but the engine turns it into a pending-approval task an
                # admin must confirm -- it never auto-fires. Surface that.
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
