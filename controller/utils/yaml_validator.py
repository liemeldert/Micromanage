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

    @validator('type')
    def validate_type(cls, v):
        valid_types = ['device_model', 'serial_number', 'hostname', 'os_version', 'enrollment_date']
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
            'enrollment_date': ['after', 'before', 'equals']
        }

        if condition_type and v not in valid_operators.get(condition_type, []):
            raise ValueError(f"Invalid operator '{v}' for condition type '{condition_type}'")
        return v


class Group(BaseModel):
    name: str
    description: Optional[str]
    conditions: List[Condition]

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

        # Cross-validation
        if config and groups and apps and profiles:
            self._cross_validate(config, groups, apps, profiles)

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

                # An empty conditions list matches NO devices — surface it, since
                # a profile scoped to such a group silently deploys nowhere.
                if not group.conditions:
                    self.warnings.append(
                        f"Group '{group.name}' has no conditions and will match no devices"
                    )

                # Validate regex patterns
                for condition in group.conditions:
                    if condition.operator == 'regex':
                        try:
                            re.compile(condition.value)
                        except re.error as e:
                            self.errors.append(f"Invalid regex in group '{group.name}': {e}")

                groups.append(group)

            except Exception as e:
                self.errors.append(f"Invalid group at index {idx}: {e}")

        if not groups:
            self.warnings.append("No groups defined")

        return groups

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
