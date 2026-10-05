import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from controller.utils import yaml_config_models, yaml_dispatcher_checks, yaml_dispatcher_models, yaml_flow_checks
from controller.utils import yaml_flow_models, yaml_profile_checks
from controller.utils.yaml_config_models import (
    App, Condition, FILEVAULT_ENFORCE_PAYLOAD_TYPE, Group, Profile, Tag, TenantConfig, _condition_group_refs,
    _condition_tag_refs, _filevault_escrow_payloads, _is_dep_profile, _model_error, _profile_enables_filevault,
    _profile_has_filevault_escrow, _profile_payload_entries,
)
from controller.utils.yaml_dispatcher_models import DispatcherAction, DispatcherWebhook
from controller.utils.yaml_flow_models import Flow, FlowNode, _find_cycle_edges

# Names other modules and the tests import from here.
Rollout = yaml_config_models.Rollout
DeviceNaming = yaml_config_models.DeviceNaming
AppVersion = yaml_config_models.AppVersion
FILEVAULT_ESCROW_PAYLOAD_TYPE = yaml_config_models.FILEVAULT_ESCROW_PAYLOAD_TYPE
FILEVAULT_ESCROW_CERT_PAYLOAD_TYPE = yaml_config_models.FILEVAULT_ESCROW_CERT_PAYLOAD_TYPE
LEGACY_BRIDGE_FORBIDDEN_PAYLOAD_TYPES = yaml_config_models.LEGACY_BRIDGE_FORBIDDEN_PAYLOAD_TYPES
_escrow_payload_problems = yaml_config_models._escrow_payload_problems
_is_datetime_value = yaml_config_models._is_datetime_value
_datetime_leaf_paths = yaml_config_models._datetime_leaf_paths
_dep_profile_awaits = yaml_config_models._dep_profile_awaits
RESERVED_DECLARATION_IDS = yaml_config_models.RESERVED_DECLARATION_IDS
DeclarationItem = yaml_config_models.DeclarationItem
PAYLOAD_IDENTIFIER_PREFIX_RE = yaml_config_models.PAYLOAD_IDENTIFIER_PREFIX_RE
payload_identifier_prefix_error = yaml_config_models.payload_identifier_prefix_error
_FLOW_SCOPE_KEYS = yaml_flow_models._FLOW_SCOPE_KEYS
_reads_as_int = yaml_flow_models._reads_as_int
_reads_as_true = yaml_flow_models._reads_as_true
_DEVICE_TOUCHING_STEPS = yaml_flow_models._DEVICE_TOUCHING_STEPS
_scope_is_empty = yaml_flow_models._scope_is_empty
_quoted_list = yaml_flow_models._quoted_list
_reach_nodes = yaml_flow_models._reach_nodes
VALID_SEVERITIES = yaml_dispatcher_models.VALID_SEVERITIES
DispatcherRule = yaml_dispatcher_models.DispatcherRule
_WEBHOOK_CHECK_TIMEOUT_SECONDS = yaml_dispatcher_checks._WEBHOOK_CHECK_TIMEOUT_SECONDS


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
        # cross-validate against the documents above.
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
                        "Tenant naming template uses {hostname}; the managed name is pushed to the device as its "
                        "hostname, so re-deriving can compound the name. Prefer a stable identifier like {serial}."
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
                            f"Group '{group.name}' naming template references unknown variable '{{{var}}}'"
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
        """True when a platforms list names iOS but neither watchOS nor visionOS."""
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
        yaml_profile_checks._check_profile_payloads(self, profile)

    def _check_profile_data_keys(self, profile: Profile) -> None:
        yaml_profile_checks._check_profile_data_keys(self, profile)

    def _check_filevault_payloads(self, profile: Profile) -> None:
        yaml_profile_checks._check_filevault_payloads(self, profile)

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
                " and ".join(parts) + ". A Mac accepts one and errors on a second, so check that no Mac is in scope "
                                      "for more than one of these."
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
        return yaml_flow_checks._validate_flows(self, groups, apps, profiles, known_tags)

    def _draft_errors_demoted(self, flow: "Flow"):
        return yaml_flow_checks._draft_errors_demoted(self, flow)

    def _check_flow_scope(self, owner: str, scope: Dict[str, Any],
                          group_names: set, known_tags: Optional[set]) -> None:
        yaml_flow_checks._check_flow_scope(self, owner, scope, group_names, known_tags)

    def _warn_tag_condition_refs(self, owner: str, conditions: List[Condition],
                                 known_tags: set) -> None:
        yaml_flow_checks._warn_tag_condition_refs(self, owner, conditions, known_tags)

    def _flow_edges(self, owner: str, flow: Flow,
                    nodes_by_id: Dict[str, "FlowNode"]) -> Dict[str, List[str]]:
        return yaml_flow_checks._flow_edges(self, owner, flow, nodes_by_id)

    def _check_flow_node_params(self, owner: str, node: "FlowNode",
                                group_names: set, profile_ids: set, app_ids: set,
                                known_tags: Optional[set]) -> None:
        yaml_flow_checks._check_flow_node_params(self, owner, node, group_names, profile_ids, app_ids, known_tags)
        # end: no params.

    def _check_flow_graph(self, owner: str, edges: Dict[str, List[str]],
                          nodes_by_id: Dict[str, "FlowNode"],
                          starts: List[str]) -> None:
        yaml_flow_checks._check_flow_graph(self, owner, edges, nodes_by_id, starts)

    def _warn_checkin_start_params(self, where: str, params: Dict[str, Any]) -> None:
        yaml_flow_checks._warn_checkin_start_params(self, where, params)

    def _flow_warn(self, flow_id: str, node_id: Optional[str], code: str,
                   message: str) -> None:
        yaml_flow_checks._flow_warn(self, flow_id, node_id, code, message)

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
        yaml_flow_checks._warn_flow_semantics(self, flow_id, edges, nodes_by_id, starts, profiles, is_enrollment)

    # ==Dispatcher rules (dispatcher.yaml)==
    def _validate_dispatcher(self, groups: Optional[List[Group]],
                             apps: Optional[List[App]],
                             profiles: Optional[List[Profile]],
                             known_tags: Optional[set]) -> Optional[set]:
        return yaml_dispatcher_checks._validate_dispatcher(self, groups, apps, profiles, known_tags)

    def _warn_webhook_target(self, webhook: "DispatcherWebhook") -> None:
        yaml_dispatcher_checks._warn_webhook_target(self, webhook)

    def _webhook_delivery_blocked(self, url: str) -> bool:
        return yaml_dispatcher_checks._webhook_delivery_blocked(self, url)

    def _check_dispatcher_check(self, owner: str, check: Dict[str, Any],
                                profile_ids: set, enabled: Any = True) -> None:
        yaml_dispatcher_checks._check_dispatcher_check(self, owner, check, profile_ids, enabled)

    def _check_dispatcher_action(self, owner: str, action: "DispatcherAction",
                                 webhook_names: set, profile_ids: set, app_ids: set,
                                 known_tags: Optional[set],
                                 unscoped_profiles: Optional[set] = None) -> None:
        yaml_dispatcher_checks._check_dispatcher_action(self, owner, action, webhook_names, profile_ids, app_ids,
                                                        known_tags, unscoped_profiles)

    # ==DDM declarations (declarations.yaml)==
    def _validate_declarations(self, groups: Optional[List[Group]],
                               profiles: Optional[List[Profile]],
                               known_tags: Optional[set]) -> None:
        yaml_profile_checks._validate_declarations(self, groups, profiles, known_tags)

    def _warn_unservable_bridge(self, owner: str) -> None:
        yaml_profile_checks._warn_unservable_bridge(self, owner)

    def _check_bridged_profile(self, owner: str, profile: Profile) -> None:
        yaml_profile_checks._check_bridged_profile(self, owner, profile)
