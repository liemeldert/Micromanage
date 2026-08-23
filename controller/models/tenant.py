from datetime import datetime
from typing import Any, Dict, Optional

from tortoise import fields
from tortoise.models import Model


class Tenant(Model):
    id = fields.CharField(max_length=100, pk=True)
    name = fields.CharField(max_length=255)
    allowed_users = fields.JSONField(default=list)  # Deprecated: advisory only; authz is via User rows
    s3_config = fields.JSONField(default=dict)
    # Per-tenant authentication backend: provider local, or provider clerk with its issuer and settings. See
    # controller.auth.
    auth_config = fields.JSONField(default=dict)
    dep_enabled = fields.BooleanField(default=False)
    # Dynamic device naming: a template such as IT-{serial} plus apply_on_enroll. Mirrored from config.yaml. See
    # services.naming.
    device_naming = fields.JSONField(default=dict)
    # Expiry dates for renewal reminders. apns_cert_expires_at is always admin-entered; dep_token_expires_at is
    # mirrored from the linked DepServer on upload and admin-entered otherwise.
    apns_cert_expires_at = fields.DatetimeField(null=True)
    dep_token_expires_at = fields.DatetimeField(null=True)
    # Declarative Device Management master switch (services.ddm_manager). Off by default: enabling queues a
    # DeclarativeManagement sync to every supported device on the next reconcile.
    ddm_enabled = fields.BooleanField(default=False)
    # Reverse-DNS base for every PayloadIdentifier profile_manager composes, e.g. "com.acme.mdm". Null means the
    # built-in "com.mdm.<tenant id>" base. Changing it while profiles are deployed strands the installed copies.
    payload_identifier_prefix = fields.CharField(max_length=120, null=True)
    # Ceiling on the bytes this tenant may keep in its object store prefix. Null falls back to
    # MDM_DEFAULT_STORAGE_QUOTA_BYTES. Set by the operator only; tenant admins can read it, not change it.
    storage_quota_bytes = fields.BigIntField(null=True)
    # FileVault recovery-key escrow keypair (services.filevault_escrow), Fernet-encrypted at rest like the DEP
    # token. The certificate is public and embedded in the escrow payload beside FileVault payloads.
    fv_escrow_private_key_enc = fields.TextField(null=True)
    fv_escrow_cert_pem = fields.TextField(null=True)
    fv_escrow_cert_expires_at = fields.DatetimeField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    is_active = fields.BooleanField(default=True)

    class Meta:
        table = "tenants"

    @property
    def auth_provider(self) -> str:
        return (self.auth_config or {}).get("provider", "local")


class User(Model):
    """A principal that may authenticate to a tenant. Local users authenticate with password_hash; external
    (Clerk/OIDC) users are matched by external_id or email. role drives RBAC (admin | member)."""
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="users")
    email = fields.CharField(max_length=255)
    password_hash = fields.CharField(max_length=255, null=True)  # local auth only
    # When the password was last set. Session tokens issued before this are refused (auth.dependencies), so a
    # password change ends any sessions a thief was holding. Null means nothing to compare against, so it passes.
    password_changed_at = fields.DatetimeField(null=True)
    # When two-factor auth was last turned on or off. Same refusal mechanism as password_changed_at: disabling
    # MFA ends whatever sessions a thief was holding. Null means never touched, so it refuses nothing.
    mfa_changed_at = fields.DatetimeField(null=True)
    role = fields.CharField(max_length=20, default="member")  # admin | member
    external_id = fields.CharField(max_length=255, null=True)  # OIDC/Clerk subject
    is_active = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "users"
        unique_together = (("tenant", "email"),)


class UserMFA(Model):
    """A user's console two-factor enrollment. One row per user. secret_enc is Fernet-encrypted at rest, like
    the DEP token. confirmed_at stays null until one accepted code, and an unconfirmed row must never block
    login. last_step guards against replaying an observed code within its tolerated step window."""
    id = fields.UUIDField(pk=True)
    user = fields.ForeignKeyField("models.User", related_name="mfa", unique=True)
    secret_enc = fields.TextField()
    confirmed_at = fields.DatetimeField(null=True)
    last_step = fields.BigIntField(null=True)
    recovery_codes = fields.JSONField(default=list)  # hashed codes only
    failed_attempts = fields.IntField(default=0)
    lockout_until = fields.DatetimeField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "user_mfa"


class Device(Model):
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="devices")
    # Null while a device is a pre-provisioned placeholder, known by serial but not yet enrolled, which is how DEP
    # devices start. Postgres treats NULLs as distinct, so the unique index still allows plenty of placeholders.
    udid = fields.CharField(max_length=40, unique=True, null=True)
    serial_number = fields.CharField(max_length=20)
    device_model = fields.CharField(max_length=100)
    os_version = fields.CharField(max_length=20)
    hostname = fields.CharField(max_length=255, null=True)
    # Managed display name, either set by hand or derived from the tenant's naming template. Null falls back to
    # hostname, then serial.
    name = fields.CharField(max_length=255, null=True)
    # Lifecycle across (un)enrollments: enrolled | unenrolled | pending. Records are retained through unenroll so
    # history/state survive a re-enroll.
    enrollment_state = fields.CharField(max_length=20, default="enrolled")
    # Management backend. Only "apple_mdm" today; delimits future platforms.
    management_type = fields.CharField(max_length=30, default="apple_mdm")
    enrollment_date = fields.DatetimeField(auto_now_add=True)
    unenrolled_at = fields.DatetimeField(null=True)
    last_seen = fields.DatetimeField(auto_now=True)
    # Adaptive info-poll schedule (services.poller): when we last queried the device, and the current cadence in minutes
    # (grows as a device stays silent, resets to the base when it answers).
    last_polled_at = fields.DatetimeField(null=True)
    poll_interval_minutes = fields.IntField(default=30)
    groups = fields.JSONField(default=list)  # Computed group memberships
    # Inventory exactly as the device reports it (Apple's InstalledApplicationList / ProfileList entries).
    # Written only by webhook_handler._persist_inventory. Distinct from AppDeployment / ProfileDeployment, which
    # record what we asked for rather than what the device says it has.
    installed_apps = fields.JSONField(default=list)
    installed_profiles = fields.JSONField(default=list)
    # Everything the device says about itself (DeviceInformation QueryResponses, SecurityInfo and friends), kept as-is
    # rather than hardcoding a column per attribute.
    attributes = fields.JSONField(default=dict)
    # Imperative device labels, written by ATC flows, Dispatcher rules and by hand; matched by the tag scope
    # condition. Assignment is additive and idempotent, so a tag applied by hand survives automated writers.
    tags = fields.JSONField(default=list)
    # ADE/DEP linkage, populated when synced from Apple Business/School Manager (services.dep_manager). Null
    # for OTA/manual devices. See models.DepServer.
    dep_server_id = fields.UUIDField(null=True)
    dep_profile_uuid = fields.CharField(max_length=64, null=True)
    dep_profile_status = fields.CharField(max_length=30, null=True)
    dep_last_synced_at = fields.DatetimeField(null=True)
    # DDM state (services.ddm_manager): ddm_status is the merged StatusItems tree; ddm_declaration_status is the
    # flat per-declaration view; ddm_client_capabilities decides which declaration types this device gets.
    ddm_enabled_at = fields.DatetimeField(null=True)
    ddm_last_sync_at = fields.DatetimeField(null=True)
    ddm_last_published_token = fields.CharField(max_length=64, null=True)
    ddm_status = fields.JSONField(default=dict)
    ddm_declaration_status = fields.JSONField(default=dict)
    ddm_client_capabilities = fields.JSONField(default=dict)

    class Meta:
        table = "devices"


# Deployments record confirmed state; a Task records the attempt that last moved it. last_task_id links them,
# stamped at enqueue time rather than when the device answers, since the case that matters most is the device
# never answering. Plain UUID, not a ForeignKeyField. A dangling pointer is expected once a task
# ages out of retention, and readers must treat a missing Task that way rather than erroring.

class AppDeployment(Model):
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="app_deployments")
    device = fields.ForeignKeyField("models.Device", related_name="app_deployments")
    app_id = fields.CharField(max_length=100)
    app_version = fields.CharField(max_length=50)
    # pending, installing, accepted, installed, failed, unscoped. 'accepted' means the device acknowledged
    # InstallApplication but has not yet confirmed the app's presence in inventory. 'unscoped' means the device
    # is no longer scoped into this app; nothing was uninstalled, the sync loop just stops acting on it.
    status = fields.CharField(max_length=20)
    install_date = fields.DatetimeField(null=True)
    # What the DEVICE reports as its version (CFBundleVersion/CFBundleShortVersionString) as of the last
    # confirmed presence, distinct from app_version (the apps.yaml label); nothing requires the two to agree.
    # NULL means never confirmed, i.e. a first install.
    reported_version = fields.TextField(null=True)
    last_error = fields.TextField(null=True)
    # Task that last tried to install this app. See the note above.
    last_task_id = fields.UUIDField(null=True)
    # Consecutive failures on this deployment; spaces retries out instead of minting a failed task every retry
    # window. See services.reconciler._retry_delay_minutes.
    failed_attempts = fields.IntField(default=0)
    # The app half of ProfileDeployment.install_source, and the same rule: an app a compliance rule installed on a
    # device the app is not scoped to is held rather than retired while that rule exists.
    install_source = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "app_deployments"
        unique_together = (("device", "app_id"),)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for the API, including last_error and the task that last tried to move this row."""
        return {
            "app_id": self.app_id,
            "version": self.app_version,
            "status": self.status,
            "install_date": self.install_date,
            "last_error": self.last_error,
            "last_task_id": str(self.last_task_id) if self.last_task_id else None,
            # Who asked for it, when the device's own scope did not.
            "install_source": self.install_source,
            "updated_at": self.updated_at,
        }


class ProfileDeployment(Model):
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="profile_deployments")
    device = fields.ForeignKeyField("models.Device", related_name="profile_deployments")
    profile_id = fields.CharField(max_length=100)
    # pending, installing, installed, failed. No 'accepted' here, unlike AppDeployment: a device applies a profile
    # before it acknowledges InstallProfile, so that acknowledgement really does mean installed.
    status = fields.CharField(max_length=20)
    # Hash of the profile definition this row last ATTEMPTED. The sync loop compares it with current YAML to
    # detect an edit and re-push, and to tell an already-fixed failure apart from a repeating one. Written on
    # the way out either way, or a failing row would look freshly edited forever.
    payload_hash = fields.CharField(max_length=64, null=True)
    install_date = fields.DatetimeField(null=True)
    last_error = fields.TextField(null=True)
    # Task that last tried to install this profile. See the note above.
    last_task_id = fields.UUIDField(null=True)
    # The profile half of AppDeployment.failed_attempts; same counter, same backoff, cleared when the profile installs
    # or its definition changes.
    failed_attempts = fields.IntField(default=0)
    # Who asked for this profile, when it was not the device's own scope. 'remediation:<rule id>' marks one a
    # compliance rule installed off-scope, which the sync loop must not take back off (see
    # services.reconciler._held_by_remediation). NULL means the scope asked for it.
    install_source = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "profile_deployments"
        unique_together = (("device", "profile_id"),)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "status": self.status,
            "install_date": self.install_date,
            "last_error": self.last_error,
            "last_task_id": str(self.last_task_id) if self.last_task_id else None,
            # See AppDeployment.to_dict: the same answer to the same question.
            "install_source": self.install_source,
            "updated_at": self.updated_at,
        }


class EnrollmentProfile(Model):
    """Retained for existing databases only; nothing writes or reads this table any more."""

    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="enrollment_profiles")
    profile_id = fields.CharField(max_length=100)
    name = fields.CharField(max_length=255)
    description = fields.TextField(null=True)
    is_dep_profile = fields.BooleanField(default=False)
    payload = fields.JSONField(default=dict)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "enrollment_profiles"
        unique_together = (("tenant", "profile_id"),)


class EnrollmentAttempt(Model):
    """A POST-SCEP webhook check-in that could not be turned into, or matched to, a Device row (the two silent-
    drop points inside _upsert_device). Security: tenant is populated ONLY when a real Tenant row was resolved;
    a no_tenant drop's request tenant id is UNVERIFIED (anyone can pass ?tenant=<victim>), so it is never
    written to the FK, only optionally into detail, and never used to scope a query."""
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="enrollment_attempts", null=True)
    udid = fields.CharField(max_length=40, null=True)
    serial_number = fields.CharField(max_length=20, null=True)
    topic = fields.CharField(max_length=50, null=True)
    outcome = fields.CharField(max_length=30)  # no_tenant | no_serial
    detail = fields.JSONField(default=dict)  # never secrets; may hold an unverified tenant id
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "enrollment_attempts"
        ordering = ["-created_at"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "udid": self.udid,
            "serial_number": self.serial_number,
            "topic": self.topic,
            "outcome": self.outcome,
            "detail": self.detail or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AuditLog(Model):
    """An append-only record of who or what changed something, scoped to the tenant it happened in. A null
    actor_email/actor_role marks a machine-attributed row, which cleanup_old_audit_log relies on. detail must
    never carry a secret."""
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="audit_logs")
    actor_email = fields.CharField(max_length=255, null=True)
    actor_role = fields.CharField(max_length=30, null=True)
    action = fields.CharField(max_length=50)  # e.g. user.create | user.update | user.delete | device.forget
    target_type = fields.CharField(max_length=30, null=True)  # e.g. user | device
    target_id = fields.CharField(max_length=255, null=True)
    detail = fields.JSONField(default=dict)  # non-secret context only
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "audit_logs"
        ordering = ["-created_at"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "actor_email": self.actor_email,
            "actor_role": self.actor_role,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "detail": self.detail or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# Unit separator, not a printable char, so a bundle id or version containing the delimiter cannot collide with
# a different pair. Also what the _AUX_DDL backfill concatenates with, as E'\x1f'.
DEDUP_KEY_SEP = "\x1f"

# Keyed task types, kept in sync with task_dedup_key below by hand.
DEDUP_KEY_TYPES = ("profile_install", "profile_remove", "app_install")


def task_dedup_key(task_type: str, details: Dict[str, Any]) -> Optional[str]:
    """What makes two tasks of the same type on the same device duplicates; the reconciler will not queue a
    second task while one with the same (device, type, key) is pending or running. This is the sole definition
    of that key, shared by four call sites; they must never disagree. Returns None for tasks with no
    dedup identity. Never raises: an exception here would fail Task.save() or take down a reconcile cycle."""
    if not isinstance(details, dict):
        # Covers None and what "details or {}" does not: a JSONField holds whatever was put in it, and a list here would
        # make every .get() below raise. Same reasoning as the isinstance guard on profile_info.
        return None
    if task_type == "profile_install":
        info = details.get("profile_info")
        # isinstance rather than truthiness alone: .get() straight onto a truthy non-object raises AttributeError, and
        # this runs inside save(), so it would fail the task creation itself.
        if isinstance(info, dict) and info:
            return str(info.get("id"))
    elif task_type == "profile_remove":
        profile_id = details.get("profile_id")
        if profile_id:
            return str(profile_id)
    elif task_type == "app_install":
        info = details.get("app_info")
        if isinstance(info, dict) and info:
            return str(info.get("app_id")) + DEDUP_KEY_SEP + str(info.get("version"))
    return None


class Task(Model):
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="tasks")
    type = fields.CharField(max_length=50)  # app_install, app_remove, profile_install, profile_remove, etc.
    status = fields.CharField(max_length=20)  # pending, running, completed, failed
    device = fields.ForeignKeyField("models.Device", related_name="tasks", null=True)
    user = fields.CharField(max_length=255, null=True)  # User who initiated the task
    description = fields.TextField()
    details = fields.JSONField(default=dict)  # Task-specific details
    # The MDM CommandUUID this task is waiting on, mirrored out of details by save() so the webhook can
    # correlate a response with one indexed lookup. NULL if no command was enqueued.
    command_uuid = fields.CharField(max_length=64, null=True)
    # The reconciler's duplicate-task key, mirrored out of details by save(). Keeps the guard from reading every
    # pending task's whole details JSONB each cycle. Unbounded TEXT.
    dedup_key = fields.TextField(null=True)
    error = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    started_at = fields.DatetimeField(null=True)
    completed_at = fields.DatetimeField(null=True)
    progress = fields.IntField(default=0)  # 0-100

    class Meta:
        table = "tasks"
        ordering = ["-created_at"]

    async def save(self, *args, **kwargs):
        """Keep the command_uuid and dedup_key columns in step with details, so no writer can forget a column
        the webhook correlation and dedup guard depend on. details is the source of truth: a row whose details
        drop a value has its mirrored column cleared too."""
        # details may hold anything a JSONField was given; a non-dict here (e.g. a list) must not raise below.
        details = self.details if isinstance(self.details, dict) else {}
        uuid_in_details = details.get("command_uuid") or None
        if uuid_in_details != self.command_uuid:
            self.command_uuid = uuid_in_details
            self._widen_update_fields(kwargs, "command_uuid")
        key_in_details = task_dedup_key(self.type, self.details)
        if key_in_details != self.dedup_key:
            self.dedup_key = key_in_details
            self._widen_update_fields(kwargs, "dedup_key")
        await super().save(*args, **kwargs)

    @staticmethod
    def _widen_update_fields(kwargs: Dict[str, Any], field: str) -> None:
        """Make sure a scoped save still writes a column the mirror just moved. A save with no update_fields
        writes everything and needs nothing here; one that names its fields would otherwise leave the mirrored
        column behind in the database while the in-memory object moved on."""
        update_fields = kwargs.get("update_fields")
        if update_fields is not None and field not in update_fields:
            kwargs["update_fields"] = [*update_fields, field]

    async def update_progress(self, progress: int, status: str = None):
        """Update task progress. Saves ONLY the lifecycle fields: a full save() from a stale copy (several code
        paths hold separate Python objects for the same row) would overwrite details.command_uuid and break the
        webhook to task correlation."""
        self.progress = min(100, max(0, progress))
        if status:
            self.status = status
        if status == 'running' and not self.started_at:
            self.started_at = datetime.utcnow()
        elif status in ['completed', 'failed', 'cancelled'] and not self.completed_at:
            self.completed_at = datetime.utcnow()
        await self.save(update_fields=['progress', 'status', 'started_at', 'completed_at', 'error'])

    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for API responses"""
        return {
            'id': str(self.id),
            'type': self.type,
            'status': self.status,
            'device_id': str(self.device_id) if self.device_id else None,
            'user': self.user,
            'description': self.description,
            'progress': self.progress,
            'error': self.error,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'details': self.details
        }


class FlowRun(Model):
    """A per-device run of an ATC enrollment flow (services.atc). A state machine, not a coroutine: it runs
    forward until a wait_for barrier, persists its position, and resumes on the matching webhook signal. The
    flow definition is snapshotted into context['flow'] and fingerprinted by flow_hash, so mid-run edits to
    flows.yaml do not change what an unfinished run executes.
    """
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="flow_runs")
    device = fields.ForeignKeyField("models.Device", related_name="flow_runs")
    flow_id = fields.CharField(max_length=100)
    # The start node this run entered from and the event that started it (enroll_dep | enroll_profile | checkin
    # | schedule). Run identity is (device, flow_id, start_node); start node ids are unique only within a flow,
    # which is why flow_id is part of the key. Nullable for legacy rows.
    start_node = fields.CharField(max_length=100, null=True)
    event_kind = fields.CharField(max_length=20, null=True)
    # sha256 of the flow document at start, pinning the definition for the run's lifetime. The full snapshot lives in
    # context['flow'].
    flow_hash = fields.CharField(max_length=64)
    # running | waiting | completed | failed | cancelled
    status = fields.CharField(max_length=20, default="running")
    # Node id we are at / parked on (null once terminal).
    current_node = fields.CharField(max_length=100, null=True)
    # For a parked wait_for node: the signal we're waiting on and an optional reference (profile_id / app_id / task_id)
    # the signal must match.
    waiting_signal = fields.CharField(max_length=40, null=True)
    waiting_ref = fields.CharField(max_length=255, null=True)
    wait_deadline = fields.DatetimeField(null=True)  # timeout sweep target
    # Accumulated run state: the pinned flow snapshot, a step timeline and any per-node results. No secrets;
    # send_command redacts before recording.
    context = fields.JSONField(default=dict)
    error = fields.TextField(null=True)
    started_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    completed_at = fields.DatetimeField(null=True)

    class Meta:
        table = "flow_runs"
        ordering = ["-started_at"]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize a run for the API. The flow snapshot is left out; callers fetch the definition separately."""
        ctx = self.context or {}
        return {
            "id": str(self.id),
            "tenant_id": str(self.tenant_id),
            "device_id": str(self.device_id) if self.device_id else None,
            "flow_id": self.flow_id,
            "start_node": self.start_node,
            "event_kind": self.event_kind,
            "flow_hash": self.flow_hash,
            "status": self.status,
            "current_node": self.current_node,
            "waiting_signal": self.waiting_signal,
            "waiting_ref": self.waiting_ref,
            "wait_deadline": self.wait_deadline.isoformat() if self.wait_deadline else None,
            "error": self.error,
            "timeline": ctx.get("timeline", []),
            "visited": ctx.get("visited", []),
            # The run's gap ledger: what each barrier did not get, which the timeline of what happened does not record.
            "gaps": ctx.get("gaps", []),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class Alert(Model):
    """A Dispatcher compliance alert for a (device, rule) pair (services.dispatcher). At most one non-resolved
    row exists per (device, rule_id); re-evaluation updates it rather than adding duplicates. Lifecycle: pending
    (grace anchor) -> open (grace_minutes elapsed, actions run) -> acknowledged / resolved (compliant again or
    an operator resolved it; reversible actions are undone). Severity ranks black > red > yellow > green."""
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="alerts")
    device = fields.ForeignKeyField("models.Device", related_name="alerts")
    rule_id = fields.CharField(max_length=100)
    severity = fields.CharField(max_length=10)  # black | red | yellow | green
    # pending | open | acknowledged | resolved
    status = fields.CharField(max_length=20, default="pending")
    summary = fields.CharField(max_length=255)
    # Snapshot of the failing state + remediation ledger (attempts, outcomes, reversible tags, pending approvals). JSON,
    # never carries secrets.
    detail = fields.JSONField(default=dict)
    first_detected_at = fields.DatetimeField(auto_now_add=True)  # grace anchor
    opened_at = fields.DatetimeField(null=True)
    acknowledged_at = fields.DatetimeField(null=True)
    acknowledged_by = fields.CharField(max_length=255, null=True)
    resolved_at = fields.DatetimeField(null=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "alerts"
        ordering = ["-updated_at"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "tenant_id": str(self.tenant_id),
            "device_id": str(self.device_id) if self.device_id else None,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "status": self.status,
            "summary": self.summary,
            "detail": self.detail or {},
            "first_detected_at": self.first_detected_at.isoformat() if self.first_detected_at else None,
            "opened_at": self.opened_at.isoformat() if self.opened_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class DepServer(Model):
    """A linked Apple Business/School Manager MDM-server token (services.dep_manager). One row per ABM/ASM
    token an admin links. token_enc and private_key_enc are encrypted at rest and never serialized or logged;
    treat token_enc like a root credential, since it decides which devices enroll into which MDM org-wide.
    """
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="dep_servers")
    name = fields.CharField(max_length=100)  # admin slug label
    # unlinked | awaiting_token | linked | error
    status = fields.CharField(max_length=30, default="unlinked")
    # PKI: private key encrypted; public cert is what the admin uploads to ABM.
    private_key_enc = fields.TextField(null=True)
    public_cert_pem = fields.TextField(null=True)
    cert_expires_at = fields.DatetimeField(null=True)
    # Decrypted server token JSON (OAuth1 creds), Fernet-encrypted at rest.
    token_enc = fields.TextField(null=True)
    token_expires_at = fields.DatetimeField(null=True)  # from access_token_expiry
    # /account cache (non-secret): org_name, server_name, org_id, admin_id, ...
    account_detail = fields.JSONField(default=dict)
    # Delta-sync cursor (opaque, <7 days) + bookkeeping. TextField, not a bounded VARCHAR: Apple documents the
    # cursor as up to 1000 hex chars
    # (https://developer.apple.com/documentation/devicemanagement/), and a too-short column would silently break
    # persistence.
    sync_cursor = fields.TextField(null=True)
    cursor_fetched_at = fields.DatetimeField(null=True)
    last_sync_at = fields.DatetimeField(null=True)
    last_sync_status = fields.CharField(max_length=40, null=True)
    last_sync_error = fields.TextField(null=True)
    # Default DEP enrollment profile (profiles.yaml id) auto-assigned to new devices.
    default_profile_id = fields.CharField(max_length=100, null=True)
    last_error = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "dep_servers"
        unique_together = (("tenant", "name"),)
        ordering = ["name"]

    @property
    def is_linked(self) -> bool:
        return self.status == "linked" and bool(self.token_enc)

    def to_dict(self) -> Dict[str, Any]:
        """Non-secret projection for the API. NEVER includes token/key material."""
        acct = self.account_detail or {}
        return {
            "id": str(self.id),
            "tenant_id": str(self.tenant_id),
            "name": self.name,
            "status": self.status,
            "has_public_cert": bool(self.public_cert_pem),
            "has_token": bool(self.token_enc),
            "cert_expires_at": self.cert_expires_at.isoformat() if self.cert_expires_at else None,
            "token_expires_at": self.token_expires_at.isoformat() if self.token_expires_at else None,
            "account": {
                "org_name": acct.get("org_name"),
                "server_name": acct.get("server_name"),
                "org_id": acct.get("org_id"),
                "org_email": acct.get("org_email"),
                "admin_id": acct.get("admin_id"),
                "org_type": acct.get("org_type"),
            } if acct else {},
            "sync_cursor_at": self.cursor_fetched_at.isoformat() if self.cursor_fetched_at else None,
            "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
            "last_sync_status": self.last_sync_status,
            "last_sync_error": self.last_sync_error,
            "default_profile_id": self.default_profile_id,
            "last_error": self.last_error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class DepProfile(Model):
    """Maps a locally-authored DEP enrollment profile (profiles.yaml id) to the profile_uuid Apple returns from
    POST /profile (services.dep_manager). Per-DepServer runtime state, not config, so it lives in the DB.
    payload_hash is how the manager notices an edit and re-pushes."""
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="dep_profiles")
    dep_server = fields.ForeignKeyField("models.DepServer", related_name="profiles")
    profile_id = fields.CharField(max_length=100)  # profiles.yaml id
    profile_uuid = fields.CharField(max_length=64, null=True)  # Apple's
    payload_hash = fields.CharField(max_length=64, null=True)
    pushed_at = fields.DatetimeField(null=True)
    last_error = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "dep_profiles"
        unique_together = (("dep_server", "profile_id"),)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "dep_server_id": str(self.dep_server_id),
            "profile_id": self.profile_id,
            "profile_uuid": self.profile_uuid,
            "pushed_at": self.pushed_at.isoformat() if self.pushed_at else None,
            "last_error": self.last_error,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class DeviceSecret(Model):
    """A per-device credential store. value_enc is Fernet-encrypted at rest (services.crypto_secrets), like the
    DEP token; to_dict is the non-secret projection. One row per (device, kind); reprovisioning overwrites the
    value and clears the reveal ledger."""

    # Escrow kinds. Kept as plain strings (not an enum) to match the codebase's stringly-typed status columns; the API
    # validates against this set.
    KIND_MANAGED_ADMIN = "managed_admin_password"
    KIND_FIRMWARE = "firmware_password"
    KIND_RECOVERY_LOCK = "recovery_lock"
    KIND_FILEVAULT_PRK = "filevault_prk"
    KINDS = (KIND_MANAGED_ADMIN, KIND_FIRMWARE, KIND_RECOVERY_LOCK,
             KIND_FILEVAULT_PRK)

    _KIND_LABELS = {
        KIND_MANAGED_ADMIN: "Managed admin password",
        KIND_FIRMWARE: "Firmware password",
        KIND_RECOVERY_LOCK: "Recovery lock password",
        KIND_FILEVAULT_PRK: "FileVault recovery key",
    }

    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="device_secrets")
    device = fields.ForeignKeyField("models.Device", related_name="secrets")
    kind = fields.CharField(max_length=40)
    # Non-secret context. Safe to serialize.
    label = fields.CharField(max_length=255, null=True)
    # crypto_secrets ciphertext of the plaintext password. NEVER serialized.
    value_enc = fields.TextField()
    meta = fields.JSONField(default=dict)
    created_by = fields.CharField(max_length=255, null=True)  # atc:<flow> | admin:<email>
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    # Ledger of when the secret was revealed to an admin and by whom
    revealed_at = fields.DatetimeField(null=True)
    revealed_by = fields.CharField(max_length=255, null=True)
    reveal_count = fields.IntField(default=0)

    class Meta:
        table = "device_secrets"
        unique_together = (("device", "kind"),)
        ordering = ["kind"]

    # meta keys that carry ciphertext (a rotation parks the new password there). Never serialized: the projection below
    # and the API reveal path both filter on this.
    SECRET_META_KEYS = ("pending_value_enc",)

    @property
    def kind_label(self) -> str:
        return self._KIND_LABELS.get(self.kind, self.kind)

    def public_meta(self) -> Dict[str, Any]:
        """meta with the secret-bearing keys dropped. Safe to serialize."""
        return {k: v for k, v in (self.meta or {}).items()
                if k not in self.SECRET_META_KEYS}

    def to_dict(self) -> Dict[str, Any]:
        """Non-secret projection. NEVER includes value_enc / the plaintext."""
        return {
            "id": str(self.id),
            "device_id": str(self.device_id),
            "kind": self.kind,
            "kind_label": self.kind_label,
            "label": self.label,
            "meta": self.public_meta(),
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "revealed_at": self.revealed_at.isoformat() if self.revealed_at else None,
            "revealed_by": self.revealed_by,
            "reveal_count": self.reveal_count,
            # "sealed" = never revealed
            "sealed": self.revealed_at is None,
        }


class SchemaState(Model):
    """One row per distinct schema this database has been brought to. There is no migration tool here: each
    successful init_schema pass records a fingerprint of everything it applied, stamped with the controller
    version. The newest row is the database's state; readiness compares it against what the running code would
    produce.
    """
    fingerprint = fields.CharField(max_length=64, pk=True)
    controller_version = fields.CharField(max_length=40)
    applied_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "schema_state"
        ordering = ["-applied_at"]
