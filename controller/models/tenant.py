from tortoise.models import Model
from tortoise import fields
import json
from typing import List, Dict, Any
from datetime import datetime

class Tenant(Model):
    id = fields.CharField(max_length=100, pk=True)
    name = fields.CharField(max_length=255)
    allowed_users = fields.JSONField(default=list)  # Deprecated: advisory only; authz is via User rows
    s3_config = fields.JSONField(default=dict)
    # Per-tenant authentication backend, e.g. {"provider": "local"} or
    # {"provider": "clerk", "issuer": "https://...", ...}. See controller.auth.
    auth_config = fields.JSONField(default=dict)
    dep_enabled = fields.BooleanField(default=False)
    # Dynamic device naming: {"template": "IT-{serial}", "apply_on_enroll": bool}.
    # Mirrored from config.yaml. See services.naming.
    device_naming = fields.JSONField(default=dict)
    # Admin-entered expiry dates for renewal reminders. The controller cannot
    # read the live APNs cert (it lives in NanoMDM's own db, fed once via a
    # throwaway apns-init container) or a DEP/ABM token (no such integration
    # exists yet), so these are manually maintained, not introspected. Dates,
    # not secrets -- no redaction needed.
    apns_cert_expires_at = fields.DatetimeField(null=True)
    dep_token_expires_at = fields.DatetimeField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    is_active = fields.BooleanField(default=True)

    class Meta:
        table = "tenants"

    @property
    def auth_provider(self) -> str:
        return (self.auth_config or {}).get("provider", "local")

    def is_user_allowed(self, user_id: str) -> bool:
        return user_id in self.allowed_users


class User(Model):
    """A principal that may authenticate to a tenant.

    Local users authenticate with ``password_hash``; external (Clerk/OIDC)
    users are matched by ``external_id`` (the provider subject) or ``email``.
    The ``role`` column drives RBAC (admin | member).
    """
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="users")
    email = fields.CharField(max_length=255)
    password_hash = fields.CharField(max_length=255, null=True)  # local auth only
    role = fields.CharField(max_length=20, default="member")  # admin | member
    external_id = fields.CharField(max_length=255, null=True)  # OIDC/Clerk subject
    is_active = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "users"
        unique_together = (("tenant", "email"),)

class Device(Model):
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="devices")
    # Null while a device is a pre-provisioned placeholder (known by serial, not
    # yet enrolled -- e.g. DEP). Postgres treats NULLs as distinct so the unique
    # index still allows many placeholders.
    udid = fields.CharField(max_length=40, unique=True, null=True)
    serial_number = fields.CharField(max_length=20)
    device_model = fields.CharField(max_length=100)
    os_version = fields.CharField(max_length=20)
    hostname = fields.CharField(max_length=255, null=True)
    # Managed display name -- a manual override or derived from the tenant's
    # naming template (services.naming). Null falls back to hostname/serial.
    name = fields.CharField(max_length=255, null=True)
    # Lifecycle across (un)enrollments: enrolled | unenrolled | pending. Records
    # are retained through unenroll so history/state survive a re-enroll.
    enrollment_state = fields.CharField(max_length=20, default="enrolled")
    # Management backend. Only "apple_mdm" today; delimits future platforms.
    management_type = fields.CharField(max_length=30, default="apple_mdm")
    enrollment_date = fields.DatetimeField(auto_now_add=True)
    unenrolled_at = fields.DatetimeField(null=True)
    last_seen = fields.DatetimeField(auto_now=True)
    # Adaptive info-poll schedule (services.poller): when we last queried the
    # device, and the current cadence in minutes (grows as a device stays silent,
    # resets to the base when it answers).
    last_polled_at = fields.DatetimeField(null=True)
    poll_interval_minutes = fields.IntField(default=30)
    groups = fields.JSONField(default=list)  # Computed group memberships
    installed_apps = fields.JSONField(default=dict)
    installed_profiles = fields.JSONField(default=list)
    # Everything the device reports about itself (DeviceInformation
    # QueryResponses, SecurityInfo, ...) -- kept as-is so the UI can render
    # properties data-driven instead of hardcoding a column per attribute.
    attributes = fields.JSONField(default=dict)
    # Imperative device labels, written by ATC flows / Dispatcher rules and by
    # hand. A flat list[str] (mirrors ``groups``); matched by the ``tag`` scope
    # condition. Assignment is additive and idempotent -- automated writers only
    # add their own tags or remove tags they name explicitly, never bulk-reconcile
    # the set, so a manually-applied tag is never clobbered. Unlike groups (which
    # are computed from state), tags are the one piece of device state a flow may
    # write; a "devices tagged X" group is expressed with a ``tag`` condition.
    tags = fields.JSONField(default=list)
    # Automated Device Enrollment (ADE/DEP) linkage. Populated when a device is
    # synced from Apple Business/School Manager (services.dep_manager): which
    # DepServer owns it, the Apple profile assigned, and Apple's own
    # profile_status (empty|assigned|pushed|removed). Null for OTA/manual devices.
    # See models.DepServer / docs/specs/dep-ade-spec.md.
    dep_server_id = fields.UUIDField(null=True)
    dep_profile_uuid = fields.CharField(max_length=64, null=True)
    dep_profile_status = fields.CharField(max_length=30, null=True)
    dep_last_synced_at = fields.DatetimeField(null=True)

    class Meta:
        table = "devices"

class AppDeployment(Model):
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="app_deployments")
    device = fields.ForeignKeyField("models.Device", related_name="app_deployments")
    app_id = fields.CharField(max_length=100)
    app_version = fields.CharField(max_length=50)
    status = fields.CharField(max_length=20)  # pending, installing, installed, failed
    install_date = fields.DatetimeField(null=True)
    last_error = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    
    class Meta:
        table = "app_deployments"
        unique_together = (("device", "app_id"),)

class ProfileDeployment(Model):
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="profile_deployments")
    device = fields.ForeignKeyField("models.Device", related_name="profile_deployments")
    profile_id = fields.CharField(max_length=100)
    status = fields.CharField(max_length=20)  # pending, installing, installed, failed
    # Hash of the profile definition as deployed -- lets the sync loop detect edits
    # to an already-installed profile and re-push it (declared state reconciliation).
    payload_hash = fields.CharField(max_length=64, null=True)
    install_date = fields.DatetimeField(null=True)
    last_error = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    
    class Meta:
        table = "profile_deployments"
        unique_together = (("device", "profile_id"),)

class EnrollmentProfile(Model):
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
    """A logged POST-SCEP webhook check-in that could NOT be turned into (or
    matched to) a Device row -- observability for enrollment drops that
    otherwise fail silently (services.webhook_handler).

    SCEP-stage failures (a device that never reaches the controller at all)
    are invisible here by construction; this only covers the two known
    silent-drop points inside ``_upsert_device``.

    Security: ``tenant`` is populated ONLY when a real Tenant row was
    resolved (e.g. a no_serial drop on an already-known tenant). For a
    no_tenant drop, the attempted tenant id in the request is UNVERIFIED --
    an attacker could pass ``?tenant=<victim>`` on the enrollment ServerURL to
    try to pollute a victim's view, so it is never written to the FK; if kept
    at all it goes only in ``detail`` (never used to scope a query)."""
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
    """An append-only record of an admin action taken through the console
    (services.audit.record_audit), scoped to the acting principal's tenant.

    Security: ``detail`` must NEVER carry a secret (a password, token, API
    key, ...). The v1 call sites (user create/update/delete, device forget)
    record only non-secret facts -- e.g. which fields changed as booleans,
    never their values -- so that this log is safe to expose to any tenant
    admin. Actions that touch secret-bearing fields (tenant/config/remediation
    updates) are deliberately NOT instrumented here yet; they need a
    secret-redaction pass first."""
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


class Task(Model):
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="tasks")
    type = fields.CharField(max_length=50)  # app_install, app_remove, profile_install, profile_remove, etc.
    status = fields.CharField(max_length=20)  # pending, running, completed, failed
    device = fields.ForeignKeyField("models.Device", related_name="tasks", null=True)
    user = fields.CharField(max_length=255, null=True)  # User who initiated the task
    description = fields.TextField()
    details = fields.JSONField(default=dict)  # Task-specific details
    error = fields.TextField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    started_at = fields.DatetimeField(null=True)
    completed_at = fields.DatetimeField(null=True)
    progress = fields.IntField(default=0)  # 0-100
    
    class Meta:
        table = "tasks"
        ordering = ["-created_at"]
    
    async def update_progress(self, progress: int, status: str = None):
        """Update task progress.

        Saves ONLY the lifecycle fields. Several code paths (API process, sync
        service, webhook) hold separate Python objects for the same row; a full
        save() from a stale copy silently clobbered details.command_uuid and
        broke webhook→task correlation (tasks stuck "running" forever).
        """
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
    """A per-device run of an ATC enrollment flow (services.atc).

    A flow is NOT a synchronous script: MDM is asynchronous, so a run executes
    forward until it hits a step that must wait for the device (a ``wait_for``
    barrier), then persists its position here and resumes when the matching
    webhook signal arrives. Model it as a state machine, not a coroutine.

    The flow definition is snapshotted into ``context['flow']`` at start (and
    fingerprinted by ``flow_hash``) so an admin editing flows.yaml mid-run does
    not change the definition an in-flight run executes.
    """
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="flow_runs")
    device = fields.ForeignKeyField("models.Device", related_name="flow_runs")
    flow_id = fields.CharField(max_length=100)
    # The start node this run entered from and the event that fired it
    # (enroll_dep | enroll_profile | checkin | schedule). Run identity is
    # (device, start_node): supersede/dedup key off these so concurrent runs from
    # different starts on one device are legitimate. Nullable for legacy rows.
    start_node = fields.CharField(max_length=100, null=True)
    event_kind = fields.CharField(max_length=20, null=True)
    # sha256 of the flow document at start -- pins the definition for the run's
    # lifetime (the full snapshot lives in context['flow']).
    flow_hash = fields.CharField(max_length=64)
    # running | waiting | completed | failed | cancelled
    status = fields.CharField(max_length=20, default="running")
    # Node id we are at / parked on (null once terminal).
    current_node = fields.CharField(max_length=100, null=True)
    # For a parked wait_for node: the signal we're waiting on and an optional
    # reference (profile_id / app_id / task_id) the signal must match.
    waiting_signal = fields.CharField(max_length=40, null=True)
    waiting_ref = fields.CharField(max_length=255, null=True)
    wait_deadline = fields.DatetimeField(null=True)  # timeout sweep target
    # Accumulated run state: the pinned flow snapshot, a step timeline, and any
    # per-node results (never secrets -- send_command redacts before recording).
    context = fields.JSONField(default=dict)
    error = fields.TextField(null=True)
    started_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)
    completed_at = fields.DatetimeField(null=True)

    class Meta:
        table = "flow_runs"
        ordering = ["-started_at"]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize a run for the API / run viewer (no raw flow snapshot -- the
        editor fetches the definition separately; the timeline is what the
        viewer needs)."""
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
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class Alert(Model):
    """A Dispatcher compliance alert for a (device, rule) pair (services.dispatcher).

    At most one non-``resolved`` row exists per (device, rule_id): re-evaluation
    updates it rather than spamming duplicates. Lifecycle:

      pending  -> a violation was first seen (grace-period anchor); no actions yet
      open     -> non-compliant continuously for grace_minutes; actions fired
      acknowledged -> an operator ack'd it (still non-compliant)
      resolved -> the device became compliant (auto) or an operator resolved it;
                  reversible actions (e.g. a noncompliant tag) are undone

    Severity is an ED/911 triage label (black > red > yellow > green) the board
    ranks by. Remediation attempts / cooldowns / what fired are recorded in
    ``detail`` (never secrets)."""
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="alerts")
    device = fields.ForeignKeyField("models.Device", related_name="alerts")
    rule_id = fields.CharField(max_length=100)
    severity = fields.CharField(max_length=10)  # black | red | yellow | green
    # pending | open | acknowledged | resolved
    status = fields.CharField(max_length=20, default="pending")
    summary = fields.CharField(max_length=255)
    # Snapshot of the failing state + remediation ledger (attempts, outcomes,
    # reversible tags, pending approvals). JSON, never carries secrets.
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
    """A linked Apple Business/School Manager MDM-server token (services.dep_manager).

    One row per ABM/ASM server token an admin links. Holds the crown-jewel DEP
    server token (OAuth1 creds) and the PKI private key used to decrypt it -- BOTH
    encrypted at rest (services.crypto_secrets). These columns are secrets and are
    NEVER serialized (``to_dict`` omits them), never logged, never written to a
    config doc or history snapshot. The config dir is git-reviewable, so DEP
    credentials deliberately live here in the DB instead. See docs/specs/dep-ade-spec.md.

    Security: ``token_enc`` grants control over which devices land in which MDM for
    the whole org -- treat like a root credential. ``private_key_enc`` can decrypt a
    re-downloaded token, so it is guarded just as tightly.
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
    # Delta-sync cursor (opaque, <7 days) + bookkeeping.
    sync_cursor = fields.CharField(max_length=255, null=True)
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
    """Maps a locally-authored DEP enrollment profile (profiles.yaml id) to the
    ``profile_uuid`` Apple returns from ``POST /profile`` (services.dep_manager).

    This mapping is runtime state (per DepServer), not config -- so it lives in the
    DB, not in the git-tracked config doc. ``payload_hash`` lets the manager detect an
    edit to the authored profile and re-push it.
    """
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="dep_profiles")
    dep_server = fields.ForeignKeyField("models.DepServer", related_name="profiles")
    profile_id = fields.CharField(max_length=100)   # profiles.yaml id
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