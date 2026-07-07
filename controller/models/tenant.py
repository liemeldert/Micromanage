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
    udid = fields.CharField(max_length=40, unique=True)
    serial_number = fields.CharField(max_length=20)
    device_model = fields.CharField(max_length=100)
    os_version = fields.CharField(max_length=20)
    hostname = fields.CharField(max_length=255, null=True)
    enrollment_date = fields.DatetimeField(auto_now_add=True)
    last_seen = fields.DatetimeField(auto_now=True)
    groups = fields.JSONField(default=list)  # Computed group memberships
    installed_apps = fields.JSONField(default=dict)
    installed_profiles = fields.JSONField(default=list)
    # Everything the device reports about itself (DeviceInformation
    # QueryResponses, SecurityInfo, ...) — kept as-is so the UI can render
    # properties data-driven instead of hardcoding a column per attribute.
    attributes = fields.JSONField(default=dict)

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
    # Hash of the profile definition as deployed — lets the sync loop detect edits
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