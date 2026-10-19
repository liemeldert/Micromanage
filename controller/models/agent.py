"""Tables for the Mac agent (micromanaged): its credential and heartbeat state, enrollment codes, the task queue,
elevation requests and ingested events. Re-exported from controller.models.tenant, the module Tortoise loads."""
from tortoise import fields
from tortoise.models import Model


class DeviceAgent(Model):
    """The agent credential and last reported state for one device. Re-enrollment overwrites the credential columns.
    Tokens are stored as sha256 hex only; pending_token_enc holds a rotation token sealed until the daemon uses it."""
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="device_agents", on_delete=fields.CASCADE)
    device = fields.OneToOneField("models.Device", related_name="agent", on_delete=fields.CASCADE)
    # Null after a revoke.
    token_hash = fields.CharField(max_length=64, unique=True, null=True)
    token_prefix = fields.CharField(max_length=12)
    token_issued_at = fields.DatetimeField()
    # A rotation token sent in a heartbeat response and not yet used by the daemon.
    pending_token_hash = fields.CharField(max_length=64, unique=True, null=True)
    pending_token_issued_at = fields.DatetimeField(null=True)
    pending_token_enc = fields.TextField(null=True)
    # The superseded token, accepted for a short overlap on every route and until valid_until on task results.
    previous_token_hash = fields.CharField(max_length=64, unique=True, null=True)
    previous_token_valid_until = fields.DatetimeField(null=True)
    previous_promoted_at = fields.DatetimeField(null=True)
    rotation_requested_at = fields.DatetimeField(null=True)
    status = fields.CharField(max_length=16, default="active")  # active | revoked
    enrolled_at = fields.DatetimeField()
    enrolled_code = fields.ForeignKeyField("models.AgentEnrollmentCode", related_name="agents", null=True,
                                           on_delete=fields.SET_NULL)
    revoked_at = fields.DatetimeField(null=True)
    revoked_by = fields.CharField(max_length=255, null=True)  # email
    revoke_reason = fields.CharField(max_length=255, null=True)
    # Identity as the daemon sent it at enrollment.
    reported_serial = fields.CharField(max_length=64)
    reported_hardware_uuid = fields.CharField(max_length=64)
    reported_hostname = fields.CharField(max_length=255, null=True)
    agent_version = fields.CharField(max_length=64)
    user_agent = fields.CharField(max_length=128, null=True)
    last_seen_at = fields.DatetimeField(null=True)
    last_heartbeat_at = fields.DatetimeField(null=True)
    # request.client.host, which is the proxy's address unless FORWARDED_ALLOW_IPS is set.
    last_ip = fields.CharField(max_length=64, null=True)
    heartbeat_minutes_sent = fields.IntField(null=True)
    # The last full facts report and the daemon's digest of it, both stored as received.
    facts = fields.JSONField(null=True)
    facts_digest = fields.CharField(max_length=64, null=True)
    facts_received_at = fields.DatetimeField(null=True)
    last_digest_seen = fields.CharField(max_length=64, null=True)
    facts_error = fields.CharField(max_length=255, null=True)
    facts_error_at = fields.DatetimeField(null=True)
    grants = fields.JSONField(default=list)
    grants_reported_at = fields.DatetimeField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "device_agents"


class AgentEnrollmentCode(Model):
    """A single-use agent enrollment code bound to one device. Only its sha256 is stored."""
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="agent_enrollment_codes", on_delete=fields.CASCADE)
    device = fields.ForeignKeyField("models.Device", related_name="agent_enrollment_codes", on_delete=fields.CASCADE)
    code_hash = fields.CharField(max_length=64, unique=True)
    code_prefix = fields.CharField(max_length=12)
    created_by = fields.CharField(max_length=255)  # email
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField()
    delivery = fields.CharField(max_length=16)  # mdm_push | download
    push_task_id = fields.CharField(max_length=64, null=True)
    consumed_at = fields.DatetimeField(null=True)
    # Enrollments refused because the presented serial or hardware UUID did not match the device.
    failed_attempts = fields.IntField(default=0)
    revoked_at = fields.DatetimeField(null=True)
    revoke_reason = fields.CharField(max_length=32, null=True)  # superseded | operator | too_many_failures

    class Meta:
        table = "agent_enrollment_codes"


class AgentTask(Model):
    """A task queued for the agent. The id is sent to the daemon as the task id."""
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="agent_tasks", on_delete=fields.CASCADE)
    device = fields.ForeignKeyField("models.Device", related_name="agent_tasks", on_delete=fields.CASCADE)
    type = fields.CharField(max_length=32)
    # As validated at queue time, which can differ from the params sent to the daemon.
    params = fields.JSONField(default=dict)
    # queued | sent | completed | failed | canceled | expired | unconfirmed
    status = fields.CharField(max_length=16, default="queued")
    created_by = fields.CharField(max_length=255)  # email
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField()
    sent_at = fields.DatetimeField(null=True)
    result_at = fields.DatetimeField(null=True)
    result_status = fields.CharField(max_length=16, null=True)  # completed | failed, as the daemon sent it
    result_detail = fields.JSONField(null=True)
    canceled_by = fields.CharField(max_length=255, null=True)
    canceled_at = fields.DatetimeField(null=True)

    class Meta:
        table = "agent_tasks"


class ElevationRequest(Model):
    """A request from the Mac for temporary admin rights, and its decision."""
    id = fields.UUIDField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="agent_elevation_requests",
                                    on_delete=fields.CASCADE)
    device = fields.ForeignKeyField("models.Device", related_name="agent_elevation_requests",
                                    on_delete=fields.CASCADE)
    username = fields.CharField(max_length=64)
    requested_minutes = fields.IntField()
    reason = fields.CharField(max_length=500, null=True)
    status = fields.CharField(max_length=16, default="pending")  # pending | approved | denied | expired | withdrawn
    decided_by = fields.CharField(max_length=255, null=True)  # an email, or "policy"
    decided_at = fields.DatetimeField(null=True)
    decision_minutes = fields.IntField(null=True)
    # Never sent to the Mac.
    decision_note = fields.CharField(max_length=500, null=True)
    # First heartbeat response that carried the decision.
    delivered_at = fields.DatetimeField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField()

    class Meta:
        table = "agent_elevation_requests"


class AgentEvent(Model):
    """An event from the daemon's queue, stored once per (device, event_id)."""
    id = fields.IntField(pk=True)
    tenant = fields.ForeignKeyField("models.Tenant", related_name="agent_events", on_delete=fields.CASCADE)
    device = fields.ForeignKeyField("models.Device", related_name="agent_events", on_delete=fields.CASCADE)
    event_id = fields.CharField(max_length=64)
    kind = fields.CharField(max_length=64)
    # The Mac's clock.
    at = fields.DatetimeField()
    username = fields.CharField(max_length=64, null=True)
    detail = fields.JSONField(default=dict)
    truncated = fields.BooleanField(default=False)
    received_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "agent_events"
        unique_together = (("device", "event_id"),)
