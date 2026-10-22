import hashlib
import logging
import os
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Optional

from tortoise import Tortoise
from tortoise.utils import get_schema_sql

# Blank when unset. enforce_database_url raises at startup.
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Above Tortoise's per-process default of 5, as supervisord runs three processes and the reconciler runs up to
# MDM_MAX_CONCURRENT_TASKS handlers at once.
DB_POOL_MAX = int(os.getenv("DB_POOL_MAX_SIZE", "20"))
DB_POOL_MIN = int(os.getenv("DB_POOL_MIN_SIZE", "2"))

# Minimum pool maximum; a pool of one deadlocks init_schema, which pins a connection for the whole schema phase.
_MIN_POOL_MAX = 2


def _pooled_url(url: str) -> str:
    """Add pool sizing to a Postgres DSN, keeping a minimum the DSN already sets. Postgres only.
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    if not parts.scheme.startswith(("postgres", "asyncpg")):
        return url
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    params.setdefault("maxsize", str(DB_POOL_MAX))
    try:
        maxsize = int(params["maxsize"])
    except (TypeError, ValueError):
        # An unparseable maxsize fails downstream at asyncpg.
        maxsize = None
    if maxsize is not None and maxsize < _MIN_POOL_MAX:
        logging.getLogger(__name__).warning(
            "pool maximum %s is below the %s connections the schema phase needs; using %s. A pool of one deadlocks "
            "init_schema with the advisory lock held, and every controller process then hangs with nothing logged.",
            maxsize, _MIN_POOL_MAX, _MIN_POOL_MAX,
        )
        maxsize = _MIN_POOL_MAX
        params["maxsize"] = str(maxsize)
    if "minsize" not in params:
        minsize = DB_POOL_MIN
        if maxsize is not None and minsize > maxsize:
            logging.getLogger(__name__).warning(
                "pool minimum %s is above the configured maximum %s; using %s for both. asyncpg refuses min_size > "
                "max_size and the process would restart forever. Raise DB_POOL_MAX_SIZE if you meant the minimum.",
                minsize, maxsize, maxsize,
            )
            minsize = maxsize
        params["minsize"] = str(minsize)
    return urlunsplit(parts._replace(query=urlencode(params)))


# Columns added after the initial schema. generate_schemas() never alters existing tables, so these are applied here.
# The statements must be idempotent.
_AUX_DDL = [
    'ALTER TABLE "profile_deployments" ADD COLUMN IF NOT EXISTS "payload_hash" VARCHAR(64)',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "attributes" JSONB NOT NULL DEFAULT \'{}\'::jsonb',
    # Device lifecycle across enrollments, with DEP placeholders.
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "enrollment_state" VARCHAR(20) NOT NULL DEFAULT \'enrolled\'',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "management_type" VARCHAR(30) NOT NULL DEFAULT \'apple_mdm\'',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "unenrolled_at" TIMESTAMPTZ NULL',
    # udid is nullable for pre-provisioned placeholders (serial only).
    'ALTER TABLE "devices" ALTER COLUMN "udid" DROP NOT NULL',
    # Managed device name + per-tenant dynamic naming template.
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "name" VARCHAR(255) NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "device_naming" JSONB NOT NULL DEFAULT \'{}\'::jsonb',
    # Adaptive info-poll schedule (services.poller).
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "last_polled_at" TIMESTAMPTZ NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "poll_interval_minutes" INTEGER NOT NULL DEFAULT 30',
    # Imperative device tags (ATC, Dispatcher and manual writers), a flat list of strings matched by the "tag" scope
    # condition.
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "tags" JSONB NOT NULL DEFAULT \'[]\'::jsonb',
    # APNs cert and DEP token expiry dates, entered by an admin as the live cert and token cannot be read.
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "apns_cert_expires_at" TIMESTAMPTZ NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "dep_token_expires_at" TIMESTAMPTZ NULL',
    # Per-tenant object storage ceiling (models.tenant.Tenant.storage_quota_bytes).
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "storage_quota_bytes" BIGINT NULL',
    # FileVault recovery-key escrow keypair (services.filevault_escrow), with the private key Fernet-encrypted at rest.
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "fv_escrow_private_key_enc" TEXT NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "fv_escrow_cert_pem" TEXT NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "fv_escrow_cert_expires_at" TIMESTAMPTZ NULL',
    # ADE/DEP device linkage (services.dep_manager), set for devices synced from Apple Business/School Manager and null
    # for OTA and manual devices.
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "dep_server_id" UUID NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "dep_profile_uuid" VARCHAR(64) NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "dep_profile_status" VARCHAR(30) NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "dep_last_synced_at" TIMESTAMPTZ NULL',
    # Converts the DepServer.sync_cursor column to TEXT if it has another type. Apple allows a cursor of up to 1000
    # characters, and a save that does not fit fails, leaving the stored cursor unchanged.
    # https://developer.apple.com/documentation/devicemanagement/fetchdevicerequest
    "DO $$\n"
    "BEGIN\n"
    "    IF EXISTS (SELECT 1 FROM information_schema.columns\n"
    "               WHERE table_schema = current_schema()\n"
    "                 AND table_name = 'dep_servers'\n"
    "                 AND column_name = 'sync_cursor'\n"
    "                 AND data_type <> 'text')\n"
    "    THEN\n"
    '        ALTER TABLE "dep_servers" ALTER COLUMN "sync_cursor" TYPE TEXT;\n'
    "    END IF;\n"
    "END\n"
    "$$",
    # ATC: a run's entry node and the event that started it (run identity is device, flow_id, start_node).
    'ALTER TABLE "flow_runs" ADD COLUMN IF NOT EXISTS "start_node" VARCHAR(100) NULL',
    'ALTER TABLE "flow_runs" ADD COLUMN IF NOT EXISTS "event_kind" VARCHAR(20) NULL',
    # Who started a run and with which role.
    'ALTER TABLE "flow_runs" ADD COLUMN IF NOT EXISTS "started_by" VARCHAR(255) NULL',
    'ALTER TABLE "flow_runs" ADD COLUMN IF NOT EXISTS "started_role" VARCHAR(16) NULL',
    'CREATE INDEX IF NOT EXISTS "idx_flowruns_dev_flow_start_event" '
    'ON "flow_runs" (device_id, flow_id, start_node, event_kind, started_at)',
    'CREATE INDEX IF NOT EXISTS "idx_flowruns_tenant_flow_start_event_dev" '
    'ON "flow_runs" (tenant_id, flow_id, start_node, event_kind, device_id, started_at)',
    # Drops the flow_runs indexes keyed without flow_id, as every lookup by start node also filters on flow_id. Listed
    # after the creates, so a failed upgrade leaves one set of indexes.
    'DROP INDEX IF EXISTS "idx_flowruns_dev_start_event"',
    'DROP INDEX IF EXISTS "idx_flowruns_tenant_start_event_dev"',
    # Declarative Device Management (services.ddm_manager).
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "ddm_enabled" BOOLEAN NOT NULL DEFAULT FALSE',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "ddm_enabled_at" TIMESTAMPTZ NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "ddm_last_sync_at" TIMESTAMPTZ NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "ddm_last_published_token" VARCHAR(64) NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "ddm_status" JSONB NOT NULL DEFAULT \'{}\'::jsonb',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "ddm_declaration_status" JSONB NOT NULL DEFAULT \'{}\'::jsonb',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "ddm_client_capabilities" JSONB NOT NULL DEFAULT \'{}\'::jsonb',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "bootstrap_token_escrowed" BOOLEAN NOT NULL DEFAULT FALSE',
    # Plain UUID, no FK, as the retention sweep deletes tasks and a dangling pointer means the attempt aged out.
    'ALTER TABLE "app_deployments" ADD COLUMN IF NOT EXISTS "last_task_id" UUID NULL',
    'ALTER TABLE "profile_deployments" ADD COLUMN IF NOT EXISTS "last_task_id" UUID NULL',
    # Paces services.reconciler's retry backoff.
    'ALTER TABLE "app_deployments" ADD COLUMN IF NOT EXISTS "failed_attempts" INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE "profile_deployments" ADD COLUMN IF NOT EXISTS "failed_attempts" INTEGER NOT NULL DEFAULT 0',
    # Device-reported version, which need not match what the deployment requested. NULL means never confirmed. TEXT, as
    # the device supplies the length.
    'ALTER TABLE "app_deployments" ADD COLUMN IF NOT EXISTS "reported_version" TEXT',
    # Who requested a profile the device's scope does not, written as remediation:<rule id>; NULL is the ordinary scoped
    # case. TEXT, as a rule id is unbounded.
    'ALTER TABLE "profile_deployments" ADD COLUMN IF NOT EXISTS "install_source" TEXT NULL',
    'ALTER TABLE "app_deployments" ADD COLUMN IF NOT EXISTS "install_source" TEXT NULL',
    # Session cut-off for a password change (auth.dependencies). Null means never changed.
    'ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "password_changed_at" TIMESTAMPTZ NULL',
    # Session cut-off for disabling two-factor auth (auth.dependencies). Disabling deletes the UserMFA row, so the
    # cut-off is stored on User.
    'ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "mfa_changed_at" TIMESTAMPTZ NULL',
    # Task.command_uuid: MDM CommandUUID mirrored from details (models.tenant.Task.save) for an indexed webhook_handler
    # lookup instead of a scan of the device's 50 newest tasks.
    'ALTER TABLE "tasks" ADD COLUMN IF NOT EXISTS "command_uuid" VARCHAR(64) NULL',
    'UPDATE "tasks" SET "command_uuid" = "details"->>\'command_uuid\' '
    "WHERE \"command_uuid\" IS NULL AND \"details\"->>'command_uuid' IS NOT NULL",
    # Partial: tasks that never enqueued a command stay NULL and are never looked up this way.
    'CREATE INDEX IF NOT EXISTS "idx_tasks_command_uuid" ON "tasks" (command_uuid) WHERE command_uuid IS NOT NULL',
    # Task.dedup_key: the reconciler's duplicate-task key, mirrored like command_uuid (models.tenant.task_dedup_key).
    'ALTER TABLE "tasks" ADD COLUMN IF NOT EXISTS "dedup_key" TEXT NULL',
    # Backfill for rows whose key SQL can reproduce identically (every component a JSON string).
    # reconciler._unmirrored_task_keys computes the key in Python for the rest.
    'UPDATE "tasks" SET "dedup_key" = CASE "type" '
    'WHEN \'profile_install\' THEN "details"->\'profile_info\'->>\'id\' '
    'WHEN \'profile_remove\' THEN "details"->>\'profile_id\' '
    'WHEN \'app_install\' THEN ("details"->\'app_info\'->>\'app_id\') '
    '|| E\'\\x1f\' || ("details"->\'app_info\'->>\'version\') '
    'END '
    'WHERE "dedup_key" IS NULL AND ('
    '("type" = \'profile_install\' '
    'AND jsonb_typeof("details"->\'profile_info\'->\'id\') = \'string\') '
    'OR ("type" = \'profile_remove\' '
    'AND jsonb_typeof("details"->\'profile_id\') = \'string\' '
    'AND "details"->>\'profile_id\' <> \'\') '
    'OR ("type" = \'app_install\' '
    'AND jsonb_typeof("details"->\'app_info\'->\'app_id\') = \'string\' '
    'AND jsonb_typeof("details"->\'app_info\'->\'version\') = \'string\'))',
    # Resets installed_apps to an empty array where it holds a JSON object; the column holds an array.
    'UPDATE "devices" SET "installed_apps" = \'[]\'::jsonb '
    "WHERE jsonb_typeof(\"installed_apps\") = 'object'",

    # Indexes for frequent queries. Tortoise indexes only primary keys and unique_together. Plain CREATE INDEX, not
    # CONCURRENTLY.

    # The device command list (api.routes.devices) and the pending-task cancel on checkout.
    'CREATE INDEX IF NOT EXISTS "idx_tasks_device_created" ON "tasks" (device_id, created_at DESC)',
    # reconciler._active_task_keys / _fail_timed_out_tasks, the Tasks list page, and poller._prune_scheduled_tasks.
    'CREATE INDEX IF NOT EXISTS "idx_tasks_tenant_status_created" ON "tasks" (tenant_id, status, created_at)',
    # dispatcher._active_alert and _recent_remediation_state run per (device, rule) for every rule on every evaluation.
    'CREATE INDEX IF NOT EXISTS "idx_alerts_device_rule_status" ON "alerts" (device_id, rule_id, status)',
    # The tenant alert list and the unresolved severity counts.
    'CREATE INDEX IF NOT EXISTS "idx_alerts_tenant_status" ON "alerts" (tenant_id, status)',
    # ATC manual-gate alerts are looked up by rule_id alone (atc:gate:<run>).
    'CREATE INDEX IF NOT EXISTS "idx_alerts_rule" ON "alerts" (rule_id)',
    # The fleet sweep each pass starts with (reconciler, poller, dispatcher, ATC schedule starts) and the per-state
    # device counts in api.routes.devices.
    'CREATE INDEX IF NOT EXISTS "idx_devices_tenant_enrollstate" ON "devices" (tenant_id, enrollment_state)',
    # atc.sweep_timeouts (waiting and deadline) and the orphaned-running recovery, both run per tenant on every poll
    # tick.
    'CREATE INDEX IF NOT EXISTS "idx_flowruns_tenant_status_deadline" '
    'ON "flow_runs" (tenant_id, status, wait_deadline)',
    # The fleet run list sorts newest-first across a tenant, which the index above (leading with status) does not serve.
    'CREATE INDEX IF NOT EXISTS "idx_flowruns_tenant_started" ON "flow_runs" (tenant_id, started_at DESC)',
    # The audit log query is tenant-scoped and always newest-first.
    'CREATE INDEX IF NOT EXISTS "idx_auditlogs_tenant_created" ON "audit_logs" (tenant_id, created_at DESC)',
    # webhook_handler._record_attempt looks up on the enrollment path.
    'CREATE INDEX IF NOT EXISTS "idx_enrollattempts_udid_outcome" ON "enrollment_attempts" (udid, outcome)',
    # reconciler._fail_timed_out_tasks looks deployments up by the task that was installing them. Partial, as a row has
    # a pointer only once a deploy was attempted.
    'CREATE INDEX IF NOT EXISTS "idx_appdeploy_last_task" '
    'ON "app_deployments" (last_task_id) WHERE last_task_id IS NOT NULL',
    'CREATE INDEX IF NOT EXISTS "idx_profiledeploy_last_task" '
    'ON "profile_deployments" (last_task_id) WHERE last_task_id IS NOT NULL',
    # Both deployment tables are read tenant-wide on every tick by the reconciler, dispatcher, and poller.
    'CREATE INDEX IF NOT EXISTS "idx_appdeploy_tenant_status" ON "app_deployments" (tenant_id, status)',
    'CREATE INDEX IF NOT EXISTS "idx_profiledeploy_tenant" ON "profile_deployments" (tenant_id)',
    # The daily retention sweep (services.task_manager.run_retention), whose cross-tenant deletes cannot use the
    # tenant-led indexes above.
    'CREATE INDEX IF NOT EXISTS "idx_tasks_status_completed" ON "tasks" (status, completed_at)',
    'CREATE INDEX IF NOT EXISTS "idx_alerts_status_resolved" ON "alerts" (status, resolved_at)',
    'CREATE INDEX IF NOT EXISTS "idx_flowruns_status_started" ON "flow_runs" (status, started_at)',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "payload_identifier_prefix" VARCHAR(120) NULL',
    'CREATE TABLE IF NOT EXISTS "service_tokens" ('
    '    "id" UUID PRIMARY KEY,'
    '    "tenant_id" VARCHAR(100) NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,'
    '    "name" VARCHAR(255) NOT NULL,'
    '    "token_hash" VARCHAR(64) NOT NULL UNIQUE,'
    '    "scopes" JSONB NOT NULL DEFAULT \'[]\'::jsonb,'
    '    "expires_at" TIMESTAMPTZ NOT NULL,'
    '    "last_used_at" TIMESTAMPTZ NULL,'
    '    "revoked_at" TIMESTAMPTZ NULL,'
    '    "created_at" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,'
    '    "created_by" VARCHAR(255) NULL'
    ')',
    'CREATE INDEX IF NOT EXISTS "idx_service_tokens_tenant_hash" ON "service_tokens" (tenant_id, token_hash)',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "profile_signing_cert_pem" TEXT NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "profile_signing_key_enc" TEXT NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "profile_signing_chain_pem" TEXT NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "profile_signing_cert_expires_at" TIMESTAMPTZ NULL',
    # Enrollment identity.
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "reenrollment_allowed_until" TIMESTAMPTZ NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "erase_acked_at" TIMESTAMPTZ NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "push_token_enc" TEXT NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "identity_sha256" VARCHAR(64) NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "identity_pem" TEXT NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "bootstrap_token_enc" TEXT NULL',
    'ALTER TABLE "scep_challenges" ADD COLUMN IF NOT EXISTS "origin" VARCHAR(16) NOT NULL DEFAULT \'manual\'',
    'ALTER TABLE "scep_challenges" ADD COLUMN IF NOT EXISTS "previous_pem" TEXT NULL',
    # unique open renewal challenge per device
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_scep_challenges_open_renewal ON scep_challenges (device_id) '
    'WHERE device_id IS NOT NULL AND consumed_at IS NULL',
    # Retention reads challenges by expiry, identity.judge by bound udid, and ADE minting by tenant and serial.
    'CREATE INDEX IF NOT EXISTS "idx_scep_challenges_expires" ON "scep_challenges" (expires_at)',
    'CREATE INDEX IF NOT EXISTS "idx_scep_challenges_bound_udid" ON "scep_challenges" (bound_udid) '
    'WHERE bound_udid IS NOT NULL',
    'CREATE INDEX IF NOT EXISTS "idx_scep_challenges_tenant_serial" ON "scep_challenges" (tenant_id, serial) '
    'WHERE serial IS NOT NULL',
    # Mac agent (models.agent) and the tenant default agent policy.
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "agent_policy" JSONB NULL',
    # The tenant agent list by last check-in, a device's task queue, and the elevation request lists.
    'CREATE INDEX IF NOT EXISTS "idx_device_agents_tenant_seen" ON "device_agents" (tenant_id, last_seen_at)',
    'CREATE INDEX IF NOT EXISTS "idx_agent_tasks_device_status_created" '
    'ON "agent_tasks" (device_id, status, created_at)',
    'CREATE INDEX IF NOT EXISTS "idx_agent_elevation_tenant_status_created" '
    'ON "agent_elevation_requests" (tenant_id, status, created_at)',
    'CREATE INDEX IF NOT EXISTS "idx_agent_elevation_device_user_status" '
    'ON "agent_elevation_requests" (device_id, username, status)',
    'CREATE INDEX IF NOT EXISTS "idx_agent_enrollment_codes_device" ON "agent_enrollment_codes" (device_id)',
    'CREATE INDEX IF NOT EXISTS "idx_agent_events_device_received" ON "agent_events" (device_id, received_at)',
]

# DDL applied where possible, logged and skipped where not, for constraints that existing data might already violate.
_BEST_EFFORT_DDL = [
    # One record per serial within a tenant, so placeholder adoption and re-enroll cannot create duplicates. Blank
    # serials are excluded.
    'CREATE UNIQUE INDEX IF NOT EXISTS "devices_tenant_serial_uniq" '
    "ON \"devices\" (tenant_id, serial_number) WHERE serial_number <> ''",
]

# Serializes the schema phase between processes, as IF NOT EXISTS is not atomic. Advisory lock keys share one
# namespace per database, so the key is derived from sha256 of the DDL list's qualified name, as hash() varies per
# process under PYTHONHASHSEED.
_AUX_DDL_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"micromanage.controller.models.database._AUX_DDL").digest()[:8],
    "big",
    signed=True,
)  # -8696307116457702301

# A ContextVar so two tasks calling init_schema() at once serialize on the lock, and only nesting inside one task is
# refused.
_IN_SCHEMA_LOCK: ContextVar[bool] = ContextVar(
    "micromanage_in_schema_lock", default=False
)


def is_postgres(conn=None) -> bool:
    """True when conn, or the default connection, is Postgres."""
    conn = conn if conn is not None else Tortoise.get_connection("default")
    return getattr(conn.capabilities, "dialect", None) == "postgres"


@asynccontextmanager
async def _schema_lock(conn):
    """Hold _AUX_DDL_LOCK_KEY on one pinned connection for the whole block, yielding it (None where there are no
    advisory locks). Guarded statements must run on that connection. Not re-entrant, so a nested acquisition raises.
    """
    log = logging.getLogger(__name__)

    if _IN_SCHEMA_LOCK.get():
        raise RuntimeError(
            "nested schema advisory lock: this task already holds "
            f"{_AUX_DDL_LOCK_KEY} and a second acquisition would wait on itself forever, undetectably. init_schema() "
            "already covers the aux DDL, so call _apply_aux_ddl(_ddl_executor(conn, pinned), log) inside the hold you "
            "have, instead of ensure_aux_columns() or init_schema()."
        )
    token = _IN_SCHEMA_LOCK.set(True)
    try:
        if not is_postgres(conn):
            # sqlite has no advisory locks and no second process; both DDL lists remain Postgres-only.
            yield None
            return

        async with conn.acquire_connection() as pinned:
            await pinned.execute(
                f"SELECT pg_advisory_lock({_AUX_DDL_LOCK_KEY}::bigint)"
            )
            try:
                yield pinned
            finally:
                # Runs on every path, as a leaked session lock blocks later startups. A dead connection has already
                # dropped the lock, and its error is not masked.
                try:
                    await pinned.execute(
                        f"SELECT pg_advisory_unlock({_AUX_DDL_LOCK_KEY}::bigint)"
                    )
                except Exception as exc:
                    log.warning("schema advisory unlock failed: %s", exc)
    finally:
        _IN_SCHEMA_LOCK.reset(token)


def _ddl_executor(conn, pinned):
    """Return the one-statement-at-a-time executor for this connection.

    On Postgres, runs on the connection holding the lock; elsewhere the ordinary Tortoise path.
    """
    if pinned is None:
        return conn.execute_script

    async def execute(sql: str) -> None:
        conn.log.debug(sql)  # parity with execute_script's own debug log
        await pinned.execute(sql)

    return execute


async def _apply_aux_ddl(execute, log) -> None:
    """Run both DDL lists through execute, one statement at a time."""
    for ddl in _AUX_DDL:
        # No try/except; a failure here is a real DDL problem.
        await execute(ddl)
    for ddl in _BEST_EFFORT_DDL:
        try:
            await execute(ddl)
        except Exception as exc:
            # For example legacy duplicate serials from before soft-unenroll; app-level dedup still applies.
            log.warning("aux DDL skipped (%s): %s", ddl[:60], exc)


async def ensure_aux_columns():
    """Apply the idempotent post-create DDL under the schema lock. Call after Tortoise is initialized. init_schema()
    covers startup; inside a hold of the lock call _apply_aux_ddl instead, as _schema_lock does not nest.
    """
    log = logging.getLogger(__name__)
    conn = Tortoise.get_connection("default")
    async with _schema_lock(conn) as pinned:
        await _apply_aux_ddl(_ddl_executor(conn, pinned), log)


async def init_schema():
    """Create the missing tables and apply the aux DDL as one critical section, as all three supervisord processes
    run this at startup. Covers the default connection only.
    """
    log = logging.getLogger(__name__)
    conn = Tortoise.get_connection("default")
    async with _schema_lock(conn) as pinned:
        execute = _ddl_executor(conn, pinned)
        if pinned is None:
            await Tortoise.generate_schemas()
        else:
            schema_sql = get_schema_sql(conn, safe=True)
            if schema_sql:
                await execute(schema_sql)
        await _apply_aux_ddl(execute, log)
        if pinned is not None:
            await _run_identity_cutover(log)
        await _record_schema_state(log, pinned)


async def _run_identity_cutover(log) -> None:
    """The one-time identity cutover, under the schema lock held by the caller."""
    from controller.services import identity
    try:
        await identity.run_cutover()
    except Exception:
        log.exception("identity cutover failed; it runs again at the next start")


def schema_fingerprint() -> str:
    """sha256 over everything init_schema applies, in order. Compared with the newest schema_state row to tell
    whether a database is at the schema this build expects."""
    conn = Tortoise.get_connection("default")
    parts = [get_schema_sql(conn, safe=True) or ""]
    parts.extend(_AUX_DDL)
    parts.extend(_BEST_EFFORT_DDL)
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


async def _record_schema_state(log, pinned=None) -> None:
    """Record that this database is at the running code's schema. A failure is logged and ignored. Raw SQL on the
    pinned connection, as an ORM query would open a second one.
    """
    from controller.models.tenant import SchemaState
    from controller.version import __version__
    try:
        fingerprint = schema_fingerprint()
        if pinned is not None:
            status = await pinned.execute(
                'INSERT INTO "schema_state" ("fingerprint", "controller_version", "applied_at") '
                'VALUES ($1, $2, now()) ON CONFLICT ("fingerprint") DO NOTHING',
                fingerprint, __version__,
            )
            # asyncpg returns the command tag, "INSERT 0 1" or "INSERT 0 0".
            recorded = not str(status).endswith(" 0")
        elif not await SchemaState.exists(fingerprint=fingerprint):
            await SchemaState.create(fingerprint=fingerprint, controller_version=__version__)
            recorded = True
        else:
            recorded = False
        if recorded:
            log.info("schema: recorded state %s (controller %s)", fingerprint[:12], __version__)
    except Exception as exc:
        log.warning("schema: could not record schema state: %s", exc)


async def schema_status() -> dict:
    """The newest recorded schema state next to what this build expects."""
    from controller.models.tenant import SchemaState
    expected = schema_fingerprint()
    try:
        latest = await SchemaState.all().order_by("-applied_at").first()
    except Exception:
        # A database from before this table existed, read without init_schema (tenant_cli schema status), reports
        # nothing recorded.
        latest = None
    return {
        "expected_fingerprint": expected,
        "recorded_fingerprint": latest.fingerprint if latest else None,
        "recorded_at": latest.applied_at.isoformat() if latest else None,
        "recorded_by_version": latest.controller_version if latest else None,
        "current": bool(latest and latest.fingerprint == expected),
    }


_DATABASE_URL_UNSET = (
    "DATABASE_URL is not set, so this process has no database to connect to. Set it to this deployment's Postgres DSN, "
    "for example postgres://postgres:<DB_PASSWORD>@postgres:5432/mdm_iac, in the .env file the stack reads (see "
    ".env.example); docker-compose.prod.yml builds it from DB_PASSWORD and passes it to the controller service, so a "
    "stack brought up that way already has it. There is no default: the one that used to be here pointed at a "
    "localhost database with a password published in this repository, which a deployment missing this variable would "
    "have connected to without saying anything."
)


def current_database_url() -> str:
    """DATABASE_URL as the environment has it now, blank when unset. The module constant is read once at import."""
    return os.getenv("DATABASE_URL", "")


def database_url_error() -> Optional[str]:
    """Why this process must not connect, or None."""
    return _DATABASE_URL_UNSET if not DATABASE_URL else None


def enforce_database_url() -> None:
    """Log the reason and raise SystemExit when there is no DSN to connect with. Call it at startup, not at import,
    as test suites import api.main and api.webhook while running Tortoise on their own sqlite.
    """
    problem = database_url_error()
    if problem:
        logging.getLogger(__name__).critical("Refusing to start: %s", problem)
        raise SystemExit(1)


async def init_db():
    enforce_database_url()
    await Tortoise.init(
        db_url=_pooled_url(DATABASE_URL),
        modules={"models": ["controller.models.tenant"]}
    )
    await init_schema()


async def init_db_no_schema():
    """Connect without modifying the schema, for read-only tooling (tenant_cli schema status)."""
    enforce_database_url()
    await Tortoise.init(
        db_url=_pooled_url(DATABASE_URL),
        modules={"models": ["controller.models.tenant"]}
    )


async def close_db():
    await Tortoise.close_connections()
