import hashlib
import logging
import os
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Optional

from tortoise import Tortoise
from tortoise.utils import get_schema_sql

# Blank when unset, never a default: a default DSN would let a process that lost the variable connect to the
# wrong database instead of saying so. Not a raise here; see enforce_database_url.
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Raised above Tortoise's per-process default of 5, since supervisord runs three processes and the reconciler
# alone runs up to MDM_MAX_CONCURRENT_TASKS handlers at once.
DB_POOL_MAX = int(os.getenv("DB_POOL_MAX_SIZE", "20"))
DB_POOL_MIN = int(os.getenv("DB_POOL_MIN_SIZE", "2"))

# Floor on the pool maximum: a pool of one deadlocks init_schema's schema phase, which pins one connection for
# the whole hold while other queries wait on it.
_MIN_POOL_MAX = 2


def _pooled_url(url: str) -> str:
    """Add pool sizing to a Postgres DSN, leaving a minimum the DSN already sets alone. Postgres only, since
    sqlite has no pool.
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
        # An unparseable maxsize already fails downstream at asyncpg. Leave it to fail there instead of inventing a new
        # error here.
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
                "pool minimum %s is above the configured maximum %s; using %s for both. asyncpg refuses "
                "min_size > max_size and the process would restart forever. Raise DB_POOL_MAX_SIZE if you meant the "
                "minimum.",
                minsize, maxsize, maxsize,
            )
            minsize = maxsize
        params["minsize"] = str(minsize)
    return urlunsplit(parts._replace(query=urlencode(params)))


# Columns added after the initial schema. generate_schemas() never alters existing tables, so these are applied
# by hand here. Keep the statements idempotent.
_AUX_DDL = [
    'ALTER TABLE "profile_deployments" ADD COLUMN IF NOT EXISTS "payload_hash" VARCHAR(64)',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "attributes" JSONB NOT NULL DEFAULT \'{}\'::jsonb',
    # Device lifecycle across enrollments (retain history; support DEP placeholders).
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "enrollment_state" VARCHAR(20) NOT NULL DEFAULT \'enrolled\'',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "management_type" VARCHAR(30) NOT NULL DEFAULT \'apple_mdm\'',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "unenrolled_at" TIMESTAMPTZ NULL',
    # udid becomes nullable so pre-provisioned placeholders (serial only) can exist.
    'ALTER TABLE "devices" ALTER COLUMN "udid" DROP NOT NULL',
    # Managed device name + per-tenant dynamic naming template.
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "name" VARCHAR(255) NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "device_naming" JSONB NOT NULL DEFAULT \'{}\'::jsonb',
    # Adaptive info-poll schedule (services.poller).
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "last_polled_at" TIMESTAMPTZ NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "poll_interval_minutes" INTEGER NOT NULL DEFAULT 30',
    # Imperative device tags (ATC/Dispatcher writers + manual); flat list[str], matched by the "tag" scope condition.
    # See services.scoping / models.tenant.
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "tags" JSONB NOT NULL DEFAULT \'[]\'::jsonb',
    # Admin-entered APNs cert and DEP token expiry dates. Entered by hand, since we can't read the live cert or a DEP
    # token. See models.tenant.
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "apns_cert_expires_at" TIMESTAMPTZ NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "dep_token_expires_at" TIMESTAMPTZ NULL',
    # Per-tenant object storage ceiling (models.tenant.Tenant.storage_quota_bytes).
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "storage_quota_bytes" BIGINT NULL',
    # FileVault recovery-key escrow keypair (services.filevault_escrow). The private key is Fernet-encrypted at rest;
    # the certificate is public.
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "fv_escrow_private_key_enc" TEXT NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "fv_escrow_cert_pem" TEXT NULL',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "fv_escrow_cert_expires_at" TIMESTAMPTZ NULL',
    # Automated Device Enrollment (ADE/DEP) device linkage (services.dep_manager). Populated for devices synced from
    # Apple Business/School Manager; null for OTA/manual. See models.DepServer.
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "dep_server_id" UUID NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "dep_profile_uuid" VARCHAR(64) NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "dep_profile_status" VARCHAR(30) NULL',
    'ALTER TABLE "devices" ADD COLUMN IF NOT EXISTS "dep_last_synced_at" TIMESTAMPTZ NULL',
    # DepServer.sync_cursor widened from VARCHAR(255) to TEXT: Apple allows up to 1000 characters here and an
    # over-long cursor silently fell back to a full fleet fetch every tick.
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
    # ATC: a run's entry node and the event that started it (run identity is device, flow_id, start_node). See
    # models.py and the doc for why flow_id leads and why two indexes.
    'ALTER TABLE "flow_runs" ADD COLUMN IF NOT EXISTS "start_node" VARCHAR(100) NULL',
    'ALTER TABLE "flow_runs" ADD COLUMN IF NOT EXISTS "event_kind" VARCHAR(20) NULL',
    'CREATE INDEX IF NOT EXISTS "idx_flowruns_dev_flow_start_event" '
    'ON "flow_runs" (device_id, flow_id, start_node, event_kind, started_at)',
    'CREATE INDEX IF NOT EXISTS "idx_flowruns_tenant_flow_start_event_dev" '
    'ON "flow_runs" (tenant_id, flow_id, start_node, event_kind, device_id, started_at)',
    # The pre-multi-flow pair the two above replace. Dropped after the creates, so a failed upgrade never leaves the
    # table with neither.
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
    # Plain UUID, no FK: the retention sweep deletes tasks, and a dangling pointer just means the attempt aged
    # out. See models.tenant.AppDeployment.
    'ALTER TABLE "app_deployments" ADD COLUMN IF NOT EXISTS "last_task_id" UUID NULL',
    'ALTER TABLE "profile_deployments" ADD COLUMN IF NOT EXISTS "last_task_id" UUID NULL',
    # Paces services.reconciler's retry backoff. NOT NULL DEFAULT 0, since the loop reads this on every row.
    'ALTER TABLE "app_deployments" ADD COLUMN IF NOT EXISTS '
    '"failed_attempts" INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE "profile_deployments" ADD COLUMN IF NOT EXISTS '
    '"failed_attempts" INTEGER NOT NULL DEFAULT 0',
    # Device-reported version, which need not match what the deployment asked for. NULL means never
    # confirmed. TEXT because the device-supplied string length is not ours to promise.
    'ALTER TABLE "app_deployments" ADD COLUMN IF NOT EXISTS '
    '"reported_version" TEXT',
    # Who asked for a profile the device's own scope does not, written as remediation:<rule id>; NULL is the
    # ordinary scoped case. TEXT since a rule id is authored and unbounded. See models.tenant.ProfileDeployment.
    'ALTER TABLE "profile_deployments" ADD COLUMN IF NOT EXISTS '
    '"install_source" TEXT NULL',
    'ALTER TABLE "app_deployments" ADD COLUMN IF NOT EXISTS '
    '"install_source" TEXT NULL',
    # Session cut-off for a password change (auth.dependencies). Null on every existing row, which reads as "never
    # changed" and refuses nothing.
    'ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "password_changed_at" TIMESTAMPTZ NULL',
    # Session cut-off for disabling two-factor auth (auth.dependencies), which deletes the UserMFA row rather than
    # updating a column on it, so the cut-off has to live here on User. See models.tenant.UserMFA.
    'ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "mfa_changed_at" TIMESTAMPTZ NULL',
    # Task.command_uuid: MDM CommandUUID mirrored out of details (models.tenant.Task.save) so webhook_handler
    # gets an indexed equality lookup instead of scanning the device's 50 newest tasks.
    'ALTER TABLE "tasks" ADD COLUMN IF NOT EXISTS "command_uuid" VARCHAR(64) NULL',
    'UPDATE "tasks" SET "command_uuid" = "details"->>\'command_uuid\' '
    "WHERE \"command_uuid\" IS NULL AND \"details\"->>'command_uuid' IS NOT NULL",
    # Partial: tasks that never enqueued a command stay NULL and are never looked up this way.
    'CREATE INDEX IF NOT EXISTS "idx_tasks_command_uuid" '
    'ON "tasks" (command_uuid) WHERE command_uuid IS NOT NULL',
    # Task.dedup_key: the reconciler's duplicate-task key, mirrored the same way command_uuid is (see
    # models.tenant.task_dedup_key). TEXT not VARCHAR(n).
    'ALTER TABLE "tasks" ADD COLUMN IF NOT EXISTS "dedup_key" TEXT NULL',
    # Backfill: matches only rows whose key SQL can reproduce identically (every component a JSON string). See
    # the doc for why str() and ->> disagree otherwise, and how reconciler._unmirrored_task_keys covers the rest.
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
    # Fixes legacy rows where installed_apps holds an object (from the old model default of {}) instead of the
    # array Apple actually sends; nothing writes an object here now.
    'UPDATE "devices" SET "installed_apps" = \'[]\'::jsonb '
    "WHERE jsonb_typeof(\"installed_apps\") = 'object'",

    # ==Indexes for the hot paths==
    # Tortoise indexes only primary keys and unique_together, so every query below was a sequential scan.
    # Plain CREATE INDEX, not CONCURRENTLY.

    # The device command list (api.main) and the pending-task cancel on checkout.
    'CREATE INDEX IF NOT EXISTS "idx_tasks_device_created" '
    'ON "tasks" (device_id, created_at DESC)',
    # reconciler._active_task_keys / _fail_timed_out_tasks, the Tasks list page, and poller._prune_scheduled_tasks.
    'CREATE INDEX IF NOT EXISTS "idx_tasks_tenant_status_created" '
    'ON "tasks" (tenant_id, status, created_at)',
    # dispatcher._active_alert and _recent_remediation_state run per (device, rule) for every rule on every evaluation,
    # so this one is per-check-in hot.
    'CREATE INDEX IF NOT EXISTS "idx_alerts_device_rule_status" '
    'ON "alerts" (device_id, rule_id, status)',
    # The tenant alert list and the unresolved severity counts.
    'CREATE INDEX IF NOT EXISTS "idx_alerts_tenant_status" '
    'ON "alerts" (tenant_id, status)',
    # ATC manual-gate alerts are looked up by rule_id alone (atc:gate:<run>).
    'CREATE INDEX IF NOT EXISTS "idx_alerts_rule" ON "alerts" (rule_id)',
    # The fleet sweep every loop starts with: reconciler, poller, dispatcher, ATC schedule starts and the dashboard
    # counts.
    'CREATE INDEX IF NOT EXISTS "idx_devices_tenant_enrollstate" '
    'ON "devices" (tenant_id, enrollment_state)',
    # atc.sweep_timeouts (waiting + deadline) and the orphaned-running recovery, both of which run per tenant on every
    # poll tick.
    'CREATE INDEX IF NOT EXISTS "idx_flowruns_tenant_status_deadline" '
    'ON "flow_runs" (tenant_id, status, wait_deadline)',
    # The fleet run list sorts newest-first across a whole tenant, so the index above, which leads with status, does not
    # serve it. Check-in triggered flows can add dozens of rows per device per day.
    'CREATE INDEX IF NOT EXISTS "idx_flowruns_tenant_started" '
    'ON "flow_runs" (tenant_id, started_at DESC)',
    # The audit log query is tenant-scoped and always newest-first.
    'CREATE INDEX IF NOT EXISTS "idx_auditlogs_tenant_created" '
    'ON "audit_logs" (tenant_id, created_at DESC)',
    # webhook_handler._record_attempt does this lookup on the enrollment path, for exactly the devices that are already
    # failing repeatedly.
    'CREATE INDEX IF NOT EXISTS "idx_enrollattempts_udid_outcome" '
    'ON "enrollment_attempts" (udid, outcome)',
    # reconciler._fail_timed_out_tasks looks deployments up by the task that was installing them. Partial, because a row
    # only has a pointer once something has tried to deploy it.
    'CREATE INDEX IF NOT EXISTS "idx_appdeploy_last_task" '
    'ON "app_deployments" (last_task_id) WHERE last_task_id IS NOT NULL',
    'CREATE INDEX IF NOT EXISTS "idx_profiledeploy_last_task" '
    'ON "profile_deployments" (last_task_id) WHERE last_task_id IS NOT NULL',
    # Both deployment tables are read tenant-wide on every tick by the reconciler, dispatcher, and poller. See
    # the doc for why status is the second column on the app one but not the profile one.
    'CREATE INDEX IF NOT EXISTS "idx_appdeploy_tenant_status" '
    'ON "app_deployments" (tenant_id, status)',
    'CREATE INDEX IF NOT EXISTS "idx_profiledeploy_tenant" '
    'ON "profile_deployments" (tenant_id)',
    # The daily retention sweep (services.task_manager.run_retention), whose cross-tenant deletes miss every
    # tenant-led index above. Status leads and this is composite, not partial.
    'CREATE INDEX IF NOT EXISTS "idx_tasks_status_completed" '
    'ON "tasks" (status, completed_at)',
    'CREATE INDEX IF NOT EXISTS "idx_alerts_status_resolved" '
    'ON "alerts" (status, resolved_at)',
    'CREATE INDEX IF NOT EXISTS "idx_flowruns_status_started" '
    'ON "flow_runs" (status, started_at)',
    'ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "payload_identifier_prefix" VARCHAR(120) NULL',
]

# Best-effort DDL: applied where possible, logged and skipped where not. For constraints that existing data might
# already violate.
_BEST_EFFORT_DDL = [
    # A physical device is uniquely identified within a tenant by its serial. Enforces one record per serial so
    # placeholder adoption / re-enroll can't create duplicates. Excludes blank serials (placeholders always have one).
    'CREATE UNIQUE INDEX IF NOT EXISTS "devices_tenant_serial_uniq" '
    "ON \"devices\" (tenant_id, serial_number) WHERE serial_number <> ''",
]

# Serializes the whole schema-establishment phase between processes, since IF NOT EXISTS is not atomic.
# Derived, not picked: advisory lock keys share one namespace per database, so sha256 of the DDL list's
# qualified name, not hash() since PYTHONHASHSEED would give each process a different key.
_AUX_DDL_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"micromanage.controller.models.database._AUX_DDL").digest()[:8],
    "big",
    signed=True,
)  # -8696307116457702301

# ContextVar, not a module flag: two separate tasks calling init_schema() at once should serialize correctly
# in Postgres, and only nesting inside one task is a bug. See _schema_lock.
_IN_SCHEMA_LOCK: ContextVar[bool] = ContextVar(
    "micromanage_in_schema_lock", default=False
)


@asynccontextmanager
async def _schema_lock(conn):
    """Hold _AUX_DDL_LOCK_KEY on one pinned connection for the whole block (yielded, or None with no advisory
    locks). Must stay on that one connection; a lock taken through the pool is gone before the next statement
    runs. Not re-entrant: refuses rather than hangs, since a nested acquisition deadlocks invisibly to Postgres.
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
        if getattr(conn.capabilities, "dialect", None) != "postgres":
            # sqlite has no advisory locks and no second process to race. Does not make the module portable;
            # both DDL lists are still Postgres-only.
            yield None
            return

        async with conn.acquire_connection() as pinned:
            await pinned.execute(
                f"SELECT pg_advisory_lock({_AUX_DDL_LOCK_KEY}::bigint)"
            )
            try:
                yield pinned
            finally:
                # Every path, including a raising one: a leaked session lock would block every later startup.
                # Guarded since a dead connection has already dropped the lock and must not mask its own error.
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
        # No try/except. These are the statements the schema is required to have, and the advisory lock above removes
        # the one failure that was benign, so anything still raising is a real DDL problem.
        await execute(ddl)
    for ddl in _BEST_EFFORT_DDL:
        try:
            await execute(ddl)
        except Exception as exc:
            # e.g. legacy duplicate serials from before soft-unenroll existed; app-level dedup still applies (adoption
            # tolerates duplicates).
            log.warning("aux DDL skipped (%s): %s", ddl[:60], exc)


async def ensure_aux_columns():
    """Apply the idempotent post-create DDL. Call after Tortoise is initialized.

    Mutually exclusive between processes via the session-level advisory lock (_AUX_DDL_LOCK_KEY). Nothing in the
    repo calls this today; init_schema() covers startup. Never call from inside a hold of the lock, since
    _schema_lock refuses to nest; call _apply_aux_ddl directly there instead.
    """
    log = logging.getLogger(__name__)
    conn = Tortoise.get_connection("default")
    async with _schema_lock(conn) as pinned:
        await _apply_aux_ddl(_ddl_executor(conn, pinned), log)


async def init_schema():
    """Create the missing tables and apply the aux DDL, as one critical section.

    All three supervisord processes run this at startup and race on a fresh database, so both phases sit inside
    one hold of _AUX_DDL_LOCK_KEY rather than two sequential ones. Covers the default connection only. See the
    doc for why the schema SQL runs on the pinned connection instead of Tortoise.generate_schemas().
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
        await _record_schema_state(log, pinned)


def schema_fingerprint() -> str:
    """sha256 over everything init_schema applies, in order. Compared with the newest schema_state row to tell
    whether a database is at the schema this build expects."""
    conn = Tortoise.get_connection("default")
    parts = [get_schema_sql(conn, safe=True) or ""]
    parts.extend(_AUX_DDL)
    parts.extend(_BEST_EFFORT_DDL)
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


async def _record_schema_state(log, pinned=None) -> None:
    """Record that this database is at the running code's schema.

    Idempotent; a failure is logged and swallowed, since the schema is applied either way. Writes through the
    pinned connection as SQL, not the ORM: an ORM query would ask the pool for a second connection that a pool
    of one can never supply while the caller holds the schema lock on the first.
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
        # A database from before this table existed, read without init_schema (tenant_cli schema status). Nothing
        # recorded is the honest answer.
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
    """DATABASE_URL as the environment has it now, blank when unset.

    The module constant is read once at import; this is for a caller running long after import that wants
    whatever the environment says then (services.nanomdm_store).
    """
    return os.getenv("DATABASE_URL", "")


def database_url_error() -> Optional[str]:
    """Why this process must not connect, or None."""
    return _DATABASE_URL_UNSET if not DATABASE_URL else None


def enforce_database_url() -> None:
    """Refuse to go on when there is no DSN to connect with.

    Startup only, never at import: api.main and api.webhook build their register_tortoise config from this at
    import, and test suites import both while running Tortoise on their own sqlite. Raises SystemExit with one
    explanatory line, so the reason is the last thing in the container's output, not buried in a restart loop.
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
    """Connect without touching the schema, for read-only tooling that wants to describe the database as it is
    (tenant_cli schema status)."""
    enforce_database_url()
    await Tortoise.init(
        db_url=_pooled_url(DATABASE_URL),
        modules={"models": ["controller.models.tenant"]}
    )


async def close_db():
    await Tortoise.close_connections()
