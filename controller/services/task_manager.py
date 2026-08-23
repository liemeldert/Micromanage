import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

from controller.models.tenant import Alert, AuditLog, Device, FlowRun, Task, Tenant

logger = logging.getLogger(__name__)

# Retention windows for the three tables that grow with fleet activity rather than fleet size. Check-ins produce tasks,
# alerts and flow runs continuously, and without a sweep the only bound is disk.
TASK_RETENTION_DAYS = int(os.getenv("TASK_RETENTION_DAYS", "30"))
ALERT_RETENTION_DAYS = int(os.getenv("ALERT_RETENTION_DAYS", "90"))
FLOW_RUN_RETENTION_DAYS = int(os.getenv("FLOW_RUN_RETENTION_DAYS", "30"))

# Audit log retention defaults to 0; see DEPLOY.md and the doc for reasoning.
AUDIT_LOG_RETENTION_DAYS = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "0"))

# Row count that starts a warning on every retention pass, independent of deletion, so an operator sees the table
# growing while AUDIT_LOG_RETENTION_DAYS is left at 0.
AUDIT_LOG_SIZE_WARNING_ROWS = int(os.getenv("AUDIT_LOG_SIZE_WARNING_ROWS", "100000"))


class TaskManager:
    """Background task bookkeeping: creates Task rows and tracks the asyncio tasks running in this process."""

    def __init__(self):
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.task_handlers: Dict[str, Callable] = {}

    async def create_task(self, tenant: Tenant, task_type: str,
                          description: str, device: Optional[Device] = None,
                          user: Optional[str] = None, details: Dict[str, Any] = None) -> Task:
        task = await Task.create(
            tenant=tenant,
            type=task_type,
            status='pending',
            description=description,
            device=device,
            user=user,
            details=details or {}
        )
        logger.info(f"Created task {task.id}: {description}")
        return task

    async def execute_task(self, task: Task, handler: Callable):
        """Execute a task with the given handler. See the doc for status ownership details."""
        task_id = str(task.id)

        try:
            await task.update_progress(0, 'running')

            async_task = asyncio.create_task(handler(task))
            self.running_tasks[task_id] = async_task

            await async_task

            # Re-read: the handler and deploy path update the row through separate objects.
            await task.refresh_from_db()
            if task.status in ('pending', 'running') and not (task.details or {}).get('command_uuid'):
                await task.update_progress(100, 'completed')

        except asyncio.CancelledError:
            await task.update_progress(task.progress, 'cancelled')
            raise
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            task.error = str(e)
            await task.update_progress(task.progress, 'failed')
        finally:
            self.running_tasks.pop(task_id, None)

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel the in-process asyncio task, if this process is running it. Callers must cancel the DB row separately."""
        if task_id in self.running_tasks:
            self.running_tasks[task_id].cancel()
            return True
        return False

    async def cleanup_old_tasks(self, days: int = None):
        """Delete finished tasks older than the retention window, across every tenant. See the doc for completion_at/created_at logic."""
        days = TASK_RETENTION_DAYS if days is None else days
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        from tortoise.expressions import Q

        deleted_count = await Task.filter(
            Q(completed_at__lt=cutoff_date)
            | Q(completed_at__isnull=True, created_at__lt=cutoff_date),
            status__in=['completed', 'failed', 'cancelled'],
        ).delete()

        if deleted_count:
            logger.info(f"retention: deleted {deleted_count} finished task(s)")
        return deleted_count

    async def get_task_stats(self, tenant: Tenant) -> Dict[str, Any]:
        """Task totals for a tenant, plus how many of them are running in this process."""
        from tortoise.functions import Count

        stats = await Task.filter(tenant=tenant).annotate(
            count=Count('id')
        ).group_by('status').values('status', 'count')

        return {
            'total': sum(s['count'] for s in stats),
            'by_status': {s['status']: s['count'] for s in stats},
            'running': len([t for t in self.running_tasks.values() if not t.done()])
        }


async def cleanup_resolved_alerts(days: int = None) -> int:
    """Delete resolved alerts past the retention window. Pending, open and acknowledged are live triage state."""
    days = ALERT_RETENTION_DAYS if days is None else days
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = await Alert.filter(status="resolved", resolved_at__lt=cutoff).delete()
    if deleted:
        logger.info(f"retention: deleted {deleted} resolved alert(s)")
    return deleted


async def cleanup_old_flow_runs(days: int = None) -> int:
    """Delete terminal ATC flow runs past the retention window. See the doc for retention reasoning."""
    days = FLOW_RUN_RETENTION_DAYS if days is None else days
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = await FlowRun.filter(
        status__in=["completed", "failed", "cancelled"], started_at__lt=cutoff
    ).delete()
    if deleted:
        logger.info(f"retention: deleted {deleted} finished flow run(s)")
    return deleted


async def cleanup_old_audit_log(days: int = None) -> int:
    """Delete machine-attributed audit log rows past the retention window. Disabled by default; see the doc."""
    days = AUDIT_LOG_RETENTION_DAYS if days is None else days
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = await AuditLog.filter(actor_email__isnull=True, created_at__lt=cutoff).delete()
    if deleted:
        logger.info(f"retention: deleted {deleted} machine-attributed audit log row(s)")
    return deleted


async def warn_on_audit_log_size(threshold: int = None) -> int:
    """Log a warning once audit log crosses threshold, and return row count. Runs every pass regardless of retention setting."""
    threshold = AUDIT_LOG_SIZE_WARNING_ROWS if threshold is None else threshold
    count = await AuditLog.all().count()
    if count >= threshold:
        logger.warning(
            "retention: audit_logs has grown to %d rows (warning threshold %d); expected with "
            "AUDIT_LOG_RETENTION_DAYS at its default of 0, which deletes nothing. Read DEPLOY.md's audit log "
            "retention section before changing it: it only ever prunes machine-attributed rows",
            count, threshold,
        )
    return count


async def run_retention() -> Dict[str, int]:
    """Run one maintenance pass: delete old tasks, alerts, flow runs; warn on audit log size. Each step is independent."""
    out = {"tasks": 0, "alerts": 0, "flow_runs": 0, "audit_log": 0}
    for key, fn in (("tasks", TaskManager().cleanup_old_tasks),
                    ("alerts", cleanup_resolved_alerts),
                    ("flow_runs", cleanup_old_flow_runs),
                    ("audit_log", cleanup_old_audit_log)):
        try:
            out[key] = await fn() or 0
        except Exception:
            logger.exception("retention: %s sweep failed", key)
    try:
        await warn_on_audit_log_size()
    except Exception:
        logger.exception("retention: audit log size check failed")
    return out
